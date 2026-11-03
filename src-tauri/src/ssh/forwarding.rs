//! Forwarding as ssh does it for a session with ssh_config settings:
//! LocalForward, RemoteForward and DynamicForward (TCP and Unix sockets,
//! SOCKS 4/4a/5), GatewayPorts, ExitOnForwardFailure, ClearAllForwardings,
//! PermitRemoteOpen, StreamLocalBindMask/Unlink, ChannelTimeout, and
//! ForwardAgent. Ported from channels.c and clientloop.c.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::client::Msg;
use russh::Channel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::client::SharedHandle;
use super::sshconf::forward::{End, Forward};
use super::userauth::AgentChoice;

/// What ssh_config says about forwarding.
#[derive(Debug, Clone, Default)]
pub struct ForwardPolicy {
    /// LocalForward and DynamicForward (connect None), in order.
    pub local: Vec<Forward>,
    pub remote: Vec<Forward>,
    pub gateway_ports: bool,
    pub exit_on_failure: bool,
    /// PermitRemoteOpen for remote dynamic forwards: `None` is any.
    pub permit_remote_open: Option<Vec<String>>,
    pub bind_mask: u32,
    pub bind_unlink: bool,
    /// ForwardAgent, when on and approved.
    pub agent: Option<AgentChoice>,
    /// ChannelTimeout entries, (type pattern, idle time).
    pub timeouts: Vec<(String, Duration)>,
    /// ForwardX11, when on and approved.
    pub x11: Option<super::x11::X11Config>,
    /// Tunnel, when on and approved (see `tun`).
    pub tun: Option<super::tun::TunConfig>,
}

impl ForwardPolicy {
    fn timeout_for(&self, kind: &str) -> Option<Duration> {
        self.timeouts.iter().find(|(p, _)| p == "global" || super::sshconf::pattern::match_pattern(kind, p)).map(|(_, d)| *d)
    }
}

/// A forward the server listens for, and where its connections go.
#[derive(Debug, Clone)]
struct RemoteEntry {
    /// The address and port as the server reports them on each channel.
    listen_host: String,
    listen_port: u32,
    listen_path: Option<String>,
    /// `None`: remote dynamic forwarding (Reach answers SOCKS).
    target: Option<End>,
}

/// What the handler needs to answer channels the server opens.
#[derive(Debug, Default)]
pub struct ForwardTable {
    remote: Mutex<Vec<RemoteEntry>>,
    policy: Mutex<ForwardPolicy>,
    /// The X11 cookies the session asked for; X11 channels are refused
    /// without them.
    x11: Mutex<Option<super::x11::X11Auth>>,
    /// X11 was set up (or tried and failed) for this connection already.
    x11_tried: std::sync::atomic::AtomicBool,
}

impl ForwardTable {
    pub fn new(policy: ForwardPolicy) -> Arc<Self> {
        Arc::new(ForwardTable { remote: Mutex::new(Vec::new()), policy: Mutex::new(policy), x11: Mutex::new(None), x11_tried: Default::default() })
    }

    fn policy(&self) -> ForwardPolicy {
        self.policy.lock().unwrap().clone()
    }

    /// The X11 cookies prepared already (`prepare_x11`), if any.
    pub fn prepared_x11(&self) -> Option<super::x11::X11Auth> {
        self.x11.lock().unwrap().clone()
    }

    /// The X11 request for the session channel, when ForwardX11 is on.
    /// A setup failure leaves X11 off and the session going, as with ssh.
    pub async fn prepare_x11(&self) -> Option<super::x11::X11Auth> {
        let cfg = self.policy().x11?;
        if self.x11_tried.swap(true, std::sync::atomic::Ordering::SeqCst) {
            // Once per connection: a failure says so once, not per step.
            return self.prepared_x11();
        }
        match super::x11::prepare(&cfg).await {
            Ok(a) => {
                *self.x11.lock().unwrap() = Some(a.clone());
                Some(a)
            }
            Err(e) => {
                tracing::warn!("X11 forwarding: {e}");
                None
            }
        }
    }
}

fn end_label(e: &End) -> String {
    match e {
        End::Tcp { host: Some(h), port } => format!("{h}:{port}"),
        End::Tcp { host: None, port } => port.to_string(),
        End::Socket { path } => path.clone(),
    }
}

pub fn describe(f: &Forward) -> String {
    match &f.connect {
        Some(c) => format!("{} -> {}", end_label(&f.listen), end_label(c)),
        None => format!("{} (SOCKS)", end_label(&f.listen)),
    }
}

/// channel_fwd_bind_addr for a client: no address is loopback (all
/// addresses under GatewayPorts); "" or "*" is all; "localhost" is
/// loopback; anything else is that address.
fn bind_addrs(host: Option<&str>, port: u16, gateway_ports: bool) -> Vec<SocketAddr> {
    let loopback = vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))];
    let wildcard = vec![SocketAddr::from(([0, 0, 0, 0], port)), SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port))];
    match host {
        None if gateway_ports => wildcard,
        None => loopback,
        Some("") | Some("*") => wildcard,
        Some("localhost") => loopback,
        Some(h) => {
            use std::net::ToSocketAddrs;
            (h, port).to_socket_addrs().map(|a| a.collect()).unwrap_or_default()
        }
    }
}

/// Copy both ways until either side ends, closing early when idle longer
/// than `idle` (ChannelTimeout).
pub(crate) async fn relay<A, B>(a: A, b: B, idle: Option<Duration>)
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let started = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let l1 = last.clone();
    let l2 = last.clone();
    let one = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match ar.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            l1.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
            if bw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = bw.shutdown().await;
    };
    let two = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            l2.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
            if aw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = aw.shutdown().await;
    };
    let watch = async {
        let Some(limit) = idle else { return std::future::pending::<()>().await };
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let since = started.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
            if since >= limit {
                return;
            }
        }
    };
    tokio::select! {
        _ = async { tokio::join!(one, two) } => {}
        _ = watch => tracing::info!("Forwarded connection closed after {}s idle (ChannelTimeout)", idle.unwrap_or_default().as_secs()),
    }
}

/// The SOCKS request a client sent: where it wants to go.
struct SocksRequest {
    host: String,
    port: u16,
    version: u8,
}

/// Read a SOCKS 4, 4a or 5 CONNECT request (no authentication), as ssh's
/// dynamic forwarding accepts them.
async fn socks_read<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<SocksRequest> {
    let bad = |m: &str| std::io::Error::other(m.to_string());
    let v = s.read_u8().await?;
    match v {
        4 => {
            let cmd = s.read_u8().await?;
            if cmd != 1 {
                return Err(bad("SOCKS4: only CONNECT"));
            }
            let port = s.read_u16().await?;
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            let _user = read_cstr(s).await?;
            // 4a: 0.0.0.x means a host name follows.
            let host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
                String::from_utf8_lossy(&read_cstr(s).await?).into_owned()
            } else {
                std::net::Ipv4Addr::from(ip).to_string()
            };
            Ok(SocksRequest { host, port, version: 4 })
        }
        5 => {
            let n = s.read_u8().await?;
            let mut methods = vec![0u8; n as usize];
            s.read_exact(&mut methods).await?;
            if !methods.contains(&0) {
                s.write_all(&[5, 0xff]).await?;
                return Err(bad("SOCKS5: no acceptable method"));
            }
            s.write_all(&[5, 0]).await?;
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await?;
            if head[1] != 1 {
                s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                return Err(bad("SOCKS5: only CONNECT"));
            }
            let host = match head[3] {
                1 => {
                    let mut ip = [0u8; 4];
                    s.read_exact(&mut ip).await?;
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                3 => {
                    let len = s.read_u8().await?;
                    let mut name = vec![0u8; len as usize];
                    s.read_exact(&mut name).await?;
                    String::from_utf8_lossy(&name).into_owned()
                }
                4 => {
                    let mut ip = [0u8; 16];
                    s.read_exact(&mut ip).await?;
                    std::net::Ipv6Addr::from(ip).to_string()
                }
                _ => return Err(bad("SOCKS5: bad address type")),
            };
            let port = s.read_u16().await?;
            Ok(SocksRequest { host, port, version: 5 })
        }
        _ => Err(bad("not a SOCKS request")),
    }
}

/// A NUL-terminated string (SOCKS4 user id and 4a host name).
async fn read_cstr<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = s.read_u8().await?;
        if b == 0 || out.len() > 255 {
            break;
        }
        out.push(b);
    }
    Ok(out)
}

async fn socks_reply<S: AsyncWrite + Unpin>(s: &mut S, version: u8, ok: bool) -> std::io::Result<()> {
    if version == 4 {
        s.write_all(&[0, if ok { 0x5a } else { 0x5b }, 0, 0, 0, 0, 0, 0]).await
    } else {
        s.write_all(&[5, if ok { 0 } else { 5 }, 0, 1, 0, 0, 0, 0, 0, 0]).await
    }
}

/// Open the channel a local forward's connection goes through.
async fn open_to(handle: &SharedHandle, target: &End, from: &str, from_port: u32) -> Result<Channel<Msg>, String> {
    let h = handle.lock().await;
    match target {
        End::Tcp { host, port } => h
            .channel_open_direct_tcpip(host.clone().unwrap_or_else(|| "localhost".into()), *port as u32, from, from_port)
            .await
            .map_err(|e| e.to_string()),
        End::Socket { path } => h.channel_open_direct_streamlocal(path.clone()).await.map_err(|e| e.to_string()),
    }
}

/// One listener of a local forward; dropping it stops the forward.
pub struct LocalForwardTask {
    pub forward: Forward,
    stop: tokio::sync::watch::Sender<bool>,
}

impl Drop for LocalForwardTask {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// A connection's forwards, as they run.
pub struct Forwarder {
    handle: SharedHandle,
    table: Arc<ForwardTable>,
    locals: tokio::sync::Mutex<Vec<LocalForwardTask>>,
    tun: tokio::sync::Mutex<Option<super::tun::TunTask>>,
}

impl Forwarder {
    /// Set up every forward the config names. Under ExitOnForwardFailure
    /// a forward that cannot be set up fails the connection, as in ssh;
    /// otherwise it is reported and the rest go on.
    pub async fn start(handle: SharedHandle, table: Arc<ForwardTable>) -> Result<(Arc<Forwarder>, Vec<String>), String> {
        let policy = table.policy();
        let f = Arc::new(Forwarder { handle, table, locals: tokio::sync::Mutex::new(Vec::new()), tun: tokio::sync::Mutex::new(None) });
        let mut notes = Vec::new();
        for fwd in &policy.local {
            match f.add_local(fwd.clone()).await {
                Ok(m) => notes.push(m),
                Err(e) if policy.exit_on_failure => return Err(format!("LocalForward {}: {e} (ExitOnForwardFailure)", describe(fwd))),
                Err(e) => notes.push(format!("Warning: LocalForward {}: {e}", describe(fwd))),
            }
        }
        for fwd in &policy.remote {
            match f.add_remote(fwd.clone()).await {
                Ok(m) => notes.push(m),
                Err(e) if policy.exit_on_failure => return Err(format!("RemoteForward {}: {e} (ExitOnForwardFailure)", describe(fwd))),
                Err(e) => notes.push(format!("Warning: RemoteForward {}: {e}", describe(fwd))),
            }
        }
        // Then the tunnel, as ssh_init_forwarding does.
        if let Some(cfg) = &policy.tun {
            match super::tun::start(&f.handle, cfg).await {
                Ok((task, m)) => {
                    notes.push(m);
                    *f.tun.lock().await = Some(task);
                }
                Err(e) if policy.exit_on_failure => return Err(format!("Tunnel: {e} (ExitOnForwardFailure)")),
                Err(e) => notes.push(format!("Warning: Tunnel: {e}")),
            }
        }
        Ok((f, notes))
    }

    /// LocalForward or DynamicForward (no connect end).
    pub async fn add_local(&self, fwd: Forward) -> Result<String, String> {
        let policy = self.table.policy();
        let (tx, rx) = tokio::sync::watch::channel(false);
        match &fwd.listen {
            End::Tcp { host, port } => {
                let mut listeners = Vec::new();
                let mut last_err = String::from("no address to listen on");
                for addr in bind_addrs(host.as_deref(), *port, policy.gateway_ports) {
                    match tokio::net::TcpListener::bind(addr).await {
                        Ok(l) => listeners.push(l),
                        Err(e) => last_err = format!("cannot listen on {addr}: {e}"),
                    }
                }
                if listeners.is_empty() {
                    return Err(last_err);
                }
                for l in listeners {
                    let handle = self.handle.clone();
                    let target = fwd.connect.clone();
                    let mut rx = rx.clone();
                    let idle = policy.timeout_for(if target.is_some() { "direct-tcpip" } else { "dynamic-tcpip" });
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = rx.changed() => break,
                                accepted = l.accept() => {
                                    let Ok((sock, peer)) = accepted else { continue };
                                    let handle = handle.clone();
                                    let target = target.clone();
                                    tokio::spawn(async move { serve_local(handle, sock, peer, target, idle).await });
                                }
                            }
                        }
                    });
                }
            }
            End::Socket { path } => {
                #[cfg(unix)]
                {
                    let l = bind_socket(path, policy.bind_mask, policy.bind_unlink)?;
                    let handle = self.handle.clone();
                    let target = fwd.connect.clone();
                    let mut rx = rx.clone();
                    let idle = policy.timeout_for("direct-streamlocal@openssh.com");
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = rx.changed() => break,
                                accepted = l.accept() => {
                                    let Ok((sock, _)) = accepted else { continue };
                                    let handle = handle.clone();
                                    let target = target.clone();
                                    tokio::spawn(async move {
                                        let peer = SocketAddr::from(([127, 0, 0, 1], 0));
                                        serve_local(handle, sock, peer, target, idle).await
                                    });
                                }
                            }
                        }
                    });
                }
                #[cfg(not(unix))]
                return Err(format!("a Unix socket ({path}) cannot be listened on here"));
            }
        }
        let msg = format!("Forwarding {}", describe(&fwd));
        self.locals.lock().await.push(LocalForwardTask { forward: fwd, stop: tx });
        Ok(msg)
    }

    /// RemoteForward: the server listens and opens a channel per connection.
    pub async fn add_remote(&self, fwd: Forward) -> Result<String, String> {
        let h = self.handle.lock().await;
        match &fwd.listen {
            End::Tcp { host, port } => {
                // A forward with no address asks for localhost; "" and "*"
                // ask for every address (the server's GatewayPorts decides).
                let addr = match host.as_deref() {
                    None => "localhost".to_string(),
                    Some("*") => String::new(),
                    Some(h) => h.to_string(),
                };
                let got = h.tcpip_forward(addr.clone(), *port as u32).await.map_err(|e| format!("the server refused: {e}"))?;
                let actual = if *port == 0 { got } else { *port as u32 };
                self.table.remote.lock().unwrap().push(RemoteEntry {
                    listen_host: addr.clone(),
                    listen_port: actual,
                    listen_path: None,
                    target: fwd.connect.clone(),
                });
                let shown = if *port == 0 { format!("Allocated port {actual} for remote forward to {}", fwd.connect.as_ref().map_or("SOCKS".into(), end_label)) } else { format!("Remote forwarding {}", describe(&fwd)) };
                Ok(shown)
            }
            End::Socket { path } => {
                h.streamlocal_forward(path.clone()).await.map_err(|e| format!("the server refused: {e}"))?;
                self.table.remote.lock().unwrap().push(RemoteEntry { listen_host: String::new(), listen_port: 0, listen_path: Some(path.clone()), target: fwd.connect.clone() });
                Ok(format!("Remote forwarding {}", describe(&fwd)))
            }
        }
    }

    /// ~C -KL / -KD: stop a local forward by its listening port.
    pub async fn cancel_local(&self, port: u16) -> bool {
        let mut l = self.locals.lock().await;
        let before = l.len();
        l.retain(|t| !matches!(&t.forward.listen, End::Tcp { port: p, .. } if *p == port));
        l.len() != before
    }

    /// ~C -KR: cancel a remote forward by its port.
    pub async fn cancel_remote(&self, port: u16) -> Result<(), String> {
        let entry = {
            let mut r = self.table.remote.lock().unwrap();
            let i = r.iter().position(|e| e.listen_port == port as u32).ok_or("no such remote forward")?;
            r.remove(i)
        };
        let h = self.handle.lock().await;
        h.cancel_tcpip_forward(entry.listen_host, entry.listen_port).await.map_err(|e| e.to_string())
    }

    /// The forwards that are up, for ~#.
    pub async fn list(&self) -> Vec<String> {
        let mut out: Vec<String> = self.locals.lock().await.iter().map(|t| format!("local {}", describe(&t.forward))).collect();
        for e in self.table.remote.lock().unwrap().iter() {
            let listen = e.listen_path.clone().unwrap_or_else(|| format!("{}:{}", e.listen_host, e.listen_port));
            out.push(format!("remote {listen} -> {}", e.target.as_ref().map_or("SOCKS".into(), end_label)));
        }
        out
    }
}

/// One connection to a local forward: through a direct channel to its
/// target, or (dynamic) to where its SOCKS request says.
async fn serve_local<S>(handle: SharedHandle, mut sock: S, peer: SocketAddr, target: Option<End>, idle: Option<Duration>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (target, socks) = match target {
        Some(t) => (t, None),
        None => match socks_read(&mut sock).await {
            Ok(req) => (End::Tcp { host: Some(req.host.clone()), port: req.port }, Some(req.version)),
            Err(e) => {
                tracing::info!("SOCKS from {peer}: {e}");
                return;
            }
        },
    };
    match open_to(&handle, &target, &peer.ip().to_string(), peer.port() as u32).await {
        Ok(ch) => {
            if let Some(v) = socks {
                if socks_reply(&mut sock, v, true).await.is_err() {
                    return;
                }
            }
            relay(sock, ch.into_stream(), idle).await;
        }
        Err(e) => {
            tracing::info!("Forward to {} refused: {e}", end_label(&target));
            if let Some(v) = socks {
                let _ = socks_reply(&mut sock, v, false).await;
            }
        }
    }
}

/// PermitRemoteOpen: may a remote dynamic forward connect here?
fn permitted(list: &Option<Vec<String>>, host: &str, port: u16) -> bool {
    let Some(list) = list else { return true };
    list.iter().any(|p| {
        if p.eq_ignore_ascii_case("any") {
            return true;
        }
        if p.eq_ignore_ascii_case("none") {
            return false;
        }
        let (ph, pp) = match p.rsplit_once(':') {
            Some((h, pt)) => (h.trim_start_matches('[').trim_end_matches(']'), pt),
            None => (p.as_str(), "*"),
        };
        super::sshconf::pattern::match_pattern(&host.to_ascii_lowercase(), &ph.to_ascii_lowercase()) && (pp == "*" || pp.parse::<u16>().ok() == Some(port))
    })
}

/// A connection the server forwards to us (RemoteForward): connect where
/// the forward points, or answer SOCKS for a remote dynamic forward.
pub fn on_forwarded_tcpip(table: Arc<ForwardTable>, channel: Channel<Msg>, address: &str, port: u32) -> bool {
    let entry = table
        .remote
        .lock()
        .unwrap()
        .iter()
        .find(|e| e.listen_path.is_none() && e.listen_port == port && (e.listen_host == address || e.listen_host.is_empty() || e.listen_host == "localhost"))
        .cloned();
    let Some(entry) = entry else {
        tracing::warn!("The server forwarded a connection for {address}:{port}, which Reach did not ask for; refused");
        return false;
    };
    let policy = table.policy();
    tokio::spawn(async move {
        let idle = policy.timeout_for("forwarded-tcpip");
        let mut stream = channel.into_stream();
        let target = match entry.target {
            Some(t) => t,
            None => match socks_read(&mut stream).await {
                Ok(req) if permitted(&policy.permit_remote_open, &req.host, req.port) => {
                    let ok = connect_local(&End::Tcp { host: Some(req.host.clone()), port: req.port }).await;
                    match ok {
                        Ok(local) => {
                            let _ = socks_reply(&mut stream, req.version, true).await;
                            local_relay(stream, local, idle).await;
                        }
                        Err(_) => {
                            let _ = socks_reply(&mut stream, req.version, false).await;
                        }
                    }
                    return;
                }
                Ok(req) => {
                    tracing::warn!("Remote SOCKS to {}:{} refused by PermitRemoteOpen", req.host, req.port);
                    let _ = socks_reply(&mut stream, req.version, false).await;
                    return;
                }
                Err(e) => {
                    tracing::info!("Remote SOCKS: {e}");
                    return;
                }
            },
        };
        match connect_local(&target).await {
            Ok(local) => local_relay(stream, local, idle).await,
            Err(e) => tracing::info!("RemoteForward to {}: {e}", end_label(&target)),
        }
    });
    true
}

/// A Unix socket the server forwards to us.
pub fn on_forwarded_streamlocal(table: Arc<ForwardTable>, channel: Channel<Msg>, path: &str) -> bool {
    let entry = table.remote.lock().unwrap().iter().find(|e| e.listen_path.as_deref() == Some(path)).cloned();
    let Some(Some(target)) = entry.map(|e| e.target) else {
        tracing::warn!("The server forwarded {path}, which Reach did not ask for; refused");
        return false;
    };
    let idle = table.policy().timeout_for("forwarded-streamlocal@openssh.com");
    tokio::spawn(async move {
        match connect_local(&target).await {
            Ok(local) => local_relay(channel.into_stream(), local, idle).await,
            Err(e) => tracing::info!("RemoteForward to {}: {e}", end_label(&target)),
        }
    });
    true
}

enum Local {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

async fn connect_local(target: &End) -> std::io::Result<Local> {
    match target {
        End::Tcp { host, port } => {
            let h = host.clone().unwrap_or_else(|| "localhost".into());
            Ok(Local::Tcp(tokio::net::TcpStream::connect((h.as_str(), *port)).await?))
        }
        #[cfg(unix)]
        End::Socket { path } => Ok(Local::Unix(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(not(unix))]
        End::Socket { path } => Err(std::io::Error::other(format!("a Unix socket ({path}) cannot be reached here"))),
    }
}

async fn local_relay<S>(stream: S, local: Local, idle: Option<Duration>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match local {
        Local::Tcp(t) => relay(stream, t, idle).await,
        #[cfg(unix)]
        Local::Unix(u) => relay(stream, u, idle).await,
    }
}

/// ForwardAgent: the server's agent requests go to this machine's agent.
pub fn on_agent(table: Arc<ForwardTable>, channel: Channel<Msg>) -> bool {
    let Some(choice) = table.policy().agent else {
        tracing::warn!("The server opened an agent channel, but agent forwarding is off; refused");
        return false;
    };
    let idle = table.policy().timeout_for("agent-connection");
    tokio::spawn(async move {
        match super::userauth::connect_agent(&choice).await {
            Some(agent) => relay(channel.into_stream(), agent.into_inner(), idle).await,
            None => tracing::info!("Agent forwarding: no agent to forward to"),
        }
    });
    true
}

/// An X11 channel from the server: refused unless the session asked for
/// X11 forwarding.
pub fn on_x11(table: Arc<ForwardTable>, channel: Channel<Msg>) -> bool {
    let Some(auth) = table.x11.lock().unwrap().clone() else {
        tracing::warn!("The server opened an X11 channel, but X11 forwarding is off; refused");
        return false;
    };
    let idle = table.policy().timeout_for("x11-connection");
    tokio::spawn(super::x11::serve(channel.into_stream(), auth, idle));
    true
}

/// Listens on a unix socket with StreamLocalBindMask's mode from the first
/// moment: it is bound in a fresh private directory, given its mode there,
/// then moved into place, so no other user can connect in between.
/// Without StreamLocalBindUnlink an existing file is left alone, as ssh's
/// bind would.
#[cfg(unix)]
fn bind_socket(path: &str, mask: u32, unlink: bool) -> Result<tokio::net::UnixListener, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let target = std::path::Path::new(path);
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let fail = |e: std::io::Error| format!("cannot listen on {path}: {e}");
    let mut dir = None;
    for _ in 0..8 {
        let d = parent.join(format!(".reach-{:08x}", rand::random::<u32>()));
        match std::fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => {
                dir = Some(d);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(fail(e)),
        }
    }
    let dir = dir.ok_or_else(|| format!("cannot listen on {path}: no private directory"))?;
    let tmp = dir.join("s");
    let result = (|| {
        let l = tokio::net::UnixListener::bind(&tmp).map_err(fail)?;
        // StreamLocalBindMask, as umask: 0177 leaves 0600.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o777 & !mask)).map_err(fail)?;
        if unlink {
            std::fs::rename(&tmp, target).map_err(fail)?;
        } else {
            // A hard link never replaces an existing file.
            std::fs::hard_link(&tmp, target).map_err(fail)?;
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(l)
    })();
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_follows_channels_c() {
        let lo = bind_addrs(None, 80, false);
        assert!(lo.iter().all(|a| a.ip().is_loopback()));
        assert!(bind_addrs(None, 80, true).iter().all(|a| a.ip().is_unspecified()));
        assert!(bind_addrs(Some("*"), 80, false).iter().all(|a| a.ip().is_unspecified()));
        assert!(bind_addrs(Some("localhost"), 80, true).iter().all(|a| a.ip().is_loopback()));
    }

    #[test]
    fn permit_remote_open() {
        assert!(permitted(&None, "x", 1));
        let l = Some(vec!["db.lan:5432".to_string(), "*.web:*".to_string()]);
        assert!(permitted(&l, "db.lan", 5432));
        assert!(!permitted(&l, "db.lan", 22));
        assert!(permitted(&l, "a.web", 8080));
        assert!(!permitted(&Some(vec!["none".to_string()]), "x", 1));
    }

    #[tokio::test]
    async fn socks5_and_4a_requests() {
        let (mut c, mut s) = tokio::io::duplex(256);
        let server = tokio::spawn(async move { socks_read(&mut s).await.map(|r| (r.host, r.port, r.version)) });
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        c.write_all(&[5, 1, 0, 3, 6]).await.unwrap();
        c.write_all(b"db.lan").await.unwrap();
        c.write_all(&5432u16.to_be_bytes()).await.unwrap();
        assert_eq!(server.await.unwrap().unwrap(), ("db.lan".into(), 5432, 5));

        let (mut c, mut s) = tokio::io::duplex(256);
        let server = tokio::spawn(async move { socks_read(&mut s).await.map(|r| (r.host, r.port)) });
        c.write_all(&[4, 1]).await.unwrap();
        c.write_all(&80u16.to_be_bytes()).await.unwrap();
        c.write_all(&[0, 0, 0, 1]).await.unwrap();
        c.write_all(b"me\0example.org\0").await.unwrap();
        assert_eq!(server.await.unwrap().unwrap(), ("example.org".into(), 80));
    }
}
