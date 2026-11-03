//! X11 forwarding as ssh does it (clientloop.c client_x11_get_proto,
//! channels.c x11_request_forwarding_with_spoofing and x11_open_helper):
//! the server is given a random cookie, and each X11 connection it opens
//! must present that cookie in its first packet. Reach swaps in the real
//! cookie there, so the real one never leaves this machine. Untrusted
//! forwarding (the default) asks xauth for a cookie the X server limits
//! with the SECURITY extension, valid for ForwardX11Timeout.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The X11 settings for a session, from ssh_config.
#[derive(Debug, Clone)]
pub struct X11Config {
    /// $DISPLAY on this machine.
    pub display: String,
    /// ForwardX11Trusted, when on and approved.
    pub trusted: bool,
    /// ForwardX11Timeout for untrusted forwarding; `None` never expires.
    pub timeout: Option<Duration>,
    /// XAuthLocation.
    pub xauth: String,
}

/// What the session asked for, kept to check and rewrite each connection.
#[derive(Debug, Clone)]
pub struct X11Auth {
    pub display: String,
    pub proto: String,
    /// The real cookie, from xauth or made up.
    real: Vec<u8>,
    /// The cookie the server was given.
    fake: Vec<u8>,
    /// ForwardX11Timeout: connections after this are refused.
    deadline: Option<Instant>,
    pub screen: u32,
}

impl X11Auth {
    pub fn fake_hex(&self) -> String {
        hex(&self.fake)
    }
}

const PROTO: &str = "MIT-MAGIC-COOKIE-1";
/// ssh's X11_TIMEOUT_SLACK: the cookie outlives the forwarding a little.
const SLACK: u64 = 60;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// client_x11_display_valid: only the characters a display name has, so
/// it is safe to hand to xauth.
pub fn display_valid(d: &str) -> bool {
    !d.is_empty() && d.chars().all(|c| c.is_ascii_alphanumeric() || ":/.-_".contains(c))
}

/// The screen number in "host:display.screen".
fn screen_of(display: &str) -> u32 {
    display.rsplit_once(':').and_then(|(_, r)| r.split_once('.')).and_then(|(_, s)| s.parse().ok()).unwrap_or(0)
}

/// The display number in "host:display.screen".
fn display_number(display: &str) -> Option<u32> {
    let (_, r) = display.rsplit_once(':')?;
    r.split('.').next()?.parse().ok()
}

async fn run(cmd: &str, args: &[&str]) -> Option<String> {
    run_with(cmd, args, None).await
}

/// `run`, with XAUTHORITY set: how xauth proves itself to a server that
/// wants a cookie.
async fn run_with(cmd: &str, args: &[&str], xauthority: Option<&std::path::Path>) -> Option<String> {
    let mut c = tokio::process::Command::new(cmd);
    if let Some(a) = xauthority {
        c.env("XAUTHORITY", a);
    }
    c.args(args).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let out = tokio::time::timeout(Duration::from_secs(10), c.output()).await.ok()?.ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A directory only this user can open (mkdtemp), removed with its
/// contents when dropped.
struct PrivateDir(std::path::PathBuf);

impl PrivateDir {
    fn new() -> std::io::Result<Self> {
        let mut last = None;
        for _ in 0..8 {
            let d = std::env::temp_dir().join(format!("reach-xauth-{:016x}", rand::random::<u64>()));
            #[cfg_attr(not(unix), allow(unused_mut))]
            let mut b = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            match b.create(&d) {
                Ok(()) => return Ok(PrivateDir(d)),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no temporary directory")))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The first "display proto hexdata" line of `xauth list`.
fn parse_list(out: &str) -> Option<(String, Vec<u8>)> {
    let line = out.lines().next()?;
    let mut w = line.split_whitespace();
    let _display = w.next()?;
    let proto = w.next()?.to_string();
    let data = unhex(w.next()?)?;
    (!data.is_empty()).then_some((proto, data))
}

/// client_x11_get_proto plus the spoofing setup: the real cookie and the
/// fake one the server gets. Untrusted forwarding without a cookie from
/// xauth fails, as with ssh, instead of falling back to trusted.
pub async fn prepare(cfg: &X11Config) -> Result<X11Auth, String> {
    // Windows without DISPLAY: an X server already running here, or the
    // one Reach starts (see `xserver`), as MobaXterm brings its own.
    #[cfg(windows)]
    if cfg.display.is_empty() {
        let d = super::xserver::ensure().await?;
        let mut local = cfg.clone();
        local.display = d.name.clone();
        if let Some(x) = d.xauth.as_ref().filter(|_| !std::path::Path::new(&cfg.xauth).is_file()) {
            local.xauth = x.to_string_lossy().into_owned();
        }
        if let (Some(cookie), Some(file)) = (d.cookie, d.auth_file) {
            return prepare_own(&local, cookie, &file).await;
        }
        return Box::pin(prepare(&local)).await;
    }
    if !display_valid(&cfg.display) {
        return Err(format!("DISPLAY \"{}\" invalid; X11 forwarding is off", cfg.display));
    }
    // FamilyLocal: "localhost:N" has its entry under "unix:N".
    let lookup = match cfg.display.strip_prefix("localhost:") {
        Some(rest) => format!("unix:{rest}"),
        None => cfg.display.clone(),
    };
    let have_xauth = !cfg.xauth.is_empty() && std::path::Path::new(&cfg.xauth).exists();
    let mut got = None;
    if have_xauth {
        if cfg.trusted {
            got = run(&cfg.xauth, &["list", &lookup]).await.as_deref().and_then(parse_list);
        } else {
            let dir = PrivateDir::new().map_err(|e| format!("X11: {e}"))?;
            let file = dir.0.join("xauthfile");
            let file = file.to_string_lossy();
            let mut args = vec!["-f", &file, "generate", &lookup, PROTO, "untrusted"];
            let secs;
            if let Some(t) = cfg.timeout {
                secs = t.as_secs().saturating_add(SLACK).min(u32::MAX as u64).to_string();
                args.extend(["timeout", &secs]);
            }
            if run(&cfg.xauth, &args).await.is_some() {
                got = run(&cfg.xauth, &["-f", &file, "list", &lookup]).await.as_deref().and_then(parse_list);
            }
        }
    }
    let (proto, real) = match got {
        Some(x) => x,
        None if !cfg.trusted => {
            return Err("untrusted X11 forwarding setup failed: xauth key data not generated".into());
        }
        // The X server ignores the made-up data and uses whatever it
        // allows for local connections.
        None => (PROTO.to_string(), rand::random::<[u8; 16]>().to_vec()),
    };
    let mut fake = vec![0u8; real.len()];
    rand::fill(&mut fake[..]);
    Ok(X11Auth {
        display: cfg.display.clone(),
        proto,
        real,
        fake,
        deadline: if cfg.trusted { None } else { cfg.timeout.map(|t| Instant::now() + t) },
        screen: screen_of(&cfg.display),
    })
}

/// For the X server Reach started: the cookie is Reach's own. Trusted
/// forwarding uses it as the real one; untrusted forwarding has xauth
/// (proving itself with that cookie) ask the server for a restricted one.
#[cfg(windows)]
async fn prepare_own(cfg: &X11Config, cookie: Vec<u8>, auth_file: &std::path::Path) -> Result<X11Auth, String> {
    let real = if cfg.trusted {
        cookie
    } else {
        let dir = PrivateDir::new().map_err(|e| format!("X11: {e}"))?;
        let file = dir.0.join("xauthfile");
        let file = file.to_string_lossy();
        let mut args = vec!["-f", &file, "generate", &cfg.display, PROTO, "untrusted"];
        let secs;
        if let Some(t) = cfg.timeout {
            secs = t.as_secs().saturating_add(SLACK).min(u32::MAX as u64).to_string();
            args.extend(["timeout", &secs]);
        }
        if run_with(&cfg.xauth, &args, Some(auth_file)).await.is_none() {
            return Err("untrusted X11 forwarding setup failed: xauth key data not generated".into());
        }
        // The file holds just the generated entry.
        let listed = run_with(&cfg.xauth, &["-f", &file, "list"], Some(auth_file)).await;
        listed.as_deref().and_then(parse_list).map(|(_, d)| d).ok_or("untrusted X11 forwarding setup failed: xauth key data not generated")?
    };
    let mut fake = vec![0u8; real.len()];
    rand::fill(&mut fake[..]);
    Ok(X11Auth {
        display: cfg.display.clone(),
        proto: PROTO.to_string(),
        real,
        fake,
        deadline: if cfg.trusted { None } else { cfg.timeout.map(|t| Instant::now() + t) },
        screen: 0,
    })
}

/// Constant-time comparison, as timingsafe_bcmp.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// x11_open_helper: how many bytes of `b` the connection setup takes, or
/// `Ok(None)` while more are needed. A match swaps the fake cookie for the
/// real one in place.
pub fn rewrite_setup(b: &mut [u8], auth: &X11Auth) -> Result<Option<usize>, &'static str> {
    if b.len() < 12 {
        return Ok(None);
    }
    let (proto_len, data_len) = match b[0] {
        0x42 => (256 * b[6] as usize + b[7] as usize, 256 * b[8] as usize + b[9] as usize),
        0x6c => (b[6] as usize + 256 * b[7] as usize, b[8] as usize + 256 * b[9] as usize),
        _ => return Err("bad byte order byte"),
    };
    let pad = |n: usize| (n + 3) & !3;
    let total = 12 + pad(proto_len) + pad(data_len);
    if b.len() < total {
        return Ok(None);
    }
    if &b[12..12 + proto_len] != auth.proto.as_bytes() {
        return Err("different authentication protocol");
    }
    let at = 12 + pad(proto_len);
    if !same(&b[at..at + data_len], &auth.fake) || auth.fake.len() != auth.real.len() {
        return Err("authentication data does not match");
    }
    b[at..at + data_len].copy_from_slice(&auth.real);
    Ok(Some(total))
}

/// The first packet, rewritten, or why the connection is refused. Reads
/// at most what a setup packet can hold.
pub async fn read_setup<R: AsyncRead + Unpin>(r: &mut R, auth: &X11Auth) -> Result<Vec<u8>, String> {
    if auth.deadline.is_some_and(|d| Instant::now() >= d) {
        return Err("X11 connection refused after ForwardX11Timeout expired".into());
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match rewrite_setup(&mut buf, auth) {
            Ok(Some(_)) => return Ok(buf),
            Ok(None) => {}
            Err(e) => return Err(format!("X11 connection refused: {e}")),
        }
        if buf.len() > 12 + 65536 * 2 {
            return Err("X11 connection refused: setup too long".into());
        }
        let n = r.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("X11 connection closed during setup".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A connection to the local display (x11_connect_display).
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub async fn connect_display(display: &str) -> Result<Box<dyn Stream>, String> {
    let n = display_number(display).ok_or_else(|| format!("cannot parse display number in \"{display}\""))?;
    let (host, _) = display.rsplit_once(':').unwrap_or(("", ""));
    #[cfg(unix)]
    {
        // macOS launchd: DISPLAY is the socket path, "…/org.xquartz:0".
        if host.starts_with('/') {
            return tokio::net::UnixStream::connect(host).await.map(|s| Box::new(s) as Box<dyn Stream>).map_err(|e| format!("{host}: {e}"));
        }
        if host.is_empty() || host == "unix" {
            let path = format!("/tmp/.X11-unix/X{n}");
            return tokio::net::UnixStream::connect(&path).await.map(|s| Box::new(s) as Box<dyn Stream>).map_err(|e| format!("{path}: {e}"));
        }
    }
    // Windows X servers (VcXsrv, Xming, X410) listen on TCP.
    let host = if host.is_empty() || host == "unix" { "localhost" } else { host };
    let port = 6000u32.checked_add(n).filter(|p| *p <= 65535).ok_or("display number too large")? as u16;
    let s = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("{host}:{port}: {e}"))?;
    let _ = s.set_nodelay(true);
    Ok(Box::new(s))
}

/// Answers an X11 channel: checks and rewrites its setup, then relays it
/// to the display.
pub async fn serve<C>(mut channel: C, auth: X11Auth, idle: Option<Duration>)
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let setup = match read_setup(&mut channel, &auth).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("{e}");
            return;
        }
    };
    let mut display = match connect_display(&auth.display).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("X11 forwarding: cannot connect to the display: {e}");
            return;
        }
    };
    if display.write_all(&setup).await.is_err() {
        return;
    }
    super::forwarding::relay(channel, display, idle).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(real: &[u8], fake: &[u8]) -> X11Auth {
        X11Auth { display: ":0".into(), proto: PROTO.into(), real: real.to_vec(), fake: fake.to_vec(), deadline: None, screen: 0 }
    }

    fn setup(order: u8, proto: &str, data: &[u8]) -> Vec<u8> {
        let le = order == 0x6c;
        let n16 = |n: usize| if le { [(n & 255) as u8, (n >> 8) as u8] } else { [(n >> 8) as u8, (n & 255) as u8] };
        let mut b = vec![order, 0];
        b.extend(n16(11));
        b.extend(n16(0));
        b.extend(n16(proto.len()));
        b.extend(n16(data.len()));
        b.extend([0, 0]);
        b.extend(proto.as_bytes());
        b.resize(12 + ((proto.len() + 3) & !3), 0);
        b.extend(data);
        b.resize(b.len() + ((4 - data.len() % 4) % 4), 0);
        b
    }

    #[test]
    fn swaps_the_fake_cookie_for_the_real_one() {
        let a = auth(&[1; 16], &[2; 16]);
        for order in [0x42, 0x6c] {
            let mut b = setup(order, PROTO, &[2; 16]);
            let want = setup(order, PROTO, &[1; 16]);
            assert_eq!(rewrite_setup(&mut b, &a), Ok(Some(want.len())));
            assert_eq!(b, want);
        }
    }

    #[test]
    fn waits_for_the_whole_packet() {
        let a = auth(&[1; 16], &[2; 16]);
        let full = setup(0x6c, PROTO, &[2; 16]);
        for cut in [0, 5, 12, 30, full.len() - 1] {
            let mut b = full[..cut].to_vec();
            assert_eq!(rewrite_setup(&mut b, &a), Ok(None));
        }
    }

    #[test]
    fn refuses_a_wrong_cookie_or_protocol() {
        let a = auth(&[1; 16], &[2; 16]);
        assert!(rewrite_setup(&mut setup(0x6c, PROTO, &[1; 16]), &a).is_err());
        assert!(rewrite_setup(&mut setup(0x6c, PROTO, &[2; 15]), &a).is_err());
        assert!(rewrite_setup(&mut setup(0x6c, "XDM-AUTHORIZATION-1", &[2; 16]), &a).is_err());
        assert!(rewrite_setup(&mut setup(0x00, PROTO, &[2; 16]), &a).is_err());
    }

    #[test]
    fn display_names() {
        assert_eq!(display_number(":0"), Some(0));
        assert_eq!(display_number("localhost:10.2"), Some(10));
        assert_eq!(screen_of("localhost:10.2"), 2);
        assert_eq!(display_number("/private/tmp/com.apple.launchd.x/org.xquartz:0"), Some(0));
        assert!(display_valid("localhost:10.0"));
        assert!(!display_valid(":0; rm -rf ~"));
        assert!(!display_valid(""));
    }

    #[test]
    fn reads_xauth_list() {
        let (p, d) = parse_list("host/unix:0  MIT-MAGIC-COOKIE-1  0a0bff\n").unwrap();
        assert_eq!(p, PROTO);
        assert_eq!(d, vec![10, 11, 255]);
        assert!(parse_list("").is_none());
    }

    #[tokio::test]
    async fn refuses_after_the_timeout() {
        let mut a = auth(&[1; 16], &[2; 16]);
        a.deadline = Some(Instant::now() - Duration::from_secs(1));
        let mut r: &[u8] = &setup(0x6c, PROTO, &[2; 16]);
        assert!(read_setup(&mut r, &a).await.is_err());
    }
}
