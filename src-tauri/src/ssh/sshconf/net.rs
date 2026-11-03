//! Opening the TCP connection as ssh does (sshconnect.c): each address in
//! turn, ConnectionAttempts rounds a second apart, ConnectTimeout per try,
//! the socket bound to BindAddress or an address of BindInterface, with
//! SO_KEEPALIVE and the IPQoS type of service.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;

use super::apply::SocketPlan;

/// An address of the named interface in the family wanted: one that is not
/// loopback or link-local if there is one (check_ifaddrs).
fn interface_address(name: &str, v4: bool) -> Option<IpAddr> {
    let addrs: Vec<IpAddr> = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .filter(|i| i.name == name && i.ip().is_ipv4() == v4)
        .map(|i| i.ip())
        .collect();
    let local = |ip: &IpAddr| match ip {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback() || (a.segments()[0] & 0xffc0) == 0xfe80,
    };
    addrs.iter().find(|a| !local(a)).or(addrs.first()).copied()
}

async fn bind_address(spec: &str, v4: bool) -> Result<IpAddr, String> {
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(ip);
    }
    tokio::net::lookup_host((spec, 0))
        .await
        .map_err(|e| format!("BindAddress {spec}: {e}"))?
        .map(|a| a.ip())
        .find(|ip| ip.is_ipv4() == v4)
        .ok_or_else(|| format!("BindAddress {spec}: no address of that family"))
}

async fn try_one(addr: SocketAddr, plan: &SocketPlan, interactive: bool) -> Result<TcpStream, String> {
    let v4 = addr.is_ipv4();
    let sock = Socket::new(if v4 { Domain::IPV4 } else { Domain::IPV6 }, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("socket: {e}"))?;
    let tos = if interactive { plan.tos_interactive } else { plan.tos_bulk };
    if let Some(t) = tos {
        // Not every system lets an unprivileged program set these; ssh
        // carries on when it cannot, and so does Reach.
        if v4 {
            let _ = sock.set_tos_v4(t);
        } else {
            #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            let _ = sock.set_tclass_v6(t);
        }
    }
    if plan.tcp_keepalive {
        let _ = sock.set_keepalive(true);
    }
    if interactive {
        let _ = sock.set_tcp_nodelay(true);
    }
    let bind = if let Some(b) = &plan.bind_address {
        Some(bind_address(b, v4).await?)
    } else if let Some(i) = &plan.bind_interface {
        Some(interface_address(i, v4).ok_or_else(|| format!("BindInterface {i}: no suitable addresses"))?)
    } else {
        None
    };
    if let Some(ip) = bind {
        sock.bind(&SocketAddr::new(ip, 0).into()).map_err(|e| format!("bind {ip}: {e}"))?;
    }
    sock.set_nonblocking(true).map_err(|e| e.to_string())?;
    let std_stream: std::net::TcpStream = sock.into();
    let socket = tokio::net::TcpSocket::from_std_stream(std_stream);
    let connect = socket.connect(addr);
    match plan.connect_timeout {
        Some(t) => tokio::time::timeout(t, connect)
            .await
            .map_err(|_| format!("connect to {addr}: timed out after {}s (ConnectTimeout)", t.as_secs()))?
            .map_err(|e| format!("connect to {addr}: {e}")),
        None => connect.await.map_err(|e| format!("connect to {addr}: {e}")),
    }
}

/// Connect to `host:port` under the plan. `interactive` sets TCP_NODELAY
/// and the interactive type of service, as ssh does for a terminal.
pub async fn connect(host: &str, port: u16, plan: &SocketPlan, interactive: bool) -> Result<TcpStream, std::io::Error> {
    let io = |m: String| std::io::Error::other(m);
    let mut last = String::from("no address");
    for attempt in 0..plan.attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
            Ok(a) => a
                .filter(|a| match plan.ipv4_only {
                    Some(true) => a.is_ipv4(),
                    Some(false) => a.is_ipv6(),
                    None => true,
                })
                .collect(),
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        for addr in addrs {
            match try_one(addr, plan, interactive).await {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
    }
    Err(io(last))
}
