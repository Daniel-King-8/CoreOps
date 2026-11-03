//! LocalForward, RemoteForward and DynamicForward specifications, parsed as
//! readconf.c's `parse_forward` does.

use serde::{Deserialize, Serialize};

/// One end of a forward: a TCP host and port, or a Unix socket path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum End {
    /// `host` is `None` for "the default address" (GatewayPorts decides).
    Tcp { host: Option<String>, port: u16 },
    Socket { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    pub listen: End,
    /// `None` for a dynamic (SOCKS) forward.
    pub connect: Option<End>,
}

struct Field {
    arg: String,
    is_path: bool,
}

fn fields(spec: &str) -> Option<Vec<Field>> {
    let chars: Vec<char> = spec.trim_start().chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() && out.len() < 4 {
        if chars[i] == '[' {
            let mut j = i + 1;
            let mut is_path = false;
            while j < chars.len() && chars[j] != ']' {
                if chars[j] == '/' {
                    is_path = true;
                }
                j += 1;
            }
            if j >= chars.len() || (j + 1 < chars.len() && chars[j + 1] != ':') {
                return None;
            }
            out.push(Field { arg: chars[i + 1..j].iter().collect(), is_path });
            i = if j + 1 < chars.len() { j + 2 } else { j + 1 };
            continue;
        }
        let mut arg = String::new();
        let mut is_path = false;
        let mut ended_by_colon = false;
        while i < chars.len() {
            match chars[i] {
                '\\' => {
                    i += 1;
                    // The escaped character is taken as it is: an escaped
                    // `:` does not end the field, an escaped `/` does not
                    // make it a path.
                    match chars.get(i) {
                        Some(&c) => arg.push(c),
                        None => return None,
                    }
                }
                '/' => {
                    is_path = true;
                    arg.push('/');
                }
                ':' => {
                    i += 1;
                    ended_by_colon = true;
                    break;
                }
                c => arg.push(c),
            }
            i += 1;
        }
        out.push(Field { arg, is_path });
        // A trailing colon leaves an empty string, which ends parsing as
        // OpenSSH's does (an empty field is "end of string").
        if ended_by_colon && i >= chars.len() {
            break;
        }
    }
    if i < chars.len() {
        return None; // trailing garbage
    }
    Some(out)
}

/// a2port: a number 0–65535, or a service name. Reach knows the common
/// service names; OpenSSH asks the system's services database.
fn a2port(s: &str) -> i32 {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<u32>().ok().filter(|p| *p <= 65535).map_or(-1, |p| p as i32);
    }
    super::value::service_port(s).map_or(-1, |p| p as i32)
}

/// Parse a forward. `expanded` is the spec after `${VAR}` expansion.
pub fn parse(expanded: &str, dynamic: bool, remote: bool) -> Option<Forward> {
    let f = fields(expanded)?;
    let tcp = |host: Option<&str>, port: &str| -> Option<(Option<String>, i32)> {
        Some((host.map(str::to_string), a2port(port)))
    };
    let (listen_host, listen_port, listen_path, connect_host, connect_port, connect_path);
    match f.len() {
        1 => {
            if f[0].is_path {
                (listen_host, listen_port, listen_path) = (None, -2, Some(f[0].arg.clone()));
            } else {
                let (h, p) = tcp(None, &f[0].arg)?;
                (listen_host, listen_port, listen_path) = (h, p, None);
            }
            (connect_host, connect_port, connect_path) = (Some("socks".to_string()), 0, None);
        }
        2 => {
            if f[0].is_path && f[1].is_path {
                (listen_host, listen_port, listen_path) = (None, -2, Some(f[0].arg.clone()));
                (connect_host, connect_port, connect_path) = (None, -2, Some(f[1].arg.clone()));
            } else if f[1].is_path {
                (listen_host, listen_port, listen_path) = (None, a2port(&f[0].arg), None);
                (connect_host, connect_port, connect_path) = (None, -2, Some(f[1].arg.clone()));
            } else {
                (listen_host, listen_port, listen_path) = (Some(f[0].arg.clone()), a2port(&f[1].arg), None);
                (connect_host, connect_port, connect_path) = (Some("socks".to_string()), 0, None);
            }
        }
        3 => {
            if f[0].is_path {
                (listen_host, listen_port, listen_path) = (None, -2, Some(f[0].arg.clone()));
                (connect_host, connect_port, connect_path) = (Some(f[1].arg.clone()), a2port(&f[2].arg), None);
            } else if f[2].is_path {
                (listen_host, listen_port, listen_path) = (Some(f[0].arg.clone()), a2port(&f[1].arg), None);
                (connect_host, connect_port, connect_path) = (None, -2, Some(f[2].arg.clone()));
            } else {
                (listen_host, listen_port, listen_path) = (None, a2port(&f[0].arg), None);
                (connect_host, connect_port, connect_path) = (Some(f[1].arg.clone()), a2port(&f[2].arg), None);
            }
        }
        4 => {
            (listen_host, listen_port, listen_path) = (Some(f[0].arg.clone()), a2port(&f[1].arg), None);
            (connect_host, connect_port, connect_path) = (Some(f[2].arg.clone()), a2port(&f[3].arg), None);
        }
        _ => return None,
    }
    let n = f.len();
    if dynamic {
        if !(n == 1 || n == 2) {
            return None;
        }
    } else {
        if !(n == 3 || n == 4) && connect_path.is_none() && listen_path.is_none() {
            return None;
        }
        if connect_port <= 0 && connect_path.is_none() {
            return None;
        }
    }
    if (listen_port < 0 && listen_path.is_none()) || (!remote && listen_port == 0) {
        return None;
    }
    // NI_MAXHOST is 1025; sun_path is 108 bytes on Linux.
    if connect_host.as_ref().is_some_and(|h| h.len() >= 1025) || listen_host.as_ref().is_some_and(|h| h.len() >= 1025) {
        return None;
    }
    if connect_path.as_ref().is_some_and(|p| p.len() >= 108) || listen_path.as_ref().is_some_and(|p| p.len() >= 108) {
        return None;
    }
    let listen = match listen_path {
        Some(path) => End::Socket { path },
        None => End::Tcp { host: listen_host, port: listen_port as u16 },
    };
    // A dynamic forward (OpenSSH's connect host "socks") has no target.
    let connect = match (connect_path, connect_host) {
        (Some(path), _) => Some(End::Socket { path }),
        (None, Some(h)) if h == "socks" && connect_port == 0 => None,
        (None, Some(host)) => Some(End::Tcp { host: Some(host), port: connect_port as u16 }),
        (None, None) => None,
    };
    Some(Forward { listen, connect })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(h: Option<&str>, p: u16) -> End {
        End::Tcp { host: h.map(str::to_string), port: p }
    }

    #[test]
    fn local_forms() {
        assert_eq!(parse("8080:db:5432", false, false).unwrap(), Forward { listen: tcp(None, 8080), connect: Some(tcp(Some("db"), 5432)) });
        assert_eq!(
            parse("127.0.0.1:8080:db:5432", false, false).unwrap(),
            Forward { listen: tcp(Some("127.0.0.1"), 8080), connect: Some(tcp(Some("db"), 5432)) }
        );
        assert_eq!(
            parse("[::1]:8080:[fd00::5]:5432", false, false).unwrap(),
            Forward { listen: tcp(Some("::1"), 8080), connect: Some(tcp(Some("fd00::5"), 5432)) }
        );
        assert_eq!(
            parse("8080:/run/app.sock", false, false).unwrap(),
            Forward { listen: tcp(None, 8080), connect: Some(End::Socket { path: "/run/app.sock".into() }) }
        );
        assert!(parse("8080", false, false).is_none());
        assert!(parse("0:db:5432", false, false).is_none());
        assert!(parse("8080:db:0", false, false).is_none());
    }

    #[test]
    fn dynamic_and_remote() {
        assert_eq!(parse("1080", true, false).unwrap(), Forward { listen: tcp(None, 1080), connect: None });
        assert_eq!(parse("localhost:1080", true, false).unwrap(), Forward { listen: tcp(Some("localhost"), 1080), connect: None });
        assert!(parse("a:b:c", true, false).is_none());
        // A remote forward may listen on port 0 (the server picks one).
        assert!(parse("0:localhost:80", false, true).is_some());
    }
}
