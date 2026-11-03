//! The value syntaxes of ssh_config(5), checked as OpenSSH checks them.

/// A word list for a "multistate" keyword: each accepted word (matched
/// case-insensitively) and the value it stands for.
pub type Words = &'static [(&'static str, &'static str)];

pub const FLAG: Words = &[("true", "yes"), ("false", "no"), ("yes", "yes"), ("no", "no")];
pub const YES_NO_ASK: Words = &[("true", "yes"), ("false", "no"), ("yes", "yes"), ("no", "no"), ("ask", "ask")];
pub const STRICT_HOST_KEY: Words = &[
    ("true", "yes"),
    ("false", "no"),
    ("yes", "yes"),
    ("no", "no"),
    ("ask", "ask"),
    ("off", "no"),
    ("accept-new", "accept-new"),
];
pub const YES_NO_ASK_CONFIRM: Words =
    &[("true", "yes"), ("false", "no"), ("yes", "yes"), ("no", "no"), ("ask", "ask"), ("confirm", "confirm")];
pub const ADDRESS_FAMILY: Words = &[("inet", "inet"), ("inet6", "inet6"), ("any", "any")];
pub const CONTROL_MASTER: Words = &[
    ("true", "yes"),
    ("yes", "yes"),
    ("false", "no"),
    ("no", "no"),
    ("auto", "auto"),
    ("ask", "ask"),
    ("autoask", "autoask"),
];
pub const TUNNEL: Words = &[
    ("ethernet", "ethernet"),
    ("point-to-point", "point-to-point"),
    ("true", "point-to-point"),
    ("yes", "point-to-point"),
    ("false", "no"),
    ("no", "no"),
];
pub const REQUEST_TTY: Words =
    &[("true", "yes"), ("yes", "yes"), ("false", "no"), ("no", "no"), ("force", "force"), ("auto", "auto")];
pub const SESSION_TYPE: Words = &[("none", "none"), ("subsystem", "subsystem"), ("default", "default")];
pub const CANONICALIZE: Words =
    &[("true", "yes"), ("false", "no"), ("yes", "yes"), ("no", "no"), ("always", "always")];
pub const PUBKEY_AUTH: Words = &[
    ("true", "yes"),
    ("false", "no"),
    ("yes", "yes"),
    ("no", "no"),
    ("unbound", "unbound"),
    ("host-bound", "host-bound"),
];
pub const COMPRESSION: Words = &[("yes", "yes"), ("no", "no")];
pub const KEEPALIVES: Words = &[
    ("true", "yes"),
    ("false", "no"),
    ("yes", "yes"),
    ("no", "no"),
    ("transport", "yes"),
    ("all", "all"),
];
pub const WARN_WEAK_CRYPTO: Words =
    &[("true", "yes"), ("false", "no"), ("yes", "yes"), ("no", "no"), ("no-pq-kex", "no")];

pub fn multistate(arg: Option<&str>, words: Words) -> Result<&'static str, String> {
    let arg = arg.unwrap_or("");
    words
        .iter()
        .find(|(w, _)| w.eq_ignore_ascii_case(arg))
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("unsupported option \"{arg}\"."))
}

/// `convtime_double`: "90", "1h30m", "1.5s"; `None` when invalid.
pub fn convtime_f(s: &str) -> Option<f64> {
    if s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    let mut i = 0;
    let mut total = 0.0;
    let mut seen_seconds = false;
    while i < b.len() {
        if !b[i].is_ascii_digit() && b[i] != b'.' {
            return None;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
        }
        let num = &s[start..i];
        let val: f64 = num.parse().ok()?;
        let mult = match b.get(i) {
            None | Some(b's') | Some(b'S') => {
                if seen_seconds {
                    return None;
                }
                seen_seconds = true;
                1.0
            }
            Some(b'm') | Some(b'M') => 60.0,
            Some(b'h') | Some(b'H') => 3600.0,
            Some(b'd') | Some(b'D') => 86400.0,
            Some(b'w') | Some(b'W') => 604800.0,
            _ => return None,
        };
        if num.contains('.') && (mult > 1.0 || !num.ends_with(|c: char| c.is_ascii_digit())) {
            return None;
        }
        total += val * mult;
        if i < b.len() {
            i += 1;
        }
    }
    Some(total)
}

/// `convtime`: whole seconds that fit an int.
pub fn convtime(s: &str) -> Option<i64> {
    let v = convtime_f(s)?;
    if !(0.0..=i32::MAX as f64).contains(&v) {
        return None;
    }
    Some(v as i64)
}

/// `atoi_err`: 0..INT_MAX, as strtonum checks it.
pub fn atoi(s: Option<&str>) -> Result<i64, String> {
    let s = s.unwrap_or("");
    if s.is_empty() {
        return Err("integer value missing.".into());
    }
    let neg = s.starts_with('-');
    let digits = s.trim_start_matches(['+', '-']);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("integer value invalid.".into());
    }
    match digits.parse::<i64>() {
        Ok(v) if neg && v != 0 => Err("integer value too small.".into()),
        Ok(v) if v > i32::MAX as i64 => Err("integer value too large.".into()),
        Ok(v) => Ok(v),
        Err(_) => Err("integer value too large.".into()),
    }
}

/// `a2port`: 1–65535 or a service name (OpenSSH's checks reject 0).
pub fn port(s: &str) -> Option<u16> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<u32>().ok().filter(|p| *p <= 65535).map(|p| p as u16);
    }
    service_port(s)
}

/// TCP service names, as `getservbyname(s, "tcp")` answers them. Unix
/// systems are asked their services database first; elsewhere, and when a
/// name is missing from it, the IANA names below answer.
pub fn service_port(name: &str) -> Option<u16> {
    #[cfg(all(unix, not(target_os = "android")))]
    if let Ok(text) = std::fs::read_to_string("/etc/services") {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut parts = line.split_whitespace();
            let (Some(svc), Some(pp)) = (parts.next(), parts.next()) else { continue };
            let Some((p, proto)) = pp.split_once('/') else { continue };
            if proto == "tcp" && (svc == name || parts.any(|a| a == name)) {
                if let Ok(p) = p.parse() {
                    return Some(p);
                }
            }
        }
    }
    const IANA: &[(&str, u16)] = &[
        ("ftp", 21), ("ssh", 22), ("telnet", 23), ("smtp", 25), ("domain", 53), ("http", 80), ("www", 80),
        ("kerberos", 88), ("pop3", 110), ("nntp", 119), ("ntp", 123), ("imap", 143), ("imap2", 143),
        ("ldap", 389), ("https", 443), ("microsoft-ds", 445), ("submission", 587), ("ldaps", 636),
        ("rsync", 873), ("imaps", 993), ("pop3s", 995), ("socks", 1080), ("openvpn", 1194), ("ms-sql-s", 1433),
        ("mysql", 3306), ("ms-wbt-server", 3389), ("postgresql", 5432), ("x11", 6000), ("redis", 6379),
        ("http-alt", 8080), ("webcache", 8080),
    ];
    IANA.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
}

/// `scan_scaled`: "1G", "500M", "1.5K" (powers of 1024).
pub fn scaled(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let end = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
    let (num, suffix) = t.split_at(end);
    if num.is_empty() || num.matches('.').count() > 1 {
        return None;
    }
    let scale: i64 = match suffix {
        "" => 1,
        x if x.len() == 1 => match x.to_ascii_uppercase().as_str() {
            "B" => 1,
            "K" => 1 << 10,
            "M" => 1 << 20,
            "G" => 1 << 30,
            "T" => 1 << 40,
            "P" => 1 << 50,
            "E" => 1 << 60,
            _ => return None,
        },
        _ => return None,
    };
    let (whole, frac) = num.split_once('.').unwrap_or((num, ""));
    let whole: i64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let mut v = whole.checked_mul(scale)?;
    if !frac.is_empty() && scale > 1 {
        let f: f64 = format!("0.{frac}").parse().ok()?;
        v = v.checked_add((f * scale as f64) as i64)?;
    }
    Some(v)
}

pub const LOG_LEVELS: &[&str] = &["QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"];
pub const SYSLOG_FACILITIES: &[&str] = &[
    "DAEMON", "USER", "AUTH", "AUTHPRIV", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6",
    "LOCAL7",
];
pub const DIGESTS: &[&str] = &["MD5", "SHA1", "SHA256", "SHA384", "SHA512"];

pub const IPQOS: &[&str] = &[
    "none", "af11", "af12", "af13", "af21", "af22", "af23", "af31", "af32", "af33", "af41", "af42", "af43", "cs0", "cs1",
    "cs2", "cs3", "cs4", "cs5", "cs6", "cs7", "ef", "le", "va", "lowdelay", "throughput", "reliability",
];

pub fn ipqos(s: &str) -> bool {
    IPQOS.iter().any(|n| n.eq_ignore_ascii_case(s))
        || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok_and(|v| v <= 255))
}

/// `a2tun` for one side: "any" or 0..0x7fffffff-2.
fn tun_id(s: &str) -> bool {
    s.eq_ignore_ascii_case("any") || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u64>().is_ok_and(|v| v <= 0x7fff_fffd))
}

/// TunnelDevice: `local[:remote]`.
pub fn tunnel_device(s: &str) -> bool {
    match s.split_once(':') {
        Some((l, r)) => tun_id(l) && tun_id(r),
        None => tun_id(s),
    }
}

/// `valid_domain(name, makelower = 1)`: the domain lowercased, a trailing
/// dot dropped.
pub fn domain(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("empty domain name".into());
    }
    let first = name.as_bytes()[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return Err(format!("domain name \"{name}\" starts with invalid character"));
    }
    let lower = name.to_ascii_lowercase();
    let mut last = 0u8;
    for c in lower.bytes() {
        if last == b'.' && c == b'.' {
            return Err(format!("domain name \"{lower}\" contains consecutive separators"));
        }
        if c != b'.' && c != b'-' && c != b'_' && !c.is_ascii_alphanumeric() {
            return Err(format!("domain name \"{lower}\" contains invalid characters"));
        }
        last = c;
    }
    Ok(lower.strip_suffix('.').unwrap_or(&lower).to_string())
}

pub fn env_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Algorithm names OpenSSH 10.3 knows (`ssh -Q`), so a config written for
/// it is not refused for naming one. What Reach can negotiate is decided
/// when connecting.
pub mod algos {
    pub const CIPHERS: &[&str] = &[
        "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr",
        "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
    ];
    pub const MACS: &[&str] = &[
        "hmac-sha1", "hmac-sha1-96", "hmac-sha2-256", "hmac-sha2-512", "hmac-md5", "hmac-md5-96",
        "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com", "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
        // Removed from OpenSSH in 7.6, still in old configs; libssh and
        // older servers speak them.
        "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-ripemd160-etm@openssh.com",
    ];
    pub const KEX: &[&str] = &[
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group-exchange-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
        "curve25519-sha256", "curve25519-sha256@libssh.org", "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256",
    ];
    /// Host key and signature algorithms (HostKeyAlgorithms,
    /// PubkeyAcceptedAlgorithms, HostbasedAcceptedAlgorithms).
    pub const KEYS: &[&str] = &[
        "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519@openssh.com",
        "sk-ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "ssh-rsa", "ssh-rsa-cert-v01@openssh.com",
        "rsa-sha2-256", "rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512", "rsa-sha2-512-cert-v01@openssh.com",
        // DSA was removed in OpenSSH 10.0; old configs still name it.
        "ssh-dss", "ssh-dss-cert-v01@openssh.com",
    ];
    /// CASignatureAlgorithms: signature algorithms, no certificate types.
    pub const CA_SIGS: &[&str] = &[
        "ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "ssh-dss",
    ];
}

/// An algorithm list as ssh_config takes it: a plain list, or one starting
/// with `+` (append), `-` (remove, wildcards allowed) or `^` (put first).
/// Names are checked unless it removes.
pub fn algo_list(arg: &str, known: &[&str]) -> Result<(), String> {
    if arg.starts_with('-') {
        return Ok(());
    }
    let list = arg.strip_prefix(['+', '^']).unwrap_or(arg);
    for name in list.split(',') {
        if name.is_empty() || !known.contains(&name) {
            return Err(format!("unknown algorithm \"{name}\""));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(convtime("90"), Some(90));
        assert_eq!(convtime("1h30m"), Some(5400));
        assert_eq!(convtime("2w"), Some(1209600));
        assert_eq!(convtime("1.5"), Some(1));
        assert_eq!(convtime_f("1.5s"), Some(1.5));
        assert_eq!(convtime("1.5m"), None);
        assert_eq!(convtime("10s5s"), None);
        assert_eq!(convtime("5x"), None);
        assert_eq!(convtime(""), None);
    }

    #[test]
    fn numbers() {
        assert_eq!(atoi(Some("3")), Ok(3));
        assert!(atoi(Some("-1")).is_err());
        assert!(atoi(Some("x")).is_err());
        assert_eq!(port("2222"), Some(2222));
        assert_eq!(port("ssh"), Some(22));
        assert_eq!(port("99999"), None);
        assert_eq!(scaled("1G"), Some(1 << 30));
        assert_eq!(scaled("512"), Some(512));
        assert_eq!(scaled("1.5K"), Some(1536));
        assert_eq!(scaled("1Gb"), None);
    }

    #[test]
    fn words() {
        assert_eq!(multistate(Some("YES"), FLAG), Ok("yes"));
        assert_eq!(multistate(Some("accept-new"), STRICT_HOST_KEY), Ok("accept-new"));
        assert!(multistate(Some("maybe"), FLAG).is_err());
        assert!(multistate(None, FLAG).is_err());
    }

    #[test]
    fn algorithm_lists() {
        assert!(algo_list("+hmac-sha1", algos::MACS).is_ok());
        assert!(algo_list("-*-sha1", algos::MACS).is_ok());
        assert!(algo_list("^aes256-ctr,aes128-ctr", algos::CIPHERS).is_ok());
        assert!(algo_list("hmac-bogus", algos::MACS).is_err());
        assert!(algo_list("aes128-ctr,", algos::CIPHERS).is_err());
    }

    #[test]
    fn domains() {
        assert_eq!(domain("Example.COM.").unwrap(), "example.com");
        assert!(domain("a..b").is_err());
        assert!(domain("-a").is_err());
    }
}
