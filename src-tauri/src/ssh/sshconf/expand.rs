//! `%` tokens and `${VAR}` expansion, as OpenSSH's misc.c does them.

/// The values `%` tokens stand for.
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    /// %C: hash of %l%h%p%r%j.
    pub conn_hash: String,
    /// %L: the local host name up to its first dot.
    pub short_local: String,
    /// %d: the local home directory.
    pub home: String,
    /// %h: the remote host name.
    pub host: String,
    /// %k: HostKeyAlias, or the host name.
    pub key_alias: String,
    /// %l: the local host name.
    pub local_host: String,
    /// %n: the host name as given.
    pub original_host: String,
    /// %p: the remote port.
    pub port: String,
    /// %r: the remote user.
    pub remote_user: String,
    /// %u: the local user.
    pub local_user: String,
    /// %i: the local user id.
    pub uid: String,
    /// %j: the ProxyJump hosts, or empty.
    pub jump: String,
    /// %T: the tunnel interface, or "NONE" (LocalCommand only).
    pub tunnel: Option<String>,
    /// %f, %H, %I, %K, %t (KnownHostsCommand only).
    pub known_hosts: Option<KnownHostsTokens>,
}

#[derive(Debug, Clone, Default)]
pub struct KnownHostsTokens {
    pub fingerprint: String,
    pub hostname_or_alias: String,
    pub reason: String,
    pub key_base64: String,
    pub key_type: String,
}

/// Which tokens a keyword accepts (ssh_config(5), TOKENS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSet {
    /// Hostname: only %% and %h.
    HostnameOnly,
    /// The common set: %% %C %d %h %i %j %k %L %l %n %p %r %u.
    Default,
    /// The common set without %r and %C (User).
    NoUser,
    /// LocalCommand: the common set plus %T.
    LocalCommand,
    /// KnownHostsCommand: the common set plus %f %H %I %K %t.
    KnownHosts,
}

impl Tokens {
    fn lookup(&self, c: char, set: TokenSet) -> Option<&str> {
        if set == TokenSet::HostnameOnly {
            return (c == 'h').then_some(self.host.as_str());
        }
        let common = match c {
            'L' => Some(&self.short_local),
            'i' => Some(&self.uid),
            'k' => Some(&self.key_alias),
            'l' => Some(&self.local_host),
            'n' => Some(&self.original_host),
            'p' => Some(&self.port),
            'd' => Some(&self.home),
            'h' => Some(&self.host),
            'u' => Some(&self.local_user),
            'j' => Some(&self.jump),
            'C' if set != TokenSet::NoUser => Some(&self.conn_hash),
            'r' if set != TokenSet::NoUser => Some(&self.remote_user),
            _ => None,
        };
        if let Some(v) = common {
            return Some(v.as_str());
        }
        match (set, c) {
            (TokenSet::LocalCommand, 'T') => self.tunnel.as_deref().or(Some("NONE")),
            (TokenSet::KnownHosts, _) => {
                let k = self.known_hosts.as_ref()?;
                match c {
                    'f' => Some(&k.fingerprint),
                    'H' => Some(&k.hostname_or_alias),
                    'I' => Some(&k.reason),
                    'K' => Some(&k.key_base64),
                    't' => Some(&k.key_type),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

/// `percent_expand` (and with `dollar`, `percent_dollar_expand`). `getenv`
/// answers `${VAR}`.
pub fn expand(
    s: &str,
    tokens: &Tokens,
    set: TokenSet,
    dollar: bool,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if dollar && c == '$' && chars.get(i + 1) == Some(&'{') {
            let start = i + 2;
            let end = chars[start..].iter().position(|&c| c == '}').map(|p| start + p);
            let Some(end) = end else {
                return Err(format!("environment variable '{}' missing closing '}}'", chars[start..].iter().collect::<String>()));
            };
            if end == start {
                return Err("zero-length environment variable".into());
            }
            let name: String = chars[start..end].iter().collect();
            match getenv(&name) {
                Some(v) => out.push_str(&v),
                None => return Err(format!("env var ${{{name}}} has no value")),
            }
            i = end + 1;
            continue;
        }
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        match chars.get(i + 1) {
            None => return Err("invalid format".into()),
            Some('%') => out.push('%'),
            Some(&t) => match tokens.lookup(t, set) {
                Some(v) => out.push_str(v),
                None => return Err(format!("unknown key %{t}")),
            },
        }
        i += 2;
    }
    Ok(out)
}

/// `dollar_expand`: `${VAR}` only.
pub fn dollar(s: &str, getenv: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| format!("environment variable '{after}' missing closing '}}'"))?;
        if end == 0 {
            return Err("zero-length environment variable".into());
        }
        let name = &after[..end];
        out.push_str(&getenv(name).ok_or_else(|| format!("env var ${{{name}}} has no value"))?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `~` and `~/…` to the home directory; `~user/…` is left alone (OpenSSH
/// looks the user up; Reach only knows its own).
pub fn tilde(path: &str, home: &str) -> String {
    if path == "~" {
        return home.to_string();
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        let sep = if home.ends_with('/') || home.ends_with('\\') { "" } else { "/" };
        return format!("{home}{sep}{rest}");
    }
    path.to_string()
}

/// %C: SHA-1 of "%l%h%p%r%j", in hex, as `ssh_connection_hash` does.
pub fn connection_hash(local_host: &str, host: &str, port: &str, user: &str, jump: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    for part in [local_host, host, port, user, jump] {
        h.update(part.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks() -> Tokens {
        Tokens {
            host: "web.lan".into(),
            port: "22".into(),
            remote_user: "admin".into(),
            local_user: "me".into(),
            home: "/home/me".into(),
            original_host: "web".into(),
            ..Default::default()
        }
    }

    #[test]
    fn tokens() {
        let env = |_: &str| None;
        assert_eq!(expand("%r@%h:%p %%", &toks(), TokenSet::Default, false, &env).unwrap(), "admin@web.lan:22 %");
        assert!(expand("%r", &toks(), TokenSet::NoUser, false, &env).is_err());
        assert!(expand("%n", &toks(), TokenSet::HostnameOnly, false, &env).is_err());
        assert!(expand("trailing %", &toks(), TokenSet::Default, false, &env).is_err());
        assert_eq!(expand("%T", &toks(), TokenSet::LocalCommand, false, &env).unwrap(), "NONE");
    }

    #[test]
    fn environment() {
        let env = |k: &str| (k == "SOCK").then(|| "/run/agent".to_string());
        assert_eq!(expand("${SOCK}/x", &toks(), TokenSet::Default, true, &env).unwrap(), "/run/agent/x");
        assert!(expand("${NOPE}", &toks(), TokenSet::Default, true, &env).is_err());
        assert_eq!(expand("${SOCK}", &toks(), TokenSet::Default, false, &env).unwrap(), "${SOCK}");
    }

    #[test]
    fn connection_hash_matches_openssh() {
        // `ssh -G -F /dev/null -o ControlPath=%C -o User=u h` on a machine
        // called DESKTOP-R4IFDIE (OpenSSH 10.3).
        assert_eq!(connection_hash("DESKTOP-R4IFDIE", "h", "22", "u", ""), "84233a0a1f1c6e18a7ee13f59a09f1b332024aed");
    }
}
