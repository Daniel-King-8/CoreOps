//! Checking a server's host key as OpenSSH does (sshconnect.c
//! check_host_key) for a session with ssh_config settings:
//! StrictHostKeyChecking, the known_hosts files, HostKeyAlias, CheckHostIP,
//! @cert-authority and @revoked, RevokedHostKeys, KnownHostsCommand,
//! NoHostAuthenticationForLocalhost, RequiredRSASize, CASignatureAlgorithms,
//! HashKnownHosts, VisualHostKey and FingerprintHash.
//!
//! A session without ssh_config settings keeps Reach's own store
//! (known_hosts.json) and its trust-on-first-use question.

use std::path::PathBuf;

use russh::keys::{Algorithm, PublicKeyOrCertificate};

use super::knownhosts::{self, Check, Entry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strict {
    /// Never add a key; refuse unknown hosts.
    Yes,
    /// Add unknown hosts without asking; refuse changed keys.
    AcceptNew,
    /// Add unknown hosts and connect even when the key changed (weakening).
    No,
    /// Ask about unknown hosts (OpenSSH's default, and Reach's).
    Ask,
}

#[derive(Debug, Clone)]
pub struct HostKeyPolicy {
    pub strict: Strict,
    /// Whether the OpenSSH files are used: an imported session, or a config
    /// that names known_hosts files. Otherwise Reach's own store.
    pub use_files: bool,
    pub user_files: Vec<PathBuf>,
    pub global_files: Vec<PathBuf>,
    /// HostKeyAlias, lowercased.
    pub alias: Option<String>,
    pub check_host_ip: bool,
    pub hash: bool,
    pub no_auth_localhost: bool,
    pub revoked: Vec<PathBuf>,
    /// KnownHostsCommand, when the user approved it.
    pub command: Option<String>,
    pub visual: bool,
    /// "sha256" or "md5".
    pub fingerprint_hash: String,
    pub min_rsa_bits: usize,
    /// CASignatureAlgorithms, assembled.
    pub ca_signature_algorithms: Vec<String>,
    /// A proxy or jump host stands between: CheckHostIP has no address to check.
    pub proxied: bool,
    /// The connection's `%` tokens, for KnownHostsCommand.
    pub tokens: crate::ssh::sshconf::expand::Tokens,
    /// WarnWeakCrypto: say so when the key exchange is not post-quantum.
    pub warn_weak_crypto: bool,
    /// VerifyHostKeyDNS: 0 no, 1 yes, 2 ask.
    pub verify_dns: u8,
    /// UpdateHostKeys (see `hostkey_update`).
    pub update_host_keys: super::hostkey_update::UpdateHostKeys,
    /// HostKeyAlgorithms as offered, which announced keys must be in.
    pub host_key_algorithms: Vec<String>,
}

/// OpenSSH's default CASignatureAlgorithms (SSH_ALLOWED_CA_SIGALGS).
pub const DEFAULT_CA_SIGALGS: &[&str] = &[
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256",
];

/// What to do with the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Ask the user (unknown host under StrictHostKeyChecking ask); on yes,
    /// record it.
    Ask { fingerprint: String, randomart: Option<String> },
    /// Record it and accept (accept-new, no).
    AddAndAccept,
    Refuse(String),
}

fn blob(key: &russh::keys::PublicKey) -> Vec<u8> {
    // The key blob as known_hosts stores it (type name, then key data).
    key.to_bytes().unwrap_or_default()
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn read_entries(files: &[PathBuf]) -> Vec<Entry> {
    let mut out = Vec::new();
    for f in files {
        if let Ok(text) = std::fs::read_to_string(f) {
            let parsed = knownhosts::parse(&text, &f.display().to_string());
            for e in &parsed.errors {
                tracing::warn!("known_hosts: {e}");
            }
            out.extend(parsed.entries);
        }
    }
    out
}

impl HostKeyPolicy {
    /// The names a key is looked up by: the host (or HostKeyAlias) with its
    /// port, and with CheckHostIP the address too.
    pub fn names(&self, host: &str, port: u16) -> (String, Option<String>) {
        let name = self.alias.clone().unwrap_or_else(|| host.to_ascii_lowercase());
        let label = knownhosts::host_label(&name, port);
        let ip = if self.check_host_ip && self.alias.is_none() && !self.proxied && host.parse::<std::net::IpAddr>().is_err() {
            use std::net::ToSocketAddrs;
            (host, port).to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| knownhosts::host_label(&a.ip().to_string(), port))
        } else {
            None
        };
        (label, ip)
    }

    /// Entries from the files and, when approved, KnownHostsCommand, run
    /// once per name looked up (`%I` is HOSTNAME or ADDRESS) as
    /// load_hostkeys_command does: split into arguments, tokens expanded in
    /// the arguments after the program only, no shell.
    fn entries(&self, names: &[(String, &str)], key_type: &str, key_b64: &str, fp: &str) -> Vec<Entry> {
        let mut out = read_entries(&self.user_files);
        out.extend(read_entries(&self.global_files));
        let Some(cmd) = &self.command else { return out };
        let argv = match crate::ssh::sshconf::lex::argv_split_keep_comments(cmd) {
            Ok(a) if !a.is_empty() => a,
            _ => {
                tracing::warn!("KnownHostsCommand \"{cmd}\" contains invalid quotes or nothing to run");
                return out;
            }
        };
        for (name, invocation) in names {
            let mut tokens = self.tokens.clone();
            tokens.known_hosts = Some(crate::ssh::sshconf::expand::KnownHostsTokens {
                fingerprint: fp.to_string(),
                hostname_or_alias: name.clone(),
                reason: invocation.to_string(),
                key_base64: key_b64.to_string(),
                key_type: key_type.to_string(),
            });
            let mut args = Vec::new();
            for a in &argv[1..] {
                match crate::ssh::sshconf::expand::expand(a, &tokens, crate::ssh::sshconf::expand::TokenSet::KnownHosts, true, &|n| std::env::var(n).ok()) {
                    Ok(x) => args.push(x),
                    Err(e) => {
                        tracing::warn!("KnownHostsCommand: {e}");
                        return out;
                    }
                }
            }
            match run_capture(&argv[0], &args) {
                Ok(text) => out.extend(knownhosts::parse(&text, "KnownHostsCommand").entries),
                Err(e) => tracing::warn!("KnownHostsCommand: {e}"),
            }
        }
        out
    }

    /// The checks that do not depend on where keys are remembered:
    /// RequiredRSASize, RevokedHostKeys, NoHostAuthenticationForLocalhost.
    pub fn pre_check(&self, host: &str, presented: &PublicKeyOrCertificate) -> Option<Verdict> {
        let key = presented.public_key();
        let key_type = key.algorithm().as_str().to_string();
        let key_blob = blob(&key);
        if let Algorithm::Rsa { .. } = key.algorithm() {
            if let russh::keys::ssh_key::public::KeyData::Rsa(r) = key.key_data() {
                let bits = r.n().as_positive_bytes().map_or(0, |b| b.len() * 8);
                if bits < self.min_rsa_bits {
                    return Some(Verdict::Refuse(format!("The server's RSA host key has {bits} bits, fewer than RequiredRSASize {}", self.min_rsa_bits)));
                }
            }
        }
        for f in &self.revoked {
            match std::fs::read(f) {
                Ok(bytes) => match knownhosts::check_revoked_file(&bytes, &key_type, &key_blob) {
                    Ok(true) => return Some(Verdict::Refuse(format!("The server's host key is revoked in {}", f.display()))),
                    Ok(false) => {}
                    Err(e) => return Some(Verdict::Refuse(format!("RevokedHostKeys {} cannot be read ({e}); refusing, as ssh does", f.display()))),
                },
                Err(e) => return Some(Verdict::Refuse(format!("RevokedHostKeys {} cannot be read ({e}); refusing, as ssh does", f.display()))),
            }
        }
        if self.no_auth_localhost && self.alias.is_none() && is_loopback(host) {
            return Some(Verdict::Accept);
        }
        None
    }

    /// Check a presented key against the known_hosts files.
    pub fn verify(&self, host: &str, port: u16, presented: &PublicKeyOrCertificate) -> Verdict {
        if let Some(v) = self.pre_check(host, presented) {
            return v;
        }
        let key = presented.public_key();
        let key_type = key.algorithm().as_str().to_string();
        let key_blob = blob(&key);
        let (label, ip) = self.names(host, port);
        let fp = knownhosts::fingerprint(&key_blob, &self.fingerprint_hash);
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_blob);
        let mut lookups = vec![(label.clone(), "HOSTNAME")];
        if let Some(ip) = &ip {
            lookups.push((ip.clone(), "ADDRESS"));
        }
        let entries = self.entries(&lookups, &key_type, &b64, &fp);
        let mut names = vec![label.clone()];
        names.extend(ip.clone());

        // A host certificate: its CA must be trusted for this host.
        if let PublicKeyOrCertificate::Certificate(cert) = presented {
            let cert_blob = cert.to_bytes().unwrap_or_default();
            match knownhosts::cert_info(&cert_blob) {
                Ok(info) if knownhosts::check_ca(&entries, std::slice::from_ref(&label), &info.ca_key_type, &info.ca_key_blob) => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                    let principal = self.alias.clone().unwrap_or_else(|| host.to_ascii_lowercase());
                    let sig_alg = cert.signature().algorithm().as_str().to_string();
                    if info.cert_type != 2 {
                        return Verdict::Refuse("The server presented a user certificate as its host key".into());
                    }
                    if now < info.valid_after || now >= info.valid_before {
                        return Verdict::Refuse("The server's host certificate is not valid now".into());
                    }
                    // sshkey_cert_check_host: a principal list is required,
                    // and one entry must match the name (patterns allowed).
                    if info.principals.is_empty() {
                        return Verdict::Refuse("The server's host certificate lists no principals".into());
                    }
                    if !info.principals.iter().any(|p| crate::ssh::sshconf::pattern::match_pattern(&principal, p)) {
                        return Verdict::Refuse(format!("The server's host certificate is not for {principal}"));
                    }
                    if !self.ca_signature_algorithms.contains(&sig_alg) {
                        return Verdict::Refuse(format!("The host certificate is signed with {sig_alg}, not in CASignatureAlgorithms"));
                    }
                    if matches!(knownhosts::check(&entries, &names, &info.key_type, &info.key_blob), Check::Revoked(_)) {
                        return Verdict::Refuse("The certified host key is revoked".into());
                    }
                    return Verdict::Accept;
                }
                // No CA for it: ssh checks the plain key instead.
                _ => tracing::info!("No trusted CA for the host certificate of {label}; checking the plain key"),
            }
        }

        match knownhosts::check(&entries, std::slice::from_ref(&label), &key_type, &key_blob) {
            Check::Found(_) => {
                if let Some(ip) = &ip {
                    if let Check::Changed { .. } = knownhosts::check(&entries, std::slice::from_ref(ip), &key_type, &key_blob) {
                        tracing::warn!("The host key for {label} differs from the key for the address {ip}");
                    }
                }
                Verdict::Accept
            }
            Check::Revoked(e) => Verdict::Refuse(format!("The server's host key is marked @revoked ({}:{})", e.file, e.line)),
            Check::Changed { offending, .. } => {
                if self.strict == Strict::No {
                    tracing::warn!("Host key for {label} CHANGED; connecting anyway (StrictHostKeyChecking no)");
                    return Verdict::Accept;
                }
                Verdict::Refuse(format!(
                    "The host key for {label} has CHANGED. Someone could be intercepting the connection, or the server was reinstalled. The known key is at {}:{}; remove that line if the change is expected.",
                    offending.file, offending.line
                ))
            }
            Check::BadKey(e) => Verdict::Refuse(format!("The server's host key cannot be read: {e}")),
            Check::NotFound { .. } => match self.strict {
                Strict::Yes => Verdict::Refuse(format!("No host key is known for {label} and StrictHostKeyChecking is on")),
                Strict::AcceptNew | Strict::No => Verdict::AddAndAccept,
                Strict::Ask => Verdict::Ask {
                    fingerprint: fp,
                    randomart: self.visual.then(|| knownhosts::randomart(&key_type, None, &key_blob, &self.fingerprint_hash)),
                },
            },
        }
    }

    /// Record an accepted key where ssh would: the first user file, hashed
    /// under HashKnownHosts, with the address too under CheckHostIP.
    pub fn record(&self, host: &str, port: u16, presented: &PublicKeyOrCertificate) {
        let Some(file) = self.user_files.first() else { return };
        let key = presented.public_key();
        let (label, ip) = self.names(host, port);
        let names: Vec<String> = std::iter::once(label).chain(ip).collect();
        let line = knownhosts::format_line(&names, key.algorithm().as_str(), &blob(&key), self.hash);
        match knownhosts::append(file, &line) {
            Ok(()) => tracing::info!("Added the host key of {} to {}", names.join(","), file.display()),
            Err(e) => tracing::warn!("Could not add the host key to {}: {e}", file.display()),
        }
    }
}

/// Run a program with its arguments, no shell, and take its output.
#[cfg(not(target_os = "android"))]
fn run_capture(program: &str, args: &[String]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("exited with {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "android")]
fn run_capture(program: &str, _args: &[String]) -> Result<String, String> {
    Err(format!("A phone cannot run \"{program}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> russh::keys::PrivateKey {
        russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn presented(k: &russh::keys::PrivateKey) -> PublicKeyOrCertificate {
        PublicKeyOrCertificate::PublicKey { key: k.public_key().clone(), hash_alg: None }
    }

    fn policy(dir: &std::path::Path, strict: Strict) -> HostKeyPolicy {
        HostKeyPolicy {
            strict,
            use_files: true,
            user_files: vec![dir.join("known_hosts")],
            global_files: vec![],
            alias: None,
            check_host_ip: false,
            hash: false,
            no_auth_localhost: false,
            revoked: vec![],
            command: None,
            visual: false,
            fingerprint_hash: "sha256".into(),
            min_rsa_bits: 1024,
            ca_signature_algorithms: DEFAULT_CA_SIGALGS.iter().map(|s| s.to_string()).collect(),
            proxied: false,
            tokens: Default::default(),
            warn_weak_crypto: false,
            verify_dns: 0,
            update_host_keys: Default::default(),
            host_key_algorithms: vec![],
        }
    }

    #[test]
    fn unknown_known_changed_and_strictness() {
        let dir = std::env::temp_dir().join(format!("reach-hk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k1 = key(1);
        let k2 = key(2);
        let p = policy(&dir, Strict::Ask);
        assert!(matches!(p.verify("web", 22, &presented(&k1)), Verdict::Ask { .. }));
        assert!(matches!(policy(&dir, Strict::Yes).verify("web", 22, &presented(&k1)), Verdict::Refuse(_)));
        assert_eq!(policy(&dir, Strict::AcceptNew).verify("web", 22, &presented(&k1)), Verdict::AddAndAccept);
        p.record("web", 22, &presented(&k1));
        assert_eq!(p.verify("web", 22, &presented(&k1)), Verdict::Accept);
        // Another port is another host.
        assert!(matches!(p.verify("web", 2222, &presented(&k1)), Verdict::Ask { .. }));
        // A changed key is refused, even under accept-new; "no" lets it through.
        assert!(matches!(p.verify("web", 22, &presented(&k2)), Verdict::Refuse(m) if m.contains("CHANGED")));
        assert!(matches!(policy(&dir, Strict::AcceptNew).verify("web", 22, &presented(&k2)), Verdict::Refuse(_)));
        assert_eq!(policy(&dir, Strict::No).verify("web", 22, &presented(&k2)), Verdict::Accept);
        // HostKeyAlias looks the key up under the alias.
        let mut a = policy(&dir, Strict::Yes);
        a.alias = Some("web".into());
        assert_eq!(a.verify("10.0.0.5", 22, &presented(&k1)), Verdict::Accept);
        // Hashed lines are found too.
        let mut h = policy(&dir, Strict::Ask);
        h.hash = true;
        h.record("db", 22, &presented(&k2));
        let text = std::fs::read_to_string(dir.join("known_hosts")).unwrap();
        assert!(text.lines().last().unwrap().starts_with("|1|"));
        assert_eq!(h.verify("db", 22, &presented(&k2)), Verdict::Accept);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn known_hosts_command_runs_without_a_shell() {
        // A host name full of shell syntax reaches the program as one
        // argument; nothing is run but the program itself.
        let dir = std::env::temp_dir().join(format!("reach-hk3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("pwned");
        let mut p = policy(&dir, Strict::Yes);
        #[cfg(windows)]
        let echo = "cmd.exe /C echo";
        #[cfg(not(windows))]
        let echo = "echo";
        p.command = Some(format!("{echo} %H"));
        let evil = format!("x;touch {}&&echo", marker.display());
        let names = vec![(evil.clone(), "HOSTNAME")];
        let _ = p.entries(&names, "ssh-ed25519", "AAAA", "SHA256:x");
        assert!(!marker.exists(), "the host name was run as a command");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revoked_and_localhost() {
        let dir = std::env::temp_dir().join(format!("reach-hk2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k1 = key(3);
        let revoked = dir.join("revoked");
        std::fs::write(&revoked, k1.public_key().to_openssh().unwrap()).unwrap();
        let mut p = policy(&dir, Strict::No);
        p.revoked = vec![revoked];
        assert!(matches!(p.verify("web", 22, &presented(&k1)), Verdict::Refuse(m) if m.contains("revoked")));
        let mut l = policy(&dir, Strict::Yes);
        l.no_auth_localhost = true;
        assert_eq!(l.verify("localhost", 2222, &presented(&k1)), Verdict::Accept);
        std::fs::remove_dir_all(&dir).ok();
    }
}
