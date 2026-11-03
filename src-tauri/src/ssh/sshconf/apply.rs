//! From resolved options to what Reach's SSH engine does: algorithm lists,
//! keepalives, rekeying, the version string, and how the TCP connection is
//! made. Every keyword that reaches here is either used or reported.

use std::borrow::Cow;
use std::time::Duration;

use serde::Serialize;

use super::keyword::Kw;
use super::resolve::{Options, Resolved};
use super::value;

/// How the socket to the server (or the first hop) is opened.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SocketPlan {
    /// ConnectTimeout; `None` leaves it to the system.
    pub connect_timeout: Option<Duration>,
    /// ConnectionAttempts (at least 1), a second apart as ssh does.
    pub attempts: u32,
    /// AddressFamily: `Some(true)` IPv4 only, `Some(false)` IPv6 only.
    pub ipv4_only: Option<bool>,
    pub bind_address: Option<String>,
    pub bind_interface: Option<String>,
    /// TCPKeepAlive (SO_KEEPALIVE). On unless the config says no.
    pub tcp_keepalive: bool,
    /// IPQoS DSCP values (interactive, bulk), as TOS bytes.
    pub tos_interactive: Option<u32>,
    pub tos_bulk: Option<u32>,
}

impl Default for SocketPlan {
    /// ssh's defaults: one attempt, no timeout but the system's, keepalive on.
    fn default() -> Self {
        Self {
            connect_timeout: None,
            attempts: 1,
            ipv4_only: None,
            bind_address: None,
            bind_interface: None,
            tcp_keepalive: true,
            tos_interactive: None,
            tos_bulk: None,
        }
    }
}

/// A setting that weakens the connection, shown on the session with a
/// warning and named in the connection log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Weakening {
    pub keyword: String,
    pub value: String,
    /// Why it is weaker, for the warning.
    pub reason: String,
    /// The user approved it (or wrote it in Reach); otherwise it is held
    /// back until they do.
    pub accepted: bool,
}

/// What the plan did with a keyword it was given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "camelCase")]
pub enum Use {
    Used,
    /// Part of the value cannot be honoured here (an algorithm Reach's
    /// engine does not have, a socket option this system lacks).
    Partly(String),
    /// Not used, and why.
    NotUsed(String),
}

#[derive(Debug)]
pub struct Plan {
    pub config: russh::client::Config,
    pub socket: SocketPlan,
    pub weakenings: Vec<Weakening>,
    /// Per keyword set in the config: what became of it.
    pub uses: Vec<(Kw, Use)>,
    /// Weakenings the user approved ("Keyword value").
    pub accepted: Vec<String>,
    /// PubkeyAcceptedAlgorithms, assembled; `None` leaves OpenSSH's default.
    pub pubkey_algorithms: Option<Vec<String>>,
    /// How to log in; set for sessions with ssh_config settings.
    pub auth: Option<crate::ssh::userauth::AuthPolicy>,
    /// CASignatureAlgorithms, assembled.
    pub ca_signature_algorithms: Vec<String>,
    /// How to check the host key; set for sessions with ssh_config settings.
    pub hostkeys: Option<crate::ssh::hostkeys::HostKeyPolicy>,
    /// The session itself (target host only).
    pub session: Option<crate::ssh::session_opts::SessionPolicy>,
    /// Why the connection must not be made: RefuseConnection, or a
    /// ProxyCommand the user has not approved.
    pub refused: Option<String>,
    /// ProxyCommand, approved.
    pub proxy_command: Option<crate::ssh::proxycmd::ProxyCommand>,
    /// Forwards and agent forwarding (target only).
    pub forwards: Option<crate::ssh::forwarding::ForwardPolicy>,
    /// Lines typed into the session count as approved (options built by
    /// Reach itself); off for stored sessions, see `SshOptions::approved_by`.
    pub typed_lines_approved: bool,
    /// LogLevel and LogVerbose; set for sessions with ssh_config settings.
    pub log: Option<(Option<String>, Vec<String>)>,
    /// ControlMaster/ControlPath/ControlPersist (target only).
    pub control: Option<crate::ssh::control::ControlPlan>,
}

/// OpenSSH's default PubkeyAcceptedAlgorithms (KEX_DEFAULT_PK_ALG).
pub const DEFAULT_PUBKEY_ALGORITHMS: &[&str] = &[
    "ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com", "ssh-ed25519",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256",
];

/// How an approved weakening is stored: "Keyword value".
pub fn weakening_key(kw: Kw, value: &str) -> String {
    format!("{} {}", kw.name(), value)
}

/// The algorithms Reach's engine speaks, by OpenSSH name.
pub mod supported {
    use russh::{cipher, kex, mac};

    pub fn kex() -> Vec<(&'static str, kex::Name)> {
        use kex::*;
        vec![
            ("mlkem768x25519-sha256", MLKEM768X25519_SHA256),
            ("sntrup761x25519-sha512", SNTRUP761X25519_SHA512),
            ("sntrup761x25519-sha512@openssh.com", SNTRUP761X25519_SHA512_OPENSSH),
            ("curve25519-sha256", CURVE25519),
            ("curve25519-sha256@libssh.org", CURVE25519_PRE_RFC_8731),
            ("ecdh-sha2-nistp256", ECDH_SHA2_NISTP256),
            ("ecdh-sha2-nistp384", ECDH_SHA2_NISTP384),
            ("ecdh-sha2-nistp521", ECDH_SHA2_NISTP521),
            ("diffie-hellman-group-exchange-sha256", DH_GEX_SHA256),
            ("diffie-hellman-group18-sha512", DH_G18_SHA512),
            ("diffie-hellman-group17-sha512", DH_G17_SHA512),
            ("diffie-hellman-group16-sha512", DH_G16_SHA512),
            ("diffie-hellman-group15-sha512", DH_G15_SHA512),
            ("diffie-hellman-group14-sha256", DH_G14_SHA256),
            ("diffie-hellman-group-exchange-sha1", DH_GEX_SHA1),
            ("diffie-hellman-group14-sha1", DH_G14_SHA1),
            ("diffie-hellman-group1-sha1", DH_G1_SHA1),
        ]
    }

    pub fn ciphers() -> Vec<(&'static str, cipher::Name)> {
        use cipher::*;
        vec![
            ("chacha20-poly1305@openssh.com", CHACHA20_POLY1305),
            ("aes256-gcm@openssh.com", AES_256_GCM),
            ("aes128-gcm@openssh.com", AES_128_GCM),
            ("aes256-ctr", AES_256_CTR),
            ("aes192-ctr", AES_192_CTR),
            ("aes128-ctr", AES_128_CTR),
            ("aes256-cbc", AES_256_CBC),
            ("aes192-cbc", AES_192_CBC),
            ("aes128-cbc", AES_128_CBC),
            ("3des-cbc", TRIPLE_DES_CBC),
        ]
    }

    pub fn macs() -> Vec<(&'static str, mac::Name)> {
        use mac::*;
        vec![
            ("hmac-sha2-512-etm@openssh.com", HMAC_SHA512_ETM),
            ("hmac-sha2-256-etm@openssh.com", HMAC_SHA256_ETM),
            ("hmac-sha2-512", HMAC_SHA512),
            ("hmac-sha2-256", HMAC_SHA256),
            ("hmac-sha1-etm@openssh.com", HMAC_SHA1_ETM),
            ("hmac-sha1", HMAC_SHA1),
            ("umac-128-etm@openssh.com", UMAC_128_ETM),
            ("umac-64-etm@openssh.com", UMAC_64_ETM),
            ("umac-128@openssh.com", UMAC_128),
            ("umac-64@openssh.com", UMAC_64),
            ("hmac-sha1-96-etm@openssh.com", HMAC_SHA1_96_ETM),
            ("hmac-sha1-96", HMAC_SHA1_96),
            ("hmac-md5-etm@openssh.com", HMAC_MD5_ETM),
            ("hmac-md5-96-etm@openssh.com", HMAC_MD5_96_ETM),
            ("hmac-md5", HMAC_MD5),
            ("hmac-md5-96", HMAC_MD5_96),
            ("hmac-ripemd160-etm@openssh.com", HMAC_RIPEMD160_ETM),
            ("hmac-ripemd160@openssh.com", HMAC_RIPEMD160_OPENSSH),
            ("hmac-ripemd160", HMAC_RIPEMD160),
        ]
    }
}

/// Algorithms that weaken a connection when a config adds them.
fn weak_algorithm(name: &str) -> Option<&'static str> {
    Some(match name {
        n if n.contains("sha1") && (n.starts_with("diffie-hellman") || n.starts_with("hmac")) => {
            "SHA-1 is broken for collisions; servers that only offer it are years out of date"
        }
        n if n.contains("md5") => "MD5 is broken",
        n if n.ends_with("-cbc") => "CBC mode is open to plaintext-recovery attacks in SSH",
        "ssh-rsa" | "ssh-rsa-cert-v01@openssh.com" => "RSA signatures with SHA-1 are forgeable at a cost within reach",
        "ssh-dss" | "ssh-dss-cert-v01@openssh.com" => "DSA keys are limited to 1024 bits",
        n if n.contains("umac-64") || n.ends_with("-96") || n.contains("-96-") => "a 64- or 96-bit tag is short",
        n if n.contains("ripemd160") => "RIPEMD-160 is retired",
        _ => return None,
    })
}

/// `kex_assemble_names`: a list as written (`+`, `-`, `^` or plain) against
/// a default and the full set. Returns the names in order, and the names it
/// asked for that the engine lacks.
pub fn assemble(spec: &str, default: &[&str], all: &[&str]) -> (Vec<String>, Vec<String>) {
    let mut missing = Vec::new();
    let mut keep = |name: &str, out: &mut Vec<String>| {
        if all.contains(&name) {
            if !out.iter().any(|o| o == name) {
                out.push(name.to_string());
            }
        } else if !missing.iter().any(|m: &String| m == name) {
            missing.push(name.to_string());
        }
    };
    let mut out = Vec::new();
    if let Some(add) = spec.strip_prefix('+') {
        for d in default {
            keep(d, &mut out);
        }
        for n in add.split(',') {
            keep(n, &mut out);
        }
    } else if let Some(remove) = spec.strip_prefix('-') {
        let pats: Vec<&str> = remove.split(',').collect();
        for d in default {
            if !pats.iter().any(|p| super::pattern::match_pattern(d, p)) {
                keep(d, &mut out);
            }
        }
    } else if let Some(first) = spec.strip_prefix('^') {
        for n in first.split(',') {
            keep(n, &mut out);
        }
        for d in default {
            keep(d, &mut out);
        }
    } else {
        for n in spec.split(',') {
            keep(n, &mut out);
        }
    }
    (out, missing)
}

impl Plan {
    /// Build the plan for a resolved host. `base` is Reach's own russh
    /// configuration, which the config adjusts. `accepted` lists the
    /// weakenings the user approved ("Keyword value"); lines set in Reach
    /// itself count as approved.
    pub fn new(r: &Resolved, base: russh::client::Config, accepted: &[String], typed_lines_approved: bool) -> Plan {
        let mut p = Plan { config: base, socket: SocketPlan::default(), weakenings: vec![], uses: vec![], accepted: accepted.to_vec(), pubkey_algorithms: None, auth: None, ca_signature_algorithms: crate::ssh::hostkeys::DEFAULT_CA_SIGALGS.iter().map(|s| s.to_string()).collect(), hostkeys: None, session: None, refused: None, proxy_command: None, forwards: None, log: None, control: None, typed_lines_approved };
        let o = &r.options;
        p.algorithms(o);
        p.transport(o);
        p
    }

    /// Whether a weakening value of `kw` may apply: approved by the user, or
    /// written in Reach's own editor (the command line of a session).
    pub fn approved(&self, o: &Options, kw: Kw, value: &str) -> bool {
        (self.typed_lines_approved && o.get(kw).is_some_and(|s| s.at.file == "command line"))
            || self.accepted.iter().any(|a| *a == weakening_key(kw, value))
    }

    fn weak(&mut self, kw: Kw, value: &str, reason: &str, accepted: bool) {
        self.weakenings.push(Weakening { keyword: kw.name().into(), value: value.into(), reason: reason.into(), accepted });
    }

    /// An algorithm list: assembled as OpenSSH does against Reach's
    /// defaults, weak additions kept only once approved, names the engine
    /// lacks reported.
    fn pick<T: Clone>(&mut self, o: &Options, kw: Kw, table: &[(&str, T)], default: &[&str]) -> Option<Vec<T>> {
        let spec = o.first(kw)?.to_string();
        let all: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
        let (mut names, missing) = assemble(&spec, default, &all);
        let mut held = Vec::new();
        for n in names.clone().iter().filter(|n| !default.contains(&n.as_str())) {
            if let Some(why) = weak_algorithm(n) {
                let ok = self.approved(o, kw, n);
                self.weak(kw, n, why, ok);
                if !ok {
                    names.retain(|x| x != n);
                    held.push(n.clone());
                }
            }
        }
        let mut notes = Vec::new();
        if !held.is_empty() {
            notes.push(format!("waiting for your approval: {}", held.join(", ")));
        }
        if !missing.is_empty() {
            notes.push(format!("not available: {}", missing.join(", ")));
        }
        if names.is_empty() {
            self.uses.push((kw, Use::NotUsed(if notes.is_empty() { format!("none of {spec} is available") } else { notes.join("; ") })));
            return None;
        }
        self.uses.push((kw, if notes.is_empty() { Use::Used } else { Use::Partly(notes.join("; ")) }));
        Some(names.iter().filter_map(|n| table.iter().find(|(t, _)| t == n).map(|(_, v)| v.clone())).collect())
    }

    fn algorithms(&mut self, o: &Options) {
        let kex_table = supported::kex();
        let cur = self.config.preferred.kex.to_vec();
        let default: Vec<&str> = kex_table.iter().filter(|(_, n)| cur.contains(n)).map(|(s, _)| *s).collect();
        if let Some(mut kex) = self.pick(o, Kw::KexAlgorithms, &kex_table, &default) {
            // The extension markers russh needs (ext-info, strict kex).
            for marker in [russh::kex::EXTENSION_SUPPORT_AS_CLIENT, russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT] {
                if !kex.contains(&marker) {
                    kex.push(marker);
                }
            }
            self.config.preferred.kex = Cow::Owned(kex);
        }
        let table = supported::ciphers();
        let cur = self.config.preferred.cipher.to_vec();
        let default: Vec<&str> = table.iter().filter(|(_, n)| cur.contains(n)).map(|(s, _)| *s).collect();
        if let Some(v) = self.pick(o, Kw::Ciphers, &table, &default) {
            self.config.preferred.cipher = Cow::Owned(v);
        }
        let table = supported::macs();
        let cur = self.config.preferred.mac.to_vec();
        let default: Vec<&str> = table.iter().filter(|(_, n)| cur.contains(n)).map(|(s, _)| *s).collect();
        if let Some(v) = self.pick(o, Kw::MACs, &table, &default) {
            self.config.preferred.mac = Cow::Owned(v);
        }
        {
            use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
            let table: Vec<(&str, Algorithm)> = vec![
                ("ssh-ed25519", Algorithm::Ed25519),
                ("ecdsa-sha2-nistp256", Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }),
                ("ecdsa-sha2-nistp384", Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }),
                ("ecdsa-sha2-nistp521", Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }),
                ("rsa-sha2-512", Algorithm::Rsa { hash: Some(HashAlg::Sha512) }),
                ("rsa-sha2-256", Algorithm::Rsa { hash: Some(HashAlg::Sha256) }),
                ("ssh-rsa", Algorithm::Rsa { hash: None }),
            ];
            let cur = self.config.preferred.key.to_vec();
            let default: Vec<&str> = table.iter().filter(|(_, a)| cur.contains(a)).map(|(n, _)| *n).collect();
            if let Some(v) = self.pick(o, Kw::HostKeyAlgorithms, &table, &default) {
                self.config.preferred.key = Cow::Owned(v);
            }
        }
        {
            let table: Vec<(&str, String)> = super::value::algos::KEYS.iter().map(|n| (*n, n.to_string())).collect();
            if let Some(v) = self.pick(o, Kw::PubkeyAcceptedAlgorithms, &table, DEFAULT_PUBKEY_ALGORITHMS) {
                self.pubkey_algorithms = Some(v);
            }
            let table: Vec<(&str, String)> = super::value::algos::CA_SIGS.iter().map(|n| (*n, n.to_string())).collect();
            if let Some(v) = self.pick(o, Kw::CASignatureAlgorithms, &table, crate::ssh::hostkeys::DEFAULT_CA_SIGALGS) {
                self.ca_signature_algorithms = v;
            }
        }
        if let Some(c) = o.first(Kw::Compression) {
            if c == "yes" {
                use russh::compression::{NONE, ZLIB, ZLIB_LEGACY};
                self.config.preferred.compression = Cow::Owned(vec![ZLIB_LEGACY, ZLIB, NONE]);
            } else {
                self.config.preferred.compression = Cow::Owned(vec![russh::compression::NONE]);
            }
            self.uses.push((Kw::Compression, Use::Used));
        }
    }

    fn transport(&mut self, o: &Options) {
        let secs = |kw: Kw| o.first(kw).and_then(value::convtime).map(|s| Duration::from_secs(s as u64));
        if let Some(i) = secs(Kw::ServerAliveInterval) {
            self.config.keepalive_interval = (!i.is_zero()).then_some(i);
            self.uses.push((Kw::ServerAliveInterval, Use::Used));
        }
        if let Some(n) = o.first(Kw::ServerAliveCountMax).and_then(|n| n.parse::<usize>().ok()) {
            self.config.keepalive_max = n;
            self.uses.push((Kw::ServerAliveCountMax, Use::Used));
        }
        if let Some(s) = o.get(Kw::RekeyLimit) {
            // russh refuses limits over 1 GiB (nonce safety for its AEAD
            // ciphers); a larger value is held to that.
            const MAX: i64 = 1 << 30;
            let mut note = None;
            let bytes = if s.args[0] == "default" { None } else { value::scaled(&s.args[0]) };
            let mut limits = self.config.limits.clone();
            if let Some(b) = bytes.filter(|b| *b > 0) {
                if b > MAX {
                    note = Some(format!("{} is held to 1G, the most Reach's engine allows", s.args[0]));
                }
                let b = b.min(MAX) as usize;
                limits.rekey_write_limit = b;
                limits.rekey_read_limit = b;
            }
            if let Some(t) = s.args.get(1).filter(|t| *t != "none").and_then(|t| value::convtime(t)) {
                if t > 0 {
                    limits.rekey_time_limit = Duration::from_secs(t as u64);
                }
            }
            self.config.limits = limits;
            self.uses.push((Kw::RekeyLimit, note.map_or(Use::Used, Use::Partly)));
        }
        if let Some(a) = o.first(Kw::VersionAddendum) {
            let base = match &self.config.client_id {
                russh::SshId::Standard(s) | russh::SshId::Raw(s) => s.to_string(),
            };
            if !a.is_empty() {
                self.config.client_id = russh::SshId::Standard(Cow::Owned(format!("{base} {a}")));
            }
            self.uses.push((Kw::VersionAddendum, Use::Used));
        }
        if let Some(t) = secs(Kw::ConnectTimeout) {
            self.socket.connect_timeout = Some(t);
            self.uses.push((Kw::ConnectTimeout, Use::Used));
        }
        if let Some(n) = o.first(Kw::ConnectionAttempts).and_then(|n| n.parse::<u32>().ok()) {
            self.socket.attempts = n.max(1);
            self.uses.push((Kw::ConnectionAttempts, Use::Used));
        }
        if let Some(f) = o.first(Kw::AddressFamily) {
            self.socket.ipv4_only = match f {
                "inet" => Some(true),
                "inet6" => Some(false),
                _ => None,
            };
            self.uses.push((Kw::AddressFamily, Use::Used));
        }
        if let Some(b) = o.first(Kw::BindAddress) {
            self.socket.bind_address = Some(b.to_string());
            self.uses.push((Kw::BindAddress, Use::Used));
        }
        if let Some(b) = o.first(Kw::BindInterface) {
            self.socket.bind_interface = Some(b.to_string());
            self.uses.push((Kw::BindInterface, Use::Used));
        }
        if let Some(k) = o.first(Kw::TCPKeepAlive) {
            self.socket.tcp_keepalive = k != "no";
            self.uses.push((Kw::TCPKeepAlive, Use::Used));
        }
        if let Some(q) = o.get(Kw::IPQoS) {
            let tos = |s: &str| ipqos_tos(s);
            self.socket.tos_interactive = tos(&q.args[0]);
            self.socket.tos_bulk = q.args.get(1).map_or(self.socket.tos_interactive, |b| tos(b));
            self.uses.push((Kw::IPQoS, Use::Used));
        }
    }
}

/// An IPQoS word or number as the TOS byte OpenSSH sets (DSCP << 2).
/// `None` for "none" and the deprecated words (the system default).
pub fn ipqos_tos(s: &str) -> Option<u32> {
    let dscp = |v: u32| Some(v << 2);
    match s.to_ascii_lowercase().as_str() {
        "none" | "lowdelay" | "throughput" | "reliability" => None,
        "af11" => dscp(10),
        "af12" => dscp(12),
        "af13" => dscp(14),
        "af21" => dscp(18),
        "af22" => dscp(20),
        "af23" => dscp(22),
        "af31" => dscp(26),
        "af32" => dscp(28),
        "af33" => dscp(30),
        "af41" => dscp(34),
        "af42" => dscp(36),
        "af43" => dscp(38),
        "cs0" => dscp(0),
        "cs1" => dscp(8),
        "cs2" => dscp(16),
        "cs3" => dscp(24),
        "cs4" => dscp(32),
        "cs5" => dscp(40),
        "cs6" => dscp(48),
        "cs7" => dscp(56),
        "ef" => dscp(46),
        "le" => dscp(1),
        "va" => dscp(44),
        n => n.parse::<u32>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembling_lists_like_openssh() {
        let all = ["a", "b", "c", "d"];
        let def = ["a", "b"];
        assert_eq!(assemble("+c", &def, &all).0, ["a", "b", "c"]);
        assert_eq!(assemble("-a", &def, &all).0, ["b"]);
        assert_eq!(assemble("-*", &def, &all).0, Vec::<String>::new());
        assert_eq!(assemble("^c,d", &def, &all).0, ["c", "d", "a", "b"]);
        assert_eq!(assemble("d,a", &def, &all).0, ["d", "a"]);
        assert_eq!(assemble("+x", &def, &all).1, ["x"]);
    }

    #[test]
    fn the_discord_server_gets_hmac_sha1_offered_with_a_warning() {
        let text = "Host centreon\n  HostName 192.168.1.70\n  MACs +hmac-sha1\n";
        let src = super::super::resolve::Source { path: "c".into(), text: Some(text.into()), user: true };
        let env = super::super::env::SystemEnv::new(super::super::env::ExecPolicy::Never);
        let r = super::super::resolve::resolve(&[src], &super::super::resolve::Query { host: "centreon".into(), ..Default::default() }, &env);
        // From a file, not yet approved: held back, and said so.
        let p = Plan::new(&r, russh::client::Config::default(), &[], true);
        assert!(!p.config.preferred.mac.contains(&russh::mac::HMAC_SHA1));
        assert!(matches!(&p.uses[0].1, Use::Partly(m) if m.contains("approval")));
        assert!(!p.weakenings[0].accepted);
        // Approved: offered after Reach's own, with the warning kept.
        let p = Plan::new(&r, russh::client::Config::default(), &["MACs hmac-sha1".into()], true);
        assert!(p.config.preferred.mac.contains(&russh::mac::HMAC_SHA1));
        assert_eq!(p.config.preferred.mac.first(), Some(&russh::mac::HMAC_SHA512_ETM));
        assert_eq!(p.weakenings.len(), 1);
        assert!(p.weakenings[0].accepted);
        assert_eq!(p.uses, [(Kw::MACs, Use::Used)]);
    }

    #[test]
    fn a_weak_mac_waits_and_a_missing_algorithm_is_reported() {
        let at = super::super::resolve::At { file: "f".into(), line: 1 };
        let mut o = Options::default();
        o.single.insert(Kw::MACs, super::super::resolve::Setting { args: vec!["+hmac-md5".into()], at: at.clone() });
        // DSA host keys: OpenSSH 10 dropped them and Reach's engine has none.
        o.single.insert(Kw::HostKeyAlgorithms, super::super::resolve::Setting { args: vec!["+ssh-dss".into()], at });
        let r = Resolved { original_host: "h".into(), host: "h".into(), options: o, notes: vec![], refused: None, final_pass: false };
        let p = Plan::new(&r, russh::client::Config::default(), &[], true);
        let used = |kw: Kw| p.uses.iter().find(|(k, _)| *k == kw).map(|(_, u)| u.clone()).unwrap();
        assert!(matches!(used(Kw::MACs), Use::Partly(m) if m.contains("approval: hmac-md5")));
        assert!(matches!(used(Kw::HostKeyAlgorithms), Use::Partly(m) if m.contains("not available: ssh-dss")));
        let p = Plan::new(&r, russh::client::Config::default(), &["MACs hmac-md5".into()], true);
        assert!(p.config.preferred.mac.contains(&russh::mac::HMAC_MD5));
    }

    #[test]
    fn rekey_limit_is_held_to_what_russh_allows() {
        let mut o = Options::default();
        o.single.insert(Kw::RekeyLimit, super::super::resolve::Setting { args: vec!["4G".into(), "1h".into()], at: super::super::resolve::At { file: "f".into(), line: 1 } });
        let r = Resolved { original_host: "h".into(), host: "h".into(), options: o, notes: vec![], refused: None, final_pass: false };
        let p = Plan::new(&r, russh::client::Config::default(), &[], true);
        assert_eq!(p.config.limits.rekey_write_limit, 1 << 30);
        assert_eq!(p.config.limits.rekey_time_limit, Duration::from_secs(3600));
    }
}
