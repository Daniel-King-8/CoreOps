//! UpdateHostKeys, as OpenSSH's ssh does it (clientloop.c
//! client_input_hostkeys, client_global_hostkeys_prove_confirm and
//! update_known_hosts; the conditions in sshconnect.c check_host_key and
//! readconf.c). After login the server announces all its host keys
//! (hostkeys-00@openssh.com); keys new to known_hosts are proven by the
//! server (hostkeys-prove-00@openssh.com) before they are added, and keys
//! for this host the server no longer has are removed.

use std::path::Path;
use std::sync::Arc;

use russh::keys::{Algorithm, PublicKey, PublicKeyOrCertificate};

use super::hostkeys::HostKeyPolicy;
use super::knownhosts::{self, Check, Entry, Hosts, Marker};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateHostKeys {
    #[default]
    No,
    Yes,
    /// Show the changes and ask before writing them.
    Ask,
}

impl UpdateHostKeys {
    /// readconf.c's default when UpdateHostKeys is unset: yes, unless
    /// VerifyHostKeyDNS is on or UserKnownHostsFile names anything but
    /// ~/.ssh/known_hosts. `user_files_raw` is UserKnownHostsFile as
    /// written (None when unset).
    pub fn from_config(value: Option<&str>, verify_dns: Option<&str>, user_files_raw: Option<&[String]>) -> Self {
        match value {
            Some("yes") => Self::Yes,
            Some("ask") => Self::Ask,
            Some(_) => Self::No,
            None => {
                let dns_off = verify_dns.is_none_or(|v| v == "no");
                let default_files = match user_files_raw {
                    None => true,
                    Some([one]) => one == "~/.ssh/known_hosts",
                    Some(_) => false,
                };
                if dns_off && default_files {
                    Self::Yes
                } else {
                    Self::No
                }
            }
        }
    }
}

/// UserKnownHostsFile as written, before `~` and `%` are expanded: the
/// default rule compares the text with ~/.ssh/known_hosts.
pub fn raw_user_files(r: &crate::ssh::sshconf::resolve::Resolved) -> Option<Vec<String>> {
    use crate::ssh::sshconf::{keyword::Kw, resolve::Status};
    let set = r.options.get(Kw::UserKnownHostsFile)?;
    let written = r.notes.iter().find(|n| n.kw == Some(Kw::UserKnownHostsFile) && n.status == Status::Applied);
    Some(written.and_then(|n| crate::ssh::sshconf::lex::argv_split(&n.text).ok()).unwrap_or_else(|| set.args.clone()))
}

/// What a connection keeps for UpdateHostKeys between the host key check
/// and the server's announcement.
#[derive(Debug, Default, Clone)]
pub struct UpdateState {
    /// The host key was trusted the way ssh requires for updating.
    trusted: bool,
    /// The server already announced its keys.
    seen: bool,
}

/// sshkey_type(): the short name ssh logs keys by.
fn short_type(key: &PublicKey) -> &'static str {
    match key.algorithm() {
        Algorithm::Rsa { .. } => "RSA",
        Algorithm::Ecdsa { .. } => "ECDSA",
        Algorithm::Ed25519 => "ED25519",
        Algorithm::SkEcdsaSha2NistP256 => "ECDSA-SK",
        Algorithm::SkEd25519 => "ED25519-SK",
        _ => "UNKNOWN",
    }
}

fn blob(key: &PublicKey) -> Vec<u8> {
    key.to_bytes().unwrap_or_default()
}

fn same(a: &PublicKey, b: &PublicKey) -> bool {
    a.key_data() == b.key_data()
}

fn entry_key(e: &Entry) -> Option<PublicKey> {
    PublicKey::from_bytes(&e.key_blob).ok()
}

fn read_entries(path: &Path) -> Option<Vec<Entry>> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(knownhosts::parse(&text, &path.display().to_string()).entries)
}

/// hostkey_accepted_by_hostkeyalgs(): an RSA key counts when any RSA
/// signature algorithm is allowed.
fn accepted_by_hostkeyalgs(key: &PublicKey, algs: &[String]) -> bool {
    let has = |n: &str| algs.iter().any(|a| a == n);
    match key.algorithm() {
        Algorithm::Rsa { .. } => has("rsa-sha2-256") || has("rsa-sha2-512") || has("ssh-rsa"),
        a => has(a.as_str()),
    }
}

/// hostspec_is_complex(): wildcards, or more than "host,ip".
fn is_complex(hosts: &Hosts) -> bool {
    match hosts {
        Hosts::Hashed { .. } => false,
        Hosts::Patterns(p) => p.len() > 2 || p.iter().any(|x| x.contains('*') || x.contains('?')),
    }
}

/// The names ssh updates under: exactly those the host key was checked
/// under (the host or HostKeyAlias with its port, and with CheckHostIP the
/// address), so no other host's lines are touched. ssh turns CheckHostIP
/// off for localhost and through a proxy (sshconnect.c), so there is no
/// address then.
fn names(policy: &HostKeyPolicy, host: &str, port: u16) -> (String, Option<String>) {
    let (label, ip) = policy.names(host, port);
    let local = |l: &str| {
        let bare = l.strip_prefix('[').and_then(|r| r.rsplit_once("]:")).map_or(l, |(h, _)| h);
        bare.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
    };
    let ip = ip.filter(|i| *i != label && !local(i));
    (label, ip)
}

impl UpdateState {
    /// After the host key check passed: whether ssh would leave
    /// UpdateHostKeys on. It turns it off when the key came from a
    /// certificate, from GlobalKnownHostsFile or KnownHostsCommand, for
    /// localhost under NoHostAuthenticationForLocalhost, or when the key was
    /// not known or confirmed (accept-new, or a changed key let through).
    /// `confirmed` is the user saying yes to an unknown key.
    pub fn after_check(&mut self, policy: &HostKeyPolicy, host: &str, port: u16, presented: &PublicKeyOrCertificate, confirmed: bool) {
        self.trusted = Self::trusted(policy, host, port, presented, confirmed);
    }

    fn trusted(policy: &HostKeyPolicy, host: &str, port: u16, presented: &PublicKeyOrCertificate, confirmed: bool) -> bool {
        if policy.update_host_keys == UpdateHostKeys::No || !policy.use_files || policy.user_files.is_empty() {
            return false;
        }
        if policy.pre_check(host, presented).is_some() {
            return false;
        }
        let (label, ip) = policy.names(host, port);
        let user: Vec<Entry> = policy.user_files.iter().filter_map(|f| read_entries(f)).flatten().collect();
        let global: Vec<Entry> = policy.global_files.iter().filter_map(|f| read_entries(f)).flatten().collect();
        if let PublicKeyOrCertificate::Certificate(cert) = presented {
            let cert_blob = cert.to_bytes().unwrap_or_default();
            if let Ok(info) = knownhosts::cert_info(&cert_blob) {
                let all: Vec<Entry> = user.iter().chain(global.iter()).cloned().collect();
                if knownhosts::check_ca(&all, std::slice::from_ref(&label), &info.ca_key_type, &info.ca_key_blob) {
                    tracing::debug!("certificate host key in use; disabling UpdateHostKeys");
                    return false;
                }
            }
        }
        if confirmed {
            return true;
        }
        let key = presented.public_key();
        let key_type = key.algorithm().as_str().to_string();
        let key_blob = blob(&key);
        if !matches!(knownhosts::check(&user, std::slice::from_ref(&label), &key_type, &key_blob), Check::Found(_)) {
            tracing::debug!("host key not in UserKnownHostsFile; disabling UpdateHostKeys");
            return false;
        }
        if let Some(ip) = ip {
            let in_user = matches!(knownhosts::check(&user, std::slice::from_ref(&ip), &key_type, &key_blob), Check::Found(_));
            let in_global = matches!(knownhosts::check(&global, std::slice::from_ref(&ip), &key_type, &key_blob), Check::Found(_));
            if !in_user && in_global {
                tracing::debug!("host key found in GlobalKnownHostsFile; disabling UpdateHostKeys");
                return false;
            }
        }
        true
    }

    /// The server's hostkeys-00@openssh.com announcement. Works out which
    /// keys are new and which are gone; asks the server to prove the new
    /// ones; then edits the known_hosts files in a task of its own, since
    /// the proof is read by this session's loop. A second announcement
    /// ends the connection, as in ssh.
    pub fn announced(
        &mut self,
        policy: Arc<HostKeyPolicy>,
        host: &str,
        port: u16,
        offered: Vec<PublicKey>,
        session: &mut russh::client::Session,
        app: Option<tauri::AppHandle>,
    ) -> Result<(), russh::Error> {
        if self.seen {
            tracing::error!("{host}:{port}: server already sent hostkeys");
            return Err(russh::Error::Inconsistent);
        }
        if !self.trusted {
            return Ok(());
        }
        self.seen = true;
        let Some(plan) = plan_update(&policy, host, port, offered) else { return Ok(()) };
        let host = host.to_string();
        if plan.new_keys().is_empty() {
            tokio::spawn(async move { finish(&policy, &host, port, plan, Vec::new(), app).await });
            return Ok(());
        }
        tracing::debug!("asking server to prove ownership for {} keys", plan.new_keys().len());
        let rx = session.prove_host_keys(plan.new_keys())?;
        tokio::spawn(async move {
            match rx.await {
                Ok(Ok(proofs)) => finish(&policy, &host, port, plan, proofs, app).await,
                Ok(Err(russh::Error::RequestDenied)) => tracing::error!("Server failed to confirm ownership of private host keys"),
                Ok(Err(e)) => tracing::error!("Host key update for {host}:{port} stopped: {e}"),
                Err(_) => {}
            }
        });
        Ok(())
    }
}

/// What hostkeys_find worked out.
#[derive(Debug)]
pub(crate) struct Plan {
    pub keys: Vec<PublicKey>,
    /// Per key: already listed for this host (any name).
    pub known: Vec<bool>,
    /// Listed for this host but no longer offered.
    pub old: Vec<PublicKey>,
    pub label: String,
    pub ip: Option<String>,
}

impl Plan {
    fn new_keys(&self) -> Vec<PublicKey> {
        self.keys.iter().zip(&self.known).filter(|(_, k)| !**k).map(|(k, _)| k.clone()).collect()
    }
}

/// client_input_hostkeys up to sending the proof request: the offered keys
/// that HostKeyAlgorithms allows, matched against the user's known_hosts
/// files. `None` when there is nothing to do or ssh would skip the update.
pub(crate) fn plan_update(policy: &HostKeyPolicy, host: &str, port: u16, offered: Vec<PublicKey>) -> Option<Plan> {
    let mut keys: Vec<PublicKey> = Vec::new();
    for k in offered {
        // Unknown types and certificates are skipped, as ssh does.
        if matches!(k.algorithm(), Algorithm::Other(_)) || k.algorithm().as_str().contains("-cert-") {
            continue;
        }
        if !accepted_by_hostkeyalgs(&k, &policy.host_key_algorithms) {
            tracing::debug!("{} key not permitted by HostkeyAlgorithms", k.algorithm());
            continue;
        }
        if keys.iter().any(|x| same(x, &k)) {
            tracing::error!("received duplicated {} host key", k.algorithm());
            return None;
        }
        keys.push(k);
    }
    if keys.is_empty() {
        tracing::debug!("server sent no hostkeys");
        return None;
    }
    let (label, ip) = names(policy, host, port);
    let mut known = vec![false; keys.len()];
    let mut old: Vec<PublicKey> = Vec::new();
    let (mut complex, mut other_name_seen) = (false, false);
    let mut unmatched: Vec<PublicKey> = Vec::new();
    for f in &policy.user_files {
        let Some(entries) = read_entries(f) else { continue };
        for e in &entries {
            let Some(k) = entry_key(e) else { continue };
            let m_host = e.matches(&label);
            let m_ip = ip.as_ref().is_some_and(|i| e.matches(i));
            if !m_host && !m_ip {
                // One of the keys under another name or address.
                if keys.iter().any(|x| same(x, &k)) {
                    other_name_seen = true;
                }
                unmatched.push(k);
                continue;
            }
            if e.marker != Marker::None {
                complex = true;
                continue;
            }
            let has_comma = matches!(&e.hosts, Hosts::Patterns(p) if p.len() > 1);
            if ip.is_some() && has_comma {
                if !m_host {
                    other_name_seen = true;
                    continue;
                } else if !m_ip {
                    other_name_seen = true;
                }
            }
            if is_complex(&e.hosts) {
                complex = true;
                continue;
            }
            match keys.iter().position(|x| same(x, &k)) {
                Some(i) => known[i] = true,
                None => old.push(k),
            }
        }
    }
    let nnew = known.iter().filter(|k| !**k).count();
    if nnew == 0 && old.is_empty() {
        tracing::debug!("no new or deprecated keys from server");
        return None;
    }
    if complex {
        tracing::debug!("CA/revocation marker, manual host list or wildcard host pattern found, skipping UserKnownHostsFile update");
        return None;
    }
    if other_name_seen {
        tracing::debug!("host key found matching a different name/address, skipping UserKnownHostsFile update");
        return None;
    }
    // check_old_keys_othernames: a key to remove that another name still uses.
    if old.iter().any(|o| unmatched.iter().any(|u| same(u, o))) {
        tracing::debug!("key(s) for {label} exist under other names; skipping UserKnownHostsFile update");
        return None;
    }
    Some(Plan { keys, known, old, label, ip })
}

/// client_global_hostkeys_prove_confirm's end and update_known_hosts: the
/// keys to keep, the question under ask, and the files rewritten.
async fn finish(policy: &HostKeyPolicy, host: &str, port: u16, plan: Plan, proofs: Vec<russh::client::HostKeyProof>, app: Option<tauri::AppHandle>) {
    let mut keep: Vec<&PublicKey> = Vec::new();
    let mut learned: Vec<&PublicKey> = Vec::new();
    let mut proof = proofs.iter();
    for (k, known) in plan.keys.iter().zip(&plan.known) {
        if *known {
            keep.push(k);
            continue;
        }
        match proof.next() {
            Some(russh::client::HostKeyProof::Proven) => {
                keep.push(k);
                learned.push(k);
            }
            Some(russh::client::HostKeyProof::Disregarded) => {}
            None => return,
        }
    }
    let fp = |k: &PublicKey| knownhosts::fingerprint(&blob(k), &policy.fingerprint_hash);
    let mut lines: Vec<String> = learned.iter().map(|k| format!("Learned new hostkey: {} {}", short_type(k), fp(k))).collect();
    lines.extend(plan.old.iter().map(|k| format!("Deprecating obsolete hostkey: {} {}", short_type(k), fp(k))));
    for l in &lines {
        tracing::info!("{host}:{port}: {l}");
    }
    if policy.update_host_keys == UpdateHostKeys::Ask {
        let text = format!("The server has updated its host keys.\nThese changes were verified by the server's existing trusted key.\n{}", lines.join("\n"));
        let yes = match &app {
            Some(a) => {
                let asker: &dyn super::prompt::Asker = a;
                asker.ask(host, port, super::prompt::Kind::Confirm, "Accept updated hostkeys?", &text, vec![]).await.is_some()
            }
            None => false,
        };
        if !yes {
            return;
        }
    }
    let names: Vec<String> = std::iter::once(plan.label.clone()).chain(plan.ip.clone()).collect();
    let keep: Vec<(String, Vec<u8>)> = keep.iter().map(|k| (k.algorithm().as_str().to_string(), blob(k))).collect();
    for (i, f) in policy.user_files.iter().enumerate() {
        // Keys are added to the first file only; the others just lose the
        // host's lines.
        let keys = if i == 0 { &keep[..] } else { &[] };
        match replace_in_file(f, &names, keys, policy.hash) {
            Ok(true) => tracing::info!("Updated the host keys of {} in {}", names.join(","), f.display()),
            Ok(false) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::error!("hostfile_replace_entries failed for {}: {e}", f.display()),
        }
    }
}

/// hostfile_replace_entries' file handling: the new text written beside
/// the file, the old one kept as `<file>.old`, then the new one moved in.
/// Nothing is written when nothing changes.
pub(crate) fn replace_in_file(path: &Path, names: &[String], keep: &[(String, Vec<u8>)], hash: bool) -> std::io::Result<bool> {
    let text = std::fs::read_to_string(path)?;
    let new = knownhosts::replace_host_keys(&text, names, keep, hash);
    if new == text {
        return Ok(false);
    }
    let suffix: u64 = rand::random();
    let temp = path.with_file_name(format!("{}.{suffix:011x}", path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()));
    let back = path.with_file_name(format!("{}.old", path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        use std::io::Write;
        let mut f = opts.open(&temp)?;
        f.write_all(new.as_bytes())?;
        f.sync_all()?;
        drop(f);
        match std::fs::remove_file(&back) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        if std::fs::hard_link(path, &back).is_err() {
            std::fs::copy(path, &back)?;
        }
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::hostkeys::{Strict, DEFAULT_CA_SIGALGS};

    fn key(seed: u8) -> russh::keys::PrivateKey {
        russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn policy(dir: &Path) -> HostKeyPolicy {
        HostKeyPolicy {
            strict: Strict::Ask,
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
            update_host_keys: UpdateHostKeys::Yes,
            host_key_algorithms: vec!["ssh-ed25519".into(), "rsa-sha2-512".into()],
        }
    }

    fn line(name: &str, k: &russh::keys::PrivateKey) -> String {
        format!("{name} {}\n", k.public_key().to_openssh().unwrap())
    }

    #[test]
    fn default_follows_readconf() {
        assert_eq!(UpdateHostKeys::from_config(None, None, None), UpdateHostKeys::Yes);
        assert_eq!(UpdateHostKeys::from_config(None, Some("yes"), None), UpdateHostKeys::No);
        assert_eq!(UpdateHostKeys::from_config(None, None, Some(&["~/.ssh/known_hosts".into()])), UpdateHostKeys::Yes);
        assert_eq!(UpdateHostKeys::from_config(None, None, Some(&["~/.ssh/other".into()])), UpdateHostKeys::No);
        assert_eq!(UpdateHostKeys::from_config(Some("ask"), Some("yes"), None), UpdateHostKeys::Ask);
    }

    #[test]
    fn plans_new_and_deprecated_keys() {
        let dir = std::env::temp_dir().join(format!("reach-hku-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, c) = (key(1), key(2), key(3));
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a) + &line("[web]:2250", &c) + &line("other", &key(9))).unwrap();
        let p = policy(&dir);
        let plan = plan_update(&p, "web", 2250, vec![a.public_key().clone(), b.public_key().clone()]).unwrap();
        assert_eq!(plan.known, vec![true, false]);
        assert_eq!(plan.old.len(), 1);
        assert!(same(&plan.old[0], c.public_key()));
        // Nothing new and nothing gone: nothing to do.
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a)).unwrap();
        assert!(plan_update(&p, "web", 2250, vec![a.public_key().clone()]).is_none());
        // The same key under another name: ssh skips the update.
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a) + &line("db", &b)).unwrap();
        assert!(plan_update(&p, "web", 2250, vec![a.public_key().clone(), b.public_key().clone()]).is_none());
        // A wildcard line for the host: skipped too.
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a) + &line("[w*]:2250", &c)).unwrap();
        assert!(plan_update(&p, "web", 2250, vec![a.public_key().clone(), b.public_key().clone()]).is_none());
        // Duplicated keys in the announcement stop it.
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a)).unwrap();
        assert!(plan_update(&p, "web", 2250, vec![b.public_key().clone(), b.public_key().clone()]).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_the_checked_names_are_rewritten() {
        let dir = std::env::temp_dir().join(format!("reach-hku4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, c) = (key(1), key(2), key(3));
        // The host under its alias, the real name and another host.
        let text = line("[web]:2250", &a) + &line("[10.0.0.5]:2250", &c) + &line("db", &c);
        std::fs::write(dir.join("known_hosts"), &text).unwrap();
        let mut p = policy(&dir);
        p.alias = Some("web".into());
        p.check_host_ip = true;
        let plan = plan_update(&p, "10.0.0.5", 2250, vec![a.public_key().clone(), b.public_key().clone()]).unwrap();
        assert_eq!(plan.label, "[web]:2250");
        assert_eq!(plan.ip, None, "the address is not a name the key was checked under");
        assert!(plan.old.is_empty(), "lines of other names are not this host's");
        let names: Vec<String> = std::iter::once(plan.label.clone()).chain(plan.ip.clone()).collect();
        let keep = vec![("ssh-ed25519".to_string(), blob(a.public_key())), ("ssh-ed25519".to_string(), blob(b.public_key()))];
        replace_in_file(&dir.join("known_hosts"), &names, &keep, false).unwrap();
        let after = std::fs::read_to_string(dir.join("known_hosts")).unwrap();
        assert!(after.contains(&line("[10.0.0.5]:2250", &c)) && after.contains(&line("db", &c)), "{after}");
        assert!(after.contains(&line("[web]:2250", &b)));
        // Under CheckHostIP the loopback address is not used (ssh turns it off).
        let mut q = policy(&dir);
        q.check_host_ip = true;
        assert_eq!(super::names(&q, "localhost", 2250).1, None);
        // An unknown key type in the announcement is skipped.
        let other = PublicKey::new(
            russh::keys::ssh_key::public::KeyData::Other(russh::keys::ssh_key::public::OpaquePublicKey::new(vec![1, 2, 3], Algorithm::new("x-unknown@example.com").unwrap())),
            "",
        );
        let mut p2 = policy(&dir);
        p2.host_key_algorithms.push("x-unknown@example.com".into());
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a)).unwrap();
        assert!(plan_update(&p2, "web", 2250, vec![a.public_key().clone(), other]).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_is_rewritten_with_a_backup() {
        let dir = std::env::temp_dir().join(format!("reach-hku2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (key(1), key(2));
        let f = dir.join("known_hosts");
        let before = line("# keep me", &a) + &line("[web]:2250", &a) + &line("other", &b);
        std::fs::write(&f, &before).unwrap();
        let names = vec!["[web]:2250".to_string()];
        let keep = vec![("ssh-ed25519".to_string(), blob(b.public_key()))];
        assert!(replace_in_file(&f, &names, &keep, false).unwrap());
        let after = std::fs::read_to_string(&f).unwrap();
        assert!(after.contains(&line("other", &b)));
        assert!(after.contains(&line("[web]:2250", &b)));
        assert!(!after.contains(&line("[web]:2250", &a)));
        assert_eq!(std::fs::read_to_string(dir.join("known_hosts.old")).unwrap(), before);
        // Again: nothing to change, nothing written.
        assert!(!replace_in_file(&f, &names, &keep, false).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trust_rules() {
        let dir = std::env::temp_dir().join(format!("reach-hku3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = key(1);
        let presented = PublicKeyOrCertificate::PublicKey { key: a.public_key().clone(), hash_alg: None };
        let mut p = policy(&dir);
        // Not in the file: off (accept-new adds without trusting).
        assert!(!UpdateState::trusted(&p, "web", 2250, &presented, false));
        // Confirmed by the user: on.
        assert!(UpdateState::trusted(&p, "web", 2250, &presented, true));
        std::fs::write(dir.join("known_hosts"), line("[web]:2250", &a)).unwrap();
        assert!(UpdateState::trusted(&p, "web", 2250, &presented, false));
        p.update_host_keys = UpdateHostKeys::No;
        assert!(!UpdateState::trusted(&p, "web", 2250, &presented, false));
        // Known only from the global file: off.
        let mut g = policy(&dir);
        g.user_files = vec![dir.join("none")];
        g.global_files = vec![dir.join("known_hosts")];
        assert!(!UpdateState::trusted(&g, "web", 2250, &presented, false));
        std::fs::remove_dir_all(&dir).ok();
    }
}
