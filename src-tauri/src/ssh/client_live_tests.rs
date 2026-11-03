//! Against a real SSH server: Reach's own login code, with keys as they
//! arrive from another device. Run with
//! `REACH_SSH_TEST=host:port REACH_SSH_USER=user REACH_SSH_KEYS=dir
//! cargo test --lib ssh::client::live -- --ignored --nocapture`, where `dir`
//! holds `k_good` and `k_rsa` (both in the server's authorized_keys) and
//! `k_other` (not).

use super::*;

/// Accepts any host key: the test server's identity is not under test, and
/// this keeps the user's own known-hosts list out of it.
struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn env() -> Option<(String, u16, String, std::path::PathBuf)> {
    let addr = std::env::var("REACH_SSH_TEST").ok()?;
    let (host, port) = addr.rsplit_once(':')?;
    Some((
        host.to_string(),
        port.parse().ok()?,
        std::env::var("REACH_SSH_USER").ok()?,
        std::env::var("REACH_SSH_KEYS").ok()?.into(),
    ))
}

/// Log in with `material` as an imported key, no agent: as on a phone.
async fn login(host: &str, port: u16, user: &str, material: &str) -> Result<bool, String> {
    login_with(host, port, user, material, false).await
}

async fn login_with(host: &str, port: u16, user: &str, material: &str, allow_agent: bool) -> Result<bool, String> {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, (host, port), AnyHost).await.map_err(|e| e.to_string())?;
    let auth = AuthParams {
        key: Some(KeyAuth { source: KeySource::Material(material.to_string()), passphrase: None }),
        password: None,
        allow_agent,
    };
    let outcome = cascade_authenticate(&mut handle, user, &auth).await.map_err(|e| e.to_string())?;
    if outcome.by == Some(AuthBy::Agent) && outcome.refused_key.is_some() {
        println!("      (Reach now warns: logged in through the agent, this session's key was refused)");
    }
    outcome.into_result().map(|_| true).map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_imported_keys() {
    let Some((host, port, user, dir)) = env() else { panic!("set REACH_SSH_TEST, REACH_SSH_USER, REACH_SSH_KEYS") };
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();

    let mut cases: Vec<(String, String)> = Vec::new();
    for key in ["k_good", "k_rsa", "k_other"] {
        let text = read(key);
        cases.push((format!("{key} as made"), text.clone()));
        cases.push((format!("{key} CRLF"), text.replace('\n', "\r\n")));
        cases.push((format!("{key} trailing spaces"), text.lines().map(|l| format!("{l}  ")).collect::<Vec<_>>().join("\n")));
        cases.push((format!("{key} BOM"), format!("\u{feff}{text}")));
        cases.push((format!("{key} leading blank line"), format!("\n{text}")));
    }
    for (name, material) in cases {
        let out = match login(&host, port, &user, &material).await {
            Ok(true) => "LOGGED IN".to_string(),
            Ok(false) => "REFUSED by the server".to_string(),
            Err(e) => format!("ERROR: {e}"),
        };
        println!("{name:>30}: {out}");
    }
}

/// The same session on a Windows PC with an agent and on a phone without:
/// a key the server refuses is hidden by the agent on one and not the other.
#[tokio::test]
#[ignore = "needs an SSH server and an agent holding k_good"]
async fn live_agent_hides_a_refused_key() {
    let Some((host, port, user, dir)) = env() else { panic!("set REACH_SSH_TEST, REACH_SSH_USER, REACH_SSH_KEYS") };
    let wrong = std::fs::read_to_string(dir.join("k_other")).unwrap();
    for (name, agent) in [("Windows, agent running", true), ("phone, no agent", false)] {
        let out = match login_with(&host, port, &user, &wrong, agent).await {
            Ok(true) => "LOGGED IN".to_string(),
            Ok(false) => "REFUSED by the server".to_string(),
            Err(e) => format!("ERROR: {e}"),
        };
        println!("{name:>24}: {out}");
    }
}

/// A session whose key the server refuses makes exactly one attempt, with an
/// agent holding the right key running: the agent is not offered behind it.
/// Count the server's own `Failed publickey` lines for the proof.
#[tokio::test]
#[ignore = "needs an SSH server and an agent holding k_good"]
async fn live_one_attempt_per_refused_key() {
    let Some((host, port, user, dir)) = env() else { panic!("set REACH_SSH_TEST, REACH_SSH_USER, REACH_SSH_KEYS") };
    let wrong = std::fs::read_to_string(dir.join("k_other")).unwrap();
    let auth = crate::ipc::ssh_commands::build_auth("key", None, Some(KeySource::Material(wrong)), None, false).unwrap();
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, (host.as_str(), port), AnyHost).await.unwrap();
    let outcome = cascade_authenticate(&mut handle, &user, &auth).await.unwrap();
    println!("default session, wrong key, agent running: {:?}", outcome.into_result().map_err(|e| e.to_string()));
}

/// A server that only offers old MACs (and no AEAD cipher), as in the
/// Discord report: fails with Reach's defaults, logs in once the session
/// says `MACs +hmac-sha1`. Run with `REACH_SSH_LEGACY=host:port`, plus
/// REACH_SSH_USER and REACH_SSH_KEYS as above.
#[tokio::test]
#[ignore = "needs an SSH server offering only legacy MACs"]
async fn live_legacy_macs() {
    let addr = std::env::var("REACH_SSH_LEGACY").expect("REACH_SSH_LEGACY");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let user = std::env::var("REACH_SSH_USER").unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();

    async fn attempt(host: &str, port: u16, user: &str, key: &str, opts: Option<&crate::ssh::sshconf::session::SshOptions>) -> Result<(), String> {
        let plan = crate::ssh::sshconf::session::plan_for(opts, host, port, user, false);
        let stream = crate::ssh::sshconf::net::connect(host, port, &plan.socket, true).await.map_err(|e| e.to_string())?;
        let mut handle = russh::client::connect_stream(Arc::new(plan.config), stream, AnyHost).await.map_err(|e| e.to_string())?;
        let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key.to_string()), passphrase: None }), password: None, allow_agent: false };
        cascade_authenticate(&mut handle, user, &auth).await.map_err(|e| e.to_string())?.into_result().map(|_| ()).map_err(|e| e.to_string())
    }

    let before = attempt(host, port, &user, &key, None).await;
    println!("Reach's defaults: {before:?}");
    assert!(before.as_ref().is_err_and(|e| e.to_lowercase().contains("mac")), "{before:?}");

    let opts = crate::ssh::sshconf::session::SshOptions { lines: vec!["MACs +hmac-sha1".into()], ..Default::default() };
    let after = attempt(host, port, &user, &key, Some(&opts)).await;
    println!("With MACs +hmac-sha1: {after:?}");
    assert!(after.is_ok(), "{after:?}");

    // The MACs added to the vendored russh, each alone, through Reach's plan.
    for mac in ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"] {
        let opts = crate::ssh::sshconf::session::SshOptions { lines: vec![format!("MACs {mac}")], ..Default::default() };
        let r = attempt(host, port, &user, &key, Some(&opts)).await;
        println!("With MACs {mac}: {r:?}");
        assert!(r.is_ok(), "{mac}: {r:?}");
    }
}

/// OpenSSH-style login from ssh_config settings, against real servers.
/// Run with `REACH_SSH_AUTH=127.0.0.1:2226` (TrustedUserCAKeys, password
/// and keyboard-interactive on), `REACH_SSH_TEST=127.0.0.1:2222`, and
/// REACH_SSH_KEYS holding k_good, k_enc (passphrase enc-pass-123),
/// k_certkey with k_certkey-cert.pub signed by the server's CA; user
/// `plain` has the password plain-test-pw.
#[tokio::test]
#[ignore = "needs the SSH test servers"]
async fn live_config_login() {
    use crate::ssh::sshconf::session::{ConfigFile, FileRole, Imported, SshOptions};
    let addr = |var: &str| -> (String, u16) {
        let a = std::env::var(var).unwrap_or_else(|_| panic!("{var}"));
        let (h, p) = a.rsplit_once(':').unwrap();
        (h.to_string(), p.parse().unwrap())
    };
    let (h1, p1) = addr("REACH_SSH_TEST");
    let (h2, p2) = addr("REACH_SSH_AUTH");
    let keys = std::path::PathBuf::from(std::env::var("REACH_SSH_KEYS").unwrap());
    let k = |n: &str| keys.join(n).display().to_string().replace('\\', "/");

    fn options(text: String) -> SshOptions {
        SshOptions {
            imported: Some(Imported { alias: "t".into(), files: vec![ConfigFile { path: "cfg".into(), text, role: FileRole::User }], at: 0 }),
            ..Default::default()
        }
    }
    async fn run(host: &str, port: u16, user: &str, text: String, auth: AuthParams) -> Result<AuthBy, String> {
        let o = options(text);
        let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, user, false);
        let opts: HopOptions = plan.into();
        let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.map_err(|e| e.to_string())?;
        let mut handle = russh::client::connect_stream(opts.config.clone(), stream, AnyHost).await.map_err(|e| e.to_string())?;
        crate::ssh::client::login(&mut handle, user, &auth, &opts, None, host, port).await.map_err(|e| e.to_string())?.into_result().map_err(|e| e.to_string())
    }

    let mut results = Vec::new();
    let mut check = |name: &str, got: Result<AuthBy, String>, want: Result<AuthBy, ()>| {
        println!("{name}: {got:?}");
        let ok = match (&got, &want) {
            (Ok(a), Ok(b)) => a == b,
            (Err(_), Err(())) => true,
            _ => false,
        };
        results.push((name.to_string(), ok));
    };

    check("IdentityFile from the config", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {}\n  IdentitiesOnly yes\n", k("k_good")), AuthParams::default()).await, Ok(AuthBy::Key));
    check("certificate (CertificateFile)", run(&h2, p2, "reach", format!("Host t\n  IdentityFile {}\n  CertificateFile {}\n  IdentitiesOnly yes\n  PreferredAuthentications publickey\n", k("k_certkey"), k("k_certkey-cert.pub")), AuthParams::default()).await, Ok(AuthBy::Key));
    let bare = keys.join("k_certkey_bare");
    std::fs::copy(keys.join("k_certkey"), &bare).unwrap();
    check("the same key without its certificate", run(&h2, p2, "reach", format!("Host t\n  IdentityFile {}\n  IdentitiesOnly yes\n  PreferredAuthentications publickey\n", bare.display().to_string().replace('\\', "/")), AuthParams::default()).await, Err(()));
    std::fs::remove_file(&bare).ok();
    check("password", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications password\n".into(), AuthParams::from_password("plain-test-pw".into())).await, Ok(AuthBy::Password));
    check("keyboard-interactive (PAM) with the stored password", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications keyboard-interactive\n".into(), AuthParams::from_password("plain-test-pw".into())).await, Ok(AuthBy::Password));
    check("wrong password refused", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications password\n  NumberOfPasswordPrompts 1\n".into(), AuthParams::from_password("nope".into())).await, Err(()));
    check("PasswordAuthentication no", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications password\n  PasswordAuthentication no\n".into(), AuthParams::from_password("plain-test-pw".into())).await, Err(()));
    let enc = k("k_enc");
    check("encrypted key, BatchMode, no passphrase", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {enc}\n  IdentitiesOnly yes\n  BatchMode yes\n"), AuthParams::default()).await, Err(()));
    crate::vault::manager::keychain_entry_in("Reach SSH key passphrase", &enc).unwrap().set_password("enc-pass-123").unwrap();
    check("encrypted key, passphrase from UseKeychain", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {enc}\n  IdentitiesOnly yes\n  UseKeychain yes\n"), AuthParams::default()).await, Ok(AuthBy::Key));
    check("PubkeyAuthentication no", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {}\n  PubkeyAuthentication no\n  PreferredAuthentications publickey\n", k("k_good")), AuthParams::default()).await, Err(()));

    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).map(|(n, _)| n.clone()).collect();
    assert!(failed.is_empty(), "failed: {failed:?}");
}

/// Host keys under ssh_config settings, through Reach's handshake. Run with
/// `REACH_SSH_HOSTCERT=127.0.0.1:2227` (a server presenting a host
/// certificate for 127.0.0.1), `REACH_SSH_TEST=127.0.0.1:2222` (plain host
/// key), REACH_SSH_KEYS holding k_good and hostca.out (the CA's public key on
/// its last line).
#[tokio::test]
#[ignore = "needs the SSH test servers"]
async fn live_config_hostkeys() {
    use crate::ssh::sshconf::session::SshOptions;
    let addr = |var: &str| -> (String, u16) {
        let a = std::env::var(var).unwrap_or_else(|_| panic!("{var}"));
        let (h, p) = a.rsplit_once(':').unwrap();
        (h.to_string(), p.parse().unwrap())
    };
    let (h1, p1) = addr("REACH_SSH_TEST");
    let (h2, p2) = addr("REACH_SSH_HOSTCERT");
    let keys = std::path::PathBuf::from(std::env::var("REACH_SSH_KEYS").unwrap());
    let key = std::fs::read_to_string(keys.join("k_good")).unwrap();
    let ca = std::fs::read_to_string(keys.join("hostca.out")).unwrap().lines().last().unwrap().to_string();
    let dir = std::env::temp_dir().join(format!("reach-live-hk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = |n: &str| dir.join(n).display().to_string().replace('\\', "/");

    async fn connect(host: &str, port: u16, key: &str, lines: Vec<String>) -> Result<(), String> {
        let o = SshOptions { lines, ..Default::default() };
        let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, "reach", false);
        let opts: HopOptions = plan.into();
        let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.map_err(|e| e.to_string())?;
        let handler = SshClientHandler::new(host, port, None).with_hostkeys(opts.hostkeys.clone());
        let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.map_err(|e| e.to_string())?;
        let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key.to_string()), passphrase: None }), password: None, allow_agent: false };
        crate::ssh::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.map_err(|e| e.to_string())?.into_result().map(|_| ()).map_err(|e| e.to_string())
    }
    let kh = |file: &str, strict: &str| vec![format!("UserKnownHostsFile {}", path(file)), "GlobalKnownHostsFile none".into(), format!("StrictHostKeyChecking {strict}")];

    let mut failed = Vec::new();
    let mut expect = |name: &str, r: Result<(), String>, ok: bool| {
        println!("{name}: {r:?}");
        if r.is_ok() != ok {
            failed.push(name.to_string());
        }
    };

    std::fs::write(dir.join("ca"), format!("@cert-authority [127.0.0.1]:{p2} {ca}\n")).unwrap();
    expect("host certificate trusted through @cert-authority, strict", connect(&h2, p2, &key, kh("ca", "yes")).await, true);
    // The CA is trusted for "other", but the certificate only names
    // 127.0.0.1: the principal check must refuse it.
    std::fs::write(dir.join("alias"), format!("@cert-authority [other]:{p2} {ca}
")).unwrap();
    let mut lines = kh("alias", "yes");
    lines.push("HostKeyAlias other".into());
    expect("certificate not naming the alias: refused", connect(&h2, p2, &key, lines).await, false);
    std::fs::write(dir.join("wrongca"), format!("@cert-authority [127.0.0.1]:{p2} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n")).unwrap();
    expect("another CA, strict: refused", connect(&h2, p2, &key, kh("wrongca", "yes")).await, false);
    expect("unknown host, strict: refused", connect(&h1, p1, &key, kh("empty", "yes")).await, false);
    expect("unknown host, accept-new: recorded", connect(&h1, p1, &key, kh("new", "accept-new")).await, true);
    let recorded = std::fs::read_to_string(dir.join("new")).unwrap_or_default();
    println!("recorded: {}", recorded.trim());
    expect("recorded key now known, strict", connect(&h1, p1, &key, kh("new", "yes")).await, true);
    let mut lines = kh("hashed", "accept-new");
    lines.push("HashKnownHosts yes".into());
    expect("accept-new, hashed", connect(&h1, p1, &key, lines).await, true);
    let hashed = std::fs::read_to_string(dir.join("hashed")).unwrap_or_default();
    expect("hashed line written", if hashed.starts_with("|1|") { Ok(()) } else { Err(hashed.clone()) }, true);
    // Another key on record for this host: a changed key.
    std::fs::write(dir.join("changed"), format!("[127.0.0.1]:{p1} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
")).unwrap();
    expect("changed key, accept-new: refused", connect(&h1, p1, &key, kh("changed", "accept-new")).await, false);
    let mut lines = kh("new", "yes");
    let pubkey = recorded.split_whitespace().skip(1).take(2).collect::<Vec<_>>().join(" ");
    std::fs::write(dir.join("revoked"), format!("{pubkey}\n")).unwrap();
    lines.push(format!("RevokedHostKeys {}", path("revoked")));
    expect("revoked host key: refused", connect(&h1, p1, &key, lines).await, false);
    std::fs::remove_dir_all(&dir).ok();
    assert!(failed.is_empty(), "failed: {failed:?}");
}

/// The session under ssh_config settings: RemoteCommand, SetEnv, RequestTTY
/// and a subsystem, through `session_opts::setup_channel`. Run with
/// REACH_SSH_TEST and REACH_SSH_KEYS (k_good) as above; the server's sshd
/// must accept LC_* (Debian's does).
#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_config_session() {
    use crate::ssh::sshconf::session::SshOptions;
    let a = std::env::var("REACH_SSH_TEST").unwrap();
    let (host, port) = a.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();

    async fn run(host: &str, port: u16, key: &str, lines: &[&str]) -> Result<String, String> {
        run_with(host, port, key, lines, &[]).await
    }
    async fn run_with(host: &str, port: u16, key: &str, lines: &[&str], accepted: &[&str]) -> Result<String, String> {
        let o = SshOptions {
            lines: lines.iter().map(|l| l.to_string()).collect(),
            accepted_weakenings: accepted.iter().map(|l| l.to_string()).collect(),
            ..Default::default()
        };
        let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, "reach", false);
        let opts: HopOptions = plan.into();
        let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.map_err(|e| e.to_string())?;
        let mut handle = russh::client::connect_stream(opts.config.clone(), stream, AnyHost).await.map_err(|e| e.to_string())?;
        let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key.to_string()), passphrase: None }), password: None, allow_agent: false };
        crate::ssh::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.map_err(|e| e.to_string())?.into_result().map_err(|e| e.to_string())?;
        let mut ch = handle.channel_open_session().await.map_err(|e| e.to_string())?;
        let p = opts.session.clone().unwrap();
        let tty = crate::ssh::session_opts::setup_channel(&ch, &p, 80, 24, None, None).await?;
        let mut out = format!("tty={tty} ");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, ch.wait()).await {
            match msg {
                ChannelMsg::Data { data } => {
                    out.push_str(&String::from_utf8_lossy(&data));
                    if p.session_type == crate::ssh::session_opts::SessionType::Subsystem {
                        break;
                    }
                }
                ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(out)
    }

    let r = run(host, port, &key, &["RemoteCommand echo cmd-$USER"]).await.unwrap();
    println!("RemoteCommand: {r:?}");
    assert!(r.starts_with("tty=false") && r.contains("cmd-reach"), "{r}");
    let r = run(host, port, &key, &["SetEnv LC_REACH=from-setenv", "RemoteCommand echo env=$LC_REACH"]).await.unwrap();
    println!("SetEnv: {r:?}");
    assert!(r.contains("env=from-setenv"), "{r}");
    // SendEnv shares nothing until approved.
    std::env::set_var("LC_REACHSEND", "from-sendenv");
    let lines = ["SendEnv LC_REACHSEND", "RemoteCommand echo send=[$LC_REACHSEND]"];
    let r = run(host, port, &key, &lines).await.unwrap();
    println!("SendEnv, not approved: {r:?}");
    assert!(r.contains("send=[]"), "{r}");
    let r = run_with(host, port, &key, &lines, &["SendEnv LC_REACHSEND"]).await.unwrap();
    println!("SendEnv, approved: {r:?}");
    assert!(r.contains("send=[from-sendenv]"), "{r}");
    let r = run(host, port, &key, &["RequestTTY force", "RemoteCommand tty"]).await.unwrap();
    println!("RequestTTY force: {r:?}");
    assert!(r.starts_with("tty=true") && r.contains("/dev/pts/"), "{r}");
    let r = run(host, port, &key, &["SessionType subsystem", "RemoteCommand sftp"]).await;
    println!("subsystem: {r:?}");
    // The SFTP server speaks first only when asked; a subsystem accepted and
    // nothing refused is the proof here.
    assert!(r.is_ok(), "{r:?}");
}

/// ProxyCommand through a real jump (`ssh -W %h:%p` via REACH_SSH_TEST) to
/// REACH_SSH_LEGACY; and refused while not approved. REACH_SSH_PROXY_SSH is
/// the ssh program to run as the proxy.
#[tokio::test]
#[ignore = "needs the SSH test servers"]
async fn live_config_proxycommand() {
    use crate::ssh::sshconf::session::SshOptions;
    let jump = std::env::var("REACH_SSH_TEST").unwrap();
    let (jh, jp) = jump.rsplit_once(':').unwrap();
    let target = std::env::var("REACH_SSH_LEGACY").unwrap();
    let (th, tp) = target.rsplit_once(':').unwrap();
    let tp: u16 = tp.parse().unwrap();
    let keys = std::path::PathBuf::from(std::env::var("REACH_SSH_KEYS").unwrap());
    let key_path = keys.join("k_good").display().to_string().replace('\\', "/");
    let key = std::fs::read_to_string(keys.join("k_good")).unwrap();
    let ssh = std::env::var("REACH_SSH_PROXY_SSH").unwrap_or_else(|_| "ssh".into());
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let cmd = format!("\"{ssh}\" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile={null} -o IdentitiesOnly=yes -i {key_path} -p {jp} -W %h:%p reach@{jh}");

    async fn run(host: &str, port: u16, key: &str, o: SshOptions) -> Result<(), String> {
        let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, "reach", false);
        let opts: HopOptions = plan.into();
        if let Some(r) = &opts.refused {
            return Err(r.clone());
        }
        let pc = opts.proxy_command.clone().ok_or("no proxy command")?;
        let c = crate::ssh::proxycmd::expand(&pc, host, port, "reach")?;
        let stream = crate::ssh::proxycmd::spawn(&c).map_err(|e| e.to_string())?;
        let mut handle = russh::client::connect_stream(opts.config.clone(), stream, AnyHost).await.map_err(|e| e.to_string())?;
        let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key.to_string()), passphrase: None }), password: None, allow_agent: false };
        crate::ssh::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.map_err(|e| e.to_string())?.into_result().map(|_| ()).map_err(|e| e.to_string())
    }

    let lines = vec![format!("ProxyCommand {cmd}"), "MACs +hmac-sha1".into()];
    let pending = run(th, tp, &key, SshOptions { lines: lines.clone(), ..Default::default() }).await;
    println!("not approved: {pending:?}");
    assert!(pending.as_ref().is_err_and(|e| e.contains("approval")), "{pending:?}");
    let approved = run(th, tp, &key, SshOptions { lines, approved_commands: vec![cmd.clone()], ..Default::default() }).await;
    println!("approved: {approved:?}");
    assert!(approved.is_ok(), "{approved:?}");
}

/// Forwards from ssh_config, end to end: LocalForward to the server's own
/// sshd (its banner comes back), DynamicForward through SOCKS5 to the same,
/// RemoteForward from the server to a listener here. REACH_SSH_TEST and
/// REACH_SSH_KEYS (k_good); the server needs bash.
#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_config_forwards() {
    use crate::ssh::sshconf::session::SshOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = std::env::var("REACH_SSH_TEST").unwrap();
    let (host, port) = a.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();
    let kh = std::env::temp_dir().join(format!("reach-fwd-kh-{}", std::process::id()));

    // Something on this side for the remote forward to reach.
    let here = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let here_port = here.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = here.accept().await {
            let _ = s.write_all(b"hello-from-reach\n").await;
        }
    });

    let lines: Vec<String> = vec![
        format!("UserKnownHostsFile {}", kh.display().to_string().replace('\\', "/")),
        "StrictHostKeyChecking accept-new".into(),
        "LocalForward 127.0.0.1:15432 127.0.0.1:22".into(),
        "DynamicForward 127.0.0.1:11080".into(),
        format!("RemoteForward 127.0.0.1:2290 127.0.0.1:{here_port}"),
    ];
    let o = SshOptions { lines, ..Default::default() };
    let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, "reach", false);
    let opts: HopOptions = plan.into();
    let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.unwrap();
    let handler = SshClientHandler::new(host, port, None).with_hostkeys(opts.hostkeys.clone()).with_forwards(opts.forwards.clone());
    let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.unwrap();
    let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key), passphrase: None }), password: None, allow_agent: false };
    crate::ssh::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.unwrap().into_result().unwrap();
    let shared: SharedHandle = Arc::new(tokio::sync::Mutex::new(handle));
    let (_fwd, notes) = crate::ssh::forwarding::Forwarder::start(shared.clone(), opts.forwards.clone().unwrap()).await.unwrap();
    println!("notes: {notes:?}");

    let banner = |mut s: tokio::net::TcpStream| async move {
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    };
    let b = banner(tokio::net::TcpStream::connect("127.0.0.1:15432").await.unwrap()).await;
    println!("LocalForward: {b:?}");
    assert!(b.starts_with("SSH-2.0-OpenSSH"), "{b}");

    let mut s = tokio::net::TcpStream::connect("127.0.0.1:11080").await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 22]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "SOCKS5 reply");
    let b = banner(s).await;
    println!("DynamicForward: {b:?}");
    assert!(b.starts_with("SSH-2.0-OpenSSH"), "{b}");

    let mut ch = shared.lock().await.channel_open_session().await.unwrap();
    ch.exec(true, "bash -c 'exec 3<>/dev/tcp/127.0.0.1/2290; head -1 <&3'").await.unwrap();
    let mut out = String::new();
    while let Ok(Some(msg)) = tokio::time::timeout(std::time::Duration::from_secs(5), ch.wait()).await {
        match msg {
            ChannelMsg::Data { data } => out.push_str(&String::from_utf8_lossy(&data)),
            ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof => break,
            _ => {}
        }
    }
    println!("RemoteForward: {out:?}");
    assert!(out.contains("hello-from-reach"), "{out}");
    std::fs::remove_file(&kh).ok();
}

/// X11 forwarding: the server gets a fake cookie, and only a connection
/// that presents it reaches the display, with the real cookie swapped in.
/// A fake X server on this side stands in for the display. Needs
/// REACH_SSH_TEST with X11Forwarding yes and xauth on the server, and
/// REACH_SSH_KEYS (k_good).
#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_config_x11() {
    use crate::ssh::sshconf::session::SshOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = std::env::var("REACH_SSH_TEST").unwrap();
    let (host, port) = a.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();
    let kh = std::env::temp_dir().join(format!("reach-x11-kh-{}", std::process::id()));

    // The display: what each connection sent first.
    let display = tokio::net::TcpListener::bind("127.0.0.1:6037").await.unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = display.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 48];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = tx.send(buf);
                    let _ = s.write_all(b"X11-OK\n").await;
                }
            });
        }
    });
    // SAFETY: this test is the only one reading DISPLAY.
    unsafe { std::env::set_var("DISPLAY", "127.0.0.1:37") };

    let lines: Vec<String> = vec![
        format!("UserKnownHostsFile {}", kh.display().to_string().replace('\\', "/")),
        "StrictHostKeyChecking accept-new".into(),
        "ForwardX11 yes".into(),
        "ForwardX11Trusted yes".into(),
        "XAuthLocation /nonexistent/xauth".into(),
    ];
    let o = SshOptions { lines, ..Default::default() };
    let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, "reach", false);
    let opts: HopOptions = plan.into();
    assert!(opts.session.is_some());
    let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.unwrap();
    let handler = SshClientHandler::new(host, port, None).with_hostkeys(opts.hostkeys.clone()).with_forwards(opts.forwards.clone());
    let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.unwrap();
    let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key), passphrase: None }), password: None, allow_agent: false };
    crate::ssh::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.unwrap().into_result().unwrap();

    let table = opts.forwards.clone().unwrap();
    let x11 = table.prepare_x11().await.expect("X11 prepared");
    let mut p = (*opts.session.clone().unwrap()).clone();
    p.remote_command = None;
    let ch = handle.channel_open_session().await.unwrap();
    // One connection with the cookie the server was given, then one with
    // a wrong cookie.
    let script = r#"
n=${DISPLAY#*:}; n=${n%.*}; port=$((6000+n))
echo "DISPLAY=$DISPLAY"
c=$(xauth list "$DISPLAY" | awk '{print $3}')
echo "COOKIE=$c"
send() { exec 3<>/dev/tcp/127.0.0.1/$port; printf '\x6c\x00\x0b\x00\x00\x00\x12\x00\x10\x00\x00\x00MIT-MAGIC-COOKIE-1\x00\x00'"$(echo "$1" | sed 's/../\\x&/g')" >&3; timeout 3 head -1 <&3; exec 3<&-; }
echo "GOOD=$(send "$c")"
echo "BAD=$(send 00112233445566778899aabbccddeeff)"
exit
"#;
    let tty = crate::ssh::session_opts::setup_channel(&ch, &p, 80, 24, Some("bash -s"), Some(&x11)).await.unwrap();
    assert!(!tty);
    ch.data(script.as_bytes()).await.unwrap();
    ch.eof().await.unwrap();
    let mut ch = ch;
    let mut out = String::new();
    while let Ok(Some(msg)) = tokio::time::timeout(std::time::Duration::from_secs(15), ch.wait()).await {
        match msg {
            ChannelMsg::Data { data } => out.push_str(&String::from_utf8_lossy(&data)),
            ChannelMsg::ExtendedData { data, .. } => out.push_str(&String::from_utf8_lossy(&data)),
            ChannelMsg::ExitStatus { .. } => break,
            _ => {}
        }
    }
    println!("{out}");
    assert!(out.contains("GOOD=X11-OK"), "{out}");
    assert!(out.contains("BAD=\n") || out.trim_end().ends_with("BAD="), "{out}");
    let cookie = out.lines().find_map(|l| l.strip_prefix("COOKIE=")).unwrap().to_string();
    assert_eq!(cookie, x11.fake_hex(), "the server holds only the fake cookie");
    let got = rx.recv().await.unwrap();
    assert_eq!(&got[12..30], b"MIT-MAGIC-COOKIE-1");
    let sent: String = got[32..48].iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(sent, cookie, "the display got the real cookie, not the fake one");
    assert!(rx.try_recv().is_err(), "the wrong cookie never reached the display");
    std::fs::remove_file(&kh).ok();
}

/// LogLevel: the banner and the connection's debug lines collected as ssh
/// would print them. REACH_SSH_BANNER: a server with a Banner;
/// REACH_SSH_KEYS (k_good).
#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_config_loglevel() {
    use crate::ssh::sshconf::session::SshOptions;
    use crate::ssh::connlog::{close, ConnLog, ConnLogFilter, ConnLogLayer};
    use tracing::Instrument;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;
    let a = std::env::var("REACH_SSH_BANNER").unwrap();
    let (host, port) = a.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();
    // russh logs through the log crate, bridged as the app bridges it.
    let _ = tracing_log::LogTracer::init();
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(ConnLogLayer.with_filter(ConnLogFilter)));
    let mut out = Vec::new();
    for level in ["DEBUG1", "ERROR"] {
        let kh = std::env::temp_dir().join(format!("reach-log-kh-{}-{level}", std::process::id()));
        let lines: Vec<String> = vec![
            format!("UserKnownHostsFile {}", kh.display().to_string().replace('\\', "/")),
            "StrictHostKeyChecking accept-new".into(),
            format!("LogLevel {level}"),
        ];
        let o = SshOptions { lines, ..Default::default() };
        let opts: HopOptions = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, "reach", false).into();
        let (l, v) = opts.log.clone().unwrap();
        let log = ConnLog::new(l.as_deref(), &v);
        let key = key.clone();
        async {
            let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.unwrap();
            let handler = SshClientHandler::new(host, port, None).with_hostkeys(opts.hostkeys.clone());
            let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.unwrap();
            let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key), passphrase: None }), password: None, allow_agent: false };
            crate::ssh::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.unwrap().into_result().unwrap();
        }
        .instrument(log.span())
        .await;
        close(&log);
        out.push(log.take());
        std::fs::remove_file(&kh).ok();
    }
    println!("DEBUG1:\n{}\n\nERROR:\n{}", out[0].join("\n"), out[1].join("\n"));
    assert!(out[0].iter().any(|l| l == "Authorized use only"), "banner at DEBUG1");
    assert!(out[0].iter().any(|l| l.starts_with("debug1: ")), "debug lines at DEBUG1");
    assert!(!out[1].iter().any(|l| l.contains("Authorized use only")), "no banner at ERROR");
    assert!(!out[1].iter().any(|l| l.starts_with("debug")), "no debug at ERROR");
}
