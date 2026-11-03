//! Against real OpenSSH servers: UpdateHostKeys, Tunnel and hostbased
//! authentication. Each test names the environment it needs; run with
//! `cargo test --lib ssh::proto_live_tests -- --ignored --nocapture`.

use super::client::{AuthParams, HopOptions, KeyAuth, KeySource, SshClientHandler};
use super::sshconf::session::SshOptions;

fn addr(var: &str) -> (String, u16) {
    let a = std::env::var(var).unwrap_or_else(|_| panic!("set {var}"));
    let (h, p) = a.rsplit_once(':').unwrap();
    (h.to_string(), p.parse().unwrap())
}

fn good_key() -> String {
    let dir = std::env::var("REACH_SSH_KEYS").expect("set REACH_SSH_KEYS");
    std::fs::read_to_string(std::path::Path::new(&dir).join("k_good")).unwrap()
}

/// Connect and log in under ssh_config lines, as a session does.
async fn connect(host: &str, port: u16, user: &str, lines: Vec<String>, key: Option<String>) -> Result<(russh::client::Handle<SshClientHandler>, HopOptions), String> {
    let o = SshOptions { lines, ..Default::default() };
    let plan = super::sshconf::session::plan_for(Some(&o), host, port, user, false);
    let opts: HopOptions = plan.into();
    let stream = super::sshconf::net::connect(host, port, &opts.socket, false).await.map_err(|e| e.to_string())?;
    super::hostbased::remember_socket(opts.auth.as_ref(), &stream);
    let handler = SshClientHandler::new(host, port, None).with_hostkeys(opts.hostkeys.clone()).with_forwards(opts.forwards.clone());
    let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.map_err(|e| e.to_string())?;
    let auth = AuthParams { key: key.map(|k| KeyAuth { source: KeySource::Material(k), passphrase: None }), password: None, allow_agent: false };
    super::client::login(&mut handle, user, &auth, &opts, None, host, port).await.map_err(|e| e.to_string())?.into_result().map_err(|e| e.to_string())?;
    Ok((handle, opts))
}

/// UpdateHostKeys: the server (REACH_SSH_UPDATEKEYS, an OpenSSH sshd with
/// several host keys) is known by one key plus a stale one. After login the
/// others are learned, proven by the server, and the stale one removed.
/// REACH_SSH_UPDATEKEYS_PUB is a file with the server's public host keys,
/// the first being the one the client knows; REACH_SSH_KEYS holds k_good.
#[tokio::test]
#[ignore = "needs an SSH server with several host keys"]
async fn live_update_host_keys() {
    let (host, port) = addr("REACH_SSH_UPDATEKEYS");
    let pubs = std::fs::read_to_string(std::env::var("REACH_SSH_UPDATEKEYS_PUB").expect("set REACH_SSH_UPDATEKEYS_PUB")).unwrap();
    let pubs: Vec<String> = pubs.lines().filter(|l| !l.trim().is_empty()).map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).collect();
    let stale = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPZ206zFSa66ELq8mjtVLhzQ5ozVqzWBf6n+f2A/fRCx";
    let label = super::knownhosts::host_label(&host, port);
    let dir = std::env::temp_dir().join(format!("reach-live-uhk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = |n: &str| dir.join(n).display().to_string().replace('\\', "/");
    let lines = |file: &str, extra: &[&str]| -> Vec<String> {
        let mut l = vec![format!("UserKnownHostsFile {}", path(file)), "GlobalKnownHostsFile none".into(), "StrictHostKeyChecking yes".into()];
        l.extend(extra.iter().map(|s| s.to_string()));
        l
    };
    let run = |file: &'static str, extra: &'static [&'static str]| {
        let (host, lines) = (host.clone(), lines(file, extra));
        async move {
            let (handle, _) = connect(&host, port, "reach", lines, Some(good_key())).await.unwrap();
            // The announcement comes after login, the proof right after.
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            drop(handle);
        }
    };
    let seed = format!("{label} {}\n{label} {stale}\n# a comment stays\n", pubs[0]);
    let count = |text: &str, k: &str| text.lines().filter(|l| l.contains(k)).count();

    // UpdateHostKeys yes: learned and pruned.
    std::fs::write(dir.join("yes"), &seed).unwrap();
    run("yes", &["UpdateHostKeys yes"]).await;
    let after = std::fs::read_to_string(dir.join("yes")).unwrap();
    println!("--- UpdateHostKeys yes, after:\n{after}");
    for p in &pubs {
        assert_eq!(count(&after, p.split_whitespace().nth(1).unwrap()), 1, "{p} listed once");
    }
    assert_eq!(count(&after, stale.split_whitespace().nth(1).unwrap()), 0, "stale key removed");
    assert!(after.contains("# a comment stays"));
    assert_eq!(std::fs::read_to_string(dir.join("yes.old")).unwrap(), seed, "backup of the old file");

    // Hashed under HashKnownHosts.
    std::fs::write(dir.join("hashed"), &seed).unwrap();
    run("hashed", &["UpdateHostKeys yes", "HashKnownHosts yes"]).await;
    let after = std::fs::read_to_string(dir.join("hashed")).unwrap();
    println!("--- hashed, after:\n{after}");
    let added: Vec<&str> = after.lines().filter(|l| !l.starts_with(&label) && !l.starts_with('#')).collect();
    assert_eq!(added.len(), pubs.len() - 1);
    assert!(added.iter().all(|l| l.starts_with("|1|")), "{added:?}");

    // Unset with a custom UserKnownHostsFile: off, as readconf.c decides.
    std::fs::write(dir.join("default"), &seed).unwrap();
    run("default", &[]).await;
    assert_eq!(std::fs::read_to_string(dir.join("default")).unwrap(), seed, "no update by default with a custom file");

    // ask with nobody to ask: nothing written.
    std::fs::write(dir.join("ask"), &seed).unwrap();
    run("ask", &["UpdateHostKeys ask"]).await;
    assert_eq!(std::fs::read_to_string(dir.join("ask")).unwrap(), seed, "ask without an answer changes nothing");

    // A key only just added (accept-new) is not trusted for updates.
    let mut l = lines("fresh", &["UpdateHostKeys yes"]);
    l[2] = "StrictHostKeyChecking accept-new".into();
    let (handle, _) = connect(&host, port, "reach", l, Some(good_key())).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    drop(handle);
    let after = std::fs::read_to_string(dir.join("fresh")).unwrap();
    println!("--- accept-new, after:\n{after}");
    assert_eq!(after.lines().count(), 1, "only the accepted key, no update");

    std::fs::remove_dir_all(&dir).ok();
}

/// Run a command on this machine and say what it printed.
#[cfg(unix)]
fn sh(cmd: &str) -> (bool, String) {
    let out = std::process::Command::new("sh").arg("-c").arg(cmd).output().unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// Run a command on the server.
#[cfg(unix)]
async fn remote(handle: &russh::client::Handle<SshClientHandler>, cmd: &str) -> String {
    let mut ch = handle.channel_open_session().await.unwrap();
    ch.exec(true, cmd).await.unwrap();
    let mut out = String::new();
    while let Ok(Some(msg)) = tokio::time::timeout(std::time::Duration::from_secs(10), ch.wait()).await {
        match msg {
            russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => out.push_str(&String::from_utf8_lossy(&data)),
            russh::ChannelMsg::ExitStatus { exit_status } => {
                out.push_str(&format!("[exit {exit_status}]"));
                break;
            }
            _ => {}
        }
    }
    out
}

/// Tunnel point-to-point, end to end: tun5 here joined to tun6 on the
/// server (REACH_SSH_TUN, an sshd with PermitTunnel yes in its own network
/// namespace, logging in as root with k_good from REACH_SSH_KEYS), then a
/// ping across. Run as root on Linux.
#[cfg(unix)]
// Several threads: the ping below blocks one while the relay runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs root and an SSH server with PermitTunnel"]
async fn live_tunnel() {
    let (host, port) = addr("REACH_SSH_TUN");
    let kh = std::env::temp_dir().join(format!("reach-tun-kh-{}", std::process::id()));
    // From an imported config, so the approval applies (Reach's own lines
    // are typed by the user, like ssh -o, and need none).
    let file = |extra: &str| super::sshconf::session::Imported {
        alias: host.clone(),
        files: vec![super::sshconf::session::ConfigFile {
            path: "/tmp/reach-tun-config".into(),
            text: format!(
                "Host *\n  UserKnownHostsFile {}\n  StrictHostKeyChecking accept-new\n  Tunnel point-to-point\n  TunnelDevice 5:6\n{extra}",
                kh.display()
            ),
            role: super::sshconf::session::FileRole::User,
        }],
        at: 0,
    };
    let approved = vec!["Tunnel point-to-point".to_string()];
    // Not approved: no tunnel.
    let o = SshOptions { imported: Some(file("")), ..Default::default() };
    let plan = super::sshconf::session::plan_for(Some(&o), &host, port, "root", false);
    assert!(plan.forwards.as_ref().unwrap().tun.is_none(), "Tunnel waits for approval");
    // ClearAllForwardings clears it, as in ssh.
    let o = SshOptions { imported: Some(file("  ClearAllForwardings yes\n")), accepted_weakenings: approved.clone(), ..Default::default() };
    assert!(super::sshconf::session::plan_for(Some(&o), &host, port, "root", false).forwards.unwrap().tun.is_none());

    let o = SshOptions { imported: Some(file("")), accepted_weakenings: approved, ..Default::default() };
    let plan = super::sshconf::session::plan_for(Some(&o), &host, port, "root", false);
    let opts: HopOptions = plan.into();
    let stream = super::sshconf::net::connect(&host, port, &opts.socket, false).await.unwrap();
    let handler = SshClientHandler::new(host.as_str(), port, None).with_hostkeys(opts.hostkeys.clone()).with_forwards(opts.forwards.clone());
    let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.unwrap();
    let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(good_key()), passphrase: None }), password: None, allow_agent: false };
    super::client::login(&mut handle, "root", &auth, &opts, None, &host, port).await.unwrap().into_result().unwrap();
    let shared: super::client::SharedHandle = std::sync::Arc::new(tokio::sync::Mutex::new(handle));
    let (_fwd, notes) = super::forwarding::Forwarder::start(shared.clone(), opts.forwards.clone().unwrap()).await.unwrap();
    println!("notes: {notes:?}");
    assert!(notes.iter().any(|n| n == "Tunnel forwarding using interface tun5"), "{notes:?}");

    let (ok, out) = sh("ip addr add 10.99.0.1/30 dev tun5 && ip link set tun5 up && ip addr show tun5");
    println!("local: {out}");
    assert!(ok);
    let out = remote(&*shared.lock().await, "ip addr add 10.99.0.2/30 dev tun6 && ip link set tun6 up && ip addr show tun6").await;
    println!("remote: {out}");
    assert!(out.contains("[exit 0]"), "{out}");
    let (ok, out) = sh("ping -c 3 -W 2 10.99.0.2");
    println!("{out}");
    assert!(ok, "ping across the tunnel");
    let out = remote(&*shared.lock().await, "ip -s link show tun6").await;
    println!("server tun6 counters: {out}");
    std::fs::remove_file(&kh).ok();
}

/// Hostbased authentication through ssh-keysign: REACH_SSH_HOSTBASED is an
/// sshd with HostbasedAuthentication yes that trusts this machine's host
/// key for REACH_SSH_HOSTBASED_USER (its ~/.shosts naming this machine and
/// the local user). Needs EnableSSHKeysign yes in /etc/ssh/ssh_config.
/// No key and no password are given: only the host vouches.
#[cfg(unix)]
#[tokio::test]
#[ignore = "needs an SSH server with HostbasedAuthentication"]
async fn live_hostbased() {
    let (host, port) = addr("REACH_SSH_HOSTBASED");
    let user = std::env::var("REACH_SSH_HOSTBASED_USER").expect("set REACH_SSH_HOSTBASED_USER");
    let kh = std::env::temp_dir().join(format!("reach-hb-kh-{}", std::process::id()));
    let base = vec![
        format!("UserKnownHostsFile {}", kh.display()),
        "StrictHostKeyChecking accept-new".to_string(),
        "PreferredAuthentications hostbased".to_string(),
    ];
    // Off by default: nothing else to log in with, so it fails.
    let r = connect(&host, port, &user, base.clone(), None).await;
    println!("without HostbasedAuthentication: {:?}", r.as_ref().err());
    assert!(r.is_err());
    let mut lines = base.clone();
    lines.push("HostbasedAuthentication yes".into());
    let (handle, _) = connect(&host, port, &user, lines, None).await.expect("hostbased login");
    let out = remote(&handle, "id -un").await;
    println!("logged in by hostbased: {out}");
    assert!(out.starts_with(&user), "{out}");
    // HostbasedAcceptedAlgorithms leaving out the host's key types: no key to try.
    let mut lines = base;
    lines.push("HostbasedAuthentication yes".into());
    lines.push("HostbasedAcceptedAlgorithms ecdsa-sha2-nistp521".into());
    assert!(connect(&host, port, &user, lines, None).await.is_err());
    std::fs::remove_file(&kh).ok();
}
