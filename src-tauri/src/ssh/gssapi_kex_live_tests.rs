//! GSS-API key exchange against a real KDC and an sshd carrying the GSSAPI
//! patch (Debian's), with `GSSAPIKeyExchange yes`. Run with
//! `REACH_GSSKEX_TEST=localhost:<port> REACH_GSS_USER=<user>
//! cargo test --lib ssh::gssapi::live_kex -- --ignored --nocapture`, holding
//! a forwardable ticket for the principal that maps to that user, where the
//! server offers every GSS method (GSSAPIKexAlgorithms with all seven).
//! Optional: `REACH_GSSKEX_NULL=<host:port>`, an sshd without host keys
//! (Debian's OpenSSH 10.0 does not start a session without one: "monitor
//! received no hostkeys"; russh's own tests cover the null host key);
//! `REACH_GSSKEX_PLAIN=<host:port>`, one with GSSAPIAuthentication but no GSS
//! key exchange; `REACH_GSS_RENEW=<command>` renews the ticket (kinit again)
//! for the re-key test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::ssh::client::{AuthBy, AuthParams, HopOptions};
use crate::ssh::sshconf::session::{ConfigFile, FileRole, Imported, SshOptions};

/// What the engine reported: each key exchange's method, and how often it
/// asked about a host key.
#[derive(Clone, Default)]
struct Seen {
    kex: Arc<Mutex<Vec<String>>>,
    host_key_checks: Arc<AtomicUsize>,
}

struct Recorder(Seen);

impl russh::client::Handler for Recorder {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        self.0.host_key_checks.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
    async fn kex_done(&mut self, _shared: Option<&[u8]>, names: &russh::Names, _session: &mut russh::client::Session) -> Result<(), Self::Error> {
        self.0.kex.lock().unwrap().push(names.kex.as_ref().to_string());
        Ok(())
    }
}

struct Outcome {
    login: Result<AuthBy, String>,
    kex: Vec<String>,
    host_key_checks: usize,
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "login {:?}, kex {:?}, host key checks {}", self.login, self.kex, self.host_key_checks)
    }
}

fn options(config: &str, approved: &[&str]) -> SshOptions {
    SshOptions {
        imported: Some(Imported { alias: "t".into(), files: vec![ConfigFile { path: "cfg".into(), text: format!("Host t\n{config}"), role: FileRole::User }], at: 0 }),
        accepted_weakenings: approved.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// Connects and logs in under `config`; with `hold`, keeps the session open
/// that long first, running `during` half way.
async fn run(addr: &str, user: &str, config: &str, approved: &[&str], hold: Option<(std::time::Duration, &dyn Fn())>) -> Outcome {
    let (host, port) = addr.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let opts: HopOptions = crate::ssh::sshconf::session::plan_for(Some(&options(config, approved)), host, port, user, false).into();
    let seen = Seen::default();
    let done = |login: Result<AuthBy, String>, seen: &Seen| Outcome {
        login,
        kex: seen.kex.lock().unwrap().clone(),
        host_key_checks: seen.host_key_checks.load(Ordering::SeqCst),
    };
    let stream = match crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await {
        Ok(s) => s,
        Err(e) => return done(Err(e.to_string()), &seen),
    };
    let config = opts.engine_config(host).await;
    let mut handle = match russh::client::connect_stream(config, stream, Recorder(seen.clone())).await {
        Ok(h) => h,
        Err(e) => return done(Err(e.to_string()), &seen),
    };
    let login = match crate::ssh::client::login(&mut handle, user, &AuthParams::default(), &opts, None, host, port).await {
        Ok(o) => o.into_result().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    if let (Ok(_), Some((d, during))) = (&login, hold) {
        tokio::time::sleep(d / 2).await;
        during();
        tokio::time::sleep(d / 2).await;
        // The session still works after the re-key.
        let mut ch = handle.channel_open_session().await.unwrap();
        ch.exec(true, "echo still-here").await.unwrap();
        let mut out = String::new();
        while let Some(msg) = ch.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => out.push_str(&String::from_utf8_lossy(&data)),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert!(out.contains("still-here"), "{out}");
    }
    done(login, &seen)
}

fn gss_kex(o: &Outcome, prefix: &str) -> bool {
    o.kex.first().is_some_and(|k| k.starts_with(prefix) && k.ends_with(russh::kex::gss::KRB5_SUFFIX))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a KDC and an sshd with GSSAPIKeyExchange"]
async fn live_gss_key_exchange() {
    let addr = std::env::var("REACH_GSSKEX_TEST").expect("REACH_GSSKEX_TEST");
    let user = std::env::var("REACH_GSS_USER").expect("REACH_GSS_USER");
    let mut failed = Vec::new();
    let mut check = |name: &str, o: Outcome, ok: &dyn Fn(&Outcome) -> bool| {
        println!("--- {name}: {o:?}");
        if !ok(&o) {
            failed.push(name.to_string());
        }
    };
    // The default list: the first method both sides have, then gssapi-keyex
    // with no other method allowed; no host key asked about.
    let gss_only = "  GSSAPIKeyExchange yes\n  PreferredAuthentications gssapi-keyex\n";
    check("GSSAPIKeyExchange yes, default GSSAPIKexAlgorithms", run(&addr, &user, gss_only, &[], None).await, &|o| {
        gss_kex(o, "gss-group14-sha256-") && o.host_key_checks == 0 && o.login.as_ref().is_ok_and(|b| *b == AuthBy::Gssapi)
    });
    // Each method alone.
    for (prefix, _) in russh::kex::GSS_KEX_ALGORITHMS {
        let approved = format!("GSSAPIKexAlgorithms {prefix}");
        let cfg = format!("{gss_only}  GSSAPIKexAlgorithms {prefix}\n");
        let o = run(&addr, &user, &cfg, &[approved.as_str()], None).await;
        check(&format!("GSSAPIKexAlgorithms {prefix}"), o, &|o| {
            gss_kex(o, prefix) && o.host_key_checks == 0 && o.login.as_ref().is_ok_and(|b| *b == AuthBy::Gssapi)
        });
    }
    // gss-group1-sha1- waits for approval: then no GSS method is left, the
    // usual key exchange runs, the host key is checked, and gssapi-keyex has
    // no context to sign with.
    check(
        "GSSAPIKexAlgorithms gss-group1-sha1-, not approved",
        run(&addr, &user, &format!("{gss_only}  GSSAPIKexAlgorithms gss-group1-sha1-\n"), &[], None).await,
        &|o| !o.kex.is_empty() && !o.kex[0].starts_with("gss-") && o.host_key_checks == 1 && o.login.is_err(),
    );
    // A list limited to two, in the order given.
    check(
        "GSSAPIKexAlgorithms gss-nistp256-sha256-,gss-curve25519-sha256-",
        run(&addr, &user, &format!("{gss_only}  GSSAPIKexAlgorithms gss-nistp256-sha256-,gss-curve25519-sha256-\n"), &[], None).await,
        &|o| gss_kex(o, "gss-nistp256-sha256-") && o.login.is_ok(),
    );
    // GSSAPIKeyExchange off: the usual exchange, the host key checked.
    check("GSSAPIKeyExchange no", run(&addr, &user, "  PreferredAuthentications gssapi-keyex\n", &[], None).await, &|o| {
        !o.kex.is_empty() && !o.kex[0].starts_with("gss-") && o.host_key_checks == 1 && o.login.is_err()
    });
    // The server's name from GSSAPIServerIdentity, connecting by address.
    let by_addr = addr.replace("localhost", "127.0.0.1");
    check(
        "by address, GSSAPIServerIdentity localhost",
        run(&by_addr, &user, &format!("{gss_only}  GSSAPIServerIdentity localhost\n"), &[], None).await,
        &|o| gss_kex(o, "gss-group14-sha256-") && o.login.is_ok(),
    );
    // By address with no host/127.0.0.1 principal: the mechanism check
    // fails, so no GSS method is offered.
    check("by address, no principal for it", run(&by_addr, &user, gss_only, &[], None).await, &|o| {
        !o.kex.is_empty() && !o.kex[0].starts_with("gss-") && o.host_key_checks == 1
    });
    // Delegation, approved, in the key exchange.
    check(
        "GSSAPIDelegateCredentials yes, approved",
        run(&addr, &user, &format!("{gss_only}  GSSAPIDelegateCredentials yes\n"), &["GSSAPIDelegateCredentials yes"], None).await,
        &|o| gss_kex(o, "gss-group14-sha256-") && o.login.is_ok(),
    );
    // A server without host keys: the null host key.
    if let Ok(null) = std::env::var("REACH_GSSKEX_NULL") {
        check("server without host keys", run(&null, &user, gss_only, &[], None).await, &|o| {
            gss_kex(o, "gss-group14-sha256-") && o.host_key_checks == 0 && o.login.is_ok()
        });
    }
    // A server without GSS key exchange: the usual exchange, then
    // gssapi-keyex skipped and gssapi-with-mic.
    if let Ok(plain) = std::env::var("REACH_GSSKEX_PLAIN") {
        check(
            "server without GSS key exchange",
            run(&plain, &user, "  GSSAPIKeyExchange yes\n  GSSAPIAuthentication yes\n  PreferredAuthentications gssapi-keyex,gssapi-with-mic\n", &[], None).await,
            &|o| !o.kex.is_empty() && !o.kex[0].starts_with("gss-") && o.host_key_checks == 1 && o.login.as_ref().is_ok_and(|b| *b == AuthBy::Gssapi),
        );
    }
    assert!(failed.is_empty(), "failed: {failed:?}");
}

/// GSSAPIRenewalForcesRekey: the ticket renewed (kinit again) during the
/// session, a re-key follows within the 10 s check, with GSS again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a KDC and an sshd with GSSAPIKeyExchange"]
async fn live_gss_renewal_rekey() {
    let addr = std::env::var("REACH_GSSKEX_TEST").expect("REACH_GSSKEX_TEST");
    let user = std::env::var("REACH_GSS_USER").expect("REACH_GSS_USER");
    let renew = std::env::var("REACH_GSS_RENEW").expect("REACH_GSS_RENEW");
    let cfg = "  GSSAPIKeyExchange yes\n  PreferredAuthentications gssapi-keyex\n  GSSAPIDelegateCredentials yes\n  GSSAPIRenewalForcesRekey yes\n";
    let during = || {
        let st = std::process::Command::new("sh").arg("-c").arg(&renew).status().unwrap();
        println!("renewed the ticket: {st}");
    };
    // Renewed 15 s in, so the new ticket ends more than 10 s after the old.
    let o = run(&addr, &user, cfg, &["GSSAPIDelegateCredentials yes"], Some((std::time::Duration::from_secs(30), &during))).await;
    println!("--- renewal: {o:?}");
    assert!(o.login.is_ok());
    assert!(o.kex.len() >= 2, "no re-key: {o:?}");
    assert!(o.kex.iter().all(|k| k.starts_with("gss-group14-sha256-")), "{o:?}");
    assert_eq!(o.host_key_checks, 0);

    // Without delegation nothing is saved, so renewal forces nothing (as
    // ssh_gssapi_credentials_updated is only told of delegated exchanges).
    let cfg = "  GSSAPIKeyExchange yes\n  PreferredAuthentications gssapi-keyex\n  GSSAPIRenewalForcesRekey yes\n";
    let o = run(&addr, &user, cfg, &[], Some((std::time::Duration::from_secs(30), &during))).await;
    println!("--- renewal without delegation: {o:?}");
    assert!(o.login.is_ok());
    assert_eq!(o.kex.len(), 1, "{o:?}");
}

/// KRB5CCNAME naming a cache that does not exist: no GSS method offered,
/// the usual key exchange, the host key checked.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a KDC and an sshd with GSSAPIKeyExchange"]
async fn live_gss_kex_without_ticket() {
    let addr = std::env::var("REACH_GSSKEX_TEST").expect("REACH_GSSKEX_TEST");
    let user = std::env::var("REACH_GSS_USER").expect("REACH_GSS_USER");
    let o = run(&addr, &user, "  GSSAPIKeyExchange yes\n  PreferredAuthentications gssapi-keyex\n", &[], None).await;
    println!("--- no ticket: {o:?}");
    assert!(!o.kex.is_empty() && !o.kex[0].starts_with("gss-"), "{o:?}");
    assert_eq!(o.host_key_checks, 1);
    assert!(o.login.is_err());
}
