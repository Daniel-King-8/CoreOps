//! Against a real KDC and an sshd that takes Kerberos logins. Run with
//! `REACH_GSS_TEST=localhost:2250 REACH_GSS_USER=reach
//! cargo test --lib ssh::gssapi::live -- --ignored --nocapture`, holding a
//! forwardable ticket for the principal that maps to that user (kinit -f),
//! where the KDC has `host/localhost` in the server's keytab and nothing
//! for `host/127.0.0.1`. With `REACH_GSS_PRINCIPAL=<the user's principal>`
//! and `REACH_GSS_OTHER=<principal>` naming a second principal in the same
//! cache collection (DIR: or KEYRING:) that the server does not map to the
//! user, GSSAPIClientIdentity is tried too. `REACH_GSS_SERVER_STORES=1`
//! when the server writes delegated tickets to a cache for the session.

use crate::ssh::client::{AuthBy, AuthParams, HopOptions};
use crate::ssh::sshconf::session::{ConfigFile, FileRole, Imported, SshOptions};

/// Accepts any host key: the server's identity is not under test.
struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Logs in under `config` and, once in, runs `klist` on the server: the
/// way it ended, and what the server holds for the session.
async fn run(host: &str, port: u16, user: &str, config: &str, approved: &[&str]) -> (Result<AuthBy, String>, String) {
    let o = SshOptions {
        imported: Some(Imported { alias: "t".into(), files: vec![ConfigFile { path: "cfg".into(), text: format!("Host t\n{config}"), role: FileRole::User }], at: 0 }),
        accepted_weakenings: approved.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    let opts: HopOptions = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, user, false).into();
    let stream = match crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await {
        Ok(s) => s,
        Err(e) => return (Err(e.to_string()), String::new()),
    };
    let mut handle = match russh::client::connect_stream(opts.config.clone(), stream, AnyHost).await {
        Ok(h) => h,
        Err(e) => return (Err(e.to_string()), String::new()),
    };
    let r = match crate::ssh::client::login(&mut handle, user, &AuthParams::default(), &opts, None, host, port).await {
        Ok(o) => o.into_result().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    let mut out = String::new();
    if r.is_ok() {
        let mut ch = handle.channel_open_session().await.unwrap();
        ch.exec(true, "echo KRB5CCNAME=$KRB5CCNAME; klist 2>&1").await.unwrap();
        while let Some(msg) = ch.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => out.push_str(&String::from_utf8_lossy(&data)),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
    }
    (r, out)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a KDC and an sshd with GSSAPIAuthentication"]
async fn live_gssapi_login() {
    let addr = std::env::var("REACH_GSS_TEST").expect("REACH_GSS_TEST");
    let user = std::env::var("REACH_GSS_USER").expect("REACH_GSS_USER");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let gss = "  GSSAPIAuthentication yes\n  PreferredAuthentications gssapi-with-mic\n";
    let has_ticket = |out: &str| out.contains("krbtgt/");
    // Whether the server keeps delegated tickets for the session; Debian's
    // OpenSSH 10.0 sshd receives them but fails to store them
    // ("gss_krb5_copy_ccache() failed"), for OpenSSH's own client too.
    let stores = std::env::var("REACH_GSS_SERVER_STORES").is_ok();

    let mut failed = Vec::new();
    let mut check = |name: &str, (got, out): (Result<AuthBy, String>, String), want_in: bool, want_ticket: bool| {
        println!("--- {name}: {got:?}\n{}", out.trim());
        let ok = got.as_ref().is_ok_and(|b| *b == AuthBy::Gssapi) == want_in && (!want_in || has_ticket(&out) == want_ticket);
        if !ok {
            failed.push(name.to_string());
        }
    };

    check("Kerberos login", run(host, port, &user, gss, &[]).await, true, false);
    check("GSSAPIAuthentication off", run(host, port, &user, "  PreferredAuthentications gssapi-with-mic\n", &[]).await, false, false);
    check("by address: no host/127.0.0.1 principal", run("127.0.0.1", port, &user, gss, &[]).await, false, false);
    check(
        "by address, GSSAPIServerIdentity localhost",
        run("127.0.0.1", port, &user, &format!("{gss}  GSSAPIServerIdentity localhost\n"), &[]).await,
        true,
        false,
    );
    check("by address, GSSAPITrustDns yes", run("127.0.0.1", port, &user, &format!("{gss}  GSSAPITrustDns yes\n"), &[]).await, true, false);
    let deleg = format!("{gss}  GSSAPIDelegateCredentials yes\n");
    check("GSSAPIDelegateCredentials yes, not approved", run(host, port, &user, &deleg, &[]).await, true, false);
    check(
        "GSSAPIDelegateCredentials yes, approved",
        run(host, port, &user, &deleg, &["GSSAPIDelegateCredentials yes"]).await,
        true,
        stores,
    );
    if let Ok(other) = std::env::var("REACH_GSS_OTHER") {
        let me = std::env::var("REACH_GSS_PRINCIPAL").expect("REACH_GSS_PRINCIPAL");
        check(
            "GSSAPIClientIdentity naming the user's principal",
            run(host, port, &user, &format!("{gss}  GSSAPIClientIdentity {me}\n"), &[]).await,
            true,
            false,
        );
        check(
            "GSSAPIClientIdentity naming a principal the server refuses",
            run(host, port, &user, &format!("{gss}  GSSAPIClientIdentity {other}\n"), &[]).await,
            false,
            false,
        );
    }
    assert!(failed.is_empty(), "failed: {failed:?}");
}

/// The same server with KRB5CCNAME naming a cache that does not exist: the
/// method is not offered, and the reason says what to do.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a KDC and an sshd with GSSAPIAuthentication"]
async fn live_gssapi_without_ticket() {
    let addr = std::env::var("REACH_GSS_TEST").expect("REACH_GSS_TEST");
    let user = std::env::var("REACH_GSS_USER").expect("REACH_GSS_USER");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let e = super::probe(host, None).unwrap_err();
    println!("probe: {e}");
    assert!(e.contains("run kinit"), "{e}");
    let (r, _) = run(host, port.parse().unwrap(), &user, "  GSSAPIAuthentication yes\n  PreferredAuthentications gssapi-with-mic\n", &[]).await;
    println!("login: {r:?}");
    assert!(r.is_err());
}
