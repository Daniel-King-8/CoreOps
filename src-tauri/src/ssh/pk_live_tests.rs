//! PKCS11Provider and SecurityKeyProvider against a real server, through
//! the same login as the app. Run with `REACH_SSH_TEST=127.0.0.1:2222`
//! (user `reach`), `REACH_PKCS11=<the token library>` with
//! `REACH_PKCS11_PIN` (and `REACH_PKCS11_ED25519=1` if the token has an
//! Ed25519 key), and `REACH_SK_DIR` holding `sk-dummy.so` (OpenSSH's
//! regress/misc/sk-dummy), `sk-pinwrap.so` (sk-dummy, but verify-required
//! keys want PIN 4321) and the keys enrolled with them: `id_ed25519_sk`,
//! `id_ecdsa_sk`, `id_ed25519_sk_uv`; every public key in the server's
//! authorized_keys.
//! `cargo test --lib ssh::pk_live_tests -- --ignored --nocapture --test-threads 1`

use std::sync::atomic::{AtomicUsize, Ordering};

use super::client::{AuthBy, AuthParams, HopOptions};
use super::prompt::{Asker, Field, Kind};
use super::sshconf::session::{ConfigFile, FileRole, Imported, SshOptions};

struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Answers every PIN question with `pin`, counting questions and notices.
struct PinAsker {
    pin: Option<String>,
    asked: AtomicUsize,
    notices: AtomicUsize,
}

impl PinAsker {
    fn new(pin: Option<&str>) -> Self {
        PinAsker { pin: pin.map(str::to_string), asked: AtomicUsize::new(0), notices: AtomicUsize::new(0) }
    }
}

impl Asker for PinAsker {
    fn ask<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
        kind: Kind,
        title: &'a str,
        _instructions: &'a str,
        _fields: Vec<Field>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<String>>> + Send + 'a>> {
        println!("  asked ({kind:?}): {title}");
        self.asked.fetch_add(1, Ordering::SeqCst);
        let answer = self.pin.clone().map(|p| vec![p]);
        Box::pin(async move { answer })
    }

    fn notify_start(&self, _host: &str, _port: u16, text: &str) {
        println!("  notice: {text}");
        self.notices.fetch_add(1, Ordering::SeqCst);
    }

    fn notify_complete(&self, _host: &str, _port: u16, done: Option<&str>) {
        println!("  notice done: {done:?}");
    }
}

/// Logs in with the config imported from `text`, `approved` holding the
/// approved libraries.
async fn run(host: &str, port: u16, text: String, approved: Vec<String>, asker: &PinAsker) -> Result<AuthBy, String> {
    let o = SshOptions {
        imported: Some(Imported { alias: "t".into(), files: vec![ConfigFile { path: "cfg".into(), text, role: FileRole::User }], at: 0 }),
        approved_commands: approved,
        ..Default::default()
    };
    let plan = super::sshconf::session::plan_for(Some(&o), host, port, "reach", false);
    let opts: HopOptions = plan.into();
    let stream = super::sshconf::net::connect(host, port, &opts.socket, false).await.map_err(|e| e.to_string())?;
    let mut handle = russh::client::connect_stream(opts.config.clone(), stream, AnyHost).await.map_err(|e| e.to_string())?;
    let auth = AuthParams::default();
    super::client::login(&mut handle, "reach", &auth, &opts, Some(asker as &dyn Asker), host, port)
        .await
        .map_err(|e| e.to_string())?
        .into_result()
        .map_err(|e| e.to_string())
}

fn addr() -> (String, u16) {
    let a = std::env::var("REACH_SSH_TEST").expect("REACH_SSH_TEST");
    let (h, p) = a.rsplit_once(':').unwrap();
    (h.to_string(), p.parse().unwrap())
}

/// No agent and no other keys: only what the test names can log in.
const BASE: &str = "Host t\n  IdentityAgent none\n  IdentitiesOnly yes\n  PreferredAuthentications publickey\n  IdentityFile none\n";

#[tokio::test]
#[ignore = "needs the SSH test server and a PKCS#11 token"]
async fn live_pkcs11() {
    let (host, port) = addr();
    let lib = std::env::var("REACH_PKCS11").expect("REACH_PKCS11");
    let pin = std::env::var("REACH_PKCS11_PIN").expect("REACH_PKCS11_PIN");
    let mut failed = Vec::new();
    let mut check = |name: &str, got: Result<AuthBy, String>, ok: bool| {
        println!("{name}: {got:?}");
        if got.is_ok() != ok {
            failed.push(name.to_string());
        }
    };

    let a = PinAsker::new(Some(&pin));
    let r = run(&host, port, format!("{BASE}  PKCS11Provider {lib}\n"), vec![lib.clone()], &a).await;
    check("PKCS11Provider, approved, right PIN", r, true);
    assert_eq!(a.asked.load(Ordering::SeqCst), 1, "the PIN is asked once, when signing");

    let a = PinAsker::new(Some("000000"));
    check("PKCS11Provider, wrong PIN", run(&host, port, format!("{BASE}  PKCS11Provider {lib}\n"), vec![lib.clone()], &a).await, false);

    let a = PinAsker::new(Some(&pin));
    check("PKCS11Provider not approved", run(&host, port, format!("{BASE}  PKCS11Provider {lib}\n"), vec![], &a).await, false);
    assert_eq!(a.asked.load(Ordering::SeqCst), 0);

    let a = PinAsker::new(Some(&pin));
    check("PKCS11Provider, BatchMode", run(&host, port, format!("{BASE}  BatchMode yes\n  PKCS11Provider {lib}\n"), vec![lib.clone()], &a).await, false);

    let a = PinAsker::new(Some(&pin));
    check("PKCS11Provider none", run(&host, port, format!("{BASE}  PKCS11Provider none\n"), vec![], &a).await, false);

    // Only the RSA key, then only the ECDSA key: SHA-2 RSA and ECDSA each prove themselves.
    // REACH_PKCS11_ED25519=1 when the token also holds an Ed25519 key (CKK_EC_EDWARDS).
    let mut algs = vec!["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"];
    if std::env::var("REACH_PKCS11_ED25519").is_ok() {
        algs.push("ssh-ed25519");
    }
    for alg in algs {
        let a = PinAsker::new(Some(&pin));
        let text = format!("{BASE}  PubkeyAcceptedAlgorithms {alg}\n  PKCS11Provider {lib}\n");
        check(&format!("PKCS11Provider, {alg} only"), run(&host, port, text, vec![lib.clone()], &a).await, true);
    }

    assert!(failed.is_empty(), "failed: {failed:?}");
}

#[tokio::test]
#[ignore = "needs the SSH test server and OpenSSH's sk-dummy middleware"]
async fn live_security_key() {
    let (host, port) = addr();
    let dir = std::path::PathBuf::from(std::env::var("REACH_SK_DIR").expect("REACH_SK_DIR"));
    let p = |n: &str| dir.join(n).display().to_string();
    let dummy = p("sk-dummy.so");
    let wrap = p("sk-pinwrap.so");
    let mut failed = Vec::new();
    let mut check = |name: &str, got: Result<AuthBy, String>, ok: bool| {
        println!("{name}: {got:?}");
        if got.is_ok() != ok {
            failed.push(name.to_string());
        }
    };
    let with = |key: &str, provider: &str| format!("{BASE}  IdentityFile {}\n  SecurityKeyProvider {provider}\n", p(key));

    for key in ["id_ed25519_sk", "id_ecdsa_sk"] {
        let a = PinAsker::new(None);
        check(&format!("{key} through the middleware"), run(&host, port, with(key, &dummy), vec![dummy.clone()], &a).await, true);
        assert_eq!(a.notices.load(Ordering::SeqCst), 1, "the touch notice is shown");
        assert_eq!(a.asked.load(Ordering::SeqCst), 0, "no PIN for a key without verify-required");
    }

    let a = PinAsker::new(None);
    check("middleware not approved", run(&host, port, with("id_ed25519_sk", &dummy), vec![], &a).await, false);
    let a = PinAsker::new(None);
    check("SecurityKeyProvider none", run(&host, port, with("id_ed25519_sk", "none"), vec![], &a).await, false);

    let a = PinAsker::new(Some("4321"));
    check("verify-required key, PIN asked after PIN required", run(&host, port, with("id_ed25519_sk_uv", &wrap), vec![wrap.clone()], &a).await, true);
    assert_eq!(a.asked.load(Ordering::SeqCst), 1);
    let a = PinAsker::new(Some("1111"));
    check("verify-required key, wrong PIN", run(&host, port, with("id_ed25519_sk_uv", &wrap), vec![wrap.clone()], &a).await, false);
    let a = PinAsker::new(None);
    check("verify-required key, PIN cancelled", run(&host, port, with("id_ed25519_sk_uv", &wrap), vec![wrap.clone()], &a).await, false);

    assert!(failed.is_empty(), "failed: {failed:?}");
}
