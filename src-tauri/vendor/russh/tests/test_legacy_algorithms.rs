#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The older MACs and sntrup761x25519-sha512, end to end.
//!
//! Always run: a russh client against a russh server for every one of them,
//! with the algorithm as the only one either side allows, moving small and
//! large data both ways and checking that it is what got negotiated.
//!
//! Run only when RUSSH_INTEROP is set: the russh client against real OpenSSH
//! servers. RUSSH_INTEROP is the server address; RUSSH_INTEROP_KEY a private
//! key the user (RUSSH_INTEROP_USER, default "reach") may log in with;
//! RUSSH_INTEROP_CASES a comma-separated list of `port:mac:<name>` or
//! `port:kex:<name>`, one sshd per port configured to allow that algorithm
//! (and, for a MAC, a non-AEAD cipher such as aes128-ctr). For example
//!
//!   RUSSH_INTEROP=127.0.0.1 RUSSH_INTEROP_KEY=~/.ssh/id_ed25519 \
//!   RUSSH_INTEROP_CASES=2230:mac:hmac-md5,2240:kex:sntrup761x25519-sha512 \
//!   cargo test --test test_legacy_algorithms -- --nocapture

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::*;
use sha2::{Digest, Sha256};
use ssh_key::PrivateKey;

const NEW_MACS: &[mac::Name] = &[
    mac::HMAC_MD5,
    mac::HMAC_MD5_96,
    mac::HMAC_SHA1_96,
    mac::HMAC_MD5_ETM,
    mac::HMAC_MD5_96_ETM,
    mac::HMAC_SHA1_96_ETM,
    mac::UMAC_64,
    mac::UMAC_128,
    mac::UMAC_64_ETM,
    mac::UMAC_128_ETM,
    mac::HMAC_RIPEMD160,
    mac::HMAC_RIPEMD160_OPENSSH,
    mac::HMAC_RIPEMD160_ETM,
];

const NEW_KEXES: &[kex::Name] = &[
    kex::SNTRUP761X25519_SHA512,
    kex::SNTRUP761X25519_SHA512_OPENSSH,
];

/// The negotiated (kex, cipher, client-to-server MAC, server-to-client MAC).
type Negotiated = Arc<Mutex<Option<(String, String, String, String)>>>;

fn leak<T: Clone>(v: Vec<T>) -> &'static [T] {
    Box::leak(v.into_boxed_slice())
}

fn preferred(kex: Option<kex::Name>, mac: Option<mac::Name>) -> Preferred {
    let mut p = Preferred::default();
    if let Some(k) = kex {
        p.kex = Cow::Borrowed(leak(vec![
            k,
            kex::EXTENSION_SUPPORT_AS_CLIENT,
            kex::EXTENSION_SUPPORT_AS_SERVER,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        ]));
    }
    if let Some(m) = mac {
        // A MAC is only used with a cipher that has none of its own.
        p.cipher = Cow::Borrowed(&[cipher::AES_128_CTR]);
        p.mac = Cow::Borrowed(leak(vec![m]));
    }
    p
}

fn test_data(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..len {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        v.push((x >> 16) as u8);
    }
    v
}

// ---------------------------------------------------------------- client side

struct Client {
    negotiated: Negotiated,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        *self.negotiated.lock().unwrap() = Some((
            names.kex.as_ref().to_owned(),
            names.cipher.as_ref().to_owned(),
            names.client_mac.as_ref().to_owned(),
            names.server_mac.as_ref().to_owned(),
        ));
        Ok(())
    }
}

/// Runs `cmd` with `stdin` and returns everything it wrote to stdout.
async fn exec(session: &client::Handle<Client>, cmd: &str, stdin: &[u8]) -> Vec<u8> {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, cmd).await.unwrap();
    if !stdin.is_empty() {
        channel.data(stdin).await.unwrap();
    }
    channel.eof().await.unwrap();
    let mut out = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => {
                assert_eq!(exit_status, 0, "{cmd} failed")
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn openssh_case(host: &str, port: u16, user: &str, key: Arc<PrivateKey>, case: &str) {
    let (kind, name) = case.split_once(':').expect("kind:name");
    let (kex_name, mac_name) = match kind {
        "mac" => (None, Some(mac::Name::try_from(name).expect("known MAC"))),
        "kex" => (Some(kex::Name::try_from(name).expect("known kex")), None),
        _ => panic!("unknown case kind {kind}"),
    };
    let mut config = client::Config::default();
    config.preferred = preferred(kex_name, mac_name);
    let negotiated: Negotiated = Arc::default();
    let mut session = client::connect(
        Arc::new(config),
        (host, port),
        Client {
            negotiated: negotiated.clone(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{case}: connect to port {port}: {e}"));

    let hash_alg = session.best_supported_rsa_hash().await.unwrap().flatten();
    let auth = session
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, hash_alg))
        .await
        .unwrap();
    assert!(auth.success(), "{case}: authentication failed");

    let (kex, cipher, c2s, s2c) = negotiated.lock().unwrap().clone().unwrap();

    // A command and its output.
    let out = exec(&session, &format!("echo reach-interop {name}"), b"").await;
    assert_eq!(out, format!("reach-interop {name}\n").as_bytes(), "{case}");

    // 200 kB up (many full-size packets, over UMAC's 1024-byte L1 chunk),
    // checked by the server's sha256sum.
    let up = test_data(200_000);
    let out = exec(&session, "sha256sum", &up).await;
    let out = String::from_utf8(out).unwrap();
    assert_eq!(
        out.split_whitespace().next(),
        Some(sha256_hex(&up).as_str()),
        "{case}"
    );

    // 300 kB down.
    let out = exec(
        &session,
        "dd if=/dev/zero bs=1000 count=300 2>/dev/null | tr '\\0' z",
        b"",
    )
    .await;
    assert_eq!(out.len(), 300_000, "{case}");
    assert!(out.iter().all(|&b| b == b'z'), "{case}");

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();

    println!(
        "openssh {host}:{port} {case}: ok (kex {kex}, cipher {cipher}, mac c2s {c2s}, s2c {s2c})"
    );
    if let Some(m) = mac_name {
        assert_eq!(c2s, m.as_ref(), "{case}");
        assert_eq!(s2c, m.as_ref(), "{case}");
        assert_eq!(cipher, cipher::AES_128_CTR.as_ref(), "{case}");
    }
    if let Some(k) = kex_name {
        assert_eq!(kex, k.as_ref(), "{case}");
    }
}

#[tokio::test]
async fn openssh_interop() {
    let Ok(host) = std::env::var("RUSSH_INTEROP") else {
        println!("RUSSH_INTEROP not set; skipping the OpenSSH interop test");
        return;
    };
    let _ = env_logger::try_init();
    let key_path = std::env::var("RUSSH_INTEROP_KEY").expect("RUSSH_INTEROP_KEY");
    let user = std::env::var("RUSSH_INTEROP_USER").unwrap_or_else(|_| "reach".to_owned());
    let cases = std::env::var("RUSSH_INTEROP_CASES").expect("RUSSH_INTEROP_CASES");
    let key = Arc::new(russh::keys::load_secret_key(&key_path, None).unwrap());
    let mut n = 0;
    for case in cases.split(',').filter(|c| !c.is_empty()) {
        let (port, rest) = case.split_once(':').expect("port:kind:name");
        openssh_case(&host, port.parse().unwrap(), &user, key.clone(), rest).await;
        n += 1;
    }
    println!("openssh interop: {n} cases passed");
}

// ---------------------------------------------------------- russh to russh

#[derive(Clone)]
struct Server {}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

async fn russh_round_trip(kex_name: Option<kex::Name>, mac_name: Option<mac::Name>) {
    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    server_config.preferred = preferred(kex_name, mac_name);
    let server_config = Arc::new(server_config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handler = Server {};
    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        let _ = server::run_stream(server_config, socket, handler)
            .await
            .unwrap()
            .await;
    });

    let mut client_config = client::Config::default();
    client_config.preferred = preferred(kex_name, mac_name);
    let negotiated: Negotiated = Arc::default();
    let mut session = client::connect(
        Arc::new(client_config),
        addr,
        Client {
            negotiated: negotiated.clone(),
        },
    )
    .await
    .unwrap();
    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    assert!(
        session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None)
            )
            .await
            .unwrap()
            .success()
    );

    let mut channel = session.channel_open_session().await.unwrap();
    for len in [1usize, 100, 1024, 1025, 20_000] {
        let data = test_data(len);
        channel.data(&data[..]).await.unwrap();
        let mut back = Vec::new();
        while back.len() < len {
            match channel.wait().await.unwrap() {
                ChannelMsg::Data { data } => back.extend_from_slice(&data),
                msg => panic!("unexpected {msg:?}"),
            }
        }
        assert_eq!(back, data, "{kex_name:?} {mac_name:?} len {len}");
    }
    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();

    // Each side allows only the algorithm under test, so the server used it
    // too; the client reports what was negotiated.
    let (kex, cipher, c2s, s2c) = negotiated.lock().unwrap().clone().unwrap();
    if let Some(m) = mac_name {
        assert_eq!((c2s.as_str(), s2c.as_str()), (m.as_ref(), m.as_ref()));
        assert_eq!(cipher, cipher::AES_128_CTR.as_ref());
    }
    if let Some(k) = kex_name {
        assert_eq!(kex, k.as_ref());
    }
}

#[tokio::test]
async fn russh_to_russh_every_new_mac() {
    for &m in NEW_MACS {
        russh_round_trip(None, Some(m)).await;
    }
}

#[tokio::test]
async fn russh_to_russh_sntrup761x25519() {
    for &k in NEW_KEXES {
        russh_round_trip(Some(k), None).await;
        // and with one of the new MACs on top
        russh_round_trip(Some(k), Some(mac::UMAC_64_ETM)).await;
    }
}

#[test]
fn none_of_them_is_offered_by_default() {
    let p = Preferred::default();
    for m in NEW_MACS {
        assert!(!p.mac.contains(m), "{m:?}");
    }
    for k in NEW_KEXES {
        assert!(!p.kex.contains(k), "{k:?}");
    }
}
