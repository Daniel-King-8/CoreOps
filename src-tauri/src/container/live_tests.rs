//! Against a real server with Docker and Podman. Run with
//! `REACH_SSH_TEST=host:port REACH_SSH_USER=user REACH_SSH_KEYS=dir
//! cargo test --lib container::live -- --ignored --nocapture --test-threads=1`,
//! where `dir/k_good` logs in and the user may use both engines.

use std::sync::Arc;

use tokio::sync::Mutex;

use super::transport::{Dial, SshTransport};
use crate::ssh::client::{cascade_authenticate, AuthParams, KeyAuth, KeySource};

struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn login() -> Arc<Mutex<russh::client::Handle<AnyHost>>> {
    let addr = std::env::var("REACH_SSH_TEST").expect("set REACH_SSH_TEST");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let user = std::env::var("REACH_SSH_USER").expect("set REACH_SSH_USER");
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, (host, port.parse::<u16>().unwrap()), AnyHost).await.unwrap();
    let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key), passphrase: None }), password: None, allow_agent: false };
    cascade_authenticate(&mut handle, &user, &auth).await.unwrap().into_result().unwrap();
    Arc::new(Mutex::new(handle))
}

async fn exec_out(h: &Arc<Mutex<russh::client::Handle<AnyHost>>>, cmd: &str) -> String {
    let mut ch = h.lock().await.channel_open_session().await.unwrap();
    ch.exec(true, cmd).await.unwrap();
    let mut out = Vec::new();
    while let Some(msg) = ch.wait().await {
        if let russh::ChannelMsg::Data { data } = msg {
            out.extend_from_slice(&data);
        }
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

#[tokio::test]
#[ignore = "needs an SSH server with Docker"]
async fn live_docker_over_dial_stdio() {
    let h = login().await;
    let docker = SshTransport::new(h, Dial::Exec("docker system dial-stdio".into()), None).docker().unwrap();
    let v = docker.version().await.expect("version over SSH");
    println!("Docker {} (API {})", v.version.unwrap_or_default(), v.api_version.unwrap_or_default());
    // Many requests in a row must reuse connections, not start a process each.
    for _ in 0..20 {
        docker.ping().await.expect("ping");
    }
    let list = docker
        .list_containers(Some(bollard::query_parameters::ListContainersOptions { all: true, ..Default::default() }))
        .await
        .expect("list");
    println!("{} containers", list.len());
}

#[tokio::test]
#[ignore = "needs an SSH server with rootless Podman"]
async fn live_podman_over_socket() {
    let h = login().await;
    // As `podman system connection` finds it.
    let path = exec_out(&h, "podman info --format '{{.Host.RemoteSocket.Path}}'").await;
    println!("Podman socket: {path}");
    assert!(path.starts_with('/'), "podman info gave no socket path: {path:?}");
    let docker = SshTransport::new(h, Dial::Socket(path), None).docker().unwrap();
    let v = docker.version().await.expect("version over the socket");
    println!("Podman API {}", v.api_version.unwrap_or_default());
    for _ in 0..20 {
        docker.ping().await.expect("ping");
    }
}
