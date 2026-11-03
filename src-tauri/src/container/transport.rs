//! The Docker Engine API, carried over an SSH connection.
//!
//! Each engine is reached the way its own client reaches a remote one, so
//! the server's setup (rootless engines, contexts, socket paths, group
//! membership) counts exactly as it does for `docker` or `podman` there:
//!
//! - Docker: `docker system dial-stdio` runs on the server and relays its
//!   API connection over the channel's stdin and stdout. This is what
//!   `docker -H ssh://host` does (docker/cli `connhelper`).
//! - Podman: the API socket that `podman info` reports as
//!   `Host.RemoteSocket.Path` is opened as an SSH stream-local channel
//!   (`direct-streamlocal@openssh.com`), which is what `podman system
//!   connection` does.
//!
//! Connections are kept and reused (HTTP/1.1 keep-alive), as the Docker
//! client's own pool does, so a page of requests does not start a process
//! on the server for each one.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::sync::Mutex;

use russh::client::{Handle, Handler};

type Body = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Idle connections kept for reuse. A held connection costs a process (or a
/// socket) on the server, so only a few are kept.
const POOL: usize = 4;

/// The Host header for an API reached through a socket or SSH, as the
/// Docker client sends it.
const HOST: &str = "api.moby.localhost";

/// How the API connection is opened on the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dial {
    /// Run this command and speak HTTP over its stdin and stdout.
    Exec(String),
    /// Open this Unix socket on the server through SSH.
    Socket(String),
}

pub struct SshTransport<H: Handler> {
    handle: Arc<Mutex<Handle<H>>>,
    dial: Dial,
    idle: Mutex<Vec<SendRequest<Body>>>,
    /// Keeps a connection Reach opened for this host alive as long as the
    /// transport; `None` when it rides on a terminal tab's connection.
    _keep: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl<H: Handler + 'static> SshTransport<H> {
    pub fn new(
        handle: Arc<Mutex<Handle<H>>>,
        dial: Dial,
        keep: Option<Box<dyn std::any::Any + Send + Sync>>,
    ) -> Arc<Self> {
        Arc::new(SshTransport { handle, dial, idle: Mutex::new(Vec::new()), _keep: keep })
    }

    /// A Docker client that sends every request over this transport.
    pub fn docker(self: &Arc<Self>) -> Result<bollard::Docker, String> {
        let t = self.clone();
        bollard::Docker::connect_with_custom_transport(
            move |req: bollard::BollardRequest| {
                let t = t.clone();
                async move { t.send(req).await }
            },
            // The host part only fills the Host header; the request goes
            // wherever the channel goes.
            Some("http://docker"),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .map_err(|e| e.to_string())
    }

    async fn send(
        &self,
        req: bollard::BollardRequest,
    ) -> Result<hyper::Response<hyper::body::Incoming>, bollard::errors::Error> {
        let (mut parts, body) = req.into_parts();
        // HTTP/1.1 to an origin server: the path alone as the target, and a
        // Host header, which the engines require. The Docker client sends
        // `api.moby.localhost` for socket and SSH connections (its DummyHost).
        if let Some(pq) = parts.uri.path_and_query().cloned() {
            parts.uri = hyper::Uri::from(pq);
        }
        parts.headers.insert(hyper::header::HOST, hyper::header::HeaderValue::from_static(HOST));
        let req = hyper::Request::from_parts(parts, body.boxed_unsync());
        let mut sender = match self.take_ready().await {
            Some(s) => s,
            None => self.connect().await.map_err(|e| io_error(&e))?,
        };
        let res = sender.send_request(req).await.map_err(|e| io_error(&e.to_string()))?;
        // Ready again once this response's body has been read; `take_ready`
        // skips it until then.
        let mut idle = self.idle.lock().await;
        if idle.len() < POOL {
            idle.push(sender);
        }
        Ok(res)
    }

    /// A kept connection that can take a request now; closed ones are dropped.
    async fn take_ready(&self) -> Option<SendRequest<Body>> {
        let mut idle = self.idle.lock().await;
        idle.retain(|s| !s.is_closed());
        let at = idle.iter().position(|s| s.is_ready())?;
        Some(idle.swap_remove(at))
    }

    async fn connect(&self) -> Result<SendRequest<Body>, String> {
        let channel = {
            let h = self.handle.lock().await;
            match &self.dial {
                Dial::Exec(_) => h.channel_open_session().await,
                Dial::Socket(path) => h.channel_open_direct_streamlocal(path.as_str()).await,
            }
            .map_err(|e| format!("Could not open an SSH channel: {e}"))?
        };
        if let Dial::Exec(cmd) = &self.dial {
            channel.exec(true, cmd.as_str()).await.map_err(|e| format!("Could not run {cmd}: {e}"))?;
        }
        let io = TokioIo::new(channel.into_stream());
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("The engine did not answer: {e}"))?;
        // Upgrades are what `docker attach` and exec streams use.
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        Ok(sender)
    }
}

fn io_error(msg: &str) -> bollard::errors::Error {
    bollard::errors::Error::IOError { err: std::io::Error::other(msg.to_string()) }
}
