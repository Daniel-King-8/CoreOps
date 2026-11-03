//! HTTPS for the connection to Turso.
//!
//! libsql's built-in connector is hyper-rustls 0.25, which holds rustls-webpki
//! 0.102 and its open advisories; libsql's latest release still does. libsql
//! takes a connector of the caller's, so this is the same thing on the rustls
//! the rest of the app uses: TCP through hyper's own connector, then TLS with
//! ring and the Mozilla root set, the roots the database drivers trust too.
//!
//! Every connection is TLS unless the URL says `http://` outright. libsql
//! rewrites `libsql://` to `https://`, but a scheme this code does not know
//! must never fall through to clear text.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_014::client::connect::{Connected, Connection};
use hyper_014::client::HttpConnector;
use hyper_014::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct TursoConnector {
    http: HttpConnector,
    tls: TlsConnector,
}

impl TursoConnector {
    pub fn new() -> Result<Self, rustls::Error> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);

        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self { http, tls: TlsConnector::from(Arc::new(config)) })
    }
}

impl tower_04::Service<Uri> for TursoConnector {
    type Response = TursoStream;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<TursoStream, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        tower_04::Service::<Uri>::poll_ready(&mut self.http, cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let plain = is_clear_text(&uri);
            let host = uri.host().ok_or("URL has no host")?.trim_matches(['[', ']']).to_owned();
            let tcp = tower_04::Service::<Uri>::call(&mut http, uri).await?;
            if plain {
                return Ok(TursoStream::Plain(tcp));
            }
            let name = ServerName::try_from(host)?;
            Ok(TursoStream::Tls(Box::new(tls.connect(name, tcp).await?)))
        })
    }
}

/// Only an explicit `http://` goes out unencrypted.
fn is_clear_text(uri: &Uri) -> bool {
    uri.scheme_str() == Some("http")
}

pub enum TursoStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Connection for TursoStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for TursoStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TursoStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            TursoStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TursoStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TursoStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            TursoStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TursoStream::Plain(s) => Pin::new(s).poll_flush(cx),
            TursoStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TursoStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            TursoStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real TLS handshake with Turso's API, which serves the same kind of
    /// certificate as a database URL. Needs the network, so it is ignored by
    /// default: `cargo test --lib turso_tls -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn completes_a_tls_handshake_with_turso() {
        let mut connector = TursoConnector::new().unwrap();
        let uri: Uri = "https://api.turso.tech".parse().unwrap();
        let stream = tower_04::Service::call(&mut connector, uri).await.unwrap();
        assert!(matches!(stream, TursoStream::Tls(_)));
    }

    #[test]
    fn only_http_goes_out_in_the_clear() {
        for (url, clear) in [
            ("https://db.turso.io", false),
            ("libsql://db.turso.io", false),
            ("wss://db.turso.io", false),
            ("HTTPS://db.turso.io", false),
            ("http://127.0.0.1:8080", true),
        ] {
            assert_eq!(is_clear_text(&url.parse().unwrap()), clear, "{url}");
        }
    }
}
