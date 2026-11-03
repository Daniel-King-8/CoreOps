//! Every HTTP client Reach makes starts from [`client_builder`].
//!
//! reqwest checks certificates with the operating system's verifier. Android's
//! needs a Java component started from the activity, which Reach does not
//! ship, so there the client trusts the Mozilla root set compiled into the
//! app instead, the same roots the database drivers use.

pub fn client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder();
    #[cfg(target_os = "android")]
    let builder = builder.tls_certs_only(
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|der| reqwest::Certificate::from_der(der).ok()),
    );
    builder
}

/// A client with no settings of its own.
pub fn client() -> reqwest::Client {
    client_builder().build().unwrap_or_default()
}
