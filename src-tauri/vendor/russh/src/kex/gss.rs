//! GSS-API key exchange, client side (RFC 4462 section 2, RFC 8732), as
//! the GSSAPI patch OpenSSH carries in Debian and Fedora does it
//! (kexgssc.c).
//!
//! russh does the exchange and the Diffie-Hellman part; the GSS-API itself
//! comes from the application through [`GssKexProvider`], so russh links no
//! GSS-API library. The exchange hash is signed by the server with a GSS
//! MIC instead of a host key: the server may send no host key at all (the
//! `null` host key algorithm), and one it does send only goes into the hash.

use std::fmt::Debug;

/// One call to GSS_Init_sec_context.
#[derive(Debug, Clone, Default)]
pub struct GssKexStep {
    /// The output token; empty when there is nothing to send.
    pub token: Vec<u8>,
    /// GSS_S_COMPLETE, rather than GSS_S_CONTINUE_NEEDED.
    pub complete: bool,
    /// GSS_C_MUTUAL_FLAG in the returned flags.
    pub mutual: bool,
    /// GSS_C_INTEG_FLAG in the returned flags.
    pub integ: bool,
}

/// A security context for one key exchange, asked for with mutual
/// authentication and integrity (and delegation when the application wants
/// it).
pub trait GssKexContext: Send {
    /// GSS_Init_sec_context: `input` is `None` on the first call, then the
    /// server's token.
    fn init(&mut self, input: Option<&[u8]>) -> Result<GssKexStep, String>;

    /// GSS_VerifyMIC: `mic` over `data`, the exchange hash.
    fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<(), String>;

    /// GSS_GetMIC over `data`, for `gssapi-keyex` user authentication.
    fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// Makes the contexts, one per key exchange (the first one's context is
/// kept for `gssapi-keyex`).
pub trait GssKexProvider: Send + Sync + Debug {
    /// A fresh context for the server, as ssh_gssapi_build_ctx,
    /// ssh_gssapi_import_name and, with a client identity,
    /// ssh_gssapi_client_identity make it.
    fn context(&self) -> Result<Box<dyn GssKexContext>, String>;

    /// The exchange hash verified: the place for
    /// `ssh_gssapi_credentials_updated(ctxt)`.
    fn exchanged(&self) {}

    /// GSSAPIRenewalForcesRekey: whether the session should ask
    /// [`credentials_renewed`](Self::credentials_renewed) (every 10 seconds).
    fn renewal_rekey(&self) -> bool {
        false
    }

    /// `ssh_gssapi_credentials_updated(NULL)`: the credentials were renewed
    /// since the last exchange, so a re-key would pass them on.
    fn credentials_renewed(&self) -> bool {
        false
    }
}

/// The kind of exchange a GSS key exchange method name stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GssKexKind {
    /// A fixed group or curve: KEXGSS_INIT goes first.
    Fixed,
    /// gss-gex-sha1-: KEXGSS_GROUPREQ goes first.
    GroupExchange,
}

/// The DER encoding of Kerberos v5's OID, 1.2.840.113554.1.2.2.
pub const KRB5_MECH: [u8; 11] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// The suffix of the method names for Kerberos v5: the base64 of the MD5 of
/// the DER OID, as ssh_gssapi_kex_mechs builds it.
pub const KRB5_SUFFIX: &str = "toWM5Slw5Ew8Mqkay+al2g==";

/// A context that finished a key exchange, carried to the session for
/// `gssapi-keyex`.
pub(crate) struct KexContext(pub Box<dyn GssKexContext>);

impl Debug for KexContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GssKexContext")
    }
}

/// dh_estimate in dh.c: the group size for `bits` of security.
pub(crate) fn dh_estimate(bits: usize) -> usize {
    match bits {
        0..=112 => 2048,
        113..=128 => 3072,
        129..=192 => 7680,
        _ => 8192,
    }
}

/// DH_GRP_MIN and DH_GRP_MAX in dh.h, the bounds of a gss-gex group.
pub(crate) const GEX_MIN: usize = 2048;
pub(crate) const GEX_MAX: usize = 8192;
