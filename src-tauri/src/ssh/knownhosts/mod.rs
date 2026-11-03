//! known_hosts, as OpenSSH reads and writes it (hostfile.c, the host key
//! checks in sshconnect.c, krl.c and sshd(8) "SSH_KNOWN_HOSTS FILE
//! FORMAT"). Keys are handled as OpenSSH wire blobs (the base64-decoded
//! second field of a known_hosts line), not as ssh-key crate types.

mod digest;
mod fingerprint;
mod hostfile;
mod krl;
mod wire;

pub use fingerprint::{fingerprint, randomart};
pub use hostfile::{
    append, check, check_ca, format_line, format_line_with_salt, hash_host, host_label, parse,
    replace_host_keys, replace_host_keys_with_salt, Check, Entry, Hosts, LineError, LineErrorKind,
    Marker, Parsed,
};
pub use krl::{check_revoked_file, is_krl, krl_parse, krl_revokes, revoked_in_keylist, Krl};
pub use wire::CertInfo;

/// Reads a certificate blob's fields (serial, key ID, CA and so on), as
/// cert_parse does apart from verifying its signature.
pub fn cert_info(cert_blob: &[u8]) -> Result<CertInfo, String> {
    let k = wire::parse_key(cert_blob, true).map_err(|e| e.to_string())?;
    k.cert.ok_or_else(|| "not a certificate".to_string())
}

#[cfg(test)]
mod tests;
