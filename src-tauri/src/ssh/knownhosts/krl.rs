//! Key revocation lists (OpenSSH PROTOCOL.krl, krl.c) and the plain
//! revoked-keys file RevokedHostKeys also accepts (authfile.c).

use std::collections::BTreeSet;

use super::digest::{sha1, sha256};
use super::wire::{
    b64_decode, key_equal, key_equal_public, parse_key, CertInfo, Key, KeyError, KeyType, Reader,
};

const KRL_MAGIC: &[u8; 8] = b"SSHKRL\n\0";
const KRL_FORMAT_VERSION: u32 = 1;

const SECTION_CERTIFICATES: u8 = 1;
const SECTION_EXPLICIT_KEY: u8 = 2;
const SECTION_FINGERPRINT_SHA1: u8 = 3;
const SECTION_SIGNATURE: u8 = 4;
const SECTION_FINGERPRINT_SHA256: u8 = 5;
const SECTION_EXTENSION: u8 = 255;

const CERT_SERIAL_LIST: u8 = 0x20;
const CERT_SERIAL_RANGE: u8 = 0x21;
const CERT_SERIAL_BITMAP: u8 = 0x22;
const CERT_KEY_ID: u8 = 0x23;
const CERT_EXTENSION: u8 = 0x39;

/// Revocations for one CA, or for any CA when `ca` is None.
#[derive(Clone, Debug)]
struct CaRevocations {
    ca: Option<Key>,
    /// Inclusive serial ranges; never contain serial 0.
    serials: Vec<(u64, u64)>,
    key_ids: BTreeSet<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Krl {
    pub version: u64,
    pub generated_date: u64,
    pub flags: u64,
    pub comment: String,
    explicit: BTreeSet<Vec<u8>>,
    sha1s: BTreeSet<Vec<u8>>,
    sha256s: BTreeSet<Vec<u8>>,
    certs: Vec<CaRevocations>,
    // Section and subsection types seen, so tests can tell which encodings
    // a KRL used.
    pub(crate) sections: BTreeSet<u8>,
}

/// Whether the bytes start with the KRL magic. ssh falls back to reading a
/// plain key list when they do not.
pub fn is_krl(bytes: &[u8]) -> bool {
    bytes.len() >= KRL_MAGIC.len() && &bytes[..KRL_MAGIC.len()] == KRL_MAGIC
}

fn err(s: &str) -> String {
    s.to_string()
}

impl Krl {
    /// revoked_certs_for_ca_key(): sections for the same CA are merged.
    fn certs_for(&mut self, ca: Option<&Key>) -> &mut CaRevocations {
        let pos = self.certs.iter().position(|rc| match (&rc.ca, ca) {
            (None, None) => true,
            (Some(a), Some(b)) => key_equal(a, b),
            _ => false,
        });
        let i = match pos {
            Some(i) => i,
            None => {
                self.certs.push(CaRevocations {
                    ca: ca.cloned(),
                    serials: Vec::new(),
                    key_ids: BTreeSet::new(),
                });
                self.certs.len() - 1
            }
        };
        &mut self.certs[i]
    }

    /// ssh_krl_revoke_cert_by_serial_range(): serial 0 and reversed ranges
    /// are refused, which fails the whole KRL.
    fn revoke_range(&mut self, ca: Option<&Key>, lo: u64, hi: u64) -> Result<(), String> {
        if lo > hi || lo == 0 {
            return Err(err("invalid certificate serial range"));
        }
        self.certs_for(ca).serials.push((lo, hi));
        Ok(())
    }
}

/// ssh_krl_from_blob(). OpenSSH parses signature sections and ignores
/// them: nothing checks KRL signatures (PROTOCOL.krl suggests SSHSIG
/// signatures of the whole file instead), so neither does this.
pub fn krl_parse(bytes: &[u8]) -> Result<Krl, String> {
    if !is_krl(bytes) {
        return Err(err("not a KRL (bad magic)"));
    }
    let mut r = Reader::new(&bytes[KRL_MAGIC.len()..]);
    let hdr = || err("bad KRL header");
    let format = r.u32().ok_or_else(hdr)?;
    if format != KRL_FORMAT_VERSION {
        return Err(format!("unsupported KRL format version {format}"));
    }
    let version = r.u64().ok_or_else(hdr)?;
    let generated_date = r.u64().ok_or_else(hdr)?;
    let flags = r.u64().ok_or_else(hdr)?;
    r.string().ok_or_else(hdr)?; // reserved
    let comment = r.cstring().ok_or_else(hdr)?;
    let mut krl = Krl {
        version,
        generated_date,
        flags,
        comment: String::from_utf8_lossy(comment).into_owned(),
        explicit: BTreeSet::new(),
        sha1s: BTreeSet::new(),
        sha256s: BTreeSet::new(),
        certs: Vec::new(),
        sections: BTreeSet::new(),
    };

    while !r.is_empty() {
        let short = || err("truncated KRL section");
        let typ = r.u8().ok_or_else(short)?;
        let sect = r.string().ok_or_else(short)?;
        let mut s = Reader::new(sect);
        krl.sections.insert(typ);
        match typ {
            SECTION_CERTIFICATES => parse_certs(&mut s, &mut krl)?,
            SECTION_EXPLICIT_KEY => blob_section(&mut s, &mut krl.explicit, 0)?,
            SECTION_FINGERPRINT_SHA1 => blob_section(&mut s, &mut krl.sha1s, 20)?,
            SECTION_FINGERPRINT_SHA256 => blob_section(&mut s, &mut krl.sha256s, 32)?,
            SECTION_EXTENSION => extension(&mut s, "KRL")?,
            SECTION_SIGNATURE => {
                // signature_key was read as the section; skip the signature.
                r.string().ok_or_else(short)?;
                continue;
            }
            t => return Err(format!("unsupported KRL section {t}")),
        }
        if !s.is_empty() {
            return Err(err("KRL section contains unparsed data"));
        }
    }
    Ok(krl)
}

fn blob_section(
    s: &mut Reader,
    target: &mut BTreeSet<Vec<u8>>,
    expected_len: usize,
) -> Result<(), String> {
    while !s.is_empty() {
        let b = s.string().ok_or_else(|| err("bad KRL key section"))?;
        if expected_len != 0 && b.len() != expected_len {
            return Err(err("bad KRL fingerprint length"));
        }
        target.insert(b.to_vec());
    }
    Ok(())
}

/// Extensions: none are defined, so a critical one fails the KRL.
fn extension(s: &mut Reader, what: &str) -> Result<(), String> {
    let bad = || format!("{what} has an invalid extension section");
    let name = s.cstring().ok_or_else(bad)?;
    let critical = s.u8().ok_or_else(bad)?;
    s.string().ok_or_else(bad)?;
    if !s.is_empty() {
        return Err(bad());
    }
    if critical != 0 {
        return Err(format!(
            "{what} has an unsupported critical extension \"{}\"",
            String::from_utf8_lossy(name)
        ));
    }
    Ok(())
}

fn parse_certs(s: &mut Reader, krl: &mut Krl) -> Result<(), String> {
    let hdr = || err("bad KRL certificate section");
    let ca_blob = s.string().ok_or_else(hdr)?;
    s.string().ok_or_else(hdr)?; // reserved
                                 // An empty CA means the section applies to certificates from any CA.
    let ca = if ca_blob.is_empty() {
        None
    } else {
        Some(parse_key(ca_blob, true).map_err(|e| format!("bad KRL CA key: {e}"))?)
    };
    while !s.is_empty() {
        let typ = s.u8().ok_or_else(hdr)?;
        let sub = s.string().ok_or_else(hdr)?;
        let mut ss = Reader::new(sub);
        krl.sections.insert(typ);
        match typ {
            CERT_SERIAL_LIST => {
                while !ss.is_empty() {
                    let serial = ss.u64().ok_or_else(hdr)?;
                    krl.revoke_range(ca.as_ref(), serial, serial)?;
                }
            }
            CERT_SERIAL_RANGE => {
                let lo = ss.u64().ok_or_else(hdr)?;
                let hi = ss.u64().ok_or_else(hdr)?;
                krl.revoke_range(ca.as_ref(), lo, hi)?;
            }
            CERT_SERIAL_BITMAP => {
                let offset = ss.u64().ok_or_else(hdr)?;
                let bits = ss.mpint().ok_or_else(hdr)?;
                // Bit N of the big-endian number revokes serial offset + N.
                // mpint() strips leading zero bytes, so the first byte (if
                // any) holds the top set bit.
                let nbits = match bits.first() {
                    Some(b) => bits.len() * 8 - b.leading_zeros() as usize,
                    None => 0,
                };
                for n in 0..nbits as u64 {
                    if n > 0 && offset.wrapping_add(n) == 0 {
                        return Err(err("KRL serial bitmap wraps"));
                    }
                    let byte = bits[bits.len() - 1 - (n / 8) as usize];
                    if byte >> (n % 8) & 1 == 1 {
                        let serial = offset.wrapping_add(n);
                        krl.revoke_range(ca.as_ref(), serial, serial)?;
                    }
                }
            }
            CERT_KEY_ID => {
                while !ss.is_empty() {
                    let id = ss.cstring().ok_or_else(hdr)?;
                    krl.certs_for(ca.as_ref()).key_ids.insert(id.to_vec());
                }
            }
            CERT_EXTENSION => extension(&mut ss, "KRL certificate section")?,
            t => return Err(format!("unsupported KRL certificate section {t}")),
        }
        if !ss.is_empty() {
            return Err(err("KRL certificate section contains unparsed data"));
        }
    }
    Ok(())
}

/// is_cert_revoked(): by key ID first; serial 0 (the CA's default) is never
/// matched by serial.
fn cert_revoked(cert: &CertInfo, rc: &CaRevocations) -> bool {
    if rc.key_ids.contains(&cert.key_id_raw) {
        return true;
    }
    cert.serial != 0
        && rc
            .serials
            .iter()
            .any(|&(lo, hi)| lo <= cert.serial && cert.serial <= hi)
}

/// is_key_revoked(): fingerprints and explicit keys over the plain key,
/// then certificate sections for the issuing CA and for any CA.
fn key_revoked(krl: &Krl, k: &Key) -> bool {
    if krl.sha1s.contains(sha1(&k.plain).as_slice())
        || krl.sha256s.contains(sha256(&k.plain).as_slice())
        || krl.explicit.contains(&k.plain)
    {
        return true;
    }
    let Some(cert) = &k.cert else {
        return false;
    };
    let ca = parse_key(&cert.ca_key_blob, false).ok();
    let for_ca = krl.certs.iter().find(|rc| match (&rc.ca, &ca) {
        (Some(a), Some(b)) => key_equal(a, b),
        _ => false,
    });
    if for_ca.is_some_and(|rc| cert_revoked(cert, rc)) {
        return true;
    }
    krl.certs
        .iter()
        .find(|rc| rc.ca.is_none())
        .is_some_and(|rc| cert_revoked(cert, rc))
}

fn key_for(key_type: &str, key_blob: &[u8], cert: Option<&CertInfo>) -> Option<Key> {
    let mut k = parse_key(key_blob, true).ok()?;
    if KeyType::from_name(key_type.as_bytes()).is_none_or(|t| !t.same_as(k.ktype)) {
        return None;
    }
    if let Some(c) = cert {
        k.cert = Some(c.clone());
        k.plain = c.key_blob.clone();
    }
    Some(k)
}

/// ssh_krl_check_key(): the key itself, then for a certificate its CA key.
/// `key_blob` may be a plain key or a certificate; `cert` overrides the
/// certificate fields read from it. A blob that does not parse counts as
/// revoked, since ssh would refuse it anyway.
pub fn krl_revokes(krl: &Krl, key_type: &str, key_blob: &[u8], cert: Option<&CertInfo>) -> bool {
    let Some(k) = key_for(key_type, key_blob, cert) else {
        return true;
    };
    if key_revoked(krl, &k) {
        return true;
    }
    if let Some(c) = &k.cert {
        match parse_key(&c.ca_key_blob, false) {
            Ok(ca) => return key_revoked(krl, &ca),
            Err(_) => return true,
        }
    }
    false
}

/// sshkey_in_file(key, file, strict_type = 0, check_ca = 1): whether a
/// plain list of public keys (one `type base64 comment` per line) holds
/// the key or, for a certificate, its CA. Like ssh, any unreadable line
/// is an error (RSA keys under 1024 bits are skipped), so callers fail
/// closed.
pub fn revoked_in_keylist(text: &str, key_type: &str, key_blob: &[u8]) -> Result<bool, String> {
    let k = key_for(key_type, key_blob, None).ok_or_else(|| err("invalid key"))?;
    let ca = k
        .cert
        .as_ref()
        .and_then(|c| parse_key(&c.ca_key_blob, false).ok());
    let body = text.strip_suffix('\n').unwrap_or(text);
    for (i, line) in body.split('\n').enumerate() {
        if text.is_empty() {
            break;
        }
        let cp = line.trim_start_matches([' ', '\t']);
        if cp.is_empty() || cp.starts_with('#') {
            continue;
        }
        match read_pubkey(cp) {
            Ok(pubk) => {
                if key_equal_public(&k, &pubk)
                    || ca.as_ref().is_some_and(|ca| key_equal_public(ca, &pubk))
                {
                    return Ok(true);
                }
            }
            Err(KeyError::Length) => continue,
            Err(KeyError::Format(e)) => return Err(format!("line {}: {}", i + 1, e)),
        }
    }
    Ok(false)
}

/// sshkey_read() on a `type base64 [comment]` line.
fn read_pubkey(cp: &str) -> Result<Key, KeyError> {
    let blank = |c: char| c == ' ' || c == '\t';
    let f = |s: &str| KeyError::Format(s.to_string());
    let tend = cp.find(blank).ok_or_else(|| f("invalid format"))?;
    let t = KeyType::from_name(&cp.as_bytes()[..tend]).ok_or_else(|| f("unknown key type"))?;
    let rest = cp[tend..].trim_start_matches([' ', '\t']);
    if rest.is_empty() {
        return Err(f("invalid format"));
    }
    let bend = rest.find(blank).unwrap_or(rest.len());
    let blob = b64_decode(&rest[..bend]).ok_or_else(|| f("invalid base64"))?;
    let k = parse_key(&blob, true)?;
    if !k.ktype.same_as(t) {
        return Err(f("key type mismatch"));
    }
    Ok(k)
}

/// sshkey_check_revoked(): what RevokedHostKeys does with a file. A KRL
/// when it has the magic, a plain key list otherwise. Errors mean the
/// file could not be used; ssh then refuses the host key.
pub fn check_revoked_file(bytes: &[u8], key_type: &str, key_blob: &[u8]) -> Result<bool, String> {
    if is_krl(bytes) {
        let krl = krl_parse(bytes)?;
        return Ok(krl_revokes(&krl, key_type, key_blob, None));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| err("revoked keys file is not text"))?;
    revoked_in_keylist(text, key_type, key_blob)
}
