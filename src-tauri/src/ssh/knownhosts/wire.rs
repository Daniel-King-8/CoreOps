//! SSH wire format and public key blobs, read the way OpenSSH's sshkey.c and
//! sshbuf reads them, without any crypto library: keys are compared as the
//! blobs OpenSSH would write back out.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Largest bignum sshbuf accepts (SSHBUF_MAX_BIGNUM, 16384 bits).
const MAX_BIGNUM: usize = 16384 / 8;
/// RSA keys under this size are refused (SSH_RSA_MINIMUM_MODULUS_SIZE).
const RSA_MIN_BITS: u32 = 1024;
/// SSHKEY_CERT_MAX_PRINCIPALS.
const CERT_MAX_PRINCIPALS: usize = 256;
/// MLDSA44 public key plus an Ed25519 public key (MLDSA44_ED25519_PK_SZ).
const MLDSA44_ED25519_PK: usize = 1312 + 32;

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Some(a)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            u64::from_be_bytes(a)
        })
    }

    pub(crate) fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// sshbuf_get_cstring: a NUL is allowed only as the last byte. Returns the
    /// text up to (not including) that NUL, as C code would see it.
    pub(crate) fn cstring(&mut self) -> Option<&'a [u8]> {
        let save = self.buf;
        let s = self.string()?;
        if let Some(z) = s.iter().position(|&c| c == 0) {
            if z + 1 < s.len() {
                self.buf = save;
                return None;
            }
            return Some(&s[..z]);
        }
        Some(s)
    }

    /// sshbuf_get_bignum2_bytes_direct: refuses negative and overlong values
    /// and strips leading zero bytes.
    pub(crate) fn mpint(&mut self) -> Option<&'a [u8]> {
        let save = self.buf;
        let mut d = self.string()?;
        let bad = (!d.is_empty() && d[0] & 0x80 != 0)
            || d.len() > MAX_BIGNUM + 1
            || (d.len() == MAX_BIGNUM + 1 && d[0] != 0);
        if bad {
            self.buf = save;
            return None;
        }
        while let Some((&0, r)) = d.split_first() {
            d = r;
        }
        Some(d)
    }
}

pub(crate) fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Writes a positive bignum the way sshbuf_put_bignum2_bytes does.
fn put_mpint(out: &mut Vec<u8>, v: &[u8]) {
    let mut v = v;
    while let Some((&0, r)) = v.split_first() {
        v = r;
    }
    let pad = !v.is_empty() && v[0] & 0x80 != 0;
    out.extend_from_slice(&((v.len() + pad as usize) as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(v);
}

/// Base64 as OpenSSH's b64_pton reads it: whitespace anywhere is skipped,
/// padding is required and unused trailing bits must be zero.
pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s
        .bytes()
        .filter(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .collect();
    STANDARD.decode(clean).ok()
}

pub(crate) fn b64_encode(b: &[u8]) -> String {
    STANDARD.encode(b)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    fn ident(self) -> &'static str {
        match self {
            Curve::P256 => "nistp256",
            Curve::P384 => "nistp384",
            Curve::P521 => "nistp521",
        }
    }
    fn bits(self) -> u32 {
        match self {
            Curve::P256 => 256,
            Curve::P384 => 384,
            Curve::P521 => 521,
        }
    }
    fn field_bytes(self) -> usize {
        (self.bits() as usize).div_ceil(8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Base {
    Rsa,
    Ecdsa(Curve),
    Ed25519,
    EcdsaSk,
    Ed25519Sk,
    Mldsa44Ed25519,
}

impl Base {
    /// The name OpenSSH writes for a plain key of this type
    /// (sshkey_ssh_name_plain: the first entry in keyimpls for the type).
    pub(crate) fn plain_name(self) -> &'static str {
        match self {
            Base::Rsa => "ssh-rsa",
            Base::Ecdsa(Curve::P256) => "ecdsa-sha2-nistp256",
            Base::Ecdsa(Curve::P384) => "ecdsa-sha2-nistp384",
            Base::Ecdsa(Curve::P521) => "ecdsa-sha2-nistp521",
            Base::Ed25519 => "ssh-ed25519",
            Base::EcdsaSk => "sk-ecdsa-sha2-nistp256@openssh.com",
            Base::Ed25519Sk => "sk-ssh-ed25519@openssh.com",
            Base::Mldsa44Ed25519 => "ssh-mldsa44-ed25519",
        }
    }

    fn cert_name(self) -> &'static str {
        match self {
            Base::Rsa => "ssh-rsa-cert-v01@openssh.com",
            Base::Ecdsa(Curve::P256) => "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            Base::Ecdsa(Curve::P384) => "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            Base::Ecdsa(Curve::P521) => "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            Base::Ed25519 => "ssh-ed25519-cert-v01@openssh.com",
            Base::EcdsaSk => "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            Base::Ed25519Sk => "sk-ssh-ed25519-cert-v01@openssh.com",
            Base::Mldsa44Ed25519 => "ssh-mldsa44-ed25519-cert",
        }
    }

    /// sshkey_type()'s short name, used in randomart titles.
    fn short_name(self) -> &'static str {
        match self {
            Base::Rsa => "RSA",
            Base::Ecdsa(_) => "ECDSA",
            Base::Ed25519 => "ED25519",
            Base::EcdsaSk => "ECDSA-SK",
            Base::Ed25519Sk => "ED25519-SK",
            Base::Mldsa44Ed25519 => "MLDSA44-ED25519",
        }
    }
}

/// One key type name OpenSSH knows, as in sshkey.c's keyimpls table
/// (signature-only aliases such as rsa-sha2-256 included, since
/// peek_type_nid and sshkey_type_from_name accept them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyType {
    pub(crate) base: Base,
    pub(crate) cert: bool,
}

impl KeyType {
    pub(crate) fn from_name(name: &[u8]) -> Option<KeyType> {
        use Base::*;
        use Curve::*;
        let (base, cert) = match name {
            b"ssh-ed25519" => (Ed25519, false),
            b"ssh-ed25519-cert-v01@openssh.com" => (Ed25519, true),
            b"sk-ssh-ed25519@openssh.com" => (Ed25519Sk, false),
            b"sk-ssh-ed25519-cert-v01@openssh.com" => (Ed25519Sk, true),
            b"ssh-mldsa44-ed25519" => (Mldsa44Ed25519, false),
            b"ssh-mldsa44-ed25519-cert" => (Mldsa44Ed25519, true),
            b"ecdsa-sha2-nistp256" => (Ecdsa(P256), false),
            b"ecdsa-sha2-nistp256-cert-v01@openssh.com" => (Ecdsa(P256), true),
            b"ecdsa-sha2-nistp384" => (Ecdsa(P384), false),
            b"ecdsa-sha2-nistp384-cert-v01@openssh.com" => (Ecdsa(P384), true),
            b"ecdsa-sha2-nistp521" => (Ecdsa(P521), false),
            b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => (Ecdsa(P521), true),
            b"sk-ecdsa-sha2-nistp256@openssh.com" => (EcdsaSk, false),
            b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => (EcdsaSk, true),
            b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com" => (EcdsaSk, false),
            b"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => (EcdsaSk, true),
            b"ssh-rsa" | b"rsa-sha2-256" | b"rsa-sha2-512" => (Rsa, false),
            b"ssh-rsa-cert-v01@openssh.com"
            | b"rsa-sha2-256-cert-v01@openssh.com"
            | b"rsa-sha2-512-cert-v01@openssh.com" => (Rsa, true),
            _ => return None,
        };
        Some(KeyType { base, cert })
    }

    /// sshkey_ssh_name(): what OpenSSH writes in front of the base64.
    pub(crate) fn name(self) -> &'static str {
        if self.cert {
            self.base.cert_name()
        } else {
            self.base.plain_name()
        }
    }

    /// sshkey_type(): "ED25519", "RSA-CERT" and so on.
    pub(crate) fn short_name(self) -> String {
        let s = self.base.short_name();
        if self.cert {
            format!("{s}-CERT")
        } else {
            s.to_string()
        }
    }

    /// The type check sshkey_read does between the name at the start of a
    /// line and the name inside the blob: same key type and, for ECDSA
    /// variants, the same curve. With curves folded into Base this is plain
    /// equality.
    pub(crate) fn same_as(self, other: KeyType) -> bool {
        self == other
    }
}

/// A certificate's fields, as cert_parse reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    /// The plain key type the certificate certifies, e.g. "ssh-ed25519".
    pub key_type: String,
    /// That plain public key's blob (what fingerprints are taken over).
    pub key_blob: Vec<u8>,
    pub serial: u64,
    /// 1 = user, 2 = host.
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub ca_key_type: String,
    pub ca_key_blob: Vec<u8>,
    // Key IDs compare as C strings in krl.c, so keep the exact bytes.
    pub(crate) key_id_raw: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) ktype: KeyType,
    /// What sshkey_putb would write: re-serialised for plain keys, the
    /// original bytes for certificates.
    pub(crate) blob: Vec<u8>,
    /// The plain public key blob (certificate data dropped).
    pub(crate) plain: Vec<u8>,
    pub(crate) bits: u32,
    pub(crate) cert: Option<CertInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// SSH_ERR_KEY_LENGTH: an RSA key under 1024 bits. Some callers skip
    /// these silently rather than failing.
    Length,
    Format(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Length => write!(f, "RSA key is shorter than {RSA_MIN_BITS} bits"),
            KeyError::Format(s) => f.write_str(s),
        }
    }
}

fn bad(s: &str) -> KeyError {
    KeyError::Format(s.to_string())
}

fn bit_len(v: &[u8]) -> u32 {
    match v.first() {
        None => 0,
        Some(&b) => (v.len() as u32 - 1) * 8 + (8 - b.leading_zeros()),
    }
}

/// Reads the public fields of a key of type `base`, returning their
/// re-serialised form and the key size in bits.
fn public_fields(base: Base, r: &mut Reader) -> Result<(Vec<u8>, u32), KeyError> {
    let mut out = Vec::new();
    let ecdsa = |curve: Curve, r: &mut Reader, out: &mut Vec<u8>| -> Result<(), KeyError> {
        let ident = r.cstring().ok_or_else(|| bad("bad ECDSA curve name"))?;
        if ident != curve.ident().as_bytes() {
            return Err(bad("ECDSA curve does not match key type"));
        }
        let q = r.string().ok_or_else(|| bad("bad ECDSA point"))?;
        // OpenSSL decodes the point and checks it is on the curve; without
        // curve arithmetic only its encoding can be checked here.
        let fb = curve.field_bytes();
        let ok = match q.first() {
            Some(4) => q.len() == 1 + 2 * fb,
            Some(2) | Some(3) => q.len() == 1 + fb,
            _ => false,
        };
        if !ok {
            return Err(bad("bad ECDSA point"));
        }
        put_string(out, curve.ident().as_bytes());
        put_string(out, q);
        Ok(())
    };
    let bits = match base {
        Base::Rsa => {
            let e = r.mpint().ok_or_else(|| bad("bad RSA exponent"))?;
            let n = r.mpint().ok_or_else(|| bad("bad RSA modulus"))?;
            put_mpint(&mut out, e);
            put_mpint(&mut out, n);
            let bits = bit_len(n);
            if bits < RSA_MIN_BITS {
                return Err(KeyError::Length);
            }
            bits
        }
        Base::Ecdsa(c) => {
            ecdsa(c, r, &mut out)?;
            c.bits()
        }
        Base::EcdsaSk => {
            ecdsa(Curve::P256, r, &mut out)?;
            let app = r
                .cstring()
                .ok_or_else(|| bad("bad security key application"))?;
            put_string(&mut out, app);
            256
        }
        Base::Ed25519 | Base::Ed25519Sk => {
            let pk = r.string().ok_or_else(|| bad("bad Ed25519 key"))?;
            if pk.len() != 32 {
                return Err(bad("bad Ed25519 key length"));
            }
            put_string(&mut out, pk);
            if base == Base::Ed25519Sk {
                let app = r
                    .cstring()
                    .ok_or_else(|| bad("bad security key application"))?;
                put_string(&mut out, app);
            }
            256
        }
        Base::Mldsa44Ed25519 => {
            let pk = r.string().ok_or_else(|| bad("bad ML-DSA key"))?;
            if pk.len() != MLDSA44_ED25519_PK {
                return Err(bad("bad ML-DSA key length"));
            }
            put_string(&mut out, pk);
            512
        }
    };
    Ok((out, bits))
}

/// sshkey_from_blob: parses a whole key blob and refuses trailing data.
///
/// Not checked, because it needs the curve or signature maths OpenSSL does:
/// that an ECDSA point lies on its curve, and a certificate's signature.
pub(crate) fn parse_key(blob: &[u8], allow_cert: bool) -> Result<Key, KeyError> {
    let mut r = Reader::new(blob);
    let name = r.cstring().ok_or_else(|| bad("bad key type"))?;
    let ktype = KeyType::from_name(name).ok_or_else(|| {
        KeyError::Format(format!(
            "unknown key type {}",
            String::from_utf8_lossy(name)
        ))
    })?;
    if ktype.cert && !allow_cert {
        return Err(bad("certificate where a plain key is required"));
    }
    if ktype.cert && r.string().is_none() {
        return Err(bad("bad certificate nonce"));
    }
    let (fields, bits) = public_fields(ktype.base, &mut r)?;
    let mut plain = Vec::new();
    put_string(&mut plain, ktype.base.plain_name().as_bytes());
    plain.extend_from_slice(&fields);

    let cert = if ktype.cert {
        Some(cert_fields(&mut r, ktype, &plain)?)
    } else {
        None
    };
    if !r.is_empty() {
        return Err(bad("trailing data after key"));
    }
    let blob = if ktype.cert {
        blob.to_vec()
    } else {
        plain.clone()
    };
    Ok(Key {
        ktype,
        blob,
        plain,
        bits,
        cert,
    })
}

fn cert_fields(r: &mut Reader, ktype: KeyType, plain: &[u8]) -> Result<CertInfo, KeyError> {
    let f = || bad("bad certificate");
    let serial = r.u64().ok_or_else(f)?;
    let cert_type = r.u32().ok_or_else(f)?;
    let key_id = r.cstring().ok_or_else(f)?.to_vec();
    let principals_buf = r.string().ok_or_else(f)?;
    let valid_after = r.u64().ok_or_else(f)?;
    let valid_before = r.u64().ok_or_else(f)?;
    let crit = r.string().ok_or_else(f)?;
    let exts = r.string().ok_or_else(f)?;
    r.string().ok_or_else(f)?; // reserved
    let ca_blob = r.string().ok_or_else(f)?;
    let sig = r.string().ok_or_else(f)?;
    // sshkey_get_sigtype: the signature must at least start with its type.
    if Reader::new(sig).cstring().is_none() {
        return Err(f());
    }
    let ca = parse_key(ca_blob, false).map_err(|_| bad("bad certificate CA key"))?;
    if cert_type != 1 && cert_type != 2 {
        return Err(bad("unknown certificate type"));
    }
    let mut principals = Vec::new();
    let mut pr = Reader::new(principals_buf);
    while !pr.is_empty() {
        if principals.len() >= CERT_MAX_PRINCIPALS {
            return Err(f());
        }
        let p = pr.cstring().ok_or_else(f)?;
        principals.push(String::from_utf8_lossy(p).into_owned());
    }
    for section in [crit, exts] {
        let mut s = Reader::new(section);
        while !s.is_empty() {
            if s.string().is_none() || s.string().is_none() {
                return Err(f());
            }
        }
    }
    Ok(CertInfo {
        key_type: ktype.base.plain_name().to_string(),
        key_blob: plain.to_vec(),
        serial,
        cert_type,
        key_id: String::from_utf8_lossy(&key_id).into_owned(),
        principals,
        valid_after,
        valid_before,
        ca_key_type: ca.ktype.name().to_string(),
        ca_key_blob: ca.blob,
        key_id_raw: key_id,
    })
}

/// sshkey_equal: same certificate-ness, the same certificate bytes for
/// certificates, and the same public key.
pub(crate) fn key_equal(a: &Key, b: &Key) -> bool {
    if a.ktype.cert != b.ktype.cert {
        return false;
    }
    if a.ktype.cert && a.blob != b.blob {
        return false;
    }
    a.plain == b.plain
}

/// sshkey_equal_public: the public keys match, certificate or not.
pub(crate) fn key_equal_public(a: &Key, b: &Key) -> bool {
    a.plain == b.plain
}
