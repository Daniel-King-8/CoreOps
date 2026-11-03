//! Key fingerprints and VisualHostKey randomart, as sshkey_fingerprint()
//! prints them.

use super::digest::{md5, sha256};
use super::wire::{b64_encode, parse_key, KeyType};

enum Alg {
    Md5,
    Sha256,
}

impl Alg {
    // ssh-keygen only takes md5 and sha256 for -E; anything else is the
    // default, SHA256.
    fn from(hash: &str) -> Alg {
        if hash.eq_ignore_ascii_case("md5") {
            Alg::Md5
        } else {
            Alg::Sha256
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Alg::Md5 => "MD5",
            Alg::Sha256 => "SHA256",
        }
    }
    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Alg::Md5 => md5(data).to_vec(),
            Alg::Sha256 => sha256(data).to_vec(),
        }
    }
}

/// Fingerprints are taken over the plain key, so a certificate shows its
/// key's fingerprint (to_blob with force_plain). Blobs that do not parse
/// are hashed as given.
fn plain_blob(key_blob: &[u8]) -> Vec<u8> {
    match parse_key(key_blob, true) {
        Ok(k) => k.plain,
        Err(_) => key_blob.to_vec(),
    }
}

/// `SHA256:<base64 without padding>` or `MD5:<hex with colons>`, as
/// `ssh-keygen -l -E sha256|md5` prints it.
pub fn fingerprint(key_blob: &[u8], hash: &str) -> String {
    let alg = Alg::from(hash);
    let d = alg.digest(&plain_blob(key_blob));
    match alg {
        Alg::Md5 => {
            let hex: Vec<String> = d.iter().map(|b| format!("{b:02x}")).collect();
            format!("MD5:{}", hex.join(":"))
        }
        Alg::Sha256 => {
            let b = b64_encode(&d);
            format!("SHA256:{}", b.trim_end_matches('='))
        }
    }
}

const FLDBASE: usize = 8;
const FLDSIZE_Y: usize = FLDBASE + 1;
const FLDSIZE_X: usize = FLDBASE * 2 + 1;

/// The randomart picture (fingerprint_randomart in sshkey.c), lines joined
/// by '\n' with no trailing newline. `key_type` and `bits` are used for the
/// title when the blob cannot tell them (they normally come from the blob).
pub fn randomart(key_type: &str, bits: Option<u32>, key_blob: &[u8], hash: &str) -> String {
    let alg = Alg::from(hash);
    let parsed = parse_key(key_blob, true).ok();
    let blob = parsed
        .as_ref()
        .map(|k| k.plain.clone())
        .unwrap_or_else(|| key_blob.to_vec());
    let dgst = alg.digest(&blob);

    let short = match &parsed {
        Some(k) => k.ktype.short_name(),
        None => KeyType::from_name(key_type.as_bytes())
            .map(|t| t.short_name())
            .unwrap_or_else(|| key_type.to_string()),
    };
    let size = bits.or(parsed.as_ref().map(|k| k.bits)).unwrap_or(0);

    let aug = b" .o+=*BOX@%&#/^SE";
    let len = aug.len() - 1;
    let mut field = [[0u8; FLDSIZE_Y]; FLDSIZE_X];
    let mut x = (FLDSIZE_X / 2) as isize;
    let mut y = (FLDSIZE_Y / 2) as isize;
    for &byte in &dgst {
        let mut input = byte;
        for _ in 0..4 {
            x += if input & 1 != 0 { 1 } else { -1 };
            y += if input & 2 != 0 { 1 } else { -1 };
            x = x.clamp(0, FLDSIZE_X as isize - 1);
            y = y.clamp(0, FLDSIZE_Y as isize - 1);
            let cell = &mut field[x as usize][y as usize];
            if (*cell as usize) < len - 2 {
                *cell += 1;
            }
            input >>= 2;
        }
    }
    field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = (len - 1) as u8;
    field[x as usize][y as usize] = len as u8;

    // snprintf into a FLDSIZE_X buffer: at most 16 characters survive, and
    // the shorter "[TYPE]" form is only tried when the full one would have
    // needed more than the whole buffer.
    let fit = |s: String| -> String { s.chars().take(FLDSIZE_X - 1).collect() };
    let full = format!("[{short} {size}]");
    let title = if full.len() > FLDSIZE_X {
        fit(format!("[{short}]"))
    } else {
        fit(full)
    };
    let hashid = fit(format!("[{}]", alg.name()));

    let border = |label: &str| -> String {
        let mut s = String::from("+");
        let pad = (FLDSIZE_X - label.len()) / 2;
        s.push_str(&"-".repeat(pad));
        s.push_str(label);
        s.push_str(&"-".repeat(FLDSIZE_X - pad - label.len()));
        s.push('+');
        s
    };

    let mut out = border(&title);
    out.push('\n');
    for yy in 0..FLDSIZE_Y {
        out.push('|');
        for col in field.iter() {
            out.push(aug[(col[yy] as usize).min(len)] as char);
        }
        out.push_str("|\n");
    }
    out.push_str(&border(&hashid));
    out
}
