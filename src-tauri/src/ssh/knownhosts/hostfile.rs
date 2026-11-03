//! known_hosts files: reading, matching, checking a host key, writing and
//! replacing entries. A port of OpenSSH's hostfile.c and the host key part
//! of sshconnect.c.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::digest::hmac_sha1;
use super::wire::{
    b64_decode, b64_encode, key_equal, key_equal_public, parse_key, Key, KeyError, KeyType,
};

const HASH_MAGIC: &str = "|1|";
const CA_MARKER: &str = "@cert-authority";
const REVOKE_MARKER: &str = "@revoked";
/// match_pattern_list copies each subpattern into a 1024-byte buffer and
/// gives up (no match) on anything that does not fit.
const MAX_SUBPATTERN: usize = 1023;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    None,
    CertAuthority,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hosts {
    /// Comma-separated patterns as written, `!` kept on negated ones.
    Patterns(Vec<String>),
    /// `|1|salt|hash`. `hash` is empty when the text after the salt is not
    /// a well-formed hash; such an entry can never match, as in OpenSSH.
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub marker: Marker,
    pub hosts: Hosts,
    /// The key type as written on the line.
    pub key_type: String,
    /// The decoded key blob as written on the line.
    pub key_blob: Vec<u8>,
    pub comment: Option<String>,
    pub file: String,
    pub line: usize,
    pub(crate) key: Key,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineErrorKind {
    /// An unknown marker, a second marker, or one not followed by a blank.
    BadMarker,
    /// The line ends before the key.
    Truncated,
    /// A `|1|` name whose salt does not decode to 20 bytes.
    BadHash,
    /// The old SSH-1 RSA format (`host bits exponent modulus`), which
    /// OpenSSH no longer reads.
    UnsupportedRsa1,
    UnknownKeyType(String),
    /// An RSA key under 1024 bits, which OpenSSH refuses.
    KeyTooShort,
    BadKey(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineError {
    pub file: String,
    pub line: usize,
    pub kind: LineErrorKind,
    pub text: String,
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match &self.kind {
            LineErrorKind::BadMarker => "invalid marker".to_string(),
            LineErrorKind::Truncated => "truncated line".to_string(),
            LineErrorKind::BadHash => "bad host hash".to_string(),
            LineErrorKind::UnsupportedRsa1 => "SSH-1 RSA key, no longer supported".to_string(),
            LineErrorKind::UnknownKeyType(t) => format!("unknown key type \"{t}\""),
            LineErrorKind::KeyTooShort => "RSA key shorter than 1024 bits".to_string(),
            LineErrorKind::BadKey(s) => format!("invalid key: {s}"),
        };
        write!(f, "{}:{}: {}", self.file, self.line, what)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub entries: Vec<Entry>,
    pub errors: Vec<LineError>,
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn skip_blanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// Splits a file into lines the way getline() does: a final line without a
/// newline still counts, a trailing newline does not add an empty line.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let empty = text.is_empty();
    body.split('\n').filter(move |_| !empty)
}

/// Lines as they are parsed: a UTF-8 BOM at the start of the file and a
/// CR before the newline are dropped. OpenSSH keeps both, which only
/// changes things for files saved by Windows editors: a BOM there makes the
/// first line's host never match, and a CR is mostly ignored already (its
/// base64 decoder skips white space).
fn clean(i: usize, raw: &str) -> &str {
    let l = if i == 0 {
        raw.strip_prefix('\u{feff}').unwrap_or(raw)
    } else {
        raw
    };
    l.strip_suffix('\r').unwrap_or(l)
}

/// check_markers(): note the terminating blank is found with strchr(' ')
/// first and strchr('\t') only when the line has no space at all, so a
/// marker followed by a tab is only accepted on a line without spaces.
fn check_markers(s: &str) -> Result<(Marker, &str), ()> {
    let mut cp = s;
    let mut ret = Marker::None;
    while cp.starts_with('@') {
        if ret != Marker::None {
            return Err(());
        }
        let sp = cp.find(' ').or_else(|| cp.find('\t')).ok_or(())?;
        if sp <= 1 || sp >= 32 {
            return Err(());
        }
        ret = match &cp[..sp] {
            CA_MARKER => Marker::CertAuthority,
            REVOKE_MARKER => Marker::Revoked,
            _ => return Err(()),
        };
        cp = skip_blanks(&cp[sp..]);
    }
    Ok((ret, cp))
}

/// The comma-separated subpatterns match_pattern_list walks: a comma at the
/// very end does not start another (empty) subpattern.
fn split_patterns(s: &str) -> Vec<String> {
    let body = s.strip_suffix(',').unwrap_or(s);
    if s.is_empty() {
        return Vec::new();
    }
    body.split(',').map(str::to_string).collect()
}

/// extract_salt(): `|1|` then base64 of exactly 20 bytes up to the next `|`.
fn parse_hashed(s: &str) -> Option<Hosts> {
    let rest = s.strip_prefix(HASH_MAGIC)?;
    let p = rest.find('|')?;
    let b64salt = &rest[..p];
    if b64salt.is_empty() || b64salt.len() > 1024 {
        return None;
    }
    let salt = b64_decode(b64salt)?;
    if salt.len() != 20 {
        return None;
    }
    // host_hash() rebuilds the whole string and compares it, so the hash
    // must be exactly the base64 OpenSSH would print.
    let hash_text = &rest[p + 1..];
    let hash = match b64_decode(hash_text) {
        Some(h) if h.len() == 20 && b64_encode(&h) == hash_text => h,
        _ => Vec::new(),
    };
    Some(Hosts::Hashed { salt, hash })
}

/// Reads a known_hosts file. Lines that OpenSSH would skip as invalid are
/// reported in `errors` and left out of `entries`.
pub fn parse(text: &str, file: &str) -> Parsed {
    let mut out = Parsed::default();
    for (i, raw) in lines(text).enumerate() {
        let lineno = i + 1;
        let line = clean(i, raw);
        match parse_line(line) {
            Ok(None) => {}
            Ok(Some(mut e)) => {
                e.file = file.to_string();
                e.line = lineno;
                out.entries.push(e);
            }
            Err(kind) => out.errors.push(LineError {
                file: file.to_string(),
                line: lineno,
                kind,
                text: raw.to_string(),
            }),
        }
    }
    out
}

/// One line, as hostkeys_foreach_file reads it with the key parsed.
fn parse_line(line: &str) -> Result<Option<Entry>, LineErrorKind> {
    let cp = skip_blanks(line);
    if cp.is_empty() || cp.starts_with('#') {
        return Ok(None);
    }
    let (marker, cp) = check_markers(cp).map_err(|_| LineErrorKind::BadMarker)?;
    let end = cp
        .bytes()
        .position(is_blank)
        .ok_or(LineErrorKind::Truncated)?;
    let host_text = &cp[..end];
    let hosts = if host_text.starts_with('|') {
        parse_hashed(host_text).ok_or(LineErrorKind::BadHash)?
    } else {
        Hosts::Patterns(split_patterns(host_text))
    };
    let cp = skip_blanks(&cp[end..]);
    if cp.is_empty() || cp.starts_with('#') {
        return Err(LineErrorKind::Truncated);
    }

    // sshkey_read(): type, blanks, base64 blob, then the comment.
    let tend = cp.bytes().position(is_blank).ok_or_else(|| {
        if is_rsa1_bits(cp) {
            LineErrorKind::UnsupportedRsa1
        } else {
            LineErrorKind::Truncated
        }
    })?;
    let type_text = &cp[..tend];
    let Some(text_type) = KeyType::from_name(type_text.as_bytes()) else {
        return Err(if is_rsa1_bits(type_text) {
            LineErrorKind::UnsupportedRsa1
        } else {
            LineErrorKind::UnknownKeyType(type_text.to_string())
        });
    };
    let cp = skip_blanks(&cp[tend..]);
    if cp.is_empty() {
        return Err(LineErrorKind::Truncated);
    }
    let bend = cp.bytes().position(is_blank).unwrap_or(cp.len());
    let blob = b64_decode(&cp[..bend]).ok_or_else(|| LineErrorKind::BadKey("bad base64".into()))?;
    let key = parse_key(&blob, true).map_err(|e| match e {
        KeyError::Length => LineErrorKind::KeyTooShort,
        KeyError::Format(s) => LineErrorKind::BadKey(s),
    })?;
    if !key.ktype.same_as(text_type) {
        return Err(LineErrorKind::BadKey(
            "key type does not match the blob".into(),
        ));
    }
    let comment = skip_blanks(&cp[bend..]);
    Ok(Some(Entry {
        marker,
        hosts,
        key_type: type_text.to_string(),
        key_blob: blob,
        comment: (!comment.is_empty()).then(|| comment.to_string()),
        file: String::new(),
        line: 0,
        key,
    }))
}

/// hostkeys_foreach_file treats a short decimal first field as the legacy
/// SSH-1 format.
fn is_rsa1_bits(s: &str) -> bool {
    !s.is_empty() && s.len() < 8 && s.bytes().all(|c| c.is_ascii_digit())
}

/// put_host_port(): the name known_hosts uses for a host and port.
pub fn host_label(host: &str, port: u16) -> String {
    if port == 0 || port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// match_pattern(): `*` and `?` wildcards over bytes.
pub(crate) fn match_pattern(s: &[u8], p: &[u8]) -> bool {
    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || (p[pi] != b'*' && p[pi] == s[si])) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// match_pattern_list(): 1 for a match, -1 when a negated pattern matches
/// (which wins), 0 otherwise.
pub(crate) fn match_pattern_list(s: &str, patterns: &[String], dolower: bool) -> i32 {
    let mut got_positive = false;
    for pat in patterns {
        let (negated, sub) = match pat.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pat.as_str()),
        };
        if sub.len() >= MAX_SUBPATTERN {
            return 0;
        }
        let sub = if dolower {
            sub.to_ascii_lowercase()
        } else {
            sub.to_string()
        };
        if match_pattern(s.as_bytes(), sub.as_bytes()) {
            if negated {
                return -1;
            }
            got_positive = true;
        }
    }
    got_positive as i32
}

/// match_hostname(): the name is lowercased, so are the patterns.
pub(crate) fn match_hostname(host: &str, patterns: &[String]) -> i32 {
    match_pattern_list(&host.to_ascii_lowercase(), patterns, true)
}

/// The `|1|salt|hash` form of a name with the given salt (host_hash()).
pub fn hash_host(name: &str, salt: &[u8; 20]) -> String {
    let h = hmac_sha1(salt, name.as_bytes());
    format!("{HASH_MAGIC}{}|{}", b64_encode(salt), b64_encode(&h))
}

fn hosts_match(hosts: &Hosts, name: &str) -> bool {
    match hosts {
        // Hashed names are compared exactly as given; ssh lowercases host
        // names and HostKeyAlias before they get here.
        Hosts::Hashed { salt, hash } => {
            hmac_sha1(salt, name.as_bytes()).as_slice() == hash.as_slice()
        }
        Hosts::Patterns(p) => match_hostname(name, p) == 1,
    }
}

impl Entry {
    /// match_maybe_hashed(): whether this line is for `name`.
    pub fn matches(&self, name: &str) -> bool {
        hosts_match(&self.hosts, name)
    }

    fn matches_any(&self, names: &[String]) -> bool {
        names.iter().any(|n| self.matches(n))
    }
}

/// What check() found for a host key.
#[derive(Debug)]
pub enum Check<'a> {
    /// HOST_OK: the key (or, for a certificate, its CA) is listed.
    Found(&'a Entry),
    /// HOST_CHANGED: the host has keys listed and none is this one. As in
    /// OpenSSH this happens for a listed key of any type, not only the
    /// presented one's. `offending` is the entry ssh names ("Offending key
    /// in file:line", the last non-matching one); `known` lists them all.
    Changed {
        offending: &'a Entry,
        known: Vec<&'a Entry>,
    },
    /// HOST_REVOKED: an @revoked line for this host lists the key (or, for
    /// a certificate, the key or its CA). This wins over everything else.
    Revoked(&'a Entry),
    /// HOST_NEW. `other_types` is what show_other_keys() reports: one entry
    /// per other key type known for the host. In OpenSSH's own flow any
    /// listed plain key already gives Changed, so this is normally empty;
    /// it is filled the same way for completeness.
    NotFound { other_types: Vec<&'a Entry> },
    /// The presented blob is not a key OpenSSH would accept.
    BadKey(String),
}

fn revoked_entry<'a>(host_entries: &[&'a Entry], k: &Key) -> Option<&'a Entry> {
    let ca = k
        .cert
        .as_ref()
        .and_then(|c| parse_key(&c.ca_key_blob, false).ok());
    host_entries.iter().copied().find(|e| {
        e.marker == Marker::Revoked
            && (key_equal_public(k, &e.key)
                || ca.as_ref().is_some_and(|ca| key_equal_public(ca, &e.key)))
    })
}

/// check_key_in_hostkeys() over the entries for `names` (load_hostkeys
/// with HKF_WANT_MATCH). Pass the names of one lookup: the host label, or
/// for CheckHostIP a second call with the address label, as ssh does.
/// Names are compared as given; ssh lowercases host names first.
pub fn check<'a>(
    entries: &'a [Entry],
    names: &[String],
    key_type: &str,
    key_blob: &[u8],
) -> Check<'a> {
    let k = match parse_key(key_blob, true) {
        Ok(k) => k,
        Err(e) => return Check::BadKey(e.to_string()),
    };
    if let Some(t) = KeyType::from_name(key_type.as_bytes()) {
        if !t.same_as(k.ktype) {
            return Check::BadKey("key type does not match the blob".into());
        }
    } else {
        return Check::BadKey(format!("unknown key type \"{key_type}\""));
    }
    let host_entries: Vec<&Entry> = entries.iter().filter(|e| e.matches_any(names)).collect();

    if let Some(e) = revoked_entry(&host_entries, &k) {
        return Check::Revoked(e);
    }

    let want_marker = if k.cert.is_some() {
        Marker::CertAuthority
    } else {
        Marker::None
    };
    let ca = k
        .cert
        .as_ref()
        .and_then(|c| parse_key(&c.ca_key_blob, false).ok());
    let mut offending = None;
    for e in host_entries
        .iter()
        .copied()
        .filter(|e| e.marker == want_marker)
    {
        if let Some(ca) = &ca {
            if key_equal_public(ca, &e.key) {
                return Check::Found(e);
            }
        } else {
            if key_equal(&k, &e.key) {
                return Check::Found(e);
            }
            offending = Some(e);
        }
    }
    if let Some(offending) = offending {
        let known = host_entries
            .iter()
            .copied()
            .filter(|e| e.marker == Marker::None)
            .collect();
        return Check::Changed { offending, known };
    }
    Check::NotFound {
        other_types: other_types(&host_entries, &k),
    }
}

/// show_other_keys(): for RSA, ECDSA, Ed25519 and ML-DSA, other than the
/// presented key's own type, the first plain entry of that type that is
/// not itself revoked.
fn other_types<'a>(host_entries: &[&'a Entry], k: &Key) -> Vec<&'a Entry> {
    use super::wire::Base;
    let families: [fn(Base) -> bool; 4] = [
        |b| b == Base::Rsa,
        |b| matches!(b, Base::Ecdsa(_)),
        |b| b == Base::Ed25519,
        |b| b == Base::Mldsa44Ed25519,
    ];
    let mut out = Vec::new();
    for fam in families {
        if !k.ktype.cert && fam(k.ktype.base) {
            continue;
        }
        let found = host_entries
            .iter()
            .copied()
            .find(|e| e.marker == Marker::None && !e.key.ktype.cert && fam(e.key.ktype.base));
        if let Some(e) = found {
            if revoked_entry(host_entries, &e.key).is_none() {
                out.push(e);
            }
        }
    }
    out
}

/// Whether an @cert-authority line for one of `names` lists this CA key.
pub fn check_ca(
    entries: &[Entry],
    names: &[String],
    ca_key_type: &str,
    ca_key_blob: &[u8],
) -> bool {
    let Ok(ca) = parse_key(ca_key_blob, false) else {
        return false;
    };
    if KeyType::from_name(ca_key_type.as_bytes()).is_none_or(|t| !t.same_as(ca.ktype)) {
        return false;
    }
    entries.iter().any(|e| {
        e.marker == Marker::CertAuthority && e.matches_any(names) && key_equal_public(&ca, &e.key)
    })
}

/// sshkey_format_text(): the type OpenSSH names the key by, then base64.
fn key_text(key_type: &str, key_blob: &[u8]) -> String {
    match parse_key(key_blob, true) {
        Ok(k) => format!("{} {}", k.ktype.name(), b64_encode(&k.blob)),
        Err(_) => format!("{} {}", key_type, b64_encode(key_blob)),
    }
}

fn random_salt() -> [u8; 20] {
    let mut s = [0u8; 20];
    rand::fill(&mut s[..]);
    s
}

fn format_with(
    names: &[String],
    key_type: &str,
    key_blob: &[u8],
    hash: bool,
    salt: &mut dyn FnMut() -> [u8; 20],
) -> String {
    if names.is_empty() {
        return String::new();
    }
    let key = key_text(key_type, key_blob);
    if hash {
        // format_host_entry: with hashing each name goes on its own line.
        names
            .iter()
            .map(|n| format!("{} {}\n", hash_host(&n.to_ascii_lowercase(), &salt()), key))
            .collect()
    } else {
        format!("{} {}\n", names.join(",").to_ascii_lowercase(), key)
    }
}

/// The line(s) OpenSSH writes for these names and key, newline included:
/// `host,ip type base64` or, hashed, one `|1|salt|hash type base64` line
/// per name with a fresh random salt each.
pub fn format_line(names: &[String], key_type: &str, key_blob: &[u8], hash: bool) -> String {
    format_with(names, key_type, key_blob, hash, &mut random_salt)
}

/// Like format_line, with the salts supplied (for tests).
pub fn format_line_with_salt(
    names: &[String],
    key_type: &str,
    key_blob: &[u8],
    hash: bool,
    mut salt: impl FnMut() -> [u8; 20],
) -> String {
    format_with(names, key_type, key_blob, hash, &mut salt)
}

/// add_host_to_hostfile(): appends to the file, first adding a newline if
/// the file does not end in one. Creates the file and its directory if
/// needed; on Unix as 0600 and 0700. Existing lines are never rewritten.
pub fn append(path: &Path, line: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    let mut data = Vec::new();
    if f.seek(SeekFrom::End(0))? > 0 {
        f.seek(SeekFrom::End(-1))?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last)?;
        if last[0] != b'\n' {
            data.push(b'\n');
        }
    }
    data.extend_from_slice(line.as_bytes());
    if !line.ends_with('\n') {
        data.push(b'\n');
    }
    f.write_all(&data)?;
    f.flush()
}

/// hostfile_replace_entries() for UpdateHostKeys. `names` is the host label
/// and optionally the address label. Plain lines for those names whose key
/// is not in `keep` are dropped; @cert-authority and @revoked lines,
/// comments, invalid lines and other hosts stay as they are. Keys in `keep`
/// not yet listed for every name are appended. The text comes back
/// unchanged, byte for byte, when there is nothing to do.
pub fn replace_host_keys(
    text: &str,
    names: &[String],
    keep: &[(String, Vec<u8>)],
    hash: bool,
) -> String {
    replace_with(text, names, keep, hash, &mut random_salt)
}

/// Like replace_host_keys, with the salts supplied (for tests).
pub fn replace_host_keys_with_salt(
    text: &str,
    names: &[String],
    keep: &[(String, Vec<u8>)],
    hash: bool,
    mut salt: impl FnMut() -> [u8; 20],
) -> String {
    replace_with(text, names, keep, hash, &mut salt)
}

fn replace_with(
    text: &str,
    names: &[String],
    keep: &[(String, Vec<u8>)],
    hash: bool,
    salt: &mut dyn FnMut() -> [u8; 20],
) -> String {
    let keys: Vec<Option<Key>> = keep.iter().map(|(_, b)| parse_key(b, true).ok()).collect();
    let mut matched = vec![0u32; keys.len()];
    let mut out = String::new();
    let mut modified = false;

    for (i, raw) in lines(text).enumerate() {
        let line = clean(i, raw);
        // Which names this line is for (HKF_MATCH_HOST / HKF_MATCH_IP).
        let entry = parse_line(line).ok().flatten();
        let mut mask = 0u32;
        if let Some(e) = &entry {
            for (bit, n) in names.iter().enumerate() {
                if e.matches(n) {
                    mask |= 1 << bit;
                }
            }
        }
        match entry {
            Some(e) if mask != 0 && e.marker == Marker::None => {
                if let Some(j) = keys
                    .iter()
                    .position(|k| k.as_ref().is_some_and(|k| key_equal(k, &e.key)))
                {
                    matched[j] |= mask;
                    out.push_str(raw);
                    out.push('\n');
                } else {
                    modified = true;
                }
            }
            _ => {
                out.push_str(raw);
                out.push('\n');
            }
        }
    }

    let want: u32 = (1u32 << names.len()) - 1;
    for (j, k) in keys.iter().enumerate() {
        if k.is_none() || matched[j] & want == want {
            continue;
        }
        let missing: Vec<String> = names
            .iter()
            .enumerate()
            .filter(|(bit, _)| matched[j] & (1 << bit) == 0)
            .map(|(_, n)| n.clone())
            .collect();
        out.push_str(&format_with(&missing, &keep[j].0, &keep[j].1, hash, salt));
        modified = true;
    }
    if modified {
        out
    } else {
        text.to_string()
    }
}
