//! Unit tests, and comparisons with OpenSSH: testdata/openssh-10.3 holds
//! what ssh-keygen 10.3 printed for keys, known_hosts files and KRLs made
//! by testdata/gen.sh. The live tests rerun gen.sh with the local
//! ssh-keygen (and, when KH_WSL_DISTRO names one, the WSL distro's) and
//! check the fresh output the same way; they skip when it is missing.

use std::path::{Path, PathBuf};

use super::digest::{hmac_sha1, md5};
use super::hostfile::{match_hostname, match_pattern};
use super::wire::{b64_decode, b64_encode, parse_key, put_string};
use super::*;

// ---------------------------------------------------------------- helpers

fn testdata() -> PathBuf {
    // On a device the sources are elsewhere: the folder is pushed and named.
    if let Some(d) = std::env::var_os("REACH_KNOWNHOSTS_TESTDATA") {
        return PathBuf::from(d);
    }
    let f = Path::new(file!());
    let candidates: Vec<PathBuf> = if f.is_absolute() {
        vec![f.to_path_buf()]
    } else {
        // file!() is relative to the package or to a workspace above it.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|a| a.join(f))
            .collect()
    };
    let src = candidates
        .into_iter()
        .find(|p| p.exists())
        .expect("tests.rs location");
    src.parent().unwrap().join("testdata")
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("{}: {e}", dir.join(name).display()))
}

/// A `type base64 comment` public key file.
fn pubkey(dir: &Path, name: &str) -> (String, Vec<u8>, String) {
    let text = read(dir, name);
    let mut it = text.trim_end().splitn(3, ' ');
    let t = it.next().unwrap().to_string();
    let b = b64_decode(it.next().unwrap()).unwrap();
    (t, b, it.next().unwrap_or("").to_string())
}

/// Splits a file of "== title" blocks.
fn blocks(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if let Some(t) = line.strip_prefix("== ") {
            out.push((t.to_string(), Vec::new()));
        } else if let Some(last) = out.last_mut() {
            last.1.push(line.to_string());
        }
    }
    out
}

fn ed25519_blob(seed: u8) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-ed25519");
    put_string(&mut b, &[seed; 32]);
    b
}

fn ed_line(hosts: &str, seed: u8) -> String {
    format!("{hosts} ssh-ed25519 {}", b64_encode(&ed25519_blob(seed)))
}

fn ecdsa_blob(seed: u8) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"ecdsa-sha2-nistp256");
    put_string(&mut b, b"nistp256");
    let mut q = vec![4u8];
    q.extend_from_slice(&[seed; 64]);
    put_string(&mut b, &q);
    b
}

fn names(n: &[&str]) -> Vec<String> {
    n.iter().map(|s| s.to_string()).collect()
}

// ------------------------------------------------------------- digests

#[test]
fn md5_rfc1321_vectors() {
    let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex(md5(b"message digest")),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );
    assert_eq!(
        hex(md5(
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        )),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
}

#[test]
fn hmac_sha1_rfc2202_vectors() {
    let hex = |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(hmac_sha1(&[0x0b; 20], b"Hi There")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex(hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    assert_eq!(
        hex(hmac_sha1(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    );
}

// ------------------------------------------------------------- matching

#[test]
fn wildcards() {
    assert!(match_pattern(b"abc", b"a*"));
    assert!(match_pattern(b"abc", b"*c"));
    assert!(match_pattern(b"abc", b"a?c"));
    assert!(match_pattern(b"", b"*"));
    assert!(match_pattern(b"", b""));
    assert!(!match_pattern(b"a", b""));
    assert!(!match_pattern(b"abc", b"a?"));
    assert!(match_pattern(b"a.b.c", b"*.*"));
    assert!(match_pattern(b"aaab", b"*a*b"));
    assert!(!match_pattern(b"aaa", b"*a*b"));
}

#[test]
fn pattern_lists() {
    let p = |s: &str| s.split(',').map(str::to_string).collect::<Vec<_>>();
    assert_eq!(match_hostname("a.example", &p("*.example")), 1);
    assert_eq!(match_hostname("A.EXAMPLE", &p("*.example")), 1);
    assert_eq!(match_hostname("a.example", &p("*.EXAMPLE")), 1);
    assert_eq!(
        match_hostname("bad.example", &p("*.example,!bad.example")),
        -1
    );
    // Negation wins wherever it appears.
    assert_eq!(
        match_hostname("bad.example", &p("!bad.example,*.example")),
        -1
    );
    assert_eq!(match_hostname("x", &p("y")), 0);
    // match_pattern_list gives up on a subpattern that does not fit its
    // 1024-byte buffer, even after an earlier match.
    let long = "a".repeat(1023);
    assert_eq!(match_hostname("x", &["x".to_string(), long.clone()]), 0);
    assert_eq!(match_hostname("x", &["x".to_string(), "a".repeat(1022)]), 1);
}

#[test]
fn host_labels() {
    assert_eq!(host_label("example.com", 22), "example.com");
    assert_eq!(host_label("example.com", 0), "example.com");
    assert_eq!(host_label("example.com", 2222), "[example.com]:2222");
    assert_eq!(host_label("2001:db8::1", 2222), "[2001:db8::1]:2222");
}

// ------------------------------------------------------------- parsing

#[test]
fn parse_skips_comments_and_blank_lines() {
    let text = format!("# c\n\n   \n\t# indented\n{}\n", ed_line("a.test", 1));
    let p = parse(&text, "kh");
    assert!(p.errors.is_empty(), "{:?}", p.errors);
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.entries[0].line, 5);
    assert_eq!(p.entries[0].file, "kh");
    assert_eq!(p.entries[0].hosts, Hosts::Patterns(names(&["a.test"])));
    assert_eq!(p.entries[0].comment, None);
}

#[test]
fn parse_crlf_bom_and_missing_final_newline() {
    let text = format!(
        "\u{feff}{}\r\n{} the comment\r\n{}",
        ed_line("a.test", 1),
        ed_line("b.test", 2),
        ed_line("c.test", 3)
    );
    let p = parse(&text, "kh");
    assert!(p.errors.is_empty(), "{:?}", p.errors);
    assert_eq!(p.entries.len(), 3);
    assert!(p.entries[0].matches("a.test"));
    assert_eq!(p.entries[1].comment.as_deref(), Some("the comment"));
    assert_eq!(p.entries[2].line, 3);
}

#[test]
fn parse_reports_bad_lines_and_keeps_going() {
    let k = b64_encode(&ed25519_blob(1));
    let text = [
        format!("@bogus h ssh-ed25519 {k}"),
        "h".to_string(),
        "h ssh-ed25519".to_string(),
        "h #comment".to_string(),
        format!("h ssh-foo {k}"),
        "h 1024 35 12345".to_string(),
        "h ssh-ed25519 AAAA!!".to_string(),
        format!("h ssh-rsa {k}"),
        format!("|1|abc|def ssh-ed25519 {k}"),
        format!("@revoked @cert-authority h ssh-ed25519 {k}"),
        format!("@ h ssh-ed25519 {k}"),
        ed_line("good.test", 9),
    ]
    .join("\n");
    let p = parse(&text, "kh");
    let kinds: Vec<_> = p.errors.iter().map(|e| (e.line, e.kind.clone())).collect();
    assert_eq!(
        kinds,
        vec![
            (1, LineErrorKind::BadMarker),
            (2, LineErrorKind::Truncated),
            (3, LineErrorKind::Truncated),
            (4, LineErrorKind::Truncated),
            (5, LineErrorKind::UnknownKeyType("ssh-foo".into())),
            (6, LineErrorKind::UnsupportedRsa1),
            (7, LineErrorKind::BadKey("bad base64".into())),
            (
                8,
                LineErrorKind::BadKey("key type does not match the blob".into())
            ),
            (9, LineErrorKind::BadHash),
            (10, LineErrorKind::BadMarker),
            (11, LineErrorKind::BadMarker),
        ]
    );
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.entries[0].line, 12);
    assert_eq!(p.errors[0].to_string(), "kh:1: invalid marker");
}

#[test]
fn parse_markers_and_hashed() {
    let salt = [7u8; 20];
    let text = format!(
        "@cert-authority *.ca {}\n@revoked * {}\n{} {}\n",
        &ed_line("", 1)[1..],
        &ed_line("", 2)[1..],
        hash_host("h.test", &salt),
        &ed_line("", 3)[1..]
    );
    let p = parse(&text, "kh");
    assert!(p.errors.is_empty(), "{:?}", p.errors);
    assert_eq!(p.entries[0].marker, Marker::CertAuthority);
    assert_eq!(p.entries[1].marker, Marker::Revoked);
    match &p.entries[2].hosts {
        Hosts::Hashed { salt: s, hash } => {
            assert_eq!(s, &salt.to_vec());
            assert_eq!(hash, &hmac_sha1(&salt, b"h.test").to_vec());
        }
        h => panic!("{h:?}"),
    }
    assert!(p.entries[2].matches("h.test"));
    assert!(!p.entries[2].matches("H.test"));
}

#[test]
fn marker_followed_by_tab_needs_a_line_without_spaces() {
    // check_markers looks for a space anywhere first, then a tab.
    let k = b64_encode(&ed25519_blob(1));
    let p = parse(
        &format!("@revoked\th.test ssh-ed25519 {k}\n@revoked\th.test\tssh-ed25519\t{k}\n"),
        "kh",
    );
    assert_eq!(p.errors.len(), 1);
    assert_eq!(p.errors[0].line, 1);
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.entries[0].marker, Marker::Revoked);
}

#[test]
fn hashed_entry_with_extra_text_never_matches() {
    let salt = [3u8; 20];
    let line = format!(
        "{},other.test {}",
        hash_host("h.test", &salt),
        &ed_line("", 1)[1..]
    );
    let p = parse(&line, "kh");
    assert_eq!(p.entries.len(), 1);
    assert!(!p.entries[0].matches("h.test"));
    assert!(!p.entries[0].matches("other.test"));
}

#[test]
fn short_rsa_keys_are_refused() {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-rsa");
    put_string(&mut b, &[1, 0, 1]);
    put_string(&mut b, &[0x7f; 64]); // 511 bits
    let p = parse(&format!("h ssh-rsa {}", b64_encode(&b)), "kh");
    assert_eq!(p.errors[0].kind, LineErrorKind::KeyTooShort);
}

// ------------------------------------------------------------- checking

#[test]
fn check_found_changed_notfound() {
    let text = [
        ed_line("a.test,192.0.2.1", 1),
        format!("b.test ecdsa-sha2-nistp256 {}", b64_encode(&ecdsa_blob(5))),
    ]
    .join("\n");
    let p = parse(&text, "kh");
    let e = &p.entries;
    match check(e, &names(&["a.test"]), "ssh-ed25519", &ed25519_blob(1)) {
        Check::Found(f) => assert_eq!(f.line, 1),
        c => panic!("{c:?}"),
    }
    match check(e, &names(&["192.0.2.1"]), "ssh-ed25519", &ed25519_blob(1)) {
        Check::Found(f) => assert_eq!(f.line, 1),
        c => panic!("{c:?}"),
    }
    match check(e, &names(&["a.test"]), "ssh-ed25519", &ed25519_blob(2)) {
        Check::Changed { offending, known } => {
            assert_eq!(offending.line, 1);
            assert_eq!(known.len(), 1);
        }
        c => panic!("{c:?}"),
    }
    // A listed key of another type also counts as changed, as in OpenSSH.
    match check(e, &names(&["b.test"]), "ssh-ed25519", &ed25519_blob(1)) {
        Check::Changed { offending, .. } => assert_eq!(offending.line, 2),
        c => panic!("{c:?}"),
    }
    match check(e, &names(&["c.test"]), "ssh-ed25519", &ed25519_blob(1)) {
        Check::NotFound { other_types } => assert!(other_types.is_empty()),
        c => panic!("{c:?}"),
    }
    assert!(matches!(
        check(e, &names(&["a.test"]), "ssh-rsa", &ed25519_blob(1)),
        Check::BadKey(_)
    ));
    assert!(matches!(
        check(e, &names(&["a.test"]), "ssh-ed25519", b"junk"),
        Check::BadKey(_)
    ));
}

#[test]
fn changed_reports_the_last_non_matching_entry() {
    let text = [
        ed_line("a.test", 1),
        ed_line("a.test", 2),
        ed_line("a.test", 3),
    ]
    .join("\n");
    let p = parse(&text, "kh");
    match check(
        &p.entries,
        &names(&["a.test"]),
        "ssh-ed25519",
        &ed25519_blob(9),
    ) {
        Check::Changed { offending, known } => {
            assert_eq!(offending.line, 3);
            assert_eq!(known.len(), 3);
        }
        c => panic!("{c:?}"),
    }
    // Any matching line makes it Found, wherever it is.
    assert!(
        matches!(check(&p.entries, &names(&["a.test"]), "ssh-ed25519", &ed25519_blob(2)), Check::Found(f) if f.line == 2)
    );
}

#[test]
fn revoked_wins_and_needs_a_matching_host() {
    let text = [
        ed_line("a.test", 1),
        format!("@revoked {}", ed_line("*", 1)),
        format!("@revoked {}", ed_line("z.test", 2)),
    ]
    .join("\n");
    let p = parse(&text, "kh");
    match check(
        &p.entries,
        &names(&["a.test"]),
        "ssh-ed25519",
        &ed25519_blob(1),
    ) {
        Check::Revoked(e) => assert_eq!(e.line, 2),
        c => panic!("{c:?}"),
    }
    // An @revoked line only counts for hosts its patterns match
    // (load_hostkeys loads matching lines only).
    match check(
        &p.entries,
        &names(&["a.test"]),
        "ssh-ed25519",
        &ed25519_blob(2),
    ) {
        Check::Changed { .. } => {}
        c => panic!("{c:?}"),
    }
    assert!(matches!(
        check(
            &p.entries,
            &names(&["z.test"]),
            "ssh-ed25519",
            &ed25519_blob(2)
        ),
        Check::Revoked(_)
    ));
}

#[test]
fn other_types_skips_the_presented_type_and_revoked_keys() {
    // Only reachable with certificates in OpenSSH's flow, but the helper
    // itself follows show_other_keys.
    let text = [
        format!("@cert-authority {}", ed_line("a.test", 7)),
        format!("a.test ecdsa-sha2-nistp256 {}", b64_encode(&ecdsa_blob(5))),
    ]
    .join("\n");
    let p = parse(&text, "kh");
    let ca_blob = ed25519_blob(8);
    let cert = test_cert(&ca_blob, 1, b"id");
    match check(
        &p.entries,
        &names(&["a.test"]),
        "ssh-ed25519-cert-v01@openssh.com",
        &cert,
    ) {
        Check::NotFound { other_types } => {
            assert_eq!(other_types.len(), 1);
            assert_eq!(other_types[0].line, 2);
        }
        c => panic!("{c:?}"),
    }
}

/// A structurally valid host certificate (the signature is not checked).
fn test_cert(ca_blob: &[u8], serial: u64, key_id: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-ed25519-cert-v01@openssh.com");
    put_string(&mut b, &[0u8; 32]); // nonce
    put_string(&mut b, &[0x42; 32]); // key
    b.extend_from_slice(&serial.to_be_bytes());
    b.extend_from_slice(&2u32.to_be_bytes());
    put_string(&mut b, key_id);
    let mut pr = Vec::new();
    put_string(&mut pr, b"h.test");
    put_string(&mut b, &pr);
    b.extend_from_slice(&0u64.to_be_bytes());
    b.extend_from_slice(&u64::MAX.to_be_bytes());
    put_string(&mut b, b"");
    put_string(&mut b, b"");
    put_string(&mut b, b"");
    put_string(&mut b, ca_blob);
    let mut sig = Vec::new();
    put_string(&mut sig, b"ssh-ed25519");
    put_string(&mut sig, &[0u8; 64]);
    put_string(&mut b, &sig);
    b
}

#[test]
fn certificates_and_cert_authorities() {
    let ca = ed25519_blob(8);
    let other_ca = ed25519_blob(9);
    let text = format!("@cert-authority *.test {}\n", &ed_line("", 8)[1..]);
    let p = parse(&text, "kh");
    let cert = test_cert(&ca, 5, b"id");
    assert!(matches!(
        check(
            &p.entries,
            &names(&["h.test"]),
            "ssh-ed25519-cert-v01@openssh.com",
            &cert
        ),
        Check::Found(_)
    ));
    assert!(matches!(
        check(
            &p.entries,
            &names(&["h.other"]),
            "ssh-ed25519-cert-v01@openssh.com",
            &cert
        ),
        Check::NotFound { .. }
    ));
    let cert2 = test_cert(&other_ca, 5, b"id");
    assert!(matches!(
        check(
            &p.entries,
            &names(&["h.test"]),
            "ssh-ed25519-cert-v01@openssh.com",
            &cert2
        ),
        Check::NotFound { .. }
    ));
    assert!(check_ca(
        &p.entries,
        &names(&["h.test"]),
        "ssh-ed25519",
        &ca
    ));
    assert!(!check_ca(
        &p.entries,
        &names(&["h.nope"]),
        "ssh-ed25519",
        &ca
    ));
    assert!(!check_ca(
        &p.entries,
        &names(&["h.test"]),
        "ssh-ed25519",
        &other_ca
    ));

    // A revoked CA revokes its certificates.
    let text2 = format!("{text}@revoked * {}\n", &ed_line("", 8)[1..]);
    let p2 = parse(&text2, "kh");
    assert!(matches!(
        check(
            &p2.entries,
            &names(&["h.test"]),
            "ssh-ed25519-cert-v01@openssh.com",
            &cert
        ),
        Check::Revoked(_)
    ));

    let info = cert_info(&cert).unwrap();
    assert_eq!(info.serial, 5);
    assert_eq!(info.key_id, "id");
    assert_eq!(info.principals, names(&["h.test"]));
    assert_eq!(info.cert_type, 2);
    assert_eq!(info.ca_key_blob, ca);
    assert_eq!(info.key_type, "ssh-ed25519");
    assert!(cert_info(&ca).is_err());
}

// ------------------------------------------------------------- writing

#[test]
fn format_lines() {
    let blob = ed25519_blob(1);
    let b64 = b64_encode(&blob);
    assert_eq!(
        format_line(
            &names(&["Host.Test", "192.0.2.1"]),
            "ssh-ed25519",
            &blob,
            false
        ),
        format!("host.test,192.0.2.1 ssh-ed25519 {b64}\n")
    );
    let mut n = 0u8;
    let hashed = format_line_with_salt(
        &names(&["Host.Test", "192.0.2.1"]),
        "ssh-ed25519",
        &blob,
        true,
        || {
            n += 1;
            [n; 20]
        },
    );
    assert_eq!(
        hashed,
        format!(
            "{} ssh-ed25519 {b64}\n{} ssh-ed25519 {b64}\n",
            hash_host("host.test", &[1; 20]),
            hash_host("192.0.2.1", &[2; 20])
        )
    );
    // Random salts still produce lines that match.
    let p = parse(
        &format_line(&names(&["x.test"]), "ssh-ed25519", &blob, true),
        "kh",
    );
    assert!(p.entries[0].matches("x.test"));
    assert!(format_line(&[], "ssh-ed25519", &blob, true).is_empty());
}

#[test]
fn rsa_alias_is_written_under_its_key_name() {
    let dir = testdata().join("openssh-10.3");
    let (_, blob, _) = pubkey(&dir, "k_rsa.pub");
    let line = format_line(&names(&["h"]), "rsa-sha2-256", &blob, false);
    assert!(line.starts_with("h ssh-rsa AAAA"));
}

#[test]
fn append_creates_and_adds_missing_newline() {
    let dir = std::env::temp_dir().join(format!("kh-append-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("sub").join("known_hosts");
    append(&path, "a.test x y").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a.test x y\n");
    std::fs::write(&path, "first line no newline").unwrap();
    append(&path, "b.test x y\n").unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "first line no newline\nb.test x y\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p2 = dir.join("fresh");
        append(&p2, "c").unwrap();
        assert_eq!(
            std::fs::metadata(&p2).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replace_keeps_unrelated_lines_and_adds_new_keys() {
    let text = [
        "# comment".to_string(),
        ed_line("a.test,192.0.2.1", 1),
        ed_line("a.test", 2),
        format!("@revoked {}", ed_line("a.test", 3)),
        format!("@cert-authority {}", ed_line("a.test", 4)),
        ed_line("b.test", 2),
        "garbage line".to_string(),
    ]
    .join("\n");
    let keep = vec![
        ("ssh-ed25519".to_string(), ed25519_blob(1)),
        ("ssh-ed25519".to_string(), ed25519_blob(5)),
    ];
    let out = replace_host_keys(&text, &names(&["a.test", "192.0.2.1"]), &keep, false);
    let expect = [
        "# comment".to_string(),
        ed_line("a.test,192.0.2.1", 1),
        format!("@revoked {}", ed_line("a.test", 3)),
        format!("@cert-authority {}", ed_line("a.test", 4)),
        ed_line("b.test", 2),
        "garbage line".to_string(),
        ed_line("a.test,192.0.2.1", 5),
    ]
    .join("\n")
        + "\n";
    assert_eq!(out, expect);
    // Nothing to do: the text comes back exactly, missing newline and all.
    let same = replace_host_keys(
        &out[..out.len() - 1],
        &names(&["a.test", "192.0.2.1"]),
        &keep,
        false,
    );
    assert_eq!(same, out[..out.len() - 1]);
}

#[test]
fn replace_fixes_a_key_listed_for_only_one_name() {
    let text = ed_line("a.test", 1) + "\n";
    let keep = vec![("ssh-ed25519".to_string(), ed25519_blob(1))];
    let out =
        replace_host_keys_with_salt(&text, &names(&["a.test", "192.0.2.1"]), &keep, true, || {
            [9; 20]
        });
    assert_eq!(
        out,
        format!(
            "{}\n{} {}\n",
            ed_line("a.test", 1),
            hash_host("192.0.2.1", &[9; 20]),
            &ed_line("", 1)[1..]
        )
    );
}

// ------------------------------------------------------------- fingerprints

#[test]
fn randomart_title_falls_back_when_too_long() {
    let dir = testdata().join("openssh-10.3");
    let (t, blob, _) = pubkey(&dir, "k_ed1.pub");
    let art = randomart(&t, Some(123456789), &blob, "sha256");
    // "[ED25519 123456789]" is 19 characters: too long, so "[ED25519]".
    assert!(art.starts_with("+----[ED25519]----+\n"), "{art}");
}

// ------------------------------------------------------------- KRL

fn krl_header(comment: &[u8]) -> Vec<u8> {
    let mut b = b"SSHKRL\n\0".to_vec();
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&3u64.to_be_bytes());
    b.extend_from_slice(&0u64.to_be_bytes());
    b.extend_from_slice(&0u64.to_be_bytes());
    put_string(&mut b, b"");
    put_string(&mut b, comment);
    b
}

fn section(b: &mut Vec<u8>, typ: u8, data: &[u8]) {
    b.push(typ);
    put_string(b, data);
}

fn cert_section(ca: &[u8], subs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut s = Vec::new();
    put_string(&mut s, ca);
    put_string(&mut s, b"");
    for (t, d) in subs {
        section(&mut s, *t, d);
    }
    s
}

#[test]
fn krl_hand_built_sections() {
    let ca = ed25519_blob(8);
    let mut list = Vec::new();
    list.extend_from_slice(&10u64.to_be_bytes());
    let mut range = Vec::new();
    range.extend_from_slice(&20u64.to_be_bytes());
    range.extend_from_slice(&30u64.to_be_bytes());
    let mut bitmap = Vec::new();
    bitmap.extend_from_slice(&100u64.to_be_bytes());
    put_string(&mut bitmap, &[0x05]); // bits 0 and 2: serials 100 and 102
    let mut ids = Vec::new();
    put_string(&mut ids, b"bad-id");
    let mut b = krl_header(b"test krl");
    section(
        &mut b,
        1,
        &cert_section(
            &ca,
            &[(0x20, list), (0x21, range), (0x22, bitmap), (0x23, ids)],
        ),
    );
    let mut ext = Vec::new();
    put_string(&mut ext, b"x@example.org");
    ext.push(0);
    put_string(&mut ext, b"ignored");
    section(&mut b, 255, &ext);
    // A signature section: parsed, then ignored.
    section(&mut b, 4, &ed25519_blob(1));
    put_string(&mut b, b"signature");
    let krl = krl_parse(&b).unwrap();
    assert_eq!(krl.comment, "test krl");
    assert_eq!(krl.version, 3);
    let revoked = |serial: u64, id: &[u8]| {
        let c = test_cert(&ca, serial, id);
        krl_revokes(&krl, "ssh-ed25519-cert-v01@openssh.com", &c, None)
    };
    for s in [10, 20, 25, 30, 100, 102] {
        assert!(revoked(s, b"x"), "serial {s}");
    }
    for s in [0, 9, 11, 19, 31, 99, 101, 103] {
        assert!(!revoked(s, b"x"), "serial {s}");
    }
    assert!(revoked(0, b"bad-id"));
    // Another CA's certificates are not affected.
    let c = test_cert(&ed25519_blob(9), 10, b"x");
    assert!(!krl_revokes(
        &krl,
        "ssh-ed25519-cert-v01@openssh.com",
        &c,
        None
    ));
}

#[test]
fn krl_refuses_what_openssh_refuses() {
    let ca = ed25519_blob(8);
    let bad = |b: Vec<u8>| krl_parse(&b).is_err();
    assert!(bad(b"not a krl".to_vec()));
    let mut v = krl_header(b"");
    v[8..12].copy_from_slice(&2u32.to_be_bytes());
    assert!(bad(v));
    // Serial 0, reversed range, bitmap revoking serial 0, bitmap wrapping.
    let zero = 0u64.to_be_bytes().to_vec();
    let mut b = krl_header(b"");
    section(&mut b, 1, &cert_section(&ca, &[(0x20, zero)]));
    assert!(bad(b));
    let mut rev = 9u64.to_be_bytes().to_vec();
    rev.extend_from_slice(&3u64.to_be_bytes());
    let mut b = krl_header(b"");
    section(&mut b, 1, &cert_section(&ca, &[(0x21, rev)]));
    assert!(bad(b));
    let mut bm = 0u64.to_be_bytes().to_vec();
    put_string(&mut bm, &[1]);
    let mut b = krl_header(b"");
    section(&mut b, 1, &cert_section(&ca, &[(0x22, bm)]));
    assert!(bad(b));
    let mut wrap = u64::MAX.to_be_bytes().to_vec();
    put_string(&mut wrap, &[2]);
    let mut b = krl_header(b"");
    section(&mut b, 1, &cert_section(&ca, &[(0x22, wrap)]));
    assert!(bad(b));
    // Unknown sections, critical extensions, trailing data, bad hash sizes.
    let mut b = krl_header(b"");
    section(&mut b, 9, b"");
    assert!(bad(b));
    let mut ext = Vec::new();
    put_string(&mut ext, b"x@example.org");
    ext.push(1);
    put_string(&mut ext, b"");
    let mut b = krl_header(b"");
    section(&mut b, 255, &ext);
    assert!(bad(b));
    let mut b = krl_header(b"");
    let mut s = Vec::new();
    put_string(&mut s, &[0u8; 19]);
    section(&mut b, 3, &s);
    assert!(bad(b));
    let mut b = krl_header(b"");
    let mut s = 10u64.to_be_bytes().to_vec();
    s.push(0);
    section(&mut b, 1, &cert_section(&ca, &[(0x20, s)]));
    assert!(bad(b));
    // Empty KRL is fine.
    assert!(krl_parse(&krl_header(b"")).is_ok());
}

#[test]
fn keylist_revocation() {
    let k1 = format!("ssh-ed25519 {} one", b64_encode(&ed25519_blob(1)));
    let k8 = format!("ssh-ed25519 {} ca", b64_encode(&ed25519_blob(8)));
    let text = format!("# revoked\n\n{k1}\n{k8}\n");
    assert_eq!(
        revoked_in_keylist(&text, "ssh-ed25519", &ed25519_blob(1)),
        Ok(true)
    );
    assert_eq!(
        revoked_in_keylist(&text, "ssh-ed25519", &ed25519_blob(2)),
        Ok(false)
    );
    // A certificate is revoked by its key or by its CA.
    let cert = test_cert(&ed25519_blob(8), 1, b"x");
    assert_eq!(
        revoked_in_keylist(&text, "ssh-ed25519-cert-v01@openssh.com", &cert),
        Ok(true)
    );
    assert_eq!(
        revoked_in_keylist("", "ssh-ed25519", &ed25519_blob(2)),
        Ok(false)
    );
    // Unreadable lines fail closed; a CRLF blank line is one, as in ssh.
    assert!(revoked_in_keylist("junk\n", "ssh-ed25519", &ed25519_blob(2)).is_err());
    assert!(revoked_in_keylist(&format!("\r\n{k1}\r\n"), "ssh-ed25519", &ed25519_blob(1)).is_err());
    assert_eq!(
        revoked_in_keylist(&format!("{k1}\r\n"), "ssh-ed25519", &ed25519_blob(1)),
        Ok(true)
    );
    assert_eq!(
        check_revoked_file(text.as_bytes(), "ssh-ed25519", &ed25519_blob(1)),
        Ok(true)
    );
}

#[test]
fn keylist_skips_short_rsa_keys() {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-rsa");
    put_string(&mut b, &[1, 0, 1]);
    put_string(&mut b, &[0x7f; 64]);
    let text = format!(
        "ssh-rsa {}\nssh-ed25519 {}\n",
        b64_encode(&b),
        b64_encode(&ed25519_blob(1))
    );
    assert_eq!(
        revoked_in_keylist(&text, "ssh-ed25519", &ed25519_blob(1)),
        Ok(true)
    );
}

// ------------------------------------------------- comparisons with OpenSSH

#[derive(Default, Debug)]
struct Counts {
    fingerprints: usize,
    randomarts: usize,
    lookups: usize,
    hashed_lines: usize,
    removals: usize,
    krl_queries: usize,
}

/// Checks this module against everything gen.sh recorded in `dir`.
fn verify_dir(dir: &Path) -> Counts {
    let mut n = Counts::default();

    // ssh-keygen -lv -E sha256|md5: "bits fp comment (TYPE)", then the art.
    for (title, lines) in blocks(&read(dir, "fp.txt")) {
        let (file, hash) = title.split_once(' ').unwrap();
        let (t, blob, comment) = pubkey(dir, file);
        let k = parse_key(&blob, true).unwrap();
        let short = k.ktype.short_name();
        let fp = fingerprint(&blob, hash);
        assert_eq!(
            lines[0],
            format!("{} {} {} ({})", k.bits, fp, comment, short),
            "{title}"
        );
        n.fingerprints += 1;
        assert_eq!(
            lines[1..].join("\n"),
            randomart(&t, None, &blob, hash),
            "{title}"
        );
        n.randomarts += 1;
    }

    // ssh-keygen -F name -l: the lines found for each name, in order.
    let mut lookups = |kh: &str, find: &str| {
        let parsed = parse(&read(dir, kh), kh);
        for (name, lines) in blocks(&read(dir, find)) {
            let mut ours = Vec::new();
            for e in parsed.entries.iter().filter(|e| e.matches(&name)) {
                let mark = match e.marker {
                    Marker::None => "",
                    Marker::CertAuthority => "CA",
                    Marker::Revoked => "REVOKED",
                };
                ours.push(format!("# Host {name} found: line {} {mark}", e.line));
                let c = e
                    .comment
                    .as_deref()
                    .map(|c| format!(" {c}"))
                    .unwrap_or_default();
                ours.push(format!(
                    "{name} {} {}{c}",
                    e.key.ktype.short_name(),
                    fingerprint(&e.key_blob, "sha256")
                ));
            }
            assert_eq!(ours, lines, "{kh}: {name}");
            n.lookups += 1;
        }
    };
    lookups("kh.txt", "find.txt");
    lookups("kh_hashed.txt", "find_hashed.txt");

    // ssh-keygen -H: each name hashed on its own line. Rebuild the file
    // from the salts it chose; HMAC and layout must agree exactly.
    let hashed: Vec<String> = read(dir, "kh_hashed.txt")
        .lines()
        .map(str::to_string)
        .collect();
    let mut hi = hashed.iter();
    for line in read(dir, "kh_hash.txt").lines() {
        let (hosts, rawkey) = line.split_once(' ').unwrap();
        if hosts.starts_with('@') || hosts.contains(['*', '?', '!']) {
            assert_eq!(hi.next().unwrap(), line);
            continue;
        }
        for host in hosts.split(',') {
            let theirs = hi.next().unwrap();
            let salt_b64 = theirs.split('|').nth(2).unwrap();
            let salt: [u8; 20] = b64_decode(salt_b64).unwrap().try_into().unwrap();
            assert_eq!(
                theirs,
                &format!("{} {rawkey}", hash_host(&host.to_ascii_lowercase(), &salt))
            );
            // format_line writes the same line, without the comment.
            let mut words = rawkey.split(' ');
            let (t, b) = (
                words.next().unwrap(),
                b64_decode(words.next().unwrap()).unwrap(),
            );
            let ours = format_line_with_salt(&[host.to_string()], t, &b, true, || salt);
            assert!(theirs.starts_with(ours.trim_end()), "{ours} / {theirs}");
            n.hashed_lines += 1;
        }
    }
    assert!(hi.next().is_none());

    // ssh-keygen -R name: the same as replacing with no keys to keep.
    let del = read(dir, "kh_del.txt");
    for (i, name) in read(dir, "dnames.txt").split_whitespace().enumerate() {
        let theirs = read(dir, &format!("del_{}.txt", i + 1));
        assert_eq!(
            replace_host_keys(&del, &[name.to_string()], &[], false),
            theirs,
            "-R {name}"
        );
        n.removals += 1;
    }

    // ssh-keygen -Q -f krl key: "file (comment): ok|REVOKED".
    for krl_name in ["krl_ca", "krl_any", "krl_carev"] {
        let bytes = std::fs::read(dir.join(format!("{krl_name}.bin"))).unwrap();
        let krl = krl_parse(&bytes).unwrap();
        for line in read(dir, &format!("q_{krl_name}.txt")).lines() {
            let file = line.split(' ').next().unwrap();
            let (t, blob, _) = pubkey(dir, file);
            let revoked = line.ends_with(": REVOKED");
            assert!(revoked || line.ends_with(": ok"), "{line}");
            assert_eq!(
                krl_revokes(&krl, &t, &blob, None),
                revoked,
                "{krl_name}: {line}"
            );
            assert_eq!(check_revoked_file(&bytes, &t, &blob), Ok(revoked));
            n.krl_queries += 1;
        }
    }
    // ssh-keygen chose every encoding for krl_ca: explicit key, SHA1 and
    // SHA256 fingerprints, serial list, range and bitmap, key ID.
    let krl = krl_parse(&std::fs::read(dir.join("krl_ca.bin")).unwrap()).unwrap();
    for t in [1u8, 2, 3, 5, 0x20, 0x21, 0x22, 0x23] {
        assert!(
            krl.sections.contains(&t),
            "krl_ca lacks section {t:#x}: {:?}",
            krl.sections
        );
    }
    assert_eq!(krl.version, 7);
    n
}

#[test]
fn matches_openssh_10_3_fixtures() {
    let dir = testdata().join("openssh-10.3");
    let n = verify_dir(&dir);
    println!("{}: {n:?}", read(&dir, "version.txt").trim());
    assert_eq!(n.fingerprints, 22);
    assert_eq!(n.randomarts, 22);
    assert_eq!(n.lookups, 32);
    assert_eq!(n.hashed_lines, 4);
    assert_eq!(n.removals, 5);
    assert_eq!(n.krl_queries, 57);
}

fn live_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kh-live-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Reruns gen.sh with the local ssh-keygen (KH_SSH_KEYGEN, default
/// ssh-keygen on PATH) and checks the fresh output.
#[test]
fn matches_local_ssh_keygen() {
    if std::env::var_os("KH_NO_LIVE").is_some() {
        return;
    }
    let kg = std::env::var("KH_SSH_KEYGEN").unwrap_or_else(|_| "ssh-keygen".to_string());
    let probe = std::process::Command::new(&kg).arg("-?").output();
    let sh = std::process::Command::new("sh")
        .arg("-c")
        .arg("true")
        .status();
    if probe.is_err() || !sh.is_ok_and(|s| s.success()) {
        println!("skipped: no {kg} or sh");
        return;
    }
    let dir = live_dir("local");
    let status = std::process::Command::new("sh")
        .arg(testdata().join("gen.sh"))
        .arg(&dir)
        .arg(&kg)
        .status()
        .unwrap();
    assert!(status.success(), "gen.sh failed");
    let n = verify_dir(&dir);
    println!("{}: {n:?}", read(&dir, "version.txt").trim());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same with the ssh-keygen inside a WSL distro, when KH_WSL_DISTRO
/// names one.
#[test]
fn matches_wsl_ssh_keygen() {
    let Ok(distro) = std::env::var("KH_WSL_DISTRO") else {
        println!("skipped: KH_WSL_DISTRO not set");
        return;
    };
    let wsl_path = |p: &Path| {
        let s = p.to_string_lossy().replace('\\', "/");
        let (drive, rest) = s.split_once(":/").unwrap();
        format!("/mnt/{}/{}", drive.to_ascii_lowercase(), rest)
    };
    let dir = live_dir("wsl");
    // Generated in the distro's own /tmp: ssh-keygen refuses CA keys on
    // /mnt/c, where every file looks world-readable.
    let script = format!(
        "d=$(mktemp -d) && sh '{}' \"$d\" ssh-keygen && cp \"$d\"/* '{}' && rm -rf \"$d\"",
        wsl_path(&testdata().join("gen.sh")),
        wsl_path(&dir)
    );
    let status = std::process::Command::new("wsl")
        .args(["-d", &distro, "--exec", "sh", "-c", &script])
        .status()
        .unwrap();
    assert!(status.success(), "gen.sh in WSL failed");
    let n = verify_dir(&dir);
    println!("{}: {n:?}", read(&dir, "version.txt").trim());
    let _ = std::fs::remove_dir_all(&dir);
}
