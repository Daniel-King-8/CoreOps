#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

//! Known-answer tests for the HMAC-MD5, HMAC-SHA1 and HMAC-RIPEMD160 MACs:
//! RFC 2202 and RFC 2286, first against the HMAC types, then through the
//! SSH MAC objects the negotiation tables hand out.

use digest::KeyInit;

use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Case {
    key: Vec<u8>,
    data: Vec<u8>,
    digest: &'static str,
}

/// The seven RFC 2202 / RFC 2286 inputs; key lengths 1, 3 and 5 follow the
/// hash (16 bytes for MD5, 20 for SHA-1 and RIPEMD-160).
fn cases(hash_len: usize, digests: [&'static str; 7]) -> Vec<Case> {
    let k25: Vec<u8> = (1u8..=25).collect();
    let inputs: [(Vec<u8>, Vec<u8>); 7] = [
        (vec![0x0b; hash_len], b"Hi There".to_vec()),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec()),
        (vec![0xaa; hash_len], vec![0xdd; 50]),
        (k25, vec![0xcd; 50]),
        (vec![0x0c; hash_len], b"Test With Truncation".to_vec()),
        (
            vec![0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
        ),
        (
            vec![0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".to_vec(),
        ),
    ];
    inputs
        .into_iter()
        .zip(digests)
        .map(|((key, data), digest)| Case { key, data, digest })
        .collect()
}

fn md5_cases() -> Vec<Case> {
    cases(
        16,
        [
            "9294727a3638bb1c13f48ef8158bfc9d",
            "750c783e6ab0b503eaa86e310a5db738",
            "56be34521d144c88dbb8c733f0e8b3f6",
            "697eaf0aca3a3aea3a75164746ffaa79",
            "56461ef2342edc00f9bab995690efd4c",
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
            "6f630fad67cda0ee1fb1f562db3aa53e",
        ],
    )
}

fn sha1_cases() -> Vec<Case> {
    cases(
        20,
        [
            "b617318655057264e28bc0b6fb378c8ef146be00",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ],
    )
}

fn ripemd160_cases() -> Vec<Case> {
    cases(
        20,
        [
            "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
            "dda6c0213a485a9e24f4742064a7f033b43c4069",
            "b0b105360de759960ab4f35298e116e295d8e7c1",
            "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
            "7619693978f91d90539ae786500ff3d8e0518e39",
            "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
            "69ea60798d71616cce5fd0871e23754cd75d5a0a",
        ],
    )
}

fn hmac_hex<M: digest::Mac + KeyInit>(key: &[u8], data: &[u8]) -> String {
    let mut m = <M as KeyInit>::new_from_slice(key).unwrap();
    m.update(data);
    hex(&m.finalize().into_bytes())
}

#[test]
fn rfc2202_hmac_md5() {
    for (i, c) in md5_cases().iter().enumerate() {
        assert_eq!(
            hmac_hex::<Hmac<Md5>>(&c.key, &c.data),
            c.digest,
            "case {}",
            i + 1
        );
    }
}

#[test]
fn rfc2202_hmac_sha1() {
    for (i, c) in sha1_cases().iter().enumerate() {
        assert_eq!(
            hmac_hex::<Hmac<Sha1>>(&c.key, &c.data),
            c.digest,
            "case {}",
            i + 1
        );
    }
}

#[test]
fn rfc2286_hmac_ripemd160() {
    for (i, c) in ripemd160_cases().iter().enumerate() {
        assert_eq!(
            hmac_hex::<Hmac<Ripemd160>>(&c.key, &c.data),
            c.digest,
            "case {}",
            i + 1
        );
    }
}

/// An SSH HMAC is HMAC(key, uint32(seqno) || packet), so an RFC input of at
/// least four bytes is fed as seqno = its first four bytes (big-endian) and
/// packet = the rest. Only the cases whose key is exactly the MAC's key
/// length can go through the SSH objects (cases 1, 3 and 5).
fn check_ssh_mac(name: Name, cases: &[Case], tag_len: usize, etm: bool) {
    let alg = MACS.get(&name).unwrap();
    for (i, c) in cases.iter().enumerate() {
        if c.key.len() != alg.key_len() {
            continue;
        }
        let mac = alg.make_mac(&c.key);
        assert_eq!(mac.mac_len(), tag_len, "{name:?}");
        assert_eq!(mac.is_etm(), etm, "{name:?}");
        let seq = u32::from_be_bytes(c.data[..4].try_into().unwrap());
        let packet = &c.data[4..];
        let mut tag = vec![0u8; tag_len];
        mac.compute(seq, packet, &mut tag);
        assert_eq!(
            hex(&tag),
            c.digest[..tag_len * 2],
            "{name:?} case {}",
            i + 1
        );
        assert!(mac.verify(seq, packet, &tag), "{name:?} case {}", i + 1);
        // A changed tag, a short tag, another sequence number and another
        // packet must all fail.
        let mut bad = tag.clone();
        bad[tag_len - 1] ^= 0x80;
        assert!(!mac.verify(seq, packet, &bad));
        assert!(!mac.verify(seq, packet, &tag[..tag_len - 1]));
        assert!(!mac.verify(seq.wrapping_add(1), packet, &tag));
        assert!(!mac.verify(seq, &c.data[3..], &tag));
    }
}

#[test]
fn ssh_hmac_md5_family() {
    let c = md5_cases();
    check_ssh_mac(HMAC_MD5, &c, 16, false);
    check_ssh_mac(HMAC_MD5_ETM, &c, 16, true);
    check_ssh_mac(HMAC_MD5_96, &c, 12, false);
    check_ssh_mac(HMAC_MD5_96_ETM, &c, 12, true);
}

#[test]
fn ssh_hmac_sha1_96_family() {
    let c = sha1_cases();
    check_ssh_mac(HMAC_SHA1, &c, 20, false);
    check_ssh_mac(HMAC_SHA1_96, &c, 12, false);
    check_ssh_mac(HMAC_SHA1_96_ETM, &c, 12, true);
}

#[test]
fn ssh_hmac_ripemd160_family() {
    let c = ripemd160_cases();
    check_ssh_mac(HMAC_RIPEMD160, &c, 20, false);
    check_ssh_mac(HMAC_RIPEMD160_OPENSSH, &c, 20, false);
    check_ssh_mac(HMAC_RIPEMD160_ETM, &c, 20, true);
}

/// The RFCs' own truncated values (test case 5, "digest-96").
#[test]
fn truncation_matches_rfc_digest_96() {
    for (name, key, want) in [
        (HMAC_MD5_96, vec![0x0c; 16], "56461ef2342edc00f9bab995"),
        (HMAC_MD5_96_ETM, vec![0x0c; 16], "56461ef2342edc00f9bab995"),
        (HMAC_SHA1_96, vec![0x0c; 20], "4c1a03424b55e07fe7f27be1"),
        (HMAC_SHA1_96_ETM, vec![0x0c; 20], "4c1a03424b55e07fe7f27be1"),
    ] {
        let mac = MACS.get(&name).unwrap().make_mac(&key);
        let data = b"Test With Truncation";
        let seq = u32::from_be_bytes(data[..4].try_into().unwrap());
        let mut tag = [0u8; 12];
        mac.compute(seq, &data[4..], &mut tag);
        assert_eq!(hex(&tag), want, "{name:?}");
    }
    // RFC 2286 gives a RIPEMD-160 digest-96 too, though SSH has no -96 form.
    assert_eq!(
        &hmac_hex::<Hmac<Ripemd160>>(&[0x0c; 20], b"Test With Truncation")[..24],
        "7619693978f91d90539ae786"
    );
}

#[test]
fn key_and_tag_lengths_match_openssh() {
    // OpenSSH mac.c: key length is the hash length for HMAC, 16 for UMAC.
    for (name, key_len, tag_len, etm) in [
        (HMAC_MD5, 16, 16, false),
        (HMAC_MD5_96, 16, 12, false),
        (HMAC_SHA1_96, 20, 12, false),
        (HMAC_MD5_ETM, 16, 16, true),
        (HMAC_MD5_96_ETM, 16, 12, true),
        (HMAC_SHA1_96_ETM, 20, 12, true),
        (UMAC_64, 16, 8, false),
        (UMAC_128, 16, 16, false),
        (UMAC_64_ETM, 16, 8, true),
        (UMAC_128_ETM, 16, 16, true),
        (HMAC_RIPEMD160, 20, 20, false),
        (HMAC_RIPEMD160_OPENSSH, 20, 20, false),
        (HMAC_RIPEMD160_ETM, 20, 20, true),
    ] {
        assert_eq!(Name::try_from(name.as_ref()), Ok(name));
        let alg = MACS.get(&name).unwrap();
        assert_eq!(alg.key_len(), key_len, "{name:?}");
        let mac = alg.make_mac(&vec![7u8; key_len]);
        assert_eq!(mac.mac_len(), tag_len, "{name:?}");
        assert_eq!(mac.is_etm(), etm, "{name:?}");
        assert!(
            !crate::Preferred::DEFAULT.mac.contains(&name),
            "{name:?} must not be offered by default"
        );
    }
}
