//! UMAC (RFC 4418) with AES-128, for `umac-64@openssh.com`,
//! `umac-128@openssh.com` and their `-etm@openssh.com` forms.
//!
//! Follows RFC 4418 and OpenSSH's umac.c, from which the arithmetic of the
//! poly and inner-product layers is taken. As in OpenSSH's mac.c, the key is
//! the 16-byte MAC key, the message is the packet (the sequence number is not
//! prepended as it is for HMAC), and the nonce is the 32-bit packet sequence
//! number as a 64-bit big-endian integer in 8 bytes.

use aes::Aes128;
use cipher::{BlockCipherEncrypt, KeyInit};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{Mac, MacAlgorithm};

const KEY_LEN: usize = 16;
const BLOCK_LEN: usize = 16;
/// Bytes of message hashed by one NH call, and of NH key per iteration.
const L1_KEY_LEN: usize = 1024;

const P36: u64 = 0x0000_000F_FFFF_FFFB; // 2^36 - 5
const M36: u64 = 0x0000_000F_FFFF_FFFF;
const P64: u64 = 0xFFFF_FFFF_FFFF_FFC5; // 2^64 - 59
const P128: u128 = u128::MAX - 158; // 2^128 - 159
const POLY64_MASK: u64 = 0x01ff_ffff_01ff_ffff;
const POLY128_MASK: u128 = 0x01ff_ffff_01ff_ffff_01ff_ffff_01ff_ffff;
/// Bytes of L1 output hashed under the 64-bit prime before the 128-bit one.
const POLY64_MAX_BYTES: usize = 1 << 17;

pub struct UmacAlgorithm {
    pub(crate) taglen: usize,
    pub(crate) etm: bool,
}

impl MacAlgorithm for UmacAlgorithm {
    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn make_mac(&self, key: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(UmacMac {
            umac: Umac::new(key, self.taglen),
            etm: self.etm,
        })
    }
}

struct UmacMac {
    umac: Umac,
    etm: bool,
}

impl Mac for UmacMac {
    fn mac_len(&self) -> usize {
        self.umac.taglen
    }

    fn is_etm(&self) -> bool {
        self.etm
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        let nonce = u64::from(sequence_number).to_be_bytes();
        let tag = self.umac.tag(payload, &nonce);
        #[allow(clippy::indexing_slicing)] // taglen <= 16
        output.copy_from_slice(&tag[..self.umac.taglen]);
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        if mac.len() != self.umac.taglen {
            return false;
        }
        let nonce = u64::from(sequence_number).to_be_bytes();
        let tag = self.umac.tag(payload, &nonce);
        #[allow(clippy::indexing_slicing)] // taglen <= 16
        tag[..self.umac.taglen].ct_eq(mac).into()
    }
}

/// A keyed UMAC instance with all derived keys precomputed.
pub(crate) struct Umac {
    taglen: usize,
    iters: usize,
    /// NH key as 32-bit big-endian words: 256 words plus 4 per extra iteration.
    l1_key: Vec<u32>,
    poly_key64: [u64; 4],
    poly_key128: [u128; 4],
    /// L3-HASH K1, already reduced mod 2^36 - 5.
    l3_key1: [[u64; 8]; 4],
    l3_key2: [u32; 4],
    /// AES keyed with KDF(K, 0, 16), for the pad.
    pdf: Aes128,
}

impl Drop for Umac {
    fn drop(&mut self) {
        self.l1_key.zeroize();
        self.poly_key64.zeroize();
        self.poly_key128.zeroize();
        for k in self.l3_key1.iter_mut() {
            k.zeroize();
        }
        self.l3_key2.zeroize();
    }
}

fn aes_encrypt(cipher: &Aes128, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut b = aes::Block::default();
    b.copy_from_slice(block);
    cipher.encrypt_block(&mut b);
    let mut out = [0u8; BLOCK_LEN];
    out.copy_from_slice(&b);
    out
}

/// RFC 4418 section 3.2.
fn kdf(cipher: &Aes128, index: u64, numbytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(numbytes.div_ceil(BLOCK_LEN) * BLOCK_LEN);
    let mut i: u64 = 1;
    while out.len() < numbytes {
        let mut t = [0u8; BLOCK_LEN];
        #[allow(clippy::indexing_slicing)]
        {
            t[..8].copy_from_slice(&index.to_be_bytes());
            t[8..].copy_from_slice(&i.to_be_bytes());
        }
        let mut e = aes_encrypt(cipher, &t);
        out.extend_from_slice(&e);
        e.zeroize();
        t.zeroize();
        i += 1;
    }
    out.truncate(numbytes);
    out
}

#[allow(clippy::indexing_slicing)] // fixed-size slices of buffers sized above
fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

#[allow(clippy::indexing_slicing)]
fn be_u128(b: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    u128::from_be_bytes(a)
}

impl Umac {
    #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
    pub(crate) fn new(key: &[u8], taglen: usize) -> Self {
        assert!(matches!(taglen, 4 | 8 | 12 | 16));
        let iters = taglen / 4;
        // The key length is fixed by key_len(); new_from_slice cannot fail.
        let base = Aes128::new_from_slice(key).unwrap();

        let mut pdf_key = kdf(&base, 0, KEY_LEN);
        let pdf = Aes128::new_from_slice(&pdf_key).unwrap();
        pdf_key.zeroize();

        let mut l1 = kdf(&base, 1, L1_KEY_LEN + (iters - 1) * 16);
        let l1_key = l1
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        l1.zeroize();

        let mut l2 = kdf(&base, 2, iters * 24);
        let mut l3a = kdf(&base, 3, iters * 64);
        let mut l3b = kdf(&base, 4, iters * 4);
        let mut poly_key64 = [0u64; 4];
        let mut poly_key128 = [0u128; 4];
        let mut l3_key1 = [[0u64; 8]; 4];
        let mut l3_key2 = [0u32; 4];
        for i in 0..iters {
            poly_key64[i] = be_u64(&l2[i * 24..]) & POLY64_MASK;
            poly_key128[i] = be_u128(&l2[i * 24 + 8..]) & POLY128_MASK;
            for j in 0..8 {
                l3_key1[i][j] = be_u64(&l3a[i * 64 + j * 8..]) % P36;
            }
            let k = &l3b[i * 4..i * 4 + 4];
            l3_key2[i] = u32::from_be_bytes([k[0], k[1], k[2], k[3]]);
        }
        l2.zeroize();
        l3a.zeroize();
        l3b.zeroize();

        Umac {
            taglen,
            iters,
            l1_key,
            poly_key64,
            poly_key128,
            l3_key1,
            l3_key2,
            pdf,
        }
    }

    /// UMAC(K, M, Nonce, taglen); the first `taglen` bytes of the result are the tag.
    pub(crate) fn tag(&self, msg: &[u8], nonce: &[u8; 8]) -> [u8; 16] {
        let mut out = self.uhash(msg);
        let pad = self.pdf(nonce);
        for (o, p) in out.iter_mut().zip(pad.iter()) {
            *o ^= p;
        }
        out
    }

    /// RFC 4418 section 3.3, for an 8-byte nonce.
    #[allow(clippy::indexing_slicing)]
    fn pdf(&self, nonce: &[u8; 8]) -> [u8; 16] {
        let mut block = [0u8; BLOCK_LEN];
        block[..8].copy_from_slice(nonce);
        let mut index = 0usize;
        if self.taglen == 4 || self.taglen == 8 {
            let modulus = BLOCK_LEN / self.taglen; // 4 or 2
            index = (nonce[7] as usize) % modulus;
            block[7] ^= index as u8;
        }
        let t = aes_encrypt(&self.pdf, &block);
        let mut out = [0u8; 16];
        if self.taglen == 4 || self.taglen == 8 {
            let start = index * self.taglen;
            out[..self.taglen].copy_from_slice(&t[start..start + self.taglen]);
        } else {
            out[..self.taglen].copy_from_slice(&t[..self.taglen]);
        }
        out
    }

    /// RFC 4418 section 5.1.
    #[allow(clippy::indexing_slicing)]
    fn uhash(&self, msg: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..self.iters {
            let key = &self.l1_key[i * 4..i * 4 + L1_KEY_LEN / 4];
            let l1 = l1_hash(key, msg);
            let b: u128 = if msg.len() <= L1_KEY_LEN {
                #[allow(clippy::unwrap_used)] // l1 has exactly one word here
                u128::from(*l1.first().unwrap())
            } else {
                l2_hash(self.poly_key64[i], self.poly_key128[i], &l1)
            };
            let c = l3_hash(&self.l3_key1[i], self.l3_key2[i], b);
            out[i * 4..i * 4 + 4].copy_from_slice(&c.to_be_bytes());
        }
        out
    }
}

/// NH (RFC 4418 section 5.2.2) of `data`, a multiple of 32 bytes, with the
/// message read as little-endian words (the ENDIAN-SWAP step) and the key as
/// big-endian ones.
#[allow(clippy::indexing_slicing)]
fn nh(key: &[u32], data: &[u8]) -> u64 {
    let mut y: u64 = 0;
    for (block, k) in data.chunks_exact(32).zip(key.chunks_exact(8)) {
        let mut m = [0u32; 8];
        for (j, w) in block.chunks_exact(4).enumerate() {
            m[j] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        for j in 0..4 {
            let a = m[j].wrapping_add(k[j]) as u64;
            let b = m[j + 4].wrapping_add(k[j + 4]) as u64;
            y = y.wrapping_add(a.wrapping_mul(b));
        }
    }
    y
}

/// L1-HASH (RFC 4418 section 5.2.1): one 64-bit word per 1024-byte chunk.
#[allow(clippy::indexing_slicing)]
fn l1_hash(key: &[u32], msg: &[u8]) -> Vec<u64> {
    let mut out = Vec::with_capacity(msg.len() / L1_KEY_LEN + 1);
    let mut rest = msg;
    while rest.len() > L1_KEY_LEN {
        let (chunk, tail) = rest.split_at(L1_KEY_LEN);
        out.push(nh(key, chunk).wrapping_add((L1_KEY_LEN as u64) * 8));
        rest = tail;
    }
    // Last (or only) chunk: hash its whole 32-byte blocks in place, then the
    // zero-padded tail. An empty message still hashes one zero block.
    let full = rest.len() / 32 * 32;
    let mut y = nh(key, &rest[..full]);
    if full < rest.len() || rest.is_empty() {
        let mut block = [0u8; 32];
        block[..rest.len() - full].copy_from_slice(&rest[full..]);
        y = y.wrapping_add(nh(&key[full / 4..], &block));
        block.zeroize();
    }
    out.push(y.wrapping_add((rest.len() as u64) * 8));
    out
}

/// OpenSSH umac.c's poly64: k * cur + data modulo 2^64 - 59, with the key in
/// its masked domain, not necessarily fully reduced.
fn poly64(cur: u64, key: u64, data: u64) -> u64 {
    let key_hi = key >> 32;
    let key_lo = key & 0xffff_ffff;
    let cur_hi = cur >> 32;
    let cur_lo = cur & 0xffff_ffff;

    let x = key_hi
        .wrapping_mul(cur_lo)
        .wrapping_add(cur_hi.wrapping_mul(key_lo));
    let x_lo = x & 0xffff_ffff;
    let x_hi = x >> 32;

    let mut res = key_hi
        .wrapping_mul(cur_hi)
        .wrapping_add(x_hi)
        .wrapping_mul(59)
        .wrapping_add(key_lo.wrapping_mul(cur_lo));

    let t = x_lo << 32;
    res = res.wrapping_add(t);
    if res < t {
        res = res.wrapping_add(59);
    }
    res = res.wrapping_add(data);
    if res < data {
        res = res.wrapping_add(59);
    }
    res
}

/// 256-bit product of two 128-bit integers, as (high, low).
fn mul_128(a: u128, b: u128) -> (u128, u128) {
    let (a1, a0) = (a >> 64, a & u128::from(u64::MAX));
    let (b1, b0) = (b >> 64, b & u128::from(u64::MAX));
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let (mid, mid_carry) = p01.overflowing_add(p10);
    let (lo, lo_carry) = p00.overflowing_add(mid << 64);
    let hi = p11 + (mid >> 64) + (u128::from(mid_carry) << 64) + u128::from(lo_carry);
    (hi, lo)
}

/// (hi * 2^128 + lo) mod 2^128 - 159, using 2^128 = 159 (mod p).
fn reduce_p128(hi: u128, lo: u128) -> u128 {
    let (h2, l2) = mul_128(hi, 159);
    let (mut v, c1) = lo.overflowing_add(l2);
    // What is left above 2^128 is small: h2 < 256 plus a carry.
    let mut over = h2 + u128::from(c1);
    while over != 0 {
        let (s, c) = v.overflowing_add(over * 159);
        v = s;
        over = u128::from(c);
    }
    if v >= P128 {
        v -= P128;
    }
    v
}

fn poly128_step(y: u128, k: u128, m: u128) -> u128 {
    let (hi, lo) = mul_128(k, y);
    let ky = reduce_p128(hi, lo);
    let (s, c) = ky.overflowing_add(m);
    reduce_p128(u128::from(c), s)
}

/// POLY (RFC 4418 section 5.3.2) over 128-bit words.
fn poly128(k: u128, y: u128, words: impl Iterator<Item = u128>) -> u128 {
    const MAXWORDRANGE: u128 = u128::MAX - ((1u128 << 96) - 1); // 2^128 - 2^96
    let mut y = y;
    for m in words {
        if m >= MAXWORDRANGE {
            y = poly128_step(y, k, P128 - 1);
            y = poly128_step(y, k, m - 159);
        } else {
            y = poly128_step(y, k, m);
        }
    }
    y
}

/// L2-HASH (RFC 4418 section 5.3.1), returned as the 16-byte string's integer.
#[allow(clippy::indexing_slicing)]
fn l2_hash(k64: u64, k128: u128, l1: &[u64]) -> u128 {
    let split = l1.len().min(POLY64_MAX_BYTES / 8);
    let mut y: u64 = 1;
    for &m in &l1[..split] {
        if (m >> 32) == 0xffff_ffff {
            y = poly64(y, k64, P64 - 1);
            y = poly64(y, k64, m.wrapping_sub(59));
        } else {
            y = poly64(y, k64, m);
        }
    }
    if y >= P64 {
        y -= P64;
    }
    if split == l1.len() {
        return u128::from(y);
    }
    // Messages over 16 MiB: the rest of the L1 output, with 0x80 appended
    // and zero-padded to 16 bytes, under the 128-bit prime.
    let rest = &l1[split..];
    let mut words: Vec<u128> = Vec::with_capacity(1 + rest.len() / 2 + 1);
    words.push(u128::from(y));
    let mut pairs = rest.chunks_exact(2);
    for p in &mut pairs {
        words.push((u128::from(p[0]) << 64) | u128::from(p[1]));
    }
    match pairs.remainder() {
        [last] => words.push((u128::from(*last) << 64) | (0x80u128 << 56)),
        _ => words.push(0x80u128 << 120),
    }
    let mut it = words.into_iter();
    // POLY starts from y = 1 and hashes uint2str(y64, 16) as its first word.
    let first = it.next().unwrap_or(0);
    let y = poly128_step(1, k128, first);
    poly128(k128, y, it)
}

/// L3-HASH (RFC 4418 section 5.4.1).
fn l3_hash(k1: &[u64; 8], k2: u32, m: u128) -> u32 {
    let mut t: u64 = 0;
    for (i, k) in k1.iter().enumerate() {
        let chunk = ((m >> (112 - 16 * i)) & 0xffff) as u64;
        t = t.wrapping_add(k.wrapping_mul(chunk));
    }
    // Eight 36-bit by 16-bit products stay below 2^55; fold once.
    let mut r = (t & M36) + 5 * (t >> 36);
    if r >= P36 {
        r -= P36;
    }
    (r as u32) ^ k2
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn repeat(unit: &[u8], n: usize) -> Vec<u8> {
        unit.iter().copied().cycle().take(unit.len() * n).collect()
    }

    const K: &[u8; 16] = b"abcdefghijklmnop";
    const N: &[u8; 8] = b"bcdefghi";

    fn rfc_tag(msg: &[u8], taglen: usize) -> String {
        hex(&Umac::new(K, taglen).tag(msg, N)[..taglen])
    }

    /// RFC 4418 appendix: 32-, 64- and 96-bit tags. The RFC lists no 128-bit
    /// column; a 128-bit tag's first 12 bytes equal the 96-bit one (same
    /// UHASH iterations, same pad block), checked here, and the full 128-bit
    /// values from OpenSSH's umac128.c are checked below.
    #[test]
    fn rfc4418_vectors() {
        let cases: &[(&[u8], usize, &str, &str, &str)] = &[
            (
                b"",
                0,
                "113145fb",
                "6e155fad26900be1",
                "32fedb100c79ad58f07ff764",
            ),
            (
                b"a",
                3,
                "3b91d102",
                "44b5cb542f220104",
                "185e4fe905cba7bd85e4c2dc",
            ),
            (
                b"a",
                1 << 10,
                "599b350b",
                "26bf2f5d60118bd9",
                "7a54abe04af82d60fb298c3c",
            ),
            (
                b"a",
                1 << 15,
                "58dcf532",
                "27f8ef643b0d118d",
                "7b136bd911e4b734286ef2be",
            ),
            (
                b"a",
                1 << 20,
                "db6364d1",
                "a4477e87e9f55853",
                "f8acfa3ac31cfeea047f7b11",
            ),
            (
                b"abc",
                1,
                "abf3a3a0",
                "d4d7b9f6bd4fbfcf",
                "883c3d4b97a61976ffcf2323",
            ),
            (
                b"abc",
                500,
                "abeb3c8b",
                "d4cf26ddefd5c01a",
                "8824a260c53c66a36c9260a6",
            ),
        ];
        for (unit, n, t32, t64, t96) in cases {
            let msg = if *n == 0 {
                Vec::new()
            } else {
                repeat(unit, *n)
            };
            assert_eq!(rfc_tag(&msg, 4), *t32, "UMAC-32 {n}");
            assert_eq!(rfc_tag(&msg, 8), *t64, "UMAC-64 {n}");
            assert_eq!(rfc_tag(&msg, 12), *t96, "UMAC-96 {n}");
            assert_eq!(&rfc_tag(&msg, 16)[..24], *t96, "UMAC-128 prefix {n}");
        }
    }

    /// The 'a' * 2^25 row, the only one that reaches the 128-bit polynomial
    /// (OpenSSH's umac.c stops at 16 MiB; SSH packets never get near it).
    /// The RFC's printed values for this row are wrong; these are the
    /// corrected ones from verified erratum 3507.
    #[test]
    fn rfc4418_vector_32mib() {
        let msg = vec![b'a'; 1 << 25];
        assert_eq!(rfc_tag(&msg, 4), "85ee5cae");
        assert_eq!(rfc_tag(&msg, 8), "faca46f856e9b45f");
        assert_eq!(rfc_tag(&msg, 12), "a621c2457c0012e64f3fdae9");
    }

    /// RFC 4418 appendix intermediate values for UMAC-64 of 'abc' * 500.
    #[test]
    fn rfc4418_intermediates() {
        let u = Umac::new(K, 8);
        assert_eq!(u.l1_key[0], 0xACD79B4F);
        assert_eq!(u.l1_key[4], 0xC6DFECA2);
        assert_eq!(u.l1_key[255], 0x0BF0F56C);
        assert_eq!(u.l1_key[4 + 255], 0x744C294F);
        assert_eq!(u.poly_key64[0], 0x0094B8DD0137BEF8);
        assert_eq!(u.poly_key64[1], 0x01036F4D000E7E72);
        assert_eq!(u.l3_key1[0][4], 0x056533C3A8);
        assert_eq!(u.l3_key1[1][7], 0x04C1CB8FED);
        assert_eq!(u.l3_key2, [0x2E79F461, 0xA74C03AA, 0, 0]);
        let msg = repeat(b"abc", 500);
        assert_eq!(hex(&u.uhash(&msg)[..8]), "05f86309df9ad858");
        assert_eq!(hex(&u.pdf(N)[..8]), "d13745d4304f1842");
    }

    /// Generated by OpenSSH 10.0's umac.c and umac128.c (built against
    /// OpenSSL's AES) with the RFC key and nonce.
    #[test]
    fn openssh_umac128_rfc_inputs() {
        let cases: &[(&[u8], usize, &str)] = &[
            (b"", 0, "32fedb100c79ad58f07ff7643cc60465"),
            (b"a", 3, "185e4fe905cba7bd85e4c2dc3d117d8d"),
            (b"a", 1 << 10, "7a54abe04af82d60fb298c3cbd195bcb"),
            (b"a", 1 << 15, "7b136bd911e4b734286ef2be501f2c3c"),
            (b"a", 1 << 20, "f8acfa3ac31cfeea047f7b115b03bef5"),
            (b"abc", 1, "883c3d4b97a61976ffcf232308cba5a5"),
            (b"abc", 500, "8824a260c53c66a36c9260a62cb83aa1"),
        ];
        for (unit, n, t128) in cases {
            let msg = if *n == 0 {
                Vec::new()
            } else {
                repeat(unit, *n)
            };
            assert_eq!(rfc_tag(&msg, 16), *t128, "UMAC-128 {n}");
        }
    }

    /// SSH-style use through the Mac trait, against OpenSSH's umac.c fed as
    /// mac.c feeds it: key 00..0f, packet byte i = i * 7 + 3, nonce = the
    /// sequence number as 64-bit big-endian. Lines are "len seqno tag".
    #[test]
    fn openssh_umac_ssh_style() {
        let key: Vec<u8> = (0u8..16).collect();
        for (taglen, table) in [(8, OPENSSH_SSH64), (16, OPENSSH_SSH128)] {
            let alg = UmacAlgorithm { taglen, etm: false };
            let mac = alg.make_mac(&key);
            for line in table.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() != 3 {
                    continue;
                }
                let len: usize = f[0].parse().unwrap();
                let seq: u32 = f[1].parse().unwrap();
                let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let mut out = vec![0u8; taglen];
                mac.compute(seq, &msg, &mut out);
                assert_eq!(hex(&out), f[2], "UMAC-{} len {len} seq {seq}", taglen * 8);
                assert!(mac.verify(seq, &msg, &out));
                out[0] ^= 1;
                assert!(!mac.verify(seq, &msg, &out));
                assert!(!mac.verify(seq, &msg, &out[..taglen - 1]));
            }
        }
    }

    /// One OpenSSH context reused for consecutive packets, as a session does:
    /// 100-byte packets with byte i = seqno + i.
    #[test]
    fn openssh_umac_consecutive_packets() {
        let key: Vec<u8> = (0u8..16).collect();
        let want64 = [
            "cc9ea73377e21370",
            "cfc6f402d474ea28",
            "ae7429ffe1e846ca",
            "75a2995805073555",
            "2a7fd7c1d45782b4",
        ];
        let want128 = [
            "cc9ea73377e21370efd45d7b5d2c7978",
            "983d68b38f0586a0df19a793f1f15600",
            "ae7429ffe1e846cae8054965833f9b97",
            "000664f6a8e0f5173e741f78df058c0b",
            "2a7fd7c1d45782b478239f062965089c",
        ];
        let m64 = UmacAlgorithm {
            taglen: 8,
            etm: true,
        }
        .make_mac(&key);
        let m128 = UmacAlgorithm {
            taglen: 16,
            etm: true,
        }
        .make_mac(&key);
        for s in 0u32..5 {
            let msg: Vec<u8> = (0..100).map(|i| (s as u8).wrapping_add(i)).collect();
            let mut t = [0u8; 16];
            m64.compute(s, &msg, &mut t[..8]);
            assert_eq!(hex(&t[..8]), want64[s as usize]);
            m128.compute(s, &msg, &mut t);
            assert_eq!(hex(&t), want128[s as usize]);
        }
    }

    include!("umac_openssh_vectors.rs");
}
