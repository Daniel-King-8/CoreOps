//! Streamlined NTRU Prime sntrup761, the KEM in OpenSSH's
//! sntrup761x25519-sha512 key exchange.
//!
//! A port of OpenSSH's sntrup761.c (OpenBSD rev 1.8), which is SUPERCOP
//! 20240808's crypto_kem/sntrup761/compact with crypto_sort/int32/portable4,
//! public domain, by Daniel J. Bernstein, Chitchanok Chuengsatiansup, Tanja
//! Lange and Christine van Vredendaal. The arithmetic is kept as written there,
//! including its constant-time masks and sorting network, and C's integer
//! promotions are spelled out with explicit casts. Known-answer tests against
//! the C code are at the end of the file.

#![allow(clippy::indexing_slicing)] // fixed-size arrays indexed by loop bounds

use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const PUBLICKEYBYTES: usize = 1158;
pub(crate) const SECRETKEYBYTES: usize = 1763;
pub(crate) const CIPHERTEXTBYTES: usize = 1039;
pub(crate) const BYTES: usize = 32;

const P: usize = 761;
const Q: i32 = 4591;
const W: usize = 286;
const Q12: i32 = (Q - 1) / 2;
const HASH_BYTES: usize = 32;
const SMALL_BYTES: usize = P.div_ceil(4); // 191
const SECRETKEYS_BYTES: usize = 2 * SMALL_BYTES;
const CONFIRM_BYTES: usize = 32;
const ROUNDED_BYTES: usize = CIPHERTEXTBYTES - CONFIRM_BYTES; // 1007

type Small = i8;
type Fq = i16;

// ------------------------------------------------------------- cryptoint

fn int16_negative_mask(x: i16) -> i16 {
    x >> 15
}

fn int16_nonzero_mask(x: i16) -> i16 {
    int16_negative_mask(x | x.wrapping_neg())
}

fn int32_negative_mask(x: i32) -> i32 {
    x >> 31
}

/// djbsort's int32_MINMAX: (a, b) becomes (min, max) without branching.
fn int32_minmax(a: &mut i32, b: &mut i32) {
    let ab = *b ^ *a;
    let mut c = b.wrapping_sub(*a);
    c ^= ab & (c ^ *b);
    c >>= 31;
    c &= ab;
    *a ^= c;
    *b ^= c;
}

fn minmax_at(x: &mut [i32], i: usize, j: usize) {
    let (mut a, mut b) = (x[i], x[j]);
    int32_minmax(&mut a, &mut b);
    x[i] = a;
    x[j] = b;
}

// ------------------------------------- crypto_sort/int32/portable4/sort.c

fn crypto_sort_int32(x: &mut [i32]) {
    let n = x.len() as isize;
    if n < 2 {
        return;
    }
    let mut top: isize = 1;
    while top < n - top {
        top += top;
    }
    let u = |v: isize| v as usize;

    let mut p = top;
    while p >= 1 {
        let mut i: isize = 0;
        while i + 2 * p <= n {
            for j in i..i + p {
                minmax_at(x, u(j), u(j + p));
            }
            i += 2 * p;
        }
        for j in i..n - p {
            minmax_at(x, u(j), u(j + p));
        }

        i = 0;
        let mut j: isize = 0;
        let mut q = top;
        while q > p {
            'done: {
                if j != i {
                    loop {
                        if j == n - q {
                            break 'done;
                        }
                        let mut a = x[u(j + p)];
                        let mut r = q;
                        while r > p {
                            int32_minmax(&mut a, &mut x[u(j + r)]);
                            r >>= 1;
                        }
                        x[u(j + p)] = a;
                        j += 1;
                        if j == i + p {
                            i += 2 * p;
                            break;
                        }
                    }
                }
                while i + p <= n - q {
                    for jj in i..i + p {
                        let mut a = x[u(jj + p)];
                        let mut r = q;
                        while r > p {
                            int32_minmax(&mut a, &mut x[u(jj + r)]);
                            r >>= 1;
                        }
                        x[u(jj + p)] = a;
                    }
                    i += 2 * p;
                }
                // now i + p > n - q
                j = i;
                while j < n - q {
                    let mut a = x[u(j + p)];
                    let mut r = q;
                    while r > p {
                        int32_minmax(&mut a, &mut x[u(j + r)]);
                        r >>= 1;
                    }
                    x[u(j + p)] = a;
                    j += 1;
                }
            }
            q >>= 1;
        }
        p >>= 1;
    }
}

fn crypto_sort_uint32(x: &mut [u32; P]) {
    let mut s = [0i32; P];
    for (d, v) in s.iter_mut().zip(x.iter()) {
        *d = (*v ^ 0x8000_0000) as i32;
    }
    crypto_sort_int32(&mut s);
    for (d, v) in x.iter_mut().zip(s.iter()) {
        *d = (*v as u32) ^ 0x8000_0000;
    }
    s.zeroize();
}

// ------------------------------------------ crypto_kem/sntrup761/compact

fn f3_freeze(x: i16) -> Small {
    let x = i32::from(x);
    (x - 3 * ((10923 * x + 16384) >> 15)) as Small
}

fn fq_freeze(x: i32) -> Fq {
    const Q16: i32 = (0x10000 + Q / 2) / Q;
    const Q20: i32 = (0x100000 + Q / 2) / Q;
    const Q28: i32 = (0x1000_0000 + Q / 2) / Q;
    let mut x = x;
    x -= Q * ((Q16 * x) >> 16);
    x -= Q * ((Q20 * x) >> 20);
    (x - Q * ((Q28 * x + 0x800_0000) >> 28)) as Fq
}

fn weightw_mask(r: &[Small; P]) -> i32 {
    let mut weight: i32 = 0;
    for &v in r.iter() {
        weight += i32::from(v) & 1;
    }
    i32::from(int16_nonzero_mask((weight - W as i32) as i16))
}

fn uint32_divmod_uint14(x: u32, m: u16) -> (u32, u16) {
    let m32 = u32::from(m);
    let v: u32 = 0x8000_0000 / m32;
    let mut x = x;
    let mut qpart = ((u64::from(x) * u64::from(v)) >> 31) as u32;
    x = x.wrapping_sub(qpart.wrapping_mul(m32));
    let mut q = qpart;
    qpart = ((u64::from(x) * u64::from(v)) >> 31) as u32;
    x = x.wrapping_sub(qpart.wrapping_mul(m32));
    q = q.wrapping_add(qpart);
    x = x.wrapping_sub(m32);
    q = q.wrapping_add(1);
    let mask = int32_negative_mask(x as i32) as u32;
    x = x.wrapping_add(mask & m32);
    q = q.wrapping_add(mask);
    (q, x as u16)
}

fn uint32_mod_uint14(x: u32, m: u16) -> u16 {
    uint32_divmod_uint14(x, m).1
}

fn encode(out: &mut Vec<u8>, r: &[u16], m: &[u16]) {
    let len = r.len();
    if len == 1 {
        let mut r = u32::from(r[0]);
        let mut m = u32::from(m[0]);
        while m > 1 {
            out.push(r as u8);
            r >>= 8;
            m = (m + 255) >> 8;
        }
    }
    if len > 1 {
        let half = len.div_ceil(2);
        let mut r2 = vec![0u16; half];
        let mut m2 = vec![0u16; half];
        let mut i = 0;
        while i + 1 < len {
            let m0 = u32::from(m[i]);
            let mut rr = u32::from(r[i]) + u32::from(r[i + 1]) * m0;
            let mut mm = u32::from(m[i + 1]) * m0;
            while mm >= 16384 {
                out.push(rr as u8);
                rr >>= 8;
                mm = (mm + 255) >> 8;
            }
            r2[i / 2] = rr as u16;
            m2[i / 2] = mm as u16;
            i += 2;
        }
        if i < len {
            r2[i / 2] = r[i];
            m2[i / 2] = m[i];
        }
        encode(out, &r2, &m2);
        r2.zeroize();
    }
}

/// Decodes `m.len()` values into `out`, returning the bytes of `s` it used.
fn decode(out: &mut [u16], s: &[u8], m: &[u16]) -> usize {
    let len = m.len();
    if len == 1 {
        out[0] = if m[0] == 1 {
            0
        } else if m[0] <= 256 {
            uint32_mod_uint14(u32::from(s[0]), m[0])
        } else {
            uint32_mod_uint14(u32::from(s[0]) + (u32::from(s[1]) << 8), m[0])
        };
        return if m[0] == 1 {
            0
        } else if m[0] <= 256 {
            1
        } else {
            2
        };
    }
    let half = len.div_ceil(2);
    let mut r2 = vec![0u16; half];
    let mut m2 = vec![0u16; half];
    let mut bottomr = vec![0u16; len / 2];
    let mut bottomt = vec![0u32; len / 2];
    let mut pos = 0;
    let mut i = 0;
    while i + 1 < len {
        let mm = u32::from(m[i]) * u32::from(m[i + 1]);
        if mm > 256 * 16383 {
            bottomt[i / 2] = 256 * 256;
            bottomr[i / 2] = u16::from(s[pos]) + 256 * u16::from(s[pos + 1]);
            pos += 2;
            m2[i / 2] = ((((mm + 255) >> 8) + 255) >> 8) as u16;
        } else if mm >= 16384 {
            bottomt[i / 2] = 256;
            bottomr[i / 2] = u16::from(s[pos]);
            pos += 1;
            m2[i / 2] = ((mm + 255) >> 8) as u16;
        } else {
            bottomt[i / 2] = 1;
            bottomr[i / 2] = 0;
            m2[i / 2] = mm as u16;
        }
        i += 2;
    }
    if i < len {
        m2[i / 2] = m[i];
    }
    pos += decode(&mut r2, &s[pos..], &m2);
    let mut o = 0;
    i = 0;
    while i + 1 < len {
        let r = u32::from(bottomr[i / 2]) + bottomt[i / 2] * u32::from(r2[i / 2]);
        let (r1, r0) = uint32_divmod_uint14(r, m[i]);
        let r1 = uint32_mod_uint14(r1, m[i + 1]);
        out[o] = r0;
        out[o + 1] = r1;
        o += 2;
        i += 2;
    }
    if i < len {
        out[o] = r2[i / 2];
    }
    r2.zeroize();
    bottomr.zeroize();
    pos
}

fn r3_from_rq(out: &mut [Small; P], r: &[Fq; P]) {
    for i in 0..P {
        out[i] = f3_freeze(r[i]);
    }
}

fn r3_mult(h: &mut [Small; P], f: &[Small; P], g: &[Small; P]) {
    let mut fg = [0i32; P + P - 1];
    for i in 0..P {
        for j in 0..P {
            fg[i + j] += i32::from(f[i]) * i32::from(g[j]);
        }
    }
    for i in P..P + P - 1 {
        fg[i - P] += fg[i];
    }
    for i in P..P + P - 1 {
        fg[i - P + 1] += fg[i];
    }
    for i in 0..P {
        h[i] = f3_freeze(fg[i] as i16);
    }
    fg.zeroize();
}

fn r3_recip(out: &mut [Small; P], inp: &[Small; P]) -> i32 {
    let mut f = [0 as Small; P + 1];
    let mut g = [0 as Small; P + 1];
    let mut v = [0 as Small; P + 1];
    let mut r = [0 as Small; P + 1];
    let mut delta: i32 = 1;
    r[0] = 1;
    f[0] = 1;
    f[P - 1] = -1;
    f[P] = -1;
    for i in 0..P {
        g[P - 1 - i] = inp[i];
    }
    g[P] = 0;
    for _ in 0..2 * P - 1 {
        for i in (1..=P).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;
        let sign = -i32::from(g[0]) * i32::from(f[0]);
        let swap =
            i32::from(int16_negative_mask((-delta) as i16) & int16_nonzero_mask(i16::from(g[0])));
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for i in 0..P + 1 {
            let t = swap & (i32::from(f[i]) ^ i32::from(g[i]));
            f[i] ^= t as Small;
            g[i] ^= t as Small;
            let t = swap & (i32::from(v[i]) ^ i32::from(r[i]));
            v[i] ^= t as Small;
            r[i] ^= t as Small;
        }
        for i in 0..P + 1 {
            g[i] = f3_freeze((i32::from(g[i]) + sign * i32::from(f[i])) as i16);
        }
        for i in 0..P + 1 {
            r[i] = f3_freeze((i32::from(r[i]) + sign * i32::from(v[i])) as i16);
        }
        for i in 0..P {
            g[i] = g[i + 1];
        }
        g[P] = 0;
    }
    let sign = i32::from(f[0]);
    for i in 0..P {
        out[i] = (sign * i32::from(v[P - 1 - i])) as Small;
    }
    f.zeroize();
    g.zeroize();
    v.zeroize();
    r.zeroize();
    i32::from(int16_nonzero_mask(delta as i16))
}

fn rq_mult_small(h: &mut [Fq; P], f: &[Fq; P], g: &[Small; P]) {
    let mut fg = [0i32; P + P - 1];
    for i in 0..P {
        for j in 0..P {
            fg[i + j] += i32::from(f[i]) * i32::from(g[j]);
        }
    }
    for i in P..P + P - 1 {
        fg[i - P] += fg[i];
    }
    for i in P..P + P - 1 {
        fg[i - P + 1] += fg[i];
    }
    for i in 0..P {
        h[i] = fq_freeze(fg[i]);
    }
    fg.zeroize();
}

fn rq_mult3(h: &mut [Fq; P], f: &[Fq; P]) {
    for i in 0..P {
        h[i] = fq_freeze(3 * i32::from(f[i]));
    }
}

fn fq_recip(a1: Fq) -> Fq {
    let mut i = 1;
    let mut ai = a1;
    while i < Q - 2 {
        ai = fq_freeze(i32::from(a1) * i32::from(ai));
        i += 1;
    }
    ai
}

fn rq_recip3(out: &mut [Fq; P], inp: &[Small; P]) -> i32 {
    let mut f = [0 as Fq; P + 1];
    let mut g = [0 as Fq; P + 1];
    let mut v = [0 as Fq; P + 1];
    let mut r = [0 as Fq; P + 1];
    let mut delta: i32 = 1;
    r[0] = fq_recip(3);
    f[0] = 1;
    f[P - 1] = -1;
    f[P] = -1;
    for i in 0..P {
        g[P - 1 - i] = Fq::from(inp[i]);
    }
    g[P] = 0;
    for _ in 0..2 * P - 1 {
        for i in (1..=P).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;
        let swap = i32::from(int16_negative_mask((-delta) as i16) & int16_nonzero_mask(g[0]));
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for i in 0..P + 1 {
            let t = swap & (i32::from(f[i]) ^ i32::from(g[i]));
            f[i] ^= t as Fq;
            g[i] ^= t as Fq;
            let t = swap & (i32::from(v[i]) ^ i32::from(r[i]));
            v[i] ^= t as Fq;
            r[i] ^= t as Fq;
        }
        let f0 = i32::from(f[0]);
        let g0 = i32::from(g[0]);
        for i in 0..P + 1 {
            g[i] = fq_freeze(f0 * i32::from(g[i]) - g0 * i32::from(f[i]));
        }
        for i in 0..P + 1 {
            r[i] = fq_freeze(f0 * i32::from(r[i]) - g0 * i32::from(v[i]));
        }
        for i in 0..P {
            g[i] = g[i + 1];
        }
        g[P] = 0;
    }
    let scale = fq_recip(f[0]);
    for i in 0..P {
        out[i] = fq_freeze(i32::from(scale) * i32::from(v[P - 1 - i]));
    }
    f.zeroize();
    g.zeroize();
    v.zeroize();
    r.zeroize();
    i32::from(int16_nonzero_mask(delta as i16))
}

fn round(out: &mut [Fq; P], a: &[Fq; P]) {
    for i in 0..P {
        out[i] = (i32::from(a[i]) - i32::from(f3_freeze(a[i]))) as Fq;
    }
}

fn short_fromlist(out: &mut [Small; P], inp: &[u32; P]) {
    let mut l = [0u32; P];
    for i in 0..W {
        l[i] = inp[i] & !1u32;
    }
    for i in W..P {
        l[i] = (inp[i] & !3u32) | 1;
    }
    crypto_sort_uint32(&mut l);
    for i in 0..P {
        out[i] = ((l[i] & 3) as i32 - 1) as Small;
    }
    l.zeroize();
}

fn hash_prefix(out: &mut [u8; HASH_BYTES], b: u8, inp: &[u8]) {
    let mut h = Sha512::new();
    h.update([b]);
    h.update(inp);
    let mut d = h.finalize();
    out.copy_from_slice(&d[..HASH_BYTES]);
    d.as_mut_slice().zeroize();
}

fn urandom32(rng: &mut dyn FnMut(&mut [u8])) -> u32 {
    let mut c = [0u8; 4];
    rng(&mut c);
    let r = u32::from_le_bytes(c);
    c.zeroize();
    r
}

fn short_random(out: &mut [Small; P], rng: &mut dyn FnMut(&mut [u8])) {
    let mut l = [0u32; P];
    for v in l.iter_mut() {
        *v = urandom32(rng);
    }
    short_fromlist(out, &l);
    l.zeroize();
}

fn small_random(out: &mut [Small; P], rng: &mut dyn FnMut(&mut [u8])) {
    for v in out.iter_mut() {
        *v = ((((urandom32(rng) & 0x3fff_ffff) * 3) >> 30) as i32 - 1) as Small;
    }
}

fn key_gen(
    h: &mut [Fq; P],
    f: &mut [Small; P],
    ginv: &mut [Small; P],
    rng: &mut dyn FnMut(&mut [u8]),
) {
    let mut g = [0 as Small; P];
    let mut finv = [0 as Fq; P];
    loop {
        small_random(&mut g, rng);
        if r3_recip(ginv, &g) == 0 {
            break;
        }
    }
    short_random(f, rng);
    rq_recip3(&mut finv, f);
    rq_mult_small(h, &finv, &g);
    g.zeroize();
    finv.zeroize();
}

fn encrypt(c: &mut [Fq; P], r: &[Small; P], h: &[Fq; P]) {
    let mut hr = [0 as Fq; P];
    rq_mult_small(&mut hr, h, r);
    round(c, &hr);
    hr.zeroize();
}

fn decrypt(r: &mut [Small; P], c: &[Fq; P], f: &[Small; P], ginv: &[Small; P]) {
    let mut cf = [0 as Fq; P];
    let mut cf3 = [0 as Fq; P];
    let mut e = [0 as Small; P];
    let mut ev = [0 as Small; P];
    rq_mult_small(&mut cf, c, f);
    rq_mult3(&mut cf3, &cf);
    r3_from_rq(&mut e, &cf3);
    r3_mult(&mut ev, &e, ginv);
    let mask = weightw_mask(&ev);
    for i in 0..W {
        r[i] = (((i32::from(ev[i]) ^ 1) & !mask) ^ 1) as Small;
    }
    for i in W..P {
        r[i] = (i32::from(ev[i]) & !mask) as Small;
    }
    cf.zeroize();
    cf3.zeroize();
    e.zeroize();
    ev.zeroize();
}

fn small_encode(s: &mut [u8], f: &[Small; P]) {
    for i in 0..P / 4 {
        let mut x: u8 = 0;
        for j in 0..4 {
            x = x.wrapping_add(((f[4 * i + j] + 1) as u8) << (2 * j));
        }
        s[i] = x;
    }
    s[P / 4] = (f[P - 1] + 1) as u8;
}

fn small_decode(f: &mut [Small; P], s: &[u8]) {
    for i in 0..P / 4 {
        let x = s[i];
        for j in 0..4 {
            f[4 * i + j] = ((x >> (2 * j)) & 3) as Small - 1;
        }
    }
    f[P - 1] = (s[P / 4] & 3) as Small - 1;
}

fn rq_encode(s: &mut Vec<u8>, r: &[Fq; P]) {
    let mut rr = [0u16; P];
    let m = [Q as u16; P];
    for i in 0..P {
        rr[i] = (i32::from(r[i]) + Q12) as u16;
    }
    encode(s, &rr, &m);
}

fn rq_decode(r: &mut [Fq; P], s: &[u8]) {
    let mut rr = [0u16; P];
    let m = [Q as u16; P];
    decode(&mut rr, s, &m);
    for i in 0..P {
        r[i] = (i32::from(rr[i]) - Q12) as Fq;
    }
}

fn rounded_encode(s: &mut Vec<u8>, r: &[Fq; P]) {
    let mut rr = [0u16; P];
    let m = [((Q + 2) / 3) as u16; P];
    for i in 0..P {
        rr[i] = (((i32::from(r[i]) + Q12) * 10923) >> 15) as u16;
    }
    encode(s, &rr, &m);
    rr.zeroize();
}

fn rounded_decode(r: &mut [Fq; P], s: &[u8]) {
    let mut rr = [0u16; P];
    let m = [((Q + 2) / 3) as u16; P];
    decode(&mut rr, s, &m);
    for i in 0..P {
        r[i] = (i32::from(rr[i]) * 3 - Q12) as Fq;
    }
    rr.zeroize();
}

fn zkeygen(pk: &mut Vec<u8>, sk: &mut [u8], rng: &mut dyn FnMut(&mut [u8])) {
    let mut h = [0 as Fq; P];
    let mut f = [0 as Small; P];
    let mut v = [0 as Small; P];
    key_gen(&mut h, &mut f, &mut v, rng);
    rq_encode(pk, &h);
    small_encode(&mut sk[..SMALL_BYTES], &f);
    small_encode(&mut sk[SMALL_BYTES..SECRETKEYS_BYTES], &v);
    f.zeroize();
    v.zeroize();
}

fn zencrypt(c: &mut Vec<u8>, r: &[Small; P], pk: &[u8]) {
    let mut h = [0 as Fq; P];
    let mut cc = [0 as Fq; P];
    rq_decode(&mut h, pk);
    encrypt(&mut cc, r, &h);
    rounded_encode(c, &cc);
    cc.zeroize();
}

fn zdecrypt(r: &mut [Small; P], c: &[u8], sk: &[u8]) {
    let mut f = [0 as Small; P];
    let mut v = [0 as Small; P];
    let mut cc = [0 as Fq; P];
    small_decode(&mut f, &sk[..SMALL_BYTES]);
    small_decode(&mut v, &sk[SMALL_BYTES..]);
    rounded_decode(&mut cc, c);
    decrypt(r, &cc, &f, &v);
    f.zeroize();
    v.zeroize();
    cc.zeroize();
}

fn hash_confirm(h: &mut [u8; HASH_BYTES], r: &[u8], cache: &[u8]) {
    let mut x = [0u8; HASH_BYTES * 2];
    let mut first = [0u8; HASH_BYTES];
    hash_prefix(&mut first, 3, r);
    x[..HASH_BYTES].copy_from_slice(&first);
    x[HASH_BYTES..].copy_from_slice(&cache[..HASH_BYTES]);
    hash_prefix(h, 2, &x);
    x.zeroize();
    first.zeroize();
}

fn hash_session(k: &mut [u8; HASH_BYTES], b: u8, y: &[u8], z: &[u8]) {
    let mut x = Zeroizing::new(vec![0u8; HASH_BYTES + CIPHERTEXTBYTES]);
    let mut first = [0u8; HASH_BYTES];
    hash_prefix(&mut first, 3, y);
    x[..HASH_BYTES].copy_from_slice(&first);
    x[HASH_BYTES..].copy_from_slice(&z[..CIPHERTEXTBYTES]);
    hash_prefix(k, b, &x);
    first.zeroize();
}

/// Generates a key pair, drawing randomness from `rng` exactly as the C code
/// calls randombytes(). Returns (public key, secret key).
pub(crate) fn keypair(rng: &mut dyn FnMut(&mut [u8])) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut pk = Vec::with_capacity(PUBLICKEYBYTES);
    let mut sk = Zeroizing::new(vec![0u8; SECRETKEYBYTES]);
    zkeygen(&mut pk, &mut sk, rng);
    debug_assert_eq!(pk.len(), PUBLICKEYBYTES);
    let off = SECRETKEYS_BYTES;
    sk[off..off + PUBLICKEYBYTES].copy_from_slice(&pk);
    let off = off + PUBLICKEYBYTES;
    rng(&mut sk[off..off + SMALL_BYTES]);
    let mut cache = [0u8; HASH_BYTES];
    hash_prefix(&mut cache, 4, &pk);
    sk[off + SMALL_BYTES..].copy_from_slice(&cache);
    (pk, sk)
}

fn hide(c: &mut Vec<u8>, r_enc: &mut [u8; SMALL_BYTES], r: &[Small; P], pk: &[u8], cache: &[u8]) {
    small_encode(r_enc, r);
    c.clear();
    zencrypt(c, r, pk);
    debug_assert_eq!(c.len(), ROUNDED_BYTES);
    let mut confirm = [0u8; HASH_BYTES];
    hash_confirm(&mut confirm, r_enc, cache);
    c.extend_from_slice(&confirm);
}

/// Encapsulates to `pk` (PUBLICKEYBYTES long). Returns (ciphertext, key).
pub(crate) fn enc(pk: &[u8], rng: &mut dyn FnMut(&mut [u8])) -> (Vec<u8>, Zeroizing<[u8; BYTES]>) {
    assert_eq!(pk.len(), PUBLICKEYBYTES);
    let mut r = [0 as Small; P];
    let mut r_enc = [0u8; SMALL_BYTES];
    let mut cache = [0u8; HASH_BYTES];
    hash_prefix(&mut cache, 4, pk);
    short_random(&mut r, rng);
    let mut c = Vec::with_capacity(CIPHERTEXTBYTES);
    hide(&mut c, &mut r_enc, &r, pk, &cache);
    let mut k = Zeroizing::new([0u8; BYTES]);
    hash_session(&mut k, 1, &r_enc, &c);
    r.zeroize();
    r_enc.zeroize();
    (c, k)
}

fn ciphertexts_diff_mask(c: &[u8], c2: &[u8]) -> i32 {
    let mut differentbits: u16 = 0;
    for (a, b) in c.iter().zip(c2.iter()) {
        differentbits |= u16::from(a ^ b);
    }
    ((((i64::from(differentbits) - 1) >> 8) & 1) - 1) as i32
}

/// Decapsulates `c` (CIPHERTEXTBYTES long) with `sk` (SECRETKEYBYTES long).
/// A ciphertext that does not re-encrypt to itself yields a pseudorandom key
/// derived from the secret rho (implicit rejection), as in the C code.
pub(crate) fn dec(c: &[u8], sk: &[u8]) -> Zeroizing<[u8; BYTES]> {
    assert_eq!(c.len(), CIPHERTEXTBYTES);
    assert_eq!(sk.len(), SECRETKEYBYTES);
    let pk = &sk[SECRETKEYS_BYTES..SECRETKEYS_BYTES + PUBLICKEYBYTES];
    let rho =
        &sk[SECRETKEYS_BYTES + PUBLICKEYBYTES..SECRETKEYS_BYTES + PUBLICKEYBYTES + SMALL_BYTES];
    let cache = &sk[SECRETKEYS_BYTES + PUBLICKEYBYTES + SMALL_BYTES..];
    let mut r = [0 as Small; P];
    let mut r_enc = [0u8; SMALL_BYTES];
    let mut cnew = Vec::with_capacity(CIPHERTEXTBYTES);
    zdecrypt(&mut r, c, sk);
    hide(&mut cnew, &mut r_enc, &r, pk, cache);
    let mask = ciphertexts_diff_mask(c, &cnew);
    for i in 0..SMALL_BYTES {
        r_enc[i] ^= (mask & i32::from(r_enc[i] ^ rho[i])) as u8;
    }
    let mut k = Zeroizing::new([0u8; BYTES]);
    hash_session(&mut k, (1 + mask) as u8, &r_enc, c);
    r.zeroize();
    r_enc.zeroize();
    cnew.zeroize();
    k
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The deterministic randombytes of the C harness that produced the
    /// vectors: the stream SHA-512(seed || le32(j)) for j = 0, 1, 2, ...
    struct Stream {
        seed: Vec<u8>,
        block: [u8; 64],
        ctr: u32,
        pos: usize,
        total: usize,
    }

    impl Stream {
        fn new(seed: &str) -> Self {
            Stream {
                seed: seed.as_bytes().to_vec(),
                block: [0; 64],
                ctr: 0,
                pos: 64,
                total: 0,
            }
        }

        fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                if self.pos == 64 {
                    let mut h = Sha512::new();
                    h.update(&self.seed);
                    h.update(self.ctr.to_le_bytes());
                    self.block.copy_from_slice(&h.finalize());
                    self.ctr += 1;
                    self.pos = 0;
                }
                *b = self.block[self.pos];
                self.pos += 1;
                self.total += 1;
            }
        }
    }

    fn sha512_hex(b: &[u8]) -> String {
        hex(&Sha512::digest(b))
    }

    /// Known answers from OpenSSH 10.0's sntrup761.c compiled with the
    /// deterministic randombytes above (seeds "reach sntrup761 kat N"): the
    /// SHA-512 of the public key, secret key and ciphertext, the encapsulated
    /// and decapsulated keys, and the key decapsulated from the ciphertext
    /// with its first bit flipped (implicit rejection).
    const KAT: &[[&str; 6]] = &[
        [
            "597101fee410d1a3303ba897b42c1dd145792e5aa203c868771718f865d57880aa4f1322aabc6516e1a500a9062c67ede5042ea5bc15813a9b4b192d59b1a568",
            "aa6a04dfedbd0c83686580e15dfcb712c7f9041141117e12d5453e01c87e8dde757fbde67a22eda0bc001b5e466070f67766d578be223994f18b17a96b557ae2",
            "9d4bd929677894720d751523be604764cd9a119a7e10c056a6e0833fe78bc2ab4aa567dbe2b9fc42a36ecd5e26276116662186350cb4ad38dfb061307e614d7f",
            "83efc9cc0a60166f3e38fc3f13f062e284d0cb3047fa6d26319b9a99a254b27f",
            "83efc9cc0a60166f3e38fc3f13f062e284d0cb3047fa6d26319b9a99a254b27f",
            "459b8fda2a5d122baaab2944c2918cfda5858c97dd56381257eac7a9549c597d",
        ],
        [
            "79861eb4d22015a6d4a52657e378a7ff506db3dc455183d2ccdb6b4ac24c82013aac26cf12ecfada27db2be2e5f7628e241ca64c44fa82b8bc4e431bd2d86a04",
            "417cac759eb5f9ec570eafb9088f23fc36e34a5e8ad76eba85e90844dc6b3a24acfc95bc0a274ae4dbcbb3bbd469bb8a540a76d609419211c8670f93a2a521d9",
            "a61938b191e55b7e7e6016da728966e7a30cdc40c0aa948e74a5e68c6d0429fef2e0875596fb20ea2fd93bedc722c2754fe4a0b8e1cf69c6177b50aae03686d4",
            "0420fab273dda98b20380b8796f3506d5e21c6c2cdee527ebb1e6e0643b715b4",
            "0420fab273dda98b20380b8796f3506d5e21c6c2cdee527ebb1e6e0643b715b4",
            "df42ead65c9856239863607526c55a08714a69cc060f2237430aef7dcd623094",
        ],
        [
            "d548cae841ff02186aa2340ab6e9520adf6866713626437724adbaa66aeff86ff3d2e5dd776d13125c43e5c835a7becd02cdd66993a4a8de4115559f09e131e9",
            "3ef6c61402736f1dc32465d6b81619a3318f3f8efe9685d0648a6d8dc1817d2129e5aa11664312884fa2d4194fa60ebdd9bd02267a067575ae690ece0d895882",
            "75f21ec11753cf13b274c4d98fc2689f398b980b90e150e155d9d9fe5d6759489d4ddb4149feb06b311d29e3d0f0a18b531bbb06d73c29ef211fb86b0e0f16c2",
            "1aaac89948e8a96c1cd3dc0c5d25a7c5b50707a082fa440f844b2110a97e29e2",
            "1aaac89948e8a96c1cd3dc0c5d25a7c5b50707a082fa440f844b2110a97e29e2",
            "743eefb1fb612372ba8a7ebda507f44ce56b48fbddf53894178e4769dbd02da4",
        ],
    ];

    #[test]
    fn matches_openssh_sntrup761_c() {
        for (n, want) in KAT.iter().enumerate() {
            let mut s = Stream::new(&format!("reach sntrup761 kat {n}"));
            let (pk, sk) = keypair(&mut |b: &mut [u8]| s.fill(b));
            // The C code drew 6279 bytes for the key pair and 9323 in all.
            assert_eq!(s.total, 6279, "seed {n}");
            let (mut ct, k_enc) = enc(&pk, &mut |b: &mut [u8]| s.fill(b));
            assert_eq!(s.total, 9323, "seed {n}");
            assert_eq!(pk.len(), PUBLICKEYBYTES);
            assert_eq!(sk.len(), SECRETKEYBYTES);
            assert_eq!(ct.len(), CIPHERTEXTBYTES);
            assert_eq!(sha512_hex(&pk), want[0], "pk, seed {n}");
            assert_eq!(sha512_hex(&sk), want[1], "sk, seed {n}");
            assert_eq!(sha512_hex(&ct), want[2], "ct, seed {n}");
            assert_eq!(hex(&*k_enc), want[3], "enc key, seed {n}");
            assert_eq!(hex(&*dec(&ct, &sk)), want[4], "dec key, seed {n}");
            ct[0] ^= 1;
            assert_eq!(hex(&*dec(&ct, &sk)), want[5], "rejected key, seed {n}");
        }
    }

    #[test]
    fn random_round_trips_agree() {
        let mut rng =
            |b: &mut [u8]| rand_core::Rng::fill_bytes(&mut crate::keys::key::safe_rng(), b);
        for _ in 0..4 {
            let (pk, sk) = keypair(&mut rng);
            let (ct, k) = enc(&pk, &mut rng);
            assert_eq!(*dec(&ct, &sk), *k);
            let mut bad = ct.clone();
            bad[CIPHERTEXTBYTES - 1] ^= 0x40;
            assert_ne!(*dec(&bad, &sk), *k);
        }
    }

    #[test]
    fn sort_matches_std_sort() {
        let mut s = Stream::new("sort");
        for len in [0usize, 1, 2, 3, 5, 8, 13, 100, 761] {
            let mut v: Vec<i32> = (0..len)
                .map(|_| {
                    let mut b = [0u8; 4];
                    s.fill(&mut b);
                    i32::from_le_bytes(b)
                })
                .collect();
            if len > 3 {
                v[1] = i32::MIN;
                v[2] = i32::MAX;
                v[3] = v[0];
            }
            let mut want = v.clone();
            want.sort();
            crypto_sort_int32(&mut v);
            assert_eq!(v, want, "len {len}");
        }
    }
}
