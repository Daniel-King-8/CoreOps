//! MACs that send only a prefix of an inner MAC's tag, as `hmac-md5-96`,
//! `hmac-sha1-96` and their `-etm@openssh.com` forms do (RFC 2104 section 5,
//! RFC 4253 section 6.4): the full HMAC is computed and its first 12 bytes
//! go on the wire.

use subtle::ConstantTimeEq;

use super::{Mac, MacAlgorithm};

/// Large enough for the longest inner tag, HMAC-SHA-512's.
const MAX_INNER_LEN: usize = 64;

pub struct TruncatedMacAlgorithm<A: MacAlgorithm + 'static> {
    pub(crate) inner: A,
    pub(crate) len: usize,
}

impl<A: MacAlgorithm + 'static> MacAlgorithm for TruncatedMacAlgorithm<A> {
    fn key_len(&self) -> usize {
        self.inner.key_len()
    }

    fn make_mac(&self, key: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(TruncatedMac {
            inner: self.inner.make_mac(key),
            len: self.len,
        })
    }
}

struct TruncatedMac {
    inner: Box<dyn Mac + Send>,
    len: usize,
}

impl TruncatedMac {
    fn full_tag(&self, sequence_number: u32, payload: &[u8]) -> [u8; MAX_INNER_LEN] {
        let mut full = [0u8; MAX_INNER_LEN];
        let n = self.inner.mac_len();
        #[allow(clippy::indexing_slicing)] // n <= MAX_INNER_LEN for every inner MAC
        self.inner.compute(sequence_number, payload, &mut full[..n]);
        full
    }
}

impl Mac for TruncatedMac {
    fn mac_len(&self) -> usize {
        self.len
    }

    fn is_etm(&self) -> bool {
        self.inner.is_etm()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        let full = self.full_tag(sequence_number, payload);
        #[allow(clippy::indexing_slicing)] // len < inner length
        output.copy_from_slice(&full[..self.len]);
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        if mac.len() != self.len {
            return false;
        }
        let full = self.full_tag(sequence_number, payload);
        #[allow(clippy::indexing_slicing)] // len < inner length
        full[..self.len].ct_eq(mac).into()
    }
}
