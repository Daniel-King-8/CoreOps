//! `sntrup761x25519-sha512` (and its older name with `@openssh.com`), as in
//! OpenSSH's kexsntrup761x25519.c and draft-josefsson-ntruprime-ssh.
//!
//! The client sends its sntrup761 public key followed by an X25519 public key
//! in SSH_MSG_KEX_ECDH_INIT; the server answers with an sntrup761 ciphertext
//! followed by its X25519 public key in SSH_MSG_KEX_ECDH_REPLY. The shared
//! secret is SHA-512(sntrup761 key || X25519 shared secret), encoded as an SSH
//! string, and SHA-512 is the exchange hash. Built like the ML-KEM hybrid in
//! hybrid_mlkem.rs.

use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::montgomery::MontgomeryPoint;
use log::debug;
use rand_core::Rng;
use sha2::Digest;
use ssh_encoding::{Encode, Writer};
use zeroize::Zeroizing;

use super::sntrup761::{self, CIPHERTEXTBYTES, PUBLICKEYBYTES};
use super::{KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret, compute_keys};
use crate::keys::key::safe_rng;
use crate::mac;
use crate::session::Exchange;
use crate::{CryptoVec, Error, cipher, msg};

const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub struct Sntrup761X25519KexType {}

impl KexType for Sntrup761X25519KexType {
    fn make(&self) -> KexAlgorithm {
        Sntrup761X25519Kex {
            sntrup_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        }
        .into()
    }
}

#[doc(hidden)]
pub struct Sntrup761X25519Kex {
    sntrup_secret: Option<Zeroizing<Vec<u8>>>,
    x25519_secret: Option<Zeroizing<[u8; 32]>>,
    k_pq: Option<Zeroizing<[u8; sntrup761::BYTES]>>,
    k_cl: Option<MontgomeryPoint>,
}

impl std::fmt::Debug for Sntrup761X25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Sntrup761X25519Kex {{ sntrup_secret: [hidden], x25519_secret: [hidden], k_pq: [hidden], k_cl: [hidden] }}",
        )
    }
}

fn fill_random(b: &mut [u8]) {
    safe_rng().fill_bytes(b)
}

impl Sntrup761X25519Kex {
    /// SHA-512(k_pq || k_cl), the 64 bytes that become the shared secret.
    fn combined_secret(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let k_pq = self.k_pq.as_ref().ok_or(Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(Error::KexInit)?;
        let mut hasher = sha2::Sha512::new();
        hasher.update(&k_pq[..]);
        hasher.update(k_cl.0);
        Ok(Zeroizing::new(hasher.finalize().to_vec()))
    }
}

impl KexAlgorithmImplementor for Sntrup761X25519Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        debug!("server_dh (hybrid sntrup761)");

        if payload.first() != Some(&msg::KEX_ECDH_INIT) {
            return Err(Error::Inconsistent);
        }
        if payload.len() < 5 {
            return Err(Error::Inconsistent);
        }

        #[allow(clippy::indexing_slicing)]
        let c_init_len = BigEndian::read_u32(&payload[1..]) as usize;

        if payload.len() < 5 + c_init_len {
            return Err(Error::Inconsistent);
        }
        if c_init_len != PUBLICKEYBYTES + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }

        #[allow(clippy::indexing_slicing)]
        let c_init = &payload[5..5 + c_init_len];
        #[allow(clippy::indexing_slicing)]
        let (c_pk_sntrup, c_pk_x25519) = c_init.split_at(PUBLICKEYBYTES);

        let (s_ct, k_pq) = sntrup761::enc(c_pk_sntrup, &mut fill_random);

        let mut c_pk1 = MontgomeryPoint([0; 32]);
        c_pk1.0.copy_from_slice(c_pk_x25519);
        let s_secret = Zeroizing::new(rand::random::<[u8; 32]>());
        let s_pk1 = MontgomeryPoint::mul_base_clamped(*s_secret);
        let k_cl = c_pk1.mul_clamped(*s_secret);
        if k_cl.0 == [0u8; 32] {
            debug!("client sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend_from_slice(&s_ct);
        exchange.server_ephemeral.extend_from_slice(&s_pk1.0);

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let (pk, sk) = sntrup761::keypair(&mut fill_random);

        let x25519_secret = Zeroizing::new(rand::random::<[u8; 32]>());
        let x25519_pk = MontgomeryPoint::mul_base_clamped(*x25519_secret);

        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&pk);
        client_ephemeral.extend_from_slice(&x25519_pk.0);

        msg::KEX_ECDH_INIT.encode(writer)?;
        client_ephemeral.as_slice().encode(writer)?;

        self.sntrup_secret = Some(sk);
        self.x25519_secret = Some(x25519_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        if remote_pubkey_.len() != CIPHERTEXTBYTES + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }
        #[allow(clippy::indexing_slicing)]
        let (s_ct, s_pk_x25519) = remote_pubkey_.split_at(CIPHERTEXTBYTES);

        let sk = self.sntrup_secret.take().ok_or(Error::KexInit)?;
        let k_pq = sntrup761::dec(s_ct, &sk);

        let mut s_pk1 = MontgomeryPoint([0; 32]);
        s_pk1.0.copy_from_slice(s_pk_x25519);
        let x25519_secret = self.x25519_secret.take().ok_or(Error::KexInit)?;
        let k_cl = s_pk1.mul_clamped(*x25519_secret);
        if k_cl.0 == [0u8; 32] {
            debug!("server sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        // As for the ML-KEM hybrid: the X25519 part, the combined secret
        // being derived in compute_keys.
        self.k_cl.as_ref().map(|k| k.0.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);

        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        let k = self.combined_secret()?;
        k.as_slice().encode(buffer)?;

        let mut hasher = sha2::Sha512::new();
        hasher.update(&buffer);
        Ok(hasher.finalize().to_vec())
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error> {
        let k = self.combined_secret()?;
        let shared_secret = SharedSecret::from_string(&k)?;
        compute_keys::<sha2::Sha512>(
            Some(&shared_secret),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn new_kex() -> Sntrup761X25519Kex {
        Sntrup761X25519Kex {
            sntrup_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        }
    }

    #[test]
    fn client_and_server_agree() {
        let mut client = new_kex();
        let mut server = new_kex();
        let mut client_ephemeral = Vec::new();
        let mut init = Vec::new();
        client.client_dh(&mut client_ephemeral, &mut init).unwrap();
        assert_eq!(
            client_ephemeral.len(),
            PUBLICKEYBYTES + X25519_PUBLIC_KEY_SIZE
        );
        assert_eq!(init[0], msg::KEX_ECDH_INIT);

        let mut exchange = Exchange {
            client_id: b"SSH-2.0-Test_Client".to_vec(),
            server_id: b"SSH-2.0-Test_Server".to_vec(),
            client_kex_init: bytes::Bytes::from_static(b"client_kex_init"),
            server_kex_init: bytes::Bytes::from_static(b"server_kex_init"),
            client_ephemeral: client_ephemeral.clone(),
            server_ephemeral: Vec::new(),
            gex: None,
        };
        server.server_dh(&mut exchange, &init).unwrap();
        assert_eq!(
            exchange.server_ephemeral.len(),
            CIPHERTEXTBYTES + X25519_PUBLIC_KEY_SIZE
        );
        client
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        assert_eq!(
            *client.combined_secret().unwrap(),
            *server.combined_secret().unwrap()
        );
        let mut buf = CryptoVec::new();
        let hc = client
            .compute_exchange_hash(b"hostkey", &exchange, &mut buf)
            .unwrap();
        let hs = server
            .compute_exchange_hash(b"hostkey", &exchange, &mut buf)
            .unwrap();
        assert_eq!(hc, hs);
        assert_eq!(hc.len(), 64);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mut client = new_kex();
        let mut e = Vec::new();
        let mut init = Vec::new();
        client.client_dh(&mut e, &mut init).unwrap();
        assert!(client.compute_shared_secret(&[0u8; 100]).is_err());

        let mut server = new_kex();
        let mut bad = Vec::new();
        msg::KEX_ECDH_INIT.encode(&mut bad).unwrap();
        vec![0u8; 100].encode(&mut bad).unwrap();
        assert!(server.server_dh(&mut Exchange::default(), &bad).is_err());
        assert!(
            server
                .server_dh(&mut Exchange::default(), &[30u8, 0, 0])
                .is_err()
        );
    }

    #[test]
    fn rejects_low_order_x25519() {
        let mut client = new_kex();
        let mut e = Vec::new();
        let mut init = Vec::new();
        client.client_dh(&mut e, &mut init).unwrap();
        // A valid-length reply whose X25519 key is the all-zero point.
        let reply = vec![0u8; CIPHERTEXTBYTES + X25519_PUBLIC_KEY_SIZE];
        assert!(client.compute_shared_secret(&reply).is_err());
    }
}
