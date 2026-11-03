//! OpenSSH extensions for the client, as OpenSSH's ssh speaks them
//! (PROTOCOL in openssh-portable): proving announced host keys
//! (hostkeys-prove-00@openssh.com, for UpdateHostKeys), tunnel channels
//! (tun@openssh.com), and hostbased authentication (RFC 4252 section 9).

use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, PublicKey, Signature};
use tokio::sync::{mpsc::channel, oneshot};

use super::{AuthResult, Handle, Handler, Msg, Reply, Session};
use crate::channels::{Channel, ChannelRef};
use crate::session::GlobalRequestResponse;
use crate::{auth, msg, Error, MethodSet};

/// What became of one key the server was asked to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyProof {
    /// The server signed with it: it holds the private half.
    Proven,
    /// An RSA key signed with an algorithm OpenSSH does not trust for
    /// proofs (neither rsa-sha2-512 nor rsa-sha2-256, and no RSA host key
    /// was negotiated). ssh leaves such a key out without failing the rest.
    Disregarded,
}

/// One key of a hostkeys-00@openssh.com announcement, kept only when it is
/// a key type russh knows (OpenSSH skips unknown types) and re-encodes to
/// exactly the bytes the server sent, so the key proven and recorded is the
/// one announced, byte for byte.
pub(crate) fn announced_host_key(blob: &[u8]) -> Option<PublicKey> {
    let key = match crate::keys::key::parse_public_key(blob) {
        Ok(k) => k,
        Err(e) => {
            log::debug!("announced host key not understood: {e:?}");
            return None;
        }
    };
    if matches!(key.algorithm(), Algorithm::Other(_)) {
        log::debug!("announced host key of unknown type {}", key.algorithm());
        return None;
    }
    if key.to_bytes().ok().as_deref() != Some(blob) {
        log::debug!("announced {} host key is not in canonical form, skipped", key.algorithm());
        return None;
    }
    Some(key)
}

/// The RSA signature algorithms OpenSSH accepts for a proof when the key
/// exchange did not use an RSA host key (HOSTKEY_PROOF_RSA_ALGS).
fn trusted_rsa_proof(alg: &Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha512) | Some(ssh_key::HashAlg::Sha256)
        }
    )
}

/// The data a proof signs: the string "hostkeys-prove-00@openssh.com", the
/// session identifier and the key blob, each as an SSH string.
pub(crate) fn host_key_proof_data(session_id: &[u8], key: &PublicKey) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    "hostkeys-prove-00@openssh.com".encode(&mut data)?;
    session_id.encode(&mut data)?;
    key.to_bytes()?.encode(&mut data)?;
    Ok(data)
}

/// Checks the signatures in a hostkeys-prove reply, one per key in the
/// order asked, as client_global_hostkeys_prove_confirm does. Any bad or
/// unreadable signature fails the whole reply.
pub(crate) fn check_proofs(
    session_id: &[u8],
    negotiated: Option<&Algorithm>,
    keys: &[PublicKey],
    r: &mut &[u8],
) -> Result<Vec<HostKeyProof>, Error> {
    // An RSA host key in the key exchange: its signature type is the one
    // RSA proofs must use.
    let rsa_kexalg = negotiated.filter(|a| matches!(a, Algorithm::Rsa { .. }));
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let data = host_key_proof_data(session_id, key)?;
        let blob = Vec::<u8>::decode(r)?;
        let mut sr = &blob[..];
        let sig = Signature::decode(&mut sr)?;
        crate::parsing::ensure_end(&sr)?;
        let is_rsa = matches!(key.algorithm(), Algorithm::Rsa { .. });
        if is_rsa {
            match rsa_kexalg {
                None if !trusted_rsa_proof(&sig.algorithm()) => {
                    log::debug!(
                        "server used untrusted RSA signature algorithm {} for a host key proof, disregarding",
                        sig.algorithm()
                    );
                    out.push(HostKeyProof::Disregarded);
                    continue;
                }
                Some(want) if *want != sig.algorithm() => return Err(Error::WrongServerSig),
                _ => {}
            }
        }
        if signature::Verifier::verify(key, &data, &sig).is_err() {
            log::debug!("server gave bad signature for {} host key", key.algorithm());
            return Err(Error::WrongServerSig);
        }
        out.push(HostKeyProof::Proven);
    }
    crate::parsing::ensure_end(r)?;
    Ok(out)
}

impl Session {
    pub(crate) fn request_host_key_proofs(
        &mut self,
        keys: Vec<PublicKey>,
        reply: oneshot::Sender<Result<Vec<HostKeyProof>, Error>>,
    ) -> Result<(), Error> {
        let Some(ref mut enc) = self.common.encrypted else {
            let _ = reply.send(Err(Error::Inconsistent));
            return Ok(());
        };
        push_packet!(enc.write, {
            msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
            "hostkeys-prove-00@openssh.com".encode(&mut enc.write)?;
            1u8.encode(&mut enc.write)?;
            for k in &keys {
                k.to_bytes()?.encode(&mut enc.write)?;
            }
        });
        self.open_global_requests
            .push_back(GlobalRequestResponse::HostKeysProve(keys, reply));
        Ok(())
    }

    /// Ask the server to prove it holds the private halves of `keys`
    /// (hostkeys-prove-00@openssh.com), as ssh does for the new keys of a
    /// hostkeys-00@openssh.com announcement. Usable from inside a
    /// [`Handler`] callback: await the receiver elsewhere (a spawned task),
    /// since the reply is read by this session's own loop. Each signature
    /// is checked over the proof string, the session identifier and the key.
    pub fn prove_host_keys(
        &mut self,
        keys: Vec<PublicKey>,
    ) -> Result<oneshot::Receiver<Result<Vec<HostKeyProof>, Error>>, Error> {
        let (tx, rx) = oneshot::channel();
        self.request_host_key_proofs(keys, tx)?;
        Ok(rx)
    }

    pub(crate) fn check_host_key_proofs(
        &self,
        keys: &[PublicKey],
        r: &mut &[u8],
    ) -> Result<Vec<HostKeyProof>, Error> {
        let enc = self.common.encrypted.as_ref().ok_or(Error::Inconsistent)?;
        check_proofs(&enc.session_id, self.host_key_algorithm.as_ref(), keys, r)
    }
}

/// The data a hostbased request signs (RFC 4252 section 9, as
/// userauth_hostbased builds it): the session identifier, then the request
/// itself without the signature.
pub(crate) fn hostbased_data(
    session_id: &[u8],
    user: &str,
    algorithm: &str,
    key_blob: &[u8],
    client_host: &str,
    client_user: &str,
) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    session_id.encode(&mut b)?;
    b.push(msg::USERAUTH_REQUEST);
    user.encode(&mut b)?;
    "ssh-connection".encode(&mut b)?;
    "hostbased".encode(&mut b)?;
    algorithm.encode(&mut b)?;
    key_blob.encode(&mut b)?;
    client_host.encode(&mut b)?;
    client_user.encode(&mut b)?;
    Ok(b)
}

impl<H: Handler> Handle<H> {
    /// Ask the server to prove it holds the private halves of `keys`; see
    /// [`Session::prove_host_keys`]. Not for use inside a handler callback.
    pub async fn prove_host_keys(&self, keys: Vec<PublicKey>) -> Result<Vec<HostKeyProof>, Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Msg::ProveHostKeys {
                keys,
                reply_channel: tx,
            })
            .await
            .map_err(|_| Error::SendError)?;
        rx.await.map_err(|_| Error::Disconnect)?
    }

    /// Open a tun@openssh.com channel, as ssh -w does: `mode` 1 forwards
    /// layer 3 packets (point-to-point), 2 layer 2 frames (ethernet);
    /// `remote_unit` is the server's tun unit, 0x7fffffff for any.
    pub async fn channel_open_tun(&self, mode: u32, remote_unit: u32) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();
        self.sender
            .send(Msg::ChannelOpenTun {
                mode,
                remote_unit,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref).await
    }

    /// Hostbased authentication (RFC 4252 section 9). `algorithm` is the
    /// signature algorithm (rsa-sha2-512 for an RSA host key, say),
    /// `key_blob` the host's public key (or certificate), `client_host` the
    /// client's host name with a trailing dot, `client_user` the local user.
    /// russh builds the data to sign and `signer` signs it, as ssh-keysign
    /// does for OpenSSH. There is no probe: the signed request goes at once.
    pub async fn authenticate_hostbased_with<U: Into<String>, S: auth::HostbasedSigner>(
        &mut self,
        user: U,
        algorithm: &str,
        key_blob: Vec<u8>,
        client_host: &str,
        client_user: &str,
        signer: &mut S,
    ) -> Result<AuthResult, S::Error> {
        let user = user.into();
        let failed = AuthResult::Failure {
            remaining_methods: MethodSet::empty(),
            partial_success: false,
        };
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Msg::GetSessionId { reply_channel: tx })
            .await
            .is_err()
        {
            return Err((crate::SendError {}).into());
        }
        let Ok(Some(session_id)) = rx.await else {
            return Ok(failed);
        };
        let Ok(data) = hostbased_data(&session_id, &user, algorithm, &key_blob, client_host, client_user)
        else {
            return Ok(failed);
        };
        let signature = signer.sign_hostbased(data).await?;
        if self
            .sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::Hostbased {
                    algorithm: algorithm.to_string(),
                    key_blob,
                    client_host: client_host.to_string(),
                    client_user: client_user.to_string(),
                    signature,
                },
            })
            .await
            .is_err()
        {
            return Err((crate::SendError {}).into());
        }
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: proceed_with_methods,
                        partial_success,
                    });
                }
                None => return Ok(failed),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer as _;

    fn ed25519(seed: u8) -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn reply(sigs: &[Signature]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in sigs {
            let mut blob = Vec::new();
            s.encode(&mut blob).unwrap();
            blob.as_slice().encode(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn proofs_are_checked_over_session_and_key() {
        let sid = [7u8; 32];
        let (a, b) = (ed25519(1), ed25519(2));
        let keys = vec![a.public_key().clone(), b.public_key().clone()];
        let sig = |k: &ssh_key::PrivateKey, sid: &[u8]| -> Signature {
            k.try_sign(&host_key_proof_data(sid, k.public_key()).unwrap()).unwrap()
        };
        let good = reply(&[sig(&a, &sid), sig(&b, &sid)]);
        assert_eq!(
            check_proofs(&sid, None, &keys, &mut &good[..]).unwrap(),
            vec![HostKeyProof::Proven, HostKeyProof::Proven]
        );
        // Signed for another session: refused.
        let other = reply(&[sig(&a, &[8u8; 32]), sig(&b, &sid)]);
        assert!(check_proofs(&sid, None, &keys, &mut &other[..]).is_err());
        // Swapped: each signature must be by its own key.
        let swapped = reply(&[sig(&b, &sid), sig(&a, &sid)]);
        assert!(check_proofs(&sid, None, &keys, &mut &swapped[..]).is_err());
        // Missing one, or one too many.
        let short = reply(&[sig(&a, &sid)]);
        assert!(check_proofs(&sid, None, &keys, &mut &short[..]).is_err());
        let long = reply(&[sig(&a, &sid), sig(&b, &sid), sig(&b, &sid)]);
        assert!(check_proofs(&sid, None, &keys, &mut &long[..]).is_err());
    }

    #[test]
    fn announced_keys_must_be_canonical_and_known() {
        let k = ed25519(3);
        let blob = k.public_key().to_bytes().unwrap();
        assert!(announced_host_key(&blob).is_some());
        // Trailing bytes after a valid key: the bytes would differ from
        // what is proven and recorded, so the key is left out.
        let mut extra = blob.clone();
        extra.extend_from_slice(&[0, 0, 0, 1, 7]);
        assert!(announced_host_key(&extra).is_none());
        // A type russh does not know (a certificate, say) is skipped.
        let mut cert = Vec::new();
        "ssh-ed25519-cert-v01@openssh.com".encode(&mut cert).unwrap();
        b"nonce".as_slice().encode(&mut cert).unwrap();
        assert!(announced_host_key(&cert).is_none());
        assert!(announced_host_key(b"junk").is_none());
    }

    #[test]
    fn hostbased_data_layout() {
        let d = hostbased_data(&[1, 2], "u", "ssh-ed25519", &[9], "h.", "l").unwrap();
        let mut r = &d[..];
        assert_eq!(Vec::<u8>::decode(&mut r).unwrap(), vec![1, 2]);
        assert_eq!(u8::decode(&mut r).unwrap(), msg::USERAUTH_REQUEST);
        for want in ["u", "ssh-connection", "hostbased", "ssh-ed25519"] {
            assert_eq!(String::decode(&mut r).unwrap(), want);
        }
        assert_eq!(Vec::<u8>::decode(&mut r).unwrap(), vec![9]);
        assert_eq!(String::decode(&mut r).unwrap(), "h.");
        assert_eq!(String::decode(&mut r).unwrap(), "l");
        assert!(r.is_empty());
    }
}
