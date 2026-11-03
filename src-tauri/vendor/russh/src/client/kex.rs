use core::fmt;
use std::cell::RefCell;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use bytes::Bytes;
use log::{debug, error, warn};
use ssh_encoding::{Decode, Encode};
use ssh_key::{Certificate, Mpint, PublicKey, Signature};

use super::IncomingSshPacket;
use crate::client::{Config, NewKeys};
use crate::kex::dh::groups::DhGroup;
use crate::kex::gss::{GssKexContext, GssKexKind, GssKexProvider, KexContext};
use crate::kex::{KEXES, KexAlgorithm, KexAlgorithmImplementor, KexCause, KexProgress};
use crate::keys::key::parse_public_key;
use crate::negotiation::{Names, Select};
use crate::parsing::ensure_end;
use crate::session::Exchange;
use crate::sshbuffer::PacketWriter;
use crate::{CryptoVec, Error, SshId, msg, negotiation, strict_kex_violation};

thread_local! {
    static HASH_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ClientKexState {
    Created,
    WaitingForGexReply {
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForDhReply {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    /// GSS-API key exchange, gss-gex-sha1-: KEXGSS_GROUPREQ sent.
    WaitingForGssGroup {
        names: Names,
        gss: GssKex,
    },
    /// GSS-API key exchange: a token sent, the server's reply awaited.
    WaitingForGss {
        names: Names,
        gss: GssKex,
    },
    WaitingForNewKeys {
        /// None after a GSS-API key exchange: its host key, if the server
        /// sent one, only goes into the exchange hash.
        server_host_key: Option<PublicKey>,
        server_host_certificate: Option<Certificate>,
        newkeys: NewKeys,
        gss_context: Option<KexContext>,
    },
}

/// One GSS-API key exchange in progress (kexgssc.c).
struct GssKex {
    provider: Arc<dyn GssKexProvider>,
    ctx: Box<dyn GssKexContext>,
    kex: KexAlgorithm,
    /// The last GSS_Init_sec_context returned GSS_S_COMPLETE.
    complete: bool,
    /// Nothing sent yet: the first token goes in KEXGSS_INIT.
    first: bool,
    /// KEXGSS_HOSTKEY, at most once.
    host_key: Option<Bytes>,
    /// KEXGSS_COMPLETE: the server's public value and the MIC.
    completed: Option<(Bytes, Bytes)>,
    /// gss-gex-sha1-: what KEXGSS_GROUPREQ asked for.
    gex: Option<crate::client::GexParams>,
}

impl Debug for GssKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GssKex")
            .field("complete", &self.complete)
            .field("first", &self.first)
            .field("host_key", &self.host_key.is_some())
            .finish()
    }
}

fn gss_error(e: impl Into<String>) -> Error {
    let e = e.into();
    error!("GSS-API key exchange: {e}");
    Error::GssKex(e)
}

pub(crate) struct ClientKex {
    exchange: Exchange,
    cause: KexCause,
    state: ClientKexState,
    config: Arc<Config>,
}

impl Debug for ClientKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ClientKex");
        s.field("cause", &self.cause);
        match self.state {
            ClientKexState::Created => {
                s.field("state", &"created");
            }
            ClientKexState::WaitingForGexReply { .. } => {
                s.field("state", &"waiting for GEX response");
            }
            ClientKexState::WaitingForDhReply { .. } => {
                s.field("state", &"waiting for DH response");
            }
            ClientKexState::WaitingForGssGroup { .. } => {
                s.field("state", &"waiting for KEXGSS_GROUP");
            }
            ClientKexState::WaitingForGss { .. } => {
                s.field("state", &"waiting for the server's GSS-API reply");
            }
            ClientKexState::WaitingForNewKeys { .. } => {
                s.field("state", &"waiting for NEWKEYS");
            }
        }
        s.finish()
    }
}

impl ClientKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &SshId,
        server_sshid: &[u8],
        cause: KexCause,
    ) -> Self {
        let exchange = Exchange::new(client_sshid.as_kex_hash_bytes(), server_sshid);
        Self {
            config,
            exchange,
            cause,
            state: ClientKexState::Created,
        }
    }

    /// `Created` is "our KEXINIT is out, the peer's has not arrived".
    pub fn peer_kexinit_received(&self) -> bool {
        !matches!(self.state, ClientKexState::Created)
    }

    /// Whether strict kex was negotiated, as soon as the peer's KEXINIT has
    /// been read (i.e. before the exchange completes).
    pub fn strict_kex(&self) -> bool {
        match self.state {
            ClientKexState::Created => false,
            ClientKexState::WaitingForGexReply { ref names, .. }
            | ClientKexState::WaitingForDhReply { ref names, .. }
            | ClientKexState::WaitingForGssGroup { ref names, .. }
            | ClientKexState::WaitingForGss { ref names, .. } => names.strict_kex(),
            ClientKexState::WaitingForNewKeys { ref newkeys, .. } => newkeys.names.strict_kex(),
        }
    }

    /// A GSS-API key exchange was negotiated and is running.
    pub fn is_gss(&self) -> bool {
        matches!(
            self.state,
            ClientKexState::WaitingForGssGroup { .. } | ClientKexState::WaitingForGss { .. }
        )
    }

    pub fn kexinit(&mut self, output: &mut PacketWriter) -> Result<(), Error> {
        // With GSS-API key exchange offered, the `null` host key goes last
        // (sshconnect2.c ssh_kex2).
        self.exchange.client_kex_init = negotiation::write_kex_with(
            &self.config.preferred,
            output,
            None,
            self.config.gss_kex.is_some(),
        )?;

        Ok(())
    }

    /// The GSS_Init_sec_context loop of kexgss_client: one call, then the
    /// token sent (KEXGSS_INIT the first time, with the public value, then
    /// KEXGSS_CONTINUE), or, complete with nothing to send, the end.
    fn gss_round(
        mut self,
        names: Names,
        mut gss: GssKex,
        input: Option<&[u8]>,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        debug!("Calling gss_init_sec_context");
        let step = gss
            .ctx
            .init(input)
            .map_err(|e| gss_error(format!("gss_init_context failed: {e}")))?;
        if step.complete {
            if !step.mutual {
                return Err(gss_error("Mutual authentication failed"));
            }
            if !step.integ {
                return Err(gss_error("Integrity check failed"));
            }
        }
        gss.complete = step.complete;
        if !step.token.is_empty() {
            if gss.completed.is_some() {
                // ssh would send it and fail on the reply: the server is done.
                return Err(gss_error(
                    "Protocol error: a token to send after KEXGSS_COMPLETE",
                ));
            }
            let first = gss.first;
            let public = &self.exchange.client_ephemeral;
            output.write_packet(|w| {
                if first {
                    msg::KEXGSS_INIT.encode(w)?;
                    step.token.encode(w)?;
                    public.encode(w)?;
                } else {
                    msg::KEXGSS_CONTINUE.encode(w)?;
                    step.token.encode(w)?;
                }
                Ok(())
            })?;
            gss.first = false;
            self.state = ClientKexState::WaitingForGss { names, gss };
            return Ok(KexProgress::NeedsReply {
                kex: self,
                reset_seqn: false,
            });
        }
        if !step.complete {
            return Err(gss_error("Not complete, and no token output"));
        }
        match gss.completed.take() {
            Some((server_public, mic)) => self.gss_finish(names, gss, server_public, mic, output),
            None => Err(gss_error(
                "Didn't receive a SSH2_MSG_KEXGSS_COMPLETE when I expected it",
            )),
        }
    }

    /// The server's public value and MIC in hand, the context complete: the
    /// shared secret, the exchange hash (with the host key the server sent,
    /// or an empty one), the MIC checked over it, then NEWKEYS.
    fn gss_finish(
        mut self,
        names: Names,
        gss: GssKex,
        server_public: Bytes,
        mic: Bytes,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        let GssKex {
            provider,
            mut ctx,
            mut kex,
            host_key,
            ..
        } = gss;
        if names.kex == crate::kex::GSS_NISTP256_SHA256
            && (server_public.len() != 65 || server_public.first() != Some(&0x04))
        {
            return Err(gss_error(format!(
                "The received NIST-P256 key is not an uncompressed point of 65 bytes ({} bytes)",
                server_public.len()
            )));
        }
        self.exchange.server_ephemeral.clear();
        self.exchange
            .server_ephemeral
            .extend_from_slice(&server_public);
        kex.compute_shared_secret(&self.exchange.server_ephemeral)?;

        let mut host_key_vec = Vec::new();
        host_key.as_deref().unwrap_or(&[]).encode(&mut host_key_vec)?;
        let exchange = &self.exchange;
        let hash = HASH_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            kex.compute_exchange_hash(&host_key_vec, exchange, &mut buffer)
        })?;

        ctx.verify_mic(&hash, &mic)
            .map_err(|e| gss_error(format!("Hash's MIC didn't verify: {e}")))?;
        debug!(
            "GSS-API key exchange {} verified{}",
            names.kex.as_ref(),
            if host_key.is_some() {
                " (KEXGSS_HOSTKEY hashed)"
            } else {
                ""
            }
        );
        provider.exchanged();

        let newkeys = compute_keys(
            hash,
            kex,
            names.clone(),
            self.exchange.clone(),
            self.cause.session_id(),
        )?;
        output.write_packet(|w| {
            msg::NEWKEYS.encode(w)?;
            Ok(())
        })?;
        let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();
        self.state = ClientKexState::WaitingForNewKeys {
            server_host_key: None,
            server_host_certificate: None,
            newkeys,
            gss_context: Some(KexContext(ctx)),
        };
        Ok(KexProgress::NeedsReply {
            kex: self,
            reset_seqn,
        })
    }

    /// The key sizes the negotiated cipher and MACs need, as kex_choose_conf
    /// works out dh_need, turned into the group size a gss-gex asks for.
    fn gss_gex_bits(names: &Names) -> usize {
        let cipher = crate::cipher::CIPHERS.get(&names.cipher);
        let seclen = match cipher {
            _ if names.cipher == crate::cipher::CHACHA20_POLY1305 => 32,
            Some(c) => c.key_len(),
            None => 0,
        };
        let mut need = seclen.max(cipher.map(|c| c.nonce_len()).unwrap_or(0));
        if cipher.map(|c| c.needs_mac()).unwrap_or(false) {
            for m in [&names.client_mac, &names.server_mac] {
                if let Some(mac) = crate::mac::MACS.get(m) {
                    need = need.max(mac.key_len());
                }
            }
        }
        crate::kex::gss::dh_estimate(need * 8)
    }

    pub fn step(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        // Taken: every arm puts the next state back before returning self.
        match std::mem::replace(&mut self.state, ClientKexState::Created) {
            ClientKexState::Created => {
                // At this point we expect to read the KEXINIT from the other side

                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                let names = {
                    // read algorithms from packet.
                    self.exchange.server_kex_init = input.buffer.clone().into();
                    negotiation::Client::read_kex_with(
                        &input.buffer,
                        &self.config.preferred,
                        None,
                        None,
                        &self.cause,
                        self.config.gss_kex.is_some(),
                    )?
                };
                debug!("negotiated algorithms: {names:?}");

                // seqno has already been incremented after read()
                if names.strict_kex() && !self.cause.is_rekey() && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ));
                }

                if let Some((mut kex, kind)) = crate::kex::gss_kex(&names.kex) {
                    // kexgss_client / kexgssgex_client.
                    let provider = self.config.gss_kex.clone().ok_or(Error::KexInit)?;
                    let ctx = provider
                        .context()
                        .map_err(|e| gss_error(format!("Couldn't start the context: {e}")))?;
                    let mut gex_params = None;
                    if kind == GssKexKind::GroupExchange {
                        debug!("Doing group exchange");
                        let nbits = Self::gss_gex_bits(&names);
                        let gex = crate::client::GexParams::new(
                            crate::kex::gss::GEX_MIN,
                            nbits,
                            crate::kex::gss::GEX_MAX,
                        )?;
                        output.write_packet(|w| {
                            msg::KEXGSS_GROUPREQ.encode(w)?;
                            (gex.min_group_size() as u32).encode(w)?;
                            (gex.preferred_group_size() as u32).encode(w)?;
                            (gex.max_group_size() as u32).encode(w)?;
                            Ok(())
                        })?;
                        gex_params = Some(gex);
                    } else {
                        kex.client_dh(&mut self.exchange.client_ephemeral, &mut Vec::new())?;
                    }
                    let gss = GssKex {
                        provider,
                        ctx,
                        kex,
                        complete: false,
                        first: true,
                        host_key: None,
                        completed: None,
                        gex: gex_params,
                    };
                    if kind == GssKexKind::GroupExchange {
                        self.state = ClientKexState::WaitingForGssGroup { names, gss };
                        return Ok(KexProgress::NeedsReply {
                            kex: self,
                            reset_seqn: false,
                        });
                    }
                    return self.gss_round(names, gss, None, output);
                }
                if names.host_key_null {
                    error!("the null host key goes only with a GSS-API key exchange");
                    return Err(Error::KexInit);
                }

                let mut kex = KEXES.get(&names.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
                    // Non-standard no-kex exchange
                    let newkeys = compute_keys(
                        Vec::new(),
                        kex,
                        names.clone(),
                        self.exchange.clone(),
                        self.cause.session_id(),
                    )?;

                    output.write_packet(|w| {
                        msg::NEWKEYS.encode(w)?;
                        Ok(())
                    })?;

                    return Ok(KexProgress::Done {
                        server_host_certificate: None,
                        newkeys,
                        server_host_key: None,
                        gss_context: None,
                    });
                }

                if kex.is_dh_gex() {
                    output.write_packet(|w| {
                        kex.client_dh_gex_init(&self.config.gex, w)?;
                        Ok(())
                    })?;

                    self.state = ClientKexState::WaitingForGexReply { names, kex };
                } else {
                    output.write_packet(|w| {
                        kex.client_dh(&mut self.exchange.client_ephemeral, w)?;
                        Ok(())
                    })?;

                    self.state = ClientKexState::WaitingForDhReply { names, kex };
                }

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ClientKexState::WaitingForGexReply { names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::KEX_DH_GEX_GROUP) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                let prime = Mpint::decode(&mut r)?;
                let generator = Mpint::decode(&mut r)?;
                ensure_end(&r)?;
                debug!("received gex group: prime={prime}, generator={generator}");

                let group = DhGroup {
                    prime: prime.as_bytes().to_vec().into(),
                    generator: generator.as_bytes().to_vec().into(),
                };

                if group.bit_size() < self.config.gex.min_group_size
                    || group.bit_size() > self.config.gex.max_group_size
                {
                    warn!(
                        "DH prime size ({} bits) not within requested range",
                        group.bit_size()
                    );
                    return Err(Error::KexInit);
                }

                let exchange = &mut self.exchange;
                exchange.gex = Some((self.config.gex.clone(), group.clone()));
                kex.dh_gex_set_group(group)?;
                output.write_packet(|w| {
                    kex.client_dh(&mut exchange.client_ephemeral, w)?;
                    Ok(())
                })?;
                self.state = ClientKexState::WaitingForDhReply { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ClientKexState::WaitingForDhReply { mut names, mut kex } => {
                // At this point, we've sent ECDH_INTI and
                // are waiting for the ECDH_REPLY from the server.

                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ClientKexState::WaitingForDhReply { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                if input.buffer.first()
                    != Some(match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_REPLY,
                        false => &msg::KEX_ECDH_REPLY,
                    })
                {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let r = &mut &input.buffer[1..];

                // The raw blob is kept as well as the parsed key. It is what
                // goes into the exchange hash below: for a certificate the
                // parsed form is only the key *inside* it, and re-encoding that
                // would hash something the server never sent — a failure that
                // looks like a bad signature and is computed entirely locally,
                // so there is nothing on the wire to compare against.
                let server_host_key_blob = Bytes::decode(r)?;
                let server_host_certificate = if names.host_key_is_certificate {
                    Some(Certificate::from_bytes(&server_host_key_blob)?)
                } else {
                    None
                };
                let server_host_key = match &server_host_certificate {
                    // The certificate's own signature is checked by the client
                    // against its trusted authorities, not here; what the key
                    // exchange is signed with is the key the certificate
                    // contains. The two are separate proofs and collapsing them
                    // would accept a certificate nobody vouched for.
                    Some(certificate) => PublicKey::new(certificate.public_key().clone(), ""),
                    None => parse_public_key(&server_host_key_blob)?,
                };
                debug!(
                    "received server host key: {:?} (certificate: {})",
                    server_host_key.to_openssh(),
                    server_host_certificate.is_some()
                );

                let server_ephemeral = Bytes::decode(r)?;
                self.exchange
                    .server_ephemeral
                    .extend_from_slice(&server_ephemeral);
                kex.compute_shared_secret(&self.exchange.server_ephemeral)?;

                let mut pubkey_vec = Vec::new();
                server_host_key_blob.encode(&mut pubkey_vec)?;

                let exchange = &self.exchange;
                let hash = HASH_BUFFER.with({
                    |buffer| {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)
                    }
                })?;

                let signature = Bytes::decode(r)?;
                let mut signature_reader = &signature[..];
                let signature = Signature::decode(&mut signature_reader)?;
                ensure_end(&signature_reader)?;
                ensure_end(r)?;

                if let Err(e) =
                    signature::Verifier::verify(&server_host_key, hash.as_ref(), &signature)
                {
                    debug!("wrong server sig: {e:?}");
                    return Err(Error::WrongServerSig);
                }

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.cause.session_id(),
                )?;

                output.write_packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();

                self.state = ClientKexState::WaitingForNewKeys {
                    server_host_key: Some(server_host_key),
                    server_host_certificate,
                    newkeys,
                    gss_context: None,
                };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ClientKexState::WaitingForGssGroup { names, mut gss } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if input.buffer.first() != Some(&msg::KEXGSS_GROUP) {
                    return Err(gss_error(format!(
                        "Protocol error: expected packet type {}, got {:?}",
                        msg::KEXGSS_GROUP,
                        input.buffer.first()
                    )));
                }
                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];
                let prime = Mpint::decode(&mut r)?;
                let generator = Mpint::decode(&mut r)?;
                ensure_end(&r)?;
                let group = DhGroup {
                    prime: prime.as_bytes().to_vec().into(),
                    generator: generator.as_bytes().to_vec().into(),
                };
                let Some(gex) = gss.gex.take() else {
                    return Err(Error::Inconsistent);
                };
                if group.bit_size() < gex.min_group_size()
                    || group.bit_size() > gex.max_group_size()
                {
                    return Err(gss_error(format!(
                        "GSSGRP_GEX group out of range: {} !< {} !< {}",
                        gex.min_group_size(),
                        group.bit_size(),
                        gex.max_group_size()
                    )));
                }
                self.exchange.gex = Some((gex, group.clone()));
                gss.kex.dh_gex_set_group(group)?;
                gss.kex
                    .client_dh(&mut self.exchange.client_ephemeral, &mut Vec::new())?;
                self.gss_round(names, gss, None, output)
            }
            ClientKexState::WaitingForGss {
                mut names,
                mut gss,
            } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if names.ignore_guessed {
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ClientKexState::WaitingForGss { names, gss };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }
                let Some((&kind, mut r)) = input.buffer.split_first() else {
                    return Err(Error::KexInit);
                };
                match kind {
                    msg::KEXGSS_HOSTKEY => {
                        debug!("Received KEXGSS_HOSTKEY");
                        if gss.host_key.is_some() {
                            return Err(gss_error("Server host key received more than once"));
                        }
                        gss.host_key = Some(Bytes::decode(&mut r)?);
                        self.state = ClientKexState::WaitingForGss { names, gss };
                        Ok(KexProgress::NeedsReply {
                            kex: self,
                            reset_seqn: false,
                        })
                    }
                    msg::KEXGSS_CONTINUE => {
                        debug!("Received GSSAPI_CONTINUE");
                        if gss.complete {
                            return Err(gss_error(
                                "GSSAPI Continue received from server when complete",
                            ));
                        }
                        let token = Bytes::decode(&mut r)?;
                        ensure_end(&r)?;
                        self.gss_round(names, gss, Some(&token), output)
                    }
                    msg::KEXGSS_COMPLETE => {
                        debug!("Received GSSAPI_COMPLETE");
                        let server_public = Bytes::decode(&mut r)?;
                        let mic = Bytes::decode(&mut r)?;
                        let token = if u8::decode(&mut r)? != 0 {
                            let token = Bytes::decode(&mut r)?;
                            if gss.complete {
                                return Err(gss_error(
                                    "Protocol error: received token when complete",
                                ));
                            }
                            Some(token)
                        } else {
                            if !gss.complete {
                                return Err(gss_error(
                                    "Protocol error: did not receive final token",
                                ));
                            }
                            None
                        };
                        ensure_end(&r)?;
                        match token {
                            Some(token) => {
                                gss.completed = Some((server_public, mic));
                                self.gss_round(names, gss, Some(&token), output)
                            }
                            None => self.gss_finish(names, gss, server_public, mic, output),
                        }
                    }
                    msg::KEXGSS_ERROR => {
                        debug!("Received Error");
                        let major = u32::decode(&mut r)?;
                        let minor = u32::decode(&mut r)?;
                        let message = String::decode(&mut r)?;
                        let _lang = String::decode(&mut r)?;
                        ensure_end(&r)?;
                        Err(gss_error(format!(
                            "GSSAPI Error (major {major:#x}, minor {minor:#x}): {message}"
                        )))
                    }
                    other => Err(gss_error(format!(
                        "Protocol error: didn't expect packet type {other}"
                    ))),
                }
            }
            ClientKexState::WaitingForNewKeys {
                server_host_key,
                server_host_certificate,
                newkeys,
                gss_context,
            } => {
                // At this point the exchange is complete
                // and we're waiting for a KEWKEYS packet
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex);
                }

                #[allow(clippy::indexing_slicing, reason = "length checked")]
                let r = &input.buffer[1..];
                ensure_end(&r)?;

                Ok(KexProgress::Done {
                    server_host_certificate,
                    newkeys,
                    server_host_key,
                    gss_context,
                })
            }
        }
    }
}

fn compute_keys(
    hash: Vec<u8>,
    kex: KexAlgorithm,
    names: Names,
    exchange: Exchange,
    session_id: Option<&CryptoVec>,
) -> Result<NewKeys, Error> {
    let session_id_ref: &[u8] = match session_id {
        Some(sid) => sid,
        None => &hash,
    };
    // Now computing keys.
    let c = kex.compute_keys(
        session_id_ref,
        &hash,
        names.cipher,
        names.server_mac,
        names.client_mac,
        false,
    )?;
    // The session_id stored in NewKeys is sensitive key material
    // (used in key derivation), so keep it as CryptoVec.
    // On initial exchange the exchange hash becomes the session_id;
    // on rekey we already have it as CryptoVec.
    let session_id_cv = match session_id {
        Some(s) => s.clone(),
        None => {
            let mut cv = CryptoVec::new();
            cv.extend(&hash);
            cv
        }
    };
    Ok(NewKeys {
        exchange,
        names,
        kex,
        key: 0,
        cipher: c,
        session_id: session_id_cv,
    })
}

#[cfg(test)]
mod gss_tests {
    //! The GSS-API key exchange against scripted server messages, with a
    //! context that plays the mechanism: what goes on the wire, the null
    //! host key, KEXGSS_HOSTKEY, group exchange and the failures kexgssc.c
    //! stops at. (The exchange hash itself is proven against OpenSSH's sshd,
    //! whose MIC over it a real Kerberos context checks.)
    use std::collections::VecDeque;
    use std::num::Wrapping;
    use std::sync::{Arc, Mutex};

    use ssh_encoding::Encode;

    use super::*;
    use crate::helpers::NameList;
    use crate::kex::gss::{GssKexContext, GssKexProvider, GssKexStep};

    #[derive(Debug, Default)]
    struct Log {
        inputs: Vec<Option<Vec<u8>>>,
        verified: Vec<Vec<u8>>,
        exchanged: usize,
    }

    struct Ctx {
        script: VecDeque<GssKexStep>,
        log: Arc<Mutex<Log>>,
    }

    impl GssKexContext for Ctx {
        fn init(&mut self, input: Option<&[u8]>) -> Result<GssKexStep, String> {
            self.log.lock().unwrap().inputs.push(input.map(<[u8]>::to_vec));
            self.script.pop_front().ok_or_else(|| "no more steps".to_string())
        }
        fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<(), String> {
            self.log.lock().unwrap().verified.push(data.to_vec());
            if mic == b"MIC" { Ok(()) } else { Err("bad mic".into()) }
        }
        fn get_mic(&mut self, _data: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"KEYEX".to_vec())
        }
    }

    #[derive(Debug)]
    struct Provider {
        script: Vec<GssKexStep>,
        log: Arc<Mutex<Log>>,
    }

    impl GssKexProvider for Provider {
        fn context(&self) -> Result<Box<dyn GssKexContext>, String> {
            Ok(Box::new(Ctx { script: self.script.clone().into(), log: self.log.clone() }))
        }
        fn exchanged(&self) {
            self.log.lock().unwrap().exchanged += 1;
        }
    }

    fn step(token: &[u8], complete: bool) -> GssKexStep {
        GssKexStep { token: token.to_vec(), complete, mutual: true, integ: true }
    }

    fn client(kex: Vec<crate::kex::Name>, script: Vec<GssKexStep>) -> (ClientKex, Arc<Mutex<Log>>, PacketWriter) {
        let log = Arc::new(Mutex::new(Log::default()));
        let mut config = Config::default();
        config.preferred.kex = kex.into();
        config.gss_kex = Some(Arc::new(Provider { script, log: log.clone() }));
        let mut ck = ClientKex::new(
            Arc::new(config),
            &SshId::Standard("SSH-2.0-test".into()),
            b"SSH-2.0-server",
            KexCause::Initial,
        );
        let mut w = PacketWriter::clear();
        ck.kexinit(&mut w).unwrap();
        (ck, log, w)
    }

    /// The payloads of the cleartext packets written so far, taken out.
    fn sent(w: &mut PacketWriter) -> Vec<Vec<u8>> {
        let buf = std::mem::take(&mut w.buffer().buffer);
        let mut out = Vec::new();
        let mut rest = &buf[..];
        while rest.len() >= 5 {
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let pad = rest[4] as usize;
            out.push(rest[5..4 + len - pad].to_vec());
            rest = &rest[4 + len..];
        }
        out
    }

    fn names_of(payload: &[u8], skip_lists: usize) -> Vec<String> {
        let mut r = &payload[17..];
        for _ in 0..skip_lists {
            NameList::decode(&mut r).unwrap();
        }
        NameList::decode(&mut r).unwrap().0
    }

    fn server_kexinit(kex: &str, host_key: &str) -> Vec<u8> {
        let mut b = vec![msg::KEXINIT];
        b.extend_from_slice(&[0u8; 16]);
        for list in [kex, host_key, "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""] {
            NameList(if list.is_empty() { vec![] } else { list.split(',').map(String::from).collect() }).encode(&mut b).unwrap();
        }
        b.push(0);
        0u32.encode(&mut b).unwrap();
        b
    }

    fn packet(buffer: Vec<u8>, seqn: u32) -> IncomingSshPacket {
        IncomingSshPacket { buffer, seqn: Wrapping(seqn) }
    }

    fn complete(server_public: &[u8], mic: &[u8], token: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![msg::KEXGSS_COMPLETE];
        server_public.encode(&mut b).unwrap();
        mic.encode(&mut b).unwrap();
        match token {
            Some(t) => {
                1u8.encode(&mut b).unwrap();
                t.encode(&mut b).unwrap();
            }
            None => 0u8.encode(&mut b).unwrap(),
        }
        b
    }

    fn needs_reply(p: KexProgress<ClientKex>) -> ClientKex {
        match p {
            KexProgress::NeedsReply { kex, .. } => kex,
            KexProgress::Done { .. } => panic!("done too early"),
        }
    }

    fn err(r: Result<KexProgress<ClientKex>, Error>) -> String {
        match r {
            Err(Error::GssKex(e)) => e,
            Err(e) => format!("other error: {e:?}"),
            Ok(_) => "no error".into(),
        }
    }

    fn curve_point() -> Vec<u8> {
        curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped([7; 32]).0.to_vec()
    }

    /// Kerberos-shaped: AP-REQ in KEXGSS_INIT, AP-REP with the MIC in
    /// KEXGSS_COMPLETE, the server without a host key.
    #[test]
    fn null_host_key_and_two_rounds() {
        let gss = crate::kex::GSS_CURVE25519_SHA256;
        let (ck, log, mut w) = client(vec![gss, crate::kex::CURVE25519], vec![step(b"AP-REQ", false), step(b"", true)]);
        let kexinit = sent(&mut w).remove(0);
        // `null` offered last.
        assert_eq!(names_of(&kexinit, 1).last().map(String::as_str), Some("null"));
        assert_eq!(names_of(&kexinit, 0)[0], gss.as_ref());

        let ck = needs_reply(ck.step(Some(&mut packet(server_kexinit(gss.as_ref(), "null"), 1)), &mut w).unwrap());
        assert!(ck.is_gss());
        let init = sent(&mut w).remove(0);
        assert_eq!(init[0], msg::KEXGSS_INIT);
        let mut r = &init[1..];
        assert_eq!(&Bytes::decode(&mut r).unwrap()[..], b"AP-REQ");
        assert_eq!(Bytes::decode(&mut r).unwrap().len(), 32);
        assert!(r.is_empty());

        let ck = needs_reply(ck.step(Some(&mut packet(complete(&curve_point(), b"MIC", Some(b"AP-REP")), 2)), &mut w).unwrap());
        assert_eq!(sent(&mut w), vec![vec![msg::NEWKEYS]]);
        match ck.step(Some(&mut packet(vec![msg::NEWKEYS], 3)), &mut w).unwrap() {
            KexProgress::Done { server_host_key, server_host_certificate, newkeys, gss_context } => {
                assert!(server_host_key.is_none() && server_host_certificate.is_none());
                assert!(newkeys.names.host_key_null);
                assert!(gss_context.is_some());
            }
            KexProgress::NeedsReply { .. } => panic!("not done"),
        }
        let log = log.lock().unwrap();
        assert_eq!(log.inputs, vec![None, Some(b"AP-REP".to_vec())]);
        assert_eq!(log.verified.len(), 1);
        assert_eq!(log.verified[0].len(), 32);
        assert_eq!(log.exchanged, 1);
    }

    /// One round, KEXGSS_HOSTKEY before KEXGSS_COMPLETE: the key is hashed,
    /// not returned for checking; a second one is refused.
    #[test]
    fn host_key_is_hashed_once() {
        let gss = crate::kex::GSS_G14_SHA256;
        let blob = {
            let k = ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
            k.public_key().to_bytes().unwrap()
        };
        let mut hostkey = vec![msg::KEXGSS_HOSTKEY];
        blob.as_slice().encode(&mut hostkey).unwrap();
        let run = |twice: bool| {
            let (ck, log, mut w) = client(vec![gss], vec![step(b"TOKEN", true)]);
            sent(&mut w);
            let ck = needs_reply(ck.step(Some(&mut packet(server_kexinit(gss.as_ref(), "ssh-ed25519"), 1)), &mut w).unwrap());
            let init = sent(&mut w).remove(0);
            assert_eq!(init[0], msg::KEXGSS_INIT);
            let mut ck = needs_reply(ck.step(Some(&mut packet(hostkey.clone(), 2)), &mut w).unwrap());
            if twice {
                return (err(ck.step(Some(&mut packet(hostkey.clone(), 3)), &mut w)), log);
            }
            ck = needs_reply(ck.step(Some(&mut packet(complete(&[5], b"MIC", None), 3)), &mut w).unwrap());
            match ck.step(Some(&mut packet(vec![msg::NEWKEYS], 4)), &mut w).unwrap() {
                KexProgress::Done { server_host_key, newkeys, .. } => {
                    assert!(server_host_key.is_none());
                    assert!(!newkeys.names.host_key_null);
                }
                KexProgress::NeedsReply { .. } => panic!("not done"),
            }
            (String::new(), log)
        };
        let (e, log) = run(false);
        assert!(e.is_empty());
        assert_eq!(log.lock().unwrap().verified[0].len(), 32);
        let (e, _) = run(true);
        assert!(e.contains("more than once"), "{e}");
    }

    /// gss-gex-sha1-: KEXGSS_GROUPREQ with DH_GRP_MIN, dh_estimate of what
    /// aes256-ctr with hmac-sha2-256 needs, DH_GRP_MAX; then the group.
    #[test]
    fn group_exchange() {
        let gss = crate::kex::GSS_GEX_SHA1;
        let (ck, _log, mut w) = client(vec![gss], vec![step(b"TOKEN", true)]);
        sent(&mut w);
        let ck = needs_reply(ck.step(Some(&mut packet(server_kexinit(gss.as_ref(), "ssh-ed25519"), 1)), &mut w).unwrap());
        let req = sent(&mut w).remove(0);
        let mut want = vec![msg::KEXGSS_GROUPREQ];
        for n in [2048u32, 8192, 8192] {
            n.encode(&mut want).unwrap();
        }
        assert_eq!(req, want);
        let mut group = vec![msg::KEXGSS_GROUP];
        crate::kex::encode_mpint(&crate::kex::dh::groups::DH_GROUP14.prime, &mut group).unwrap();
        crate::kex::encode_mpint(&[2], &mut group).unwrap();
        let ck = needs_reply(ck.step(Some(&mut packet(group, 2)), &mut w).unwrap());
        let init = sent(&mut w).remove(0);
        assert_eq!(init[0], msg::KEXGSS_INIT);
        let ck = needs_reply(ck.step(Some(&mut packet(complete(&[5], b"MIC", None), 3)), &mut w).unwrap());
        assert_eq!(sent(&mut w), vec![vec![msg::NEWKEYS]]);
        drop(ck);

        // A group outside 2048..8192 bits.
        let (ck, _log, mut w) = client(vec![gss], vec![step(b"TOKEN", true)]);
        let ck = needs_reply(ck.step(Some(&mut packet(server_kexinit(gss.as_ref(), "ssh-ed25519"), 1)), &mut w).unwrap());
        let mut group = vec![msg::KEXGSS_GROUP];
        crate::kex::encode_mpint(&crate::kex::dh::groups::DH_GROUP1.prime, &mut group).unwrap();
        crate::kex::encode_mpint(&[2], &mut group).unwrap();
        assert!(err(ck.step(Some(&mut packet(group, 2)), &mut w)).contains("out of range"));
    }

    /// Where kexgssc.c stops.
    #[test]
    fn failures() {
        let gss = crate::kex::GSS_CURVE25519_SHA256;
        let start = |script: Vec<GssKexStep>| {
            let (ck, _log, mut w) = client(vec![gss], script);
            let r = ck.step(Some(&mut packet(server_kexinit(gss.as_ref(), "null"), 1)), &mut w);
            (r, w)
        };
        // Complete without mutual authentication, or without integrity.
        let (r, _) = start(vec![GssKexStep { token: b"T".to_vec(), complete: true, mutual: false, integ: true }]);
        assert!(err(r).contains("Mutual authentication failed"));
        let (r, _) = start(vec![GssKexStep { token: b"T".to_vec(), complete: true, mutual: true, integ: false }]);
        assert!(err(r).contains("Integrity check failed"));
        // Neither complete nor a token.
        let (r, _) = start(vec![step(b"", false)]);
        assert!(err(r).contains("Not complete, and no token output"));
        // The mechanism fails.
        let (r, _) = start(vec![]);
        assert!(err(r).contains("gss_init_context failed"));

        let (r, mut w) = start(vec![step(b"T", false)]);
        let ck = needs_reply(r.unwrap());
        // KEXGSS_COMPLETE without the final token while not complete.
        assert!(err(ck.step(Some(&mut packet(complete(&curve_point(), b"MIC", None), 2)), &mut w)).contains("did not receive final token"));

        let (r, mut w) = start(vec![step(b"T", true)]);
        let ck = needs_reply(r.unwrap());
        // A token when already complete.
        assert!(err(ck.step(Some(&mut packet(complete(&curve_point(), b"MIC", Some(b"X")), 2)), &mut w)).contains("received token when complete"));

        let (r, mut w) = start(vec![step(b"T", true)]);
        let ck = needs_reply(r.unwrap());
        // KEXGSS_CONTINUE when complete.
        let mut cont = vec![msg::KEXGSS_CONTINUE];
        b"X".as_slice().encode(&mut cont).unwrap();
        assert!(err(ck.step(Some(&mut packet(cont, 2)), &mut w)).contains("Continue received from server when complete"));

        let (r, mut w) = start(vec![step(b"T", true)]);
        let ck = needs_reply(r.unwrap());
        // The MIC does not verify.
        assert!(err(ck.step(Some(&mut packet(complete(&curve_point(), b"BAD", None), 2)), &mut w)).contains("MIC didn't verify"));

        let (r, mut w) = start(vec![step(b"T", false)]);
        let ck = needs_reply(r.unwrap());
        // KEXGSS_ERROR.
        let mut e = vec![msg::KEXGSS_ERROR];
        0x000d_0000u32.encode(&mut e).unwrap();
        7u32.encode(&mut e).unwrap();
        "Server not found in Kerberos database".encode(&mut e).unwrap();
        "".encode(&mut e).unwrap();
        assert!(err(ck.step(Some(&mut packet(e, 2)), &mut w)).contains("Server not found in Kerberos database"));

        // The null host key with a key exchange that is not GSS.
        let (ck, _log, mut w) = client(vec![gss, crate::kex::CURVE25519], vec![]);
        let r = ck.step(Some(&mut packet(server_kexinit("curve25519-sha256", "null"), 1)), &mut w);
        assert!(matches!(r, Err(Error::KexInit)));
    }

    /// Without a GSS provider the client offers no `null`.
    #[test]
    fn no_null_without_gss() {
        let mut ck = ClientKex::new(
            Arc::new(Config::default()),
            &SshId::Standard("SSH-2.0-test".into()),
            b"SSH-2.0-server",
            KexCause::Initial,
        );
        let mut w = PacketWriter::clear();
        ck.kexinit(&mut w).unwrap();
        let kexinit = sent(&mut w).remove(0);
        assert!(!names_of(&kexinit, 1).iter().any(|n| n == "null"));
    }
}
