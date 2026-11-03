//! Logging in the way OpenSSH's ssh does (sshconnect2.c), for a session that
//! carries ssh_config settings: the methods in PreferredAuthentications
//! order as far as the server allows them, every identity (the session's
//! key, IdentityFile, certificates, the agent's keys) offered before it is
//! signed with, so a passphrase is asked only for a key the server would
//! take, keyboard-interactive answered by the user, partial success followed
//! through, BatchMode refusing to ask anything.
//!
//! A session without ssh_config settings keeps Reach's own login
//! (`client::cascade_authenticate`): only what the session names.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use russh::MethodKind;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};

use super::client::{decode_key, expand_tilde, key_is_encrypted, AuthBy, AuthOutcome, AuthParams, KeySource, SshError};
use super::prompt::{self, Field, Kind};

/// Where the agent's keys come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentChoice {
    /// No agent (IdentityAgent none, or a Reach session that names none).
    Off,
    /// The system's agent: SSH_AUTH_SOCK, or on Windows the OpenSSH agent
    /// pipe and then Pageant.
    Default,
    /// IdentityAgent naming a socket (a named pipe on Windows).
    Socket(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddKeys {
    No,
    Yes,
    Ask,
    Confirm,
}

/// What ssh_config says about logging in.
#[derive(Debug, Clone)]
pub struct AuthPolicy {
    /// Methods in the order to try them (PreferredAuthentications, filtered
    /// by PubkeyAuthentication, KbdInteractiveAuthentication,
    /// PasswordAuthentication, GSSAPIAuthentication, HostbasedAuthentication).
    pub methods: Vec<MethodKind>,
    /// IdentityFile, expanded, in order.
    pub identity_files: Vec<String>,
    /// No IdentityFile in an imported config: OpenSSH's own ~/.ssh/id_* files.
    pub default_identities: bool,
    /// CertificateFile, expanded.
    pub certificate_files: Vec<String>,
    pub identities_only: bool,
    pub agent: AgentChoice,
    /// PubkeyAcceptedAlgorithms after assembly; `None` for OpenSSH's default.
    pub pubkey_algorithms: Option<Vec<String>>,
    pub batch_mode: bool,
    pub password_prompts: u32,
    pub kbd_devices: Option<String>,
    pub add_keys: AddKeys,
    pub add_keys_lifetime: Option<u32>,
    pub min_rsa_bits: usize,
    pub use_keychain: bool,
    /// GSSAPI settings, when GSSAPIAuthentication is on.
    pub gssapi: Option<super::gssapi::GssapiPolicy>,
    /// GSS-API key exchange, when GSSAPIKeyExchange is on; it also turns on
    /// gssapi-keyex.
    pub gss_kex: Option<super::gssapi::GssKexPolicy>,
    /// HostbasedAuthentication (see `hostbased`), when on.
    pub hostbased: Option<std::sync::Arc<super::hostbased::HostbasedContext>>,
    /// PKCS11Provider, once approved: the token library whose keys come first.
    pub pkcs11_provider: Option<String>,
    /// SecurityKeyProvider: what signs with FIDO keys; `None` skips them.
    pub sk_provider: Option<super::sk::Provider>,
}

/// Where to ask the user, and about which host.
#[derive(Clone, Copy)]
pub(crate) struct Ui<'a> {
    pub app: Option<&'a dyn prompt::Asker>,
    pub host: &'a str,
    pub port: u16,
}

impl Ui<'_> {
    pub(crate) async fn ask(&self, kind: Kind, title: &str, instructions: &str, fields: Vec<Field>) -> Option<Vec<String>> {
        match self.app {
            Some(a) => a.ask(self.host, self.port, kind, title, instructions, fields).await,
            None => None,
        }
    }
}

/// An identity to offer, with where its private half is.
struct Identity {
    public: Option<PublicKey>,
    cert: Option<Certificate>,
    source: Source,
    label: String,
}

enum Source {
    /// The session's own key (file or imported), with any stored passphrase.
    Session { material: String, passphrase: Option<String>, path: Option<String> },
    /// An IdentityFile.
    File(PathBuf),
    /// A key the agent holds.
    Agent(Box<AgentIdentity>),
    /// A key on a PKCS#11 token.
    Pkcs11(Arc<super::pkcs11::Key>),
}

pub(crate) type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

pub(crate) async fn connect_agent(choice: &AgentChoice) -> Option<Agent> {
    match choice {
        AgentChoice::Off => None,
        AgentChoice::Socket(path) => {
            #[cfg(unix)]
            {
                AgentClient::connect_uds(path).await.ok().map(|a| AgentClient::connect(a.into_inner()))
            }
            #[cfg(windows)]
            {
                AgentClient::connect_named_pipe(path).await.ok().map(|a| AgentClient::connect(a.into_inner()))
            }
        }
        AgentChoice::Default => {
            #[cfg(unix)]
            {
                AgentClient::connect_env().await.ok().map(|a| AgentClient::connect(a.into_inner()))
            }
            #[cfg(windows)]
            {
                if let Ok(a) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
                    return Some(AgentClient::connect(a.into_inner()));
                }
                if super::client::pageant_is_running() {
                    return AgentClient::connect_pageant().await.ok().map(|a| AgentClient::connect(a.into_inner()));
                }
                None
            }
        }
    }
}

/// The public half of a key file without its passphrase: the key itself
/// when it is not encrypted, else `<file>.pub` (as OpenSSH reads it).
fn public_of(path: &Path) -> Option<PublicKey> {
    let text = std::fs::read_to_string(path).ok()?;
    if key_is_encrypted(&text) == Some(false) {
        if let Ok(k) = decode_key(&text, None) {
            return Some(k.public_key().clone());
        }
    }
    let pub_text = std::fs::read_to_string(format!("{}.pub", path.display())).ok()?;
    PublicKey::from_openssh(pub_text.trim()).ok()
}

fn read_cert(path: &Path) -> Option<Certificate> {
    let text = std::fs::read_to_string(path).ok()?;
    Certificate::from_openssh(text.trim()).ok()
}

/// OpenSSH's default identities, in its order, those that exist.
fn default_identity_files() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else { return Vec::new() };
    ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"]
        .iter()
        .map(|n| home.join(".ssh").join(n))
        .filter(|p| p.is_file())
        .collect()
}

fn same_key(a: &PublicKey, b: &PublicKey) -> bool {
    a.key_data() == b.key_data()
}

/// The identity list, as pubkey_prepare builds it: PKCS11Provider keys,
/// then the session's key and IdentityFile entries, in order (the agent
/// signing for any it holds), then the agent's other keys unless
/// IdentitiesOnly.
async fn prepare(auth: &AuthParams, p: &AuthPolicy, agent: &mut Option<Agent>, ui: Ui<'_>) -> Vec<Identity> {
    let mut ids: Vec<Identity> = Vec::new();
    // ssh.c loads the token's keys before the IdentityFile entries, and
    // IdentitiesOnly does not remove them.
    if let Some(path) = &p.pkcs11_provider {
        for k in super::pkcs11::keys(path, ui, p.batch_mode).await {
            ids.push(Identity { public: Some(k.public.clone()), cert: None, label: k.label.clone(), source: Source::Pkcs11(Arc::new(k)) });
        }
    }
    if let Some(k) = &auth.key {
        let (material, path) = match &k.source {
            KeySource::Path(path) => (std::fs::read_to_string(expand_tilde(path)).unwrap_or_default(), Some(path.clone())),
            KeySource::Material(m) => (m.clone(), None),
        };
        let public = decode_key(&material, k.passphrase.as_deref())
            .ok()
            .map(|key| key.public_key().clone())
            .or_else(|| path.as_ref().and_then(|p| public_of(&expand_tilde(p))));
        let label = path.clone().unwrap_or_else(|| "the session's imported key".into());
        ids.push(Identity { public, cert: None, source: Source::Session { material, passphrase: k.passphrase.clone(), path }, label });
    }
    let mut files: Vec<PathBuf> = p.identity_files.iter().map(|f| expand_tilde(f)).collect();
    if p.default_identities && files.is_empty() {
        files = default_identity_files();
    }
    for f in files {
        if !f.is_file() {
            tracing::info!("IdentityFile {} does not exist; skipped, as ssh does", f.display());
            continue;
        }
        let public = public_of(&f);
        if ids.iter().any(|i| match (&i.public, &public) {
            (Some(a), Some(b)) => same_key(a, b),
            _ => false,
        }) {
            continue;
        }
        ids.push(Identity { public, cert: None, label: f.display().to_string(), source: Source::File(f) });
    }
    if p.sk_provider.is_none() {
        ids.retain(|i| {
            let sk = i.public.as_ref().is_some_and(super::sk::is_sk);
            if sk {
                tracing::info!("ignoring authenticator-hosted key {} as no SecurityKeyProvider has been specified", i.label);
            }
            !sk
        });
    }
    // Certificates: <key>-cert.pub beside a key file, and CertificateFile.
    let mut certs: Vec<Certificate> = Vec::new();
    for i in &ids {
        if let Source::File(f) = &i.source {
            if let Some(c) = read_cert(Path::new(&format!("{}-cert.pub", f.display()))) {
                certs.push(c);
            }
        }
    }
    for c in &p.certificate_files {
        match read_cert(&expand_tilde(c)) {
            Some(cert) => certs.push(cert),
            None => tracing::info!("CertificateFile {c} could not be read"),
        }
    }
    let mut with_certs = Vec::new();
    for i in ids {
        if let Some(public) = &i.public {
            for c in certs.iter().filter(|c| c.public_key() == public.key_data()) {
                with_certs.push(Identity {
                    public: Some(public.clone()),
                    cert: Some(c.clone()),
                    label: format!("{} (certificate)", i.label),
                    source: match &i.source {
                        Source::Session { material, passphrase, path } => {
                            Source::Session { material: material.clone(), passphrase: passphrase.clone(), path: path.clone() }
                        }
                        Source::File(f) => Source::File(f.clone()),
                        Source::Agent(a) => Source::Agent(a.clone()),
                        Source::Pkcs11(k) => Source::Pkcs11(k.clone()),
                    },
                });
            }
        }
        with_certs.push(i);
    }
    let mut ids = with_certs;
    if let Some(a) = agent.as_mut() {
        match a.request_identities().await {
            Ok(agent_ids) => {
                for aid in agent_ids {
                    let public = aid.public_key().into_owned();
                    if let Some(i) = ids.iter_mut().find(|i| i.public.as_ref().is_some_and(|p| same_key(p, &public)) && i.cert.is_none()) {
                        // The agent holds this key: it signs, no passphrase asked.
                        i.source = Source::Agent(Box::new(aid));
                        continue;
                    }
                    if !p.identities_only {
                        let label = match &aid {
                            AgentIdentity::PublicKey { comment, .. } | AgentIdentity::Certificate { comment, .. } => {
                                format!("agent key {comment}")
                            }
                        };
                        let cert = match &aid {
                            AgentIdentity::Certificate { certificate, .. } => Some(certificate.clone()),
                            _ => None,
                        };
                        ids.push(Identity { public: Some(public), cert, source: Source::Agent(Box::new(aid)), label });
                    }
                }
            }
            Err(e) => tracing::info!("SSH agent: {e}"),
        }
    }
    ids
}

/// PubkeyAcceptedAlgorithms and RequiredRSASize for one key: the hash an
/// RSA key signs with (server-sig-algs and the accepted list both allowing
/// it), or `None` to skip the key.
fn signing_hash(public: &PublicKey, cert: bool, p: &AuthPolicy, server_rsa: Option<Option<HashAlg>>) -> Option<Option<HashAlg>> {
    let allowed = |name: &str| p.pubkey_algorithms.as_ref().is_none_or(|l| l.iter().any(|a| a == name));
    let suffix = if cert { "-cert-v01@openssh.com" } else { "" };
    match public.algorithm() {
        Algorithm::Rsa { .. } => {
            if let russh::keys::ssh_key::public::KeyData::Rsa(r) = public.key_data() {
                let bits = r.n().as_positive_bytes().map_or(0, |b| b.len() * 8);
                if bits < p.min_rsa_bits {
                    tracing::info!("RSA key of {bits} bits is below RequiredRSASize {}; skipped", p.min_rsa_bits);
                    return None;
                }
            }
            // The server's preference, if it is one the config allows.
            let wanted = server_rsa.flatten();
            let ok = |h: Option<HashAlg>| {
                let name = match h {
                    Some(HashAlg::Sha512) => "rsa-sha2-512",
                    Some(HashAlg::Sha256) => "rsa-sha2-256",
                    _ => "ssh-rsa",
                };
                allowed(&format!("{name}{suffix}"))
            };
            [wanted, Some(HashAlg::Sha512), Some(HashAlg::Sha256), None].into_iter().find(|h| ok(*h))
        }
        a => allowed(&format!("{}{suffix}", a.as_str())).then_some(None),
    }
}

/// Signs with a key file or the session's key, decrypting it only when the
/// server has said it would accept the key.
struct FileSigner<'a> {
    source: &'a Source,
    label: &'a str,
    policy: &'a AuthPolicy,
    ui: Ui<'a>,
    /// The key once decrypted, kept for AddKeysToAgent.
    key: Option<PrivateKey>,
}

#[derive(Debug)]
enum SignError {
    Send,
    Key(String),
}

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        SignError::Send
    }
}

impl FileSigner<'_> {
    async fn load(&mut self) -> Result<PrivateKey, String> {
        if let Some(k) = &self.key {
            return Ok(k.clone());
        }
        let (material, stored, path) = match self.source {
            Source::Session { material, passphrase, path } => (material.clone(), passphrase.clone(), path.clone()),
            Source::File(f) => (std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?, None, Some(f.display().to_string())),
            Source::Agent(_) | Source::Pkcs11(_) => return Err("not a key file".into()),
        };
        if let Ok(k) = decode_key(&material, stored.as_deref()) {
            if !k.is_encrypted() {
                self.key = Some(k.clone());
                return Ok(k);
            }
        }
        let keychain_id = path.clone().unwrap_or_else(|| self.label.to_string());
        if self.policy.use_keychain {
            if let Some(p) = keychain::get(&keychain_id) {
                if let Ok(k) = decode_key(&material, Some(&p)) {
                    self.key = Some(k.clone());
                    return Ok(k);
                }
            }
        }
        if self.policy.batch_mode {
            return Err(format!("{} needs a passphrase and BatchMode is on", self.label));
        }
        for attempt in 0..self.policy.password_prompts.max(1) {
            let text = if attempt == 0 { format!("Enter passphrase for key '{}':", self.label) } else { "Bad passphrase, try again:".to_string() };
            let Some(answers) = self.ui.ask(Kind::Passphrase, &text, "", vec![Field { text: text.clone(), echo: false }]).await else {
                return Err("cancelled".into());
            };
            let pass = answers.into_iter().next().unwrap_or_default();
            if let Ok(k) = decode_key(&material, Some(&pass)) {
                if self.policy.use_keychain {
                    keychain::set(&keychain_id, &pass);
                }
                self.key = Some(k.clone());
                return Ok(k);
            }
        }
        Err(format!("wrong passphrase for {}", self.label))
    }
}

impl russh::Signer for FileSigner<'_> {
    type Error = SignError;

    #[allow(clippy::manual_async_fn)]
    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            let blob = if let Source::Pkcs11(k) = self.source {
                k.sign(hash_alg, &to_sign, self.ui).await.map_err(SignError::Key)?
            } else {
                let key = self.load().await.map_err(SignError::Key)?;
                if super::sk::is_sk(key.public_key()) {
                    let p = self.policy;
                    super::sk::sign(&key, &to_sign, p.sk_provider.as_ref(), p.batch_mode, self.ui, self.label).await.map_err(SignError::Key)?
                } else {
                    sign(&key, hash_alg, &to_sign).map_err(SignError::Key)?
                }
            };
            // The signature goes after the data as an SSH string.
            to_sign.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            to_sign.extend_from_slice(&blob);
            Ok(to_sign)
        }
    }
}

/// An SSH signature blob (algorithm name, then signature) over `data`.
fn sign(key: &PrivateKey, hash: Option<HashAlg>, data: &[u8]) -> Result<Vec<u8>, String> {
    use russh::keys::signature::Signer as _;
    use russh::keys::ssh_encoding::Encode as _;
    let sig = match key.key_data() {
        russh::keys::ssh_key::private::KeypairData::Rsa(rsa) => (rsa, hash).try_sign(data).map_err(|e| e.to_string())?,
        _ => key.try_sign(data).map_err(|e| e.to_string())?,
    };
    let mut out = Vec::new();
    sig.encode(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Stored key passphrases for UseKeychain, in the system's credential store.
mod keychain {
    const SERVICE: &str = "Reach SSH key passphrase";

    pub fn get(id: &str) -> Option<String> {
        crate::vault::manager::keychain_entry_in(SERVICE, id).ok()?.get_password().ok()
    }

    pub fn set(id: &str, pass: &str) {
        if let Ok(e) = crate::vault::manager::keychain_entry_in(SERVICE, id) {
            if let Err(err) = e.set_password(pass) {
                tracing::warn!("UseKeychain: could not store the passphrase: {err}");
            }
        }
    }
}

enum Step {
    Success,
    Failure { remaining: Vec<MethodKind>, partial: bool },
}

fn step(r: russh::client::AuthResult) -> Step {
    match r {
        russh::client::AuthResult::Success => Step::Success,
        russh::client::AuthResult::Failure { remaining_methods, partial_success } => {
            Step::Failure { remaining: remaining_methods.to_vec(), partial: partial_success }
        }
    }
}

fn err(e: impl std::fmt::Display) -> SshError {
    SshError::ConnectionFailed(format!("Auth error: {e}"))
}

/// Log in under the policy. The outcome reads like Reach's own login's, so
/// the callers and their messages stay the same.
pub(crate) async fn authenticate<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    user: &str,
    auth: &AuthParams,
    p: &AuthPolicy,
    ui: Ui<'_>,
) -> Result<AuthOutcome, SshError> {
    let mut outcome = AuthOutcome::default();
    // "none" first: the server answers with the methods it takes.
    let mut methods = match step(handle.authenticate_none(user).await.map_err(err)?) {
        Step::Success => {
            outcome.by = Some(AuthBy::NoCredentials);
            return Ok(outcome);
        }
        Step::Failure { remaining, .. } => remaining,
    };
    let mut agent = connect_agent(&p.agent).await;
    let mut identities: Option<Vec<Identity>> = None;
    let mut next_identity = 0usize;
    let mut passwords_tried = 0u32;
    let mut kbd_tried = 0u32;
    let mut stored_password = auth.password.clone();
    let mut done: Vec<MethodKind> = Vec::new();
    while let Some(method) = p.methods.iter().copied().find(|m| methods.contains(m) && !done.contains(m)) {
        let result = match method {
            MethodKind::PublicKey => {
                if identities.is_none() {
                    identities = Some(prepare(auth, p, &mut agent, ui).await);
                }
                let ids = identities.as_ref().unwrap();
                let Some(id) = ids.get(next_identity) else {
                    done.push(method);
                    continue;
                };
                next_identity += 1;
                let Some(public) = id.public.clone() else {
                    tracing::info!("{}: no public key without its passphrase; skipped", id.label);
                    continue;
                };
                let server_rsa = handle.best_supported_rsa_hash().await.ok().flatten();
                let Some(hash) = signing_hash(&public, id.cert.is_some(), p, server_rsa) else {
                    continue;
                };
                tracing::info!("SSH publickey: offering {}", id.label);
                let r = match (&id.source, &id.cert) {
                    (Source::Agent(_), Some(cert)) => {
                        let a = agent.as_mut().expect("agent identity without an agent");
                        handle.authenticate_certificate_with(user, cert.clone(), hash, a).await.map_err(err)?
                    }
                    (Source::Agent(_), None) => {
                        let a = agent.as_mut().expect("agent identity without an agent");
                        handle.authenticate_publickey_with(user, public.clone(), hash, a).await.map_err(err)?
                    }
                    (source, cert) => {
                        let mut signer = FileSigner { source, label: &id.label, policy: p, ui, key: None };
                        let r = match cert {
                            Some(c) => handle.authenticate_certificate_with(user, c.clone(), hash, &mut signer).await,
                            None => handle.authenticate_publickey_with(user, public.clone(), hash, &mut signer).await,
                        };
                        let r = match r {
                            Ok(r) => r,
                            Err(SignError::Key(e)) => {
                                tracing::info!("SSH publickey: {} not used: {e}", id.label);
                                continue;
                            }
                            Err(SignError::Send) => return Err(err("connection closed")),
                        };
                        if r.success() {
                            if let Some(key) = signer.key.take() {
                                add_to_agent(&mut agent, &key, p, ui).await;
                            }
                        }
                        r
                    }
                };
                let s = step(r);
                if matches!(s, Step::Failure { partial: false, .. }) {
                    if let (Source::Session { .. }, Some(public)) = (&id.source, &id.public) {
                        outcome.refused_key = Some(public.fingerprint(HashAlg::Sha256).to_string());
                    }
                } else if matches!(s, Step::Success) {
                    outcome.by = Some(if matches!(id.source, Source::Agent(_)) { AuthBy::Agent } else { AuthBy::Key });
                }
                s
            }
            MethodKind::Password => {
                if passwords_tried >= p.password_prompts.max(1) + u32::from(auth.password.is_some()) {
                    done.push(method);
                    continue;
                }
                passwords_tried += 1;
                let password = match stored_password.take() {
                    Some(pw) => pw,
                    None if p.batch_mode => {
                        done.push(method);
                        continue;
                    }
                    None => {
                        let text = if passwords_tried > 1 + u32::from(auth.password.is_some()) {
                            "Permission denied, please try again.".to_string()
                        } else {
                            format!("{user}@{}'s password:", ui.host)
                        };
                        match ui.ask(Kind::Password, &text, "", vec![Field { text: text.clone(), echo: false }]).await {
                            Some(a) => a.into_iter().next().unwrap_or_default(),
                            None => {
                                done.push(method);
                                continue;
                            }
                        }
                    }
                };
                let s = step(handle.authenticate_password(user, password).await.map_err(err)?);
                if matches!(s, Step::Success) {
                    outcome.by = Some(AuthBy::Password);
                }
                s
            }
            MethodKind::KeyboardInteractive => {
                if kbd_tried >= p.password_prompts.max(1) {
                    done.push(method);
                    continue;
                }
                kbd_tried += 1;
                let s = keyboard_interactive(handle, user, p, ui, &mut stored_password).await?;
                if matches!(s, Some(Step::Success)) {
                    outcome.by = Some(AuthBy::Password);
                }
                match s {
                    Some(s) => s,
                    None => {
                        done.push(method);
                        continue;
                    }
                }
            }
            MethodKind::GssapiKeyex => {
                // userauth_gsskeyex: once, and only after a GSS-API key
                // exchange, whose context signs the session.
                done.push(method);
                if p.gss_kex.is_none() {
                    continue;
                }
                let Some(r) = handle.authenticate_gssapi_keyex(user).await.map_err(|e| SshError::ConnectionFailed(format!("Auth error: {e}")))? else {
                    tracing::info!("SSH gssapi-keyex: no GSSAPI key exchange context; skipped");
                    continue;
                };
                let s = step(r);
                if matches!(s, Step::Success) {
                    outcome.by = Some(AuthBy::Gssapi);
                }
                s
            }
            MethodKind::GssapiWithMic => {
                // One mechanism, Kerberos, tried once: ssh moves past each
                // mechanism it tried.
                done.push(method);
                let Some(g) = &p.gssapi else { continue };
                let Some(r) = super::gssapi::authenticate(handle, user, ui.host, g).await? else { continue };
                let s = step(r);
                if matches!(s, Step::Success) {
                    outcome.by = Some(AuthBy::Gssapi);
                }
                s
            }
            MethodKind::HostBased if p.hostbased.is_some() => {
                let ctx = p.hostbased.clone().expect("checked");
                match super::hostbased::next_attempt(handle, user, &ctx).await {
                    None => {
                        done.push(method);
                        continue;
                    }
                    Some(Err(e)) => {
                        tracing::info!("SSH hostbased: {e}");
                        continue;
                    }
                    Some(Ok(r)) => {
                        let s = step(r);
                        if matches!(s, Step::Success) {
                            outcome.by = Some(AuthBy::Key);
                        }
                        s
                    }
                }
            }
            MethodKind::HostBased => {
                tracing::info!("SSH: {} is not set up for this host; skipped", <&str>::from(&method));
                done.push(method);
                continue;
            }
            MethodKind::None => {
                done.push(method);
                continue;
            }
        };
        match result {
            Step::Success => return Ok(outcome),
            Step::Failure { remaining, partial } => {
                if partial {
                    tracing::info!("SSH: partial success; the server wants another method");
                }
                methods = remaining;
            }
        }
    }
    Ok(outcome)
}

/// One keyboard-interactive exchange. `None` when the user cancels or
/// BatchMode forbids asking. A stored password answers a lone hidden
/// "Password:" question once, as servers that use PAM ask for it this way.
async fn keyboard_interactive<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    user: &str,
    p: &AuthPolicy,
    ui: Ui<'_>,
    stored_password: &mut Option<String>,
) -> Result<Option<Step>, SshError> {
    use russh::client::KeyboardInteractiveAuthResponse as K;
    let mut r = handle.authenticate_keyboard_interactive_start(user, p.kbd_devices.clone()).await.map_err(err)?;
    loop {
        match r {
            K::Success => return Ok(Some(Step::Success)),
            K::Failure { remaining_methods, partial_success } => {
                return Ok(Some(Step::Failure { remaining: remaining_methods.to_vec(), partial: partial_success }))
            }
            K::InfoRequest { name, instructions, prompts } => {
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else if prompts.len() == 1 && !prompts[0].echo && prompts[0].prompt.to_ascii_lowercase().contains("password") && stored_password.is_some() {
                    vec![stored_password.take().unwrap_or_default()]
                } else if p.batch_mode {
                    return Ok(None);
                } else {
                    let fields = prompts.iter().map(|q| Field { text: q.prompt.clone(), echo: q.echo }).collect();
                    let title = if name.is_empty() { format!("{user}@{}", ui.host) } else { name.clone() };
                    match ui.ask(Kind::Keyboard, &title, &instructions, fields).await {
                        Some(a) => a,
                        None => return Ok(None),
                    }
                };
                r = handle.authenticate_keyboard_interactive_respond(answers).await.map_err(err)?;
            }
        }
    }
}

/// AddKeysToAgent: hand a key loaded from a file to the agent after it
/// logged in.
async fn add_to_agent(agent: &mut Option<Agent>, key: &PrivateKey, p: &AuthPolicy, ui: Ui<'_>) {
    if p.add_keys == AddKeys::No {
        return;
    }
    let Some(a) = agent.as_mut() else { return };
    if p.add_keys == AddKeys::Ask {
        let text = "Add this key to the SSH agent?";
        match ui.ask(Kind::Confirm, text, "", vec![]).await {
            Some(_) => {}
            None => return,
        }
    }
    let mut constraints = Vec::new();
    if let Some(s) = p.add_keys_lifetime {
        constraints.push(russh::keys::agent::Constraint::KeyLifetime { seconds: s });
    }
    if p.add_keys == AddKeys::Confirm {
        constraints.push(russh::keys::agent::Constraint::Confirm);
    }
    match a.add_identity(key, &constraints).await {
        Ok(()) => tracing::info!("AddKeysToAgent: key added to the agent"),
        Err(e) => tracing::warn!("AddKeysToAgent: the agent refused the key: {e}"),
    }
}

/// Built from resolved options; see session.rs for where the paths are
/// expanded.
impl AuthPolicy {
    pub fn from_options(
        o: &super::sshconf::resolve::Options,
        identity_files: Vec<String>,
        certificate_files: Vec<String>,
        pubkey_algorithms: Option<Vec<String>>,
        imported: bool,
    ) -> AuthPolicy {
        use super::sshconf::keyword::Kw;
        let flag = |kw: Kw, default: bool| o.first(kw).map_or(default, |v| v != "no");
        let preferred =
            o.first(Kw::PreferredAuthentications).unwrap_or("gssapi-keyex,gssapi-with-mic,hostbased,publickey,keyboard-interactive,password");
        let methods = preferred
            .split(',')
            .filter_map(|m| m.trim().parse::<MethodKind>().ok())
            .filter(|m| match m {
                MethodKind::PublicKey => flag(Kw::PubkeyAuthentication, true),
                MethodKind::KeyboardInteractive => flag(Kw::KbdInteractiveAuthentication, true),
                MethodKind::Password => flag(Kw::PasswordAuthentication, true),
                MethodKind::GssapiWithMic => flag(Kw::GSSAPIAuthentication, false),
                MethodKind::GssapiKeyex => flag(Kw::GSSAPIKeyExchange, false),
                MethodKind::HostBased => flag(Kw::HostbasedAuthentication, false),
                MethodKind::None => false,
            })
            .collect();
        let agent = match o.first(Kw::IdentityAgent) {
            Some(a) if a.eq_ignore_ascii_case("none") => AgentChoice::Off,
            Some("SSH_AUTH_SOCK") => AgentChoice::Default,
            Some(a) if a.starts_with('$') => match std::env::var(a.trim_start_matches('$').trim_matches(['{', '}'])) {
                Ok(v) => AgentChoice::Socket(v),
                Err(_) => AgentChoice::Off,
            },
            Some(path) => AgentChoice::Socket(path.to_string()),
            None if imported => AgentChoice::Default,
            None => AgentChoice::Off,
        };
        let (add_keys, add_keys_lifetime) = match o.get(Kw::AddKeysToAgent).map(|s| s.args.clone()) {
            None => (AddKeys::No, None),
            Some(a) => {
                let life = a.get(1).and_then(|t| super::sshconf::value::convtime(t)).map(|s| s as u32);
                let k = match a[0].as_str() {
                    "yes" => AddKeys::Yes,
                    "ask" => AddKeys::Ask,
                    "confirm" => AddKeys::Confirm,
                    _ => AddKeys::No,
                };
                (k, life)
            }
        };
        AuthPolicy {
            methods,
            default_identities: imported && identity_files.is_empty(),
            identity_files,
            certificate_files,
            identities_only: flag(Kw::IdentitiesOnly, false),
            agent,
            pubkey_algorithms,
            batch_mode: flag(Kw::BatchMode, false),
            password_prompts: o.first(Kw::NumberOfPasswordPrompts).and_then(|n| n.parse().ok()).unwrap_or(3),
            kbd_devices: o.first(Kw::KbdInteractiveDevices).map(str::to_string),
            add_keys,
            add_keys_lifetime,
            min_rsa_bits: o.first(Kw::RequiredRSASize).and_then(|n| n.parse().ok()).unwrap_or(1024),
            use_keychain: flag(Kw::UseKeychain, false),
            gssapi: flag(Kw::GSSAPIAuthentication, false).then(|| super::gssapi::GssapiPolicy::from_options(o)),
            gss_kex: super::gssapi::GssKexPolicy::from_options(o),
            hostbased: None,
            // Libraries load only once approved; session.rs sets these.
            pkcs11_provider: None,
            sk_provider: super::sk::Provider::from_options(o, &[]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str, imported: bool) -> AuthPolicy {
        let src = crate::ssh::sshconf::resolve::Source { path: "c".into(), text: Some(text.into()), user: true };
        let env = crate::ssh::sshconf::env::SystemEnv::new(crate::ssh::sshconf::env::ExecPolicy::Never);
        let r = crate::ssh::sshconf::resolve::resolve(&[src], &crate::ssh::sshconf::resolve::Query { host: "h".into(), ..Default::default() }, &env);
        AuthPolicy::from_options(&r.options, vec![], vec![], None, imported)
    }

    #[test]
    fn method_order_and_switches() {
        let p = policy("PreferredAuthentications keyboard-interactive,password,publickey\nPasswordAuthentication no\n", false);
        assert_eq!(p.methods, [MethodKind::KeyboardInteractive, MethodKind::PublicKey]);
        let p = policy("GSSAPIAuthentication yes\n", false);
        assert_eq!(p.methods[0], MethodKind::GssapiWithMic);
        assert!(p.gss_kex.is_none());
        // gssapi-keyex goes first, with GSSAPIKeyExchange alone.
        let p = policy("GSSAPIKeyExchange yes\n", false);
        assert_eq!(p.methods[0], MethodKind::GssapiKeyex);
        assert!(!p.methods.contains(&MethodKind::GssapiWithMic));
        let k = p.gss_kex.unwrap();
        assert_eq!(k.algorithms.len(), 6);
        assert!(!k.renewal_rekey);
        let p = policy("GSSAPIKeyExchange yes\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-gex-sha1-\nGSSAPIRenewalForcesRekey yes\n", false);
        let k = p.gss_kex.unwrap();
        assert_eq!(k.algorithms, [russh::kex::GSS_CURVE25519_SHA256, russh::kex::GSS_GEX_SHA1]);
        assert!(k.renewal_rekey);
        assert_eq!(policy("", false).methods, [MethodKind::PublicKey, MethodKind::KeyboardInteractive, MethodKind::Password]);
    }

    #[test]
    fn agent_follows_identity_agent_and_import() {
        assert_eq!(policy("", false).agent, AgentChoice::Off);
        assert_eq!(policy("", true).agent, AgentChoice::Default);
        assert_eq!(policy("IdentityAgent none\n", true).agent, AgentChoice::Off);
        assert_eq!(policy("IdentityAgent /run/a.sock\n", false).agent, AgentChoice::Socket("/run/a.sock".into()));
        assert!(policy("", true).default_identities);
    }

    #[test]
    fn add_keys_to_agent_forms() {
        let p = policy("AddKeysToAgent confirm 5m\n", false);
        assert_eq!((p.add_keys, p.add_keys_lifetime), (AddKeys::Confirm, Some(300)));
        assert_eq!(policy("AddKeysToAgent 1h\n", false).add_keys_lifetime, Some(3600));
    }
}
