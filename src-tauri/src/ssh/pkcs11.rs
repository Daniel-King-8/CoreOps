//! PKCS11Provider: keys on a smart card or token, through the token's
//! PKCS#11 library, used the way OpenSSH's ssh-pkcs11.c uses it.
//!
//! As ssh does: the library is loaded and initialized, every slot with an
//! initialized token gets a session, and the public keys (RSA, ECDSA
//! P-256/384/521, Ed25519 where the token has CKK_EC_EDWARDS) and X.509
//! certificates on it become identities, offered before IdentityFile keys.
//! A token that shows no keys before login is logged in to first. The PIN
//! is asked only when the server would take a key and it is about to sign
//! (or by a key with CKA_ALWAYS_AUTHENTICATE, again for each signature).
//! RSA signs with CKM_RSA_PKCS over the DigestInfo of the hash, ECDSA with
//! CKM_ECDSA over the hash, Ed25519 with CKM_EDDSA over the data.
//!
//! One difference: ssh runs the library in a helper process
//! (ssh-pkcs11-helper); Reach loads it in its own, and only once the user
//! approved the path (see `provider_from`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use russh::keys::{HashAlg, PublicKey};

use super::prompt::{Field, Kind};
use super::userauth::Ui;

/// PKCS11Provider as resolved: `None` for none, or for a library the user
/// has not approved yet. Loading a library runs its code, so a path from a
/// config file waits for approval as a command does.
pub(crate) fn provider_from(o: &super::sshconf::resolve::Options, approved: &[String]) -> Option<String> {
    use super::sshconf::keyword::Kw;
    let path = o.first(Kw::PKCS11Provider).filter(|p| !p.eq_ignore_ascii_case("none"))?;
    if approved.iter().any(|a| a == path) {
        Some(path.to_string())
    } else {
        tracing::warn!("PKCS11Provider {path} waits for your approval in the session's SSH options; not loading it");
        None
    }
}

/// A loaded library, shared by the connections using it at the same time
/// and finalized when the last of them is done, as ssh finalizes it when it
/// exits.
struct Module {
    ctx: Option<Pkcs11>,
    raw: RawSign,
}

/// C_Sign from the library's own function list. cryptoki only offers
/// C_SignInit and C_Sign together, and a key with CKA_ALWAYS_AUTHENTICATE
/// needs its login between the two, as pkcs11_get_key does it.
struct RawSign {
    sign: unsafe extern "C" fn(
        cryptoki_sys::CK_SESSION_HANDLE,
        *mut cryptoki_sys::CK_BYTE,
        cryptoki_sys::CK_ULONG,
        *mut cryptoki_sys::CK_BYTE,
        *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV,
    /// The same library loaded once more, which keeps `sign` valid.
    _lib: libloading::Library,
}

impl Drop for Module {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.take() {
            if let Err(e) = ctx.finalize() {
                tracing::info!("PKCS#11: C_Finalize: {e}");
            }
        }
    }
}

impl Module {
    fn ctx(&self) -> &Pkcs11 {
        self.ctx.as_ref().expect("finalized only on drop")
    }
}

fn module(path: &str) -> Result<Arc<Module>, String> {
    static LOADED: OnceLock<Mutex<HashMap<String, Weak<Module>>>> = OnceLock::new();
    let mut loaded = LOADED.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    if let Some(m) = loaded.get(path).and_then(Weak::upgrade) {
        return Ok(m);
    }
    let ctx = Pkcs11::new(path).map_err(|e| format!("dlopen {path} failed: {e}"))?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(format!("C_Initialize for provider {path} failed: {e}")),
    }
    // SAFETY: the library is the one cryptoki just loaded and initialized;
    // C_GetFunctionList and C_Sign have the signatures pkcs11.h gives them,
    // which cryptoki-sys declares, and `_lib` keeps the library loaded for
    // as long as `sign` can be called.
    let raw = unsafe {
        let lib = libloading::Library::new(path).map_err(|e| format!("dlopen {path} failed: {e}"))?;
        let get: libloading::Symbol<unsafe extern "C" fn(*mut *mut cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_RV> =
            lib.get(b"C_GetFunctionList\0").map_err(|e| format!("dlsym(C_GetFunctionList) failed: {e}"))?;
        let mut list: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = get(&mut list);
        if rv != cryptoki_sys::CKR_OK || list.is_null() {
            return Err(format!("C_GetFunctionList for provider {path} failed: {rv}"));
        }
        let sign = (*list).C_Sign.ok_or("the provider has no C_Sign")?;
        RawSign { sign, _lib: lib }
    };
    let m = Arc::new(Module { ctx: Some(ctx), raw });
    loaded.retain(|_, w| w.strong_count() > 0);
    loaded.insert(path.to_string(), Arc::downgrade(&m));
    Ok(m)
}

/// One token's slot, with the session ssh keeps open on it for the login.
struct SlotState {
    /// Dropped before the module, so the session closes before C_Finalize.
    session: Mutex<Session>,
    label: String,
    login_required: bool,
    /// A reader with its own keypad (CKF_PROTECTED_AUTHENTICATION_PATH).
    pinpad: bool,
    logged_in: AtomicBool,
}

/// A library loaded for one login.
pub(crate) struct Provider {
    slots: Vec<SlotState>,
    module: Arc<Module>,
    path: String,
    /// Not BatchMode: PINs may be asked.
    interactive: bool,
}

#[derive(Clone, Copy)]
enum Alg {
    Rsa { len: usize },
    /// The curve's size picks the hash: SHA-256, SHA-384, SHA-512.
    Ecdsa { bits: u16, name: &'static str },
    Ed25519,
}

/// A key on a token: an identity to offer.
pub(crate) struct Key {
    provider: Arc<Provider>,
    slot: usize,
    id: Vec<u8>,
    alg: Alg,
    pub public: PublicKey,
    pub label: String,
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| format!("PKCS#11 call failed: {e}"))
}

/// The keys PKCS11Provider offers, in the token's order. Errors are logged
/// and leave no keys, as ssh goes on without them.
pub(crate) async fn keys(path: &str, ui: Ui<'_>, batch_mode: bool) -> Vec<Key> {
    match load(path, ui, !batch_mode).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("PKCS11Provider {path}: {e}");
            Vec::new()
        }
    }
}

async fn load(path: &str, ui: Ui<'_>, interactive: bool) -> Result<Vec<Key>, String> {
    let p = path.to_string();
    let provider = Arc::new(blocking(move || open(&p, interactive)).await??);
    let mut keys: Vec<Key> = Vec::new();
    for i in 0..provider.slots.len() {
        let pr = provider.clone();
        let found = blocking(move || pr.fetch(i)).await?;
        add(&mut keys, &provider, i, found);
        if keys.is_empty() && !provider.slots[i].logged_in.load(Ordering::SeqCst) && interactive {
            // Some tokens show their keys only after login.
            if let Err(e) = provider.login(i, UserType::User, ui).await {
                tracing::warn!("PKCS#11: login failed: {e}");
                continue;
            }
            let pr = provider.clone();
            let found = blocking(move || pr.fetch(i)).await?;
            add(&mut keys, &provider, i, found);
        }
    }
    tracing::info!("PKCS11Provider {path}: {} key(s)", keys.len());
    Ok(keys)
}

/// Adds keys not already found, in this slot or another (as
/// pkcs11_key_included and pkcs11_record_key skip them).
fn add(keys: &mut Vec<Key>, provider: &Arc<Provider>, slot: usize, found: Vec<(Vec<u8>, Alg, PublicKey, String)>) {
    for (id, alg, public, label) in found {
        if keys.iter().any(|k| k.public.key_data() == public.key_data()) {
            continue;
        }
        let token = &provider.slots[slot].label;
        tracing::info!("PKCS#11: slot {slot} ({token}): {} {}", public.algorithm().as_str(), public.fingerprint(HashAlg::Sha256));
        keys.push(Key { provider: provider.clone(), slot, id, alg, public, label: format!("{label} (PKCS#11 token '{token}')") });
    }
}

/// pkcs11_register_provider: load, initialize, and open a session on every
/// slot with an initialized token.
fn open(path: &str, interactive: bool) -> Result<Provider, String> {
    let module = module(path)?;
    let ctx = module.ctx();
    let slots = ctx.get_slots_with_token().map_err(|e| format!("C_GetSlotList failed: {e}"))?;
    if slots.is_empty() {
        return Err(format!("provider {path} returned no slots"));
    }
    let mut states = Vec::new();
    for slot in slots {
        let token = match ctx.get_token_info(slot) {
            Ok(t) => t,
            Err(e) => {
                tracing::info!("PKCS#11: C_GetTokenInfo for slot {slot} failed: {e}");
                continue;
            }
        };
        if !token.token_initialized() {
            tracing::info!("PKCS#11: ignoring uninitialised token in slot {slot}");
            continue;
        }
        let session = match open_session(ctx, slot) {
            Ok(s) => s,
            Err(e) => {
                tracing::info!("PKCS#11: C_OpenSession failed: {e}");
                continue;
            }
        };
        states.push(SlotState {
            session: Mutex::new(session),
            label: token.label().trim_end().to_string(),
            login_required: token.login_required(),
            pinpad: token.protected_authentication_path(),
            logged_in: AtomicBool::new(false),
        });
    }
    Ok(Provider { slots: states, module, path: path.to_string(), interactive })
}

/// A read-write serial session, as ssh opens it.
fn open_session(ctx: &Pkcs11, slot: Slot) -> Result<Session, CkError> {
    ctx.open_rw_session(slot)
}

impl Provider {
    /// pkcs11_fetch_keys and pkcs11_fetch_certs for one slot.
    fn fetch(&self, i: usize) -> Vec<(Vec<u8>, Alg, PublicKey, String)> {
        let session = self.slots[i].session.lock().unwrap();
        let mut out = Vec::new();
        match session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)]) {
            Ok(objects) => {
                for obj in objects {
                    let Ok(attrs) = session.get_attributes(obj, &[AttributeType::KeyType, AttributeType::Label]) else { continue };
                    let mut key_type = None;
                    let mut label = String::new();
                    for a in attrs {
                        match a {
                            Attribute::KeyType(t) => key_type = Some(t),
                            Attribute::Label(l) => label = String::from_utf8_lossy(&l).to_string(),
                            _ => {}
                        }
                    }
                    let wanted: &[AttributeType] = match key_type {
                        Some(KeyType::RSA) => &[AttributeType::Id, AttributeType::Modulus, AttributeType::PublicExponent],
                        Some(KeyType::EC) | Some(KeyType::EC_EDWARDS) => &[AttributeType::Id, AttributeType::EcPoint, AttributeType::EcParams],
                        other => {
                            tracing::info!("PKCS#11: skipping unsupported key type {other:?}");
                            continue;
                        }
                    };
                    let Ok(attrs) = session.get_attributes(obj, wanted) else { continue };
                    let (mut id, mut n, mut e, mut point, mut params) = (Vec::new(), None, None, None, None);
                    for a in attrs {
                        match a {
                            Attribute::Id(v) => id = v,
                            Attribute::Modulus(v) => n = Some(v),
                            Attribute::PublicExponent(v) => e = Some(v),
                            Attribute::EcPoint(v) => point = Some(v),
                            Attribute::EcParams(v) => params = Some(v),
                            _ => {}
                        }
                    }
                    let key = match (key_type, n, e, point, params) {
                        (Some(KeyType::RSA), Some(n), Some(e), _, _) => rsa_public(&n, &e),
                        (Some(KeyType::EC), _, _, Some(point), Some(params)) => ec_public(&params, &point),
                        (Some(KeyType::EC_EDWARDS), _, _, Some(point), Some(params)) => ed25519_public(&params, &point),
                        _ => None,
                    };
                    match key {
                        Some((alg, public)) => out.push((id, alg, public, label)),
                        None => tracing::info!("PKCS#11: failed to fetch key '{label}'"),
                    }
                }
            }
            Err(e) => tracing::info!("PKCS#11: C_FindObjects failed: {e}"),
        }
        match session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)]) {
            Ok(objects) => {
                for obj in objects {
                    let wanted = [AttributeType::CertificateType, AttributeType::Id, AttributeType::Value, AttributeType::Label];
                    let Ok(attrs) = session.get_attributes(obj, &wanted) else { continue };
                    let (mut kind, mut id, mut value, mut label) = (None, Vec::new(), None, String::new());
                    for a in attrs {
                        match a {
                            Attribute::CertificateType(t) => kind = Some(t),
                            Attribute::Id(v) => id = v,
                            Attribute::Value(v) => value = Some(v),
                            Attribute::Label(l) => label = String::from_utf8_lossy(&l).to_string(),
                            _ => {}
                        }
                    }
                    if kind != Some(CertificateType::X_509) {
                        tracing::info!("PKCS#11: skipping unsupported certificate type {kind:?}");
                        continue;
                    }
                    match value.as_deref().and_then(x509_public) {
                        Some((alg, public)) => out.push((id, alg, public, label)),
                        None => tracing::info!("PKCS#11: failed to fetch key from certificate '{label}'"),
                    }
                }
            }
            Err(e) => tracing::info!("PKCS#11: C_FindObjects failed: {e}"),
        }
        out
    }

    /// pkcs11_login_slot: the PIN from the user (or the reader's keypad),
    /// one try.
    async fn login(self: &Arc<Self>, i: usize, user: UserType, ui: Ui<'_>) -> Result<(), String> {
        let slot = &self.slots[i];
        if !self.interactive {
            return Err(format!("need pin entry{}", if slot.pinpad { " on reader keypad" } else { "" }));
        }
        let pin = if slot.pinpad {
            tracing::info!("PKCS#11: deferring PIN entry to reader keypad.");
            None
        } else {
            let text = format!("Enter PIN for '{}':", slot.label);
            let answer = ui.ask(Kind::Passphrase, &text, "", vec![Field { text: text.clone(), echo: false }]).await;
            Some(answer.and_then(|a| a.into_iter().next()).ok_or("no pin specified")?)
        };
        let pr = self.clone();
        blocking(move || {
            let pin = pin.map(AuthPin::from);
            let session = pr.slots[i].session.lock().unwrap();
            match session.login(user, pin.as_ref()) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
                Err(CkError::Pkcs11(RvError::PinLenRange, _)) => Err("PKCS#11 login failed: PIN length out of range".to_string()),
                Err(CkError::Pkcs11(RvError::PinIncorrect, _)) => Err("PKCS#11 login failed: PIN incorrect".to_string()),
                Err(CkError::Pkcs11(RvError::PinLocked, _)) => Err("PKCS#11 login failed: PIN locked".to_string()),
                Err(e) => Err(format!("PKCS#11 login failed: {e}")),
            }
        })
        .await??;
        slot.logged_in.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Logged in already through another session of this process: PKCS#11
    /// keeps one login per token for the whole application.
    fn session_logged_in(&self, i: usize) -> bool {
        let session = self.slots[i].session.lock().unwrap();
        matches!(session.get_session_info().map(|s| s.session_state()), Ok(SessionState::RoUser | SessionState::RwUser))
    }
}

impl Key {
    /// An SSH signature blob over `data`, as pkcs11_sign_rsa,
    /// pkcs11_sign_ecdsa and pkcs11_sign_ed25519 make it.
    pub(crate) async fn sign(&self, hash: Option<HashAlg>, data: &[u8], ui: Ui<'_>) -> Result<Vec<u8>, String> {
        let p = &self.provider;
        let i = self.slot;
        let slot = &p.slots[i];
        let mut did_login = false;
        if slot.login_required && !slot.logged_in.load(Ordering::SeqCst) {
            if p.session_logged_in(i) {
                slot.logged_in.store(true, Ordering::SeqCst);
            } else {
                p.login(i, UserType::User, ui).await.map_err(|e| format!("login failed: {e}"))?;
                did_login = true;
            }
        }
        let (input, name, max) = match self.alg {
            Alg::Rsa { len } => {
                let (prefix, digest, name): (&[u8], Vec<u8>, &str) = match hash {
                    Some(HashAlg::Sha512) => (&ID_SHA512, sha2_digest::<sha2::Sha512>(data), "rsa-sha2-512"),
                    Some(HashAlg::Sha256) => (&ID_SHA256, sha2_digest::<sha2::Sha256>(data), "rsa-sha2-256"),
                    _ => (&ID_SHA1, sha2_digest::<sha1::Sha1>(data), "ssh-rsa"),
                };
                ([prefix, &digest].concat(), name, len)
            }
            Alg::Ecdsa { bits, name } => {
                let digest = match bits {
                    256 => sha2_digest::<sha2::Sha256>(data),
                    384 => sha2_digest::<sha2::Sha384>(data),
                    _ => sha2_digest::<sha2::Sha512>(data),
                };
                (digest, name, 132)
            }
            Alg::Ed25519 => (data.to_vec(), "ssh-ed25519", 64),
        };
        let alg = self.alg;
        let id = self.id.clone();
        let pr = p.clone();
        let always_auth = blocking(move || -> Result<bool, String> {
            let session = pr.slots[i].session.lock().unwrap();
            // The private key with the same CKA_ID: with CKA_SIGN first, then without.
            let mut filter = vec![Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(id), Attribute::Sign(true)];
            let mut found = session.find_objects(&filter).unwrap_or_default();
            if found.len() != 1 {
                filter.pop();
                found = session.find_objects(&filter).unwrap_or_default();
            }
            let [obj] = found[..] else { return Err("cannot find private key".into()) };
            let mech = match alg {
                Alg::Rsa { .. } => Mechanism::RsaPkcs,
                Alg::Ecdsa { .. } => Mechanism::Ecdsa,
                Alg::Ed25519 => Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
            };
            session.sign_init(&mech, obj).map_err(|e| format!("C_SignInit failed: {e}"))?;
            let always = matches!(
                session.get_attributes(obj, &[AttributeType::AlwaysAuthenticate]).as_deref(),
                Ok([Attribute::AlwaysAuthenticate(true)])
            );
            Ok(always)
        })
        .await??;
        if always_auth && !did_login {
            tracing::info!("PKCS#11: always-auth key");
            p.login(i, UserType::ContextSpecific, ui).await.map_err(|e| format!("login failed for always-auth key: {e}"))?;
        }
        let pr = p.clone();
        let mut sig = blocking(move || -> Result<Vec<u8>, String> {
            let session = pr.slots[i].session.lock().unwrap();
            let mut input = input;
            let mut out = vec![0u8; max];
            let mut len = max as cryptoki_sys::CK_ULONG;
            // SAFETY: the session is open and a signing operation was just
            // started on it; `input` and `out` are live buffers whose sizes
            // are the lengths passed.
            let rv = unsafe { (pr.module.raw.sign)(session.handle(), input.as_mut_ptr(), input.len() as _, out.as_mut_ptr(), &mut len) };
            if rv != cryptoki_sys::CKR_OK {
                return Err(format!("C_Sign failed: {rv}"));
            }
            out.truncate(len as usize);
            Ok(out)
        })
        .await??;
        let mut blob = Vec::new();
        put_string(&mut blob, name.as_bytes());
        match self.alg {
            Alg::Rsa { len } => {
                if sig.len() > len {
                    return Err("bad C_Sign length".into());
                }
                // Short signatures are padded to the modulus size.
                let mut padded = vec![0u8; len - sig.len()];
                padded.append(&mut sig);
                put_string(&mut blob, &padded);
            }
            Alg::Ecdsa { .. } => {
                if sig.len() < 64 || sig.len() > 132 || sig.len() % 2 != 0 {
                    return Err(format!("bad signature length: {}", sig.len()));
                }
                let (r, s) = sig.split_at(sig.len() / 2);
                let mut inner = Vec::new();
                put_mpint(&mut inner, r);
                put_mpint(&mut inner, s);
                put_string(&mut blob, &inner);
            }
            Alg::Ed25519 => {
                if sig.len() != 64 {
                    return Err(format!("bad signature length: {}", sig.len()));
                }
                put_string(&mut blob, &sig);
            }
        }
        tracing::info!("PKCS#11: signed with a key from {}", p.path);
        Ok(blob)
    }
}

fn sha2_digest<D: sha2::Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

/// DigestInfo prefixes (RFC 8017 9.2), as ssh-pkcs11.c has them.
const ID_SHA1: [u8; 15] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
const ID_SHA256: [u8; 19] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
const ID_SHA512: [u8; 19] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

/// SSH wire encoding: a string.
pub(super) fn put_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// SSH wire encoding: an unsigned big-endian number as an mpint.
pub(super) fn put_mpint(out: &mut Vec<u8>, b: &[u8]) {
    let b = &b[b.iter().take_while(|x| **x == 0).count()..];
    if b.first().is_some_and(|x| x & 0x80 != 0) {
        out.extend_from_slice(&(b.len() as u32 + 1).to_be_bytes());
        out.push(0);
        out.extend_from_slice(b);
    } else {
        put_string(out, b);
    }
}

/// One DER element: its tag, its contents and what follows it.
pub(super) fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |a, x| (a << 8) | *x as usize), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

fn parse_blob(blob: &[u8]) -> Option<PublicKey> {
    PublicKey::from_bytes(blob).ok()
}

fn rsa_public(n: &[u8], e: &[u8]) -> Option<(Alg, PublicKey)> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-rsa");
    put_mpint(&mut blob, e);
    put_mpint(&mut blob, n);
    let len = n.iter().skip_while(|x| **x == 0).count();
    Some((Alg::Rsa { len }, parse_blob(&blob)?))
}

/// An EC key from its curve OID and uncompressed point.
fn ec_from_oid(oid: &[u8], point: &[u8]) -> Option<(Alg, PublicKey)> {
    let (curve, name, bits) = match oid {
        OID_P256 => ("nistp256", "ecdsa-sha2-nistp256", 256),
        OID_P384 => ("nistp384", "ecdsa-sha2-nistp384", 384),
        OID_P521 => ("nistp521", "ecdsa-sha2-nistp521", 521),
        _ => {
            tracing::info!("PKCS#11: unsupported curve");
            return None;
        }
    };
    let mut blob = Vec::new();
    put_string(&mut blob, name.as_bytes());
    put_string(&mut blob, curve.as_bytes());
    put_string(&mut blob, point);
    // Parsing checks the point is on the curve.
    Some((Alg::Ecdsa { bits, name }, parse_blob(&blob)?))
}

/// CKA_EC_PARAMS (a named curve) and CKA_EC_POINT (DER OCTET STRING).
fn ec_public(params: &[u8], point: &[u8]) -> Option<(Alg, PublicKey)> {
    let (0x06, oid, _) = der(params)? else { return None };
    if point.len() <= 2 {
        return None;
    }
    let (0x04, q, _) = der(point)? else { return None };
    ec_from_oid(oid, q)
}

fn ed25519_from(pk: &[u8]) -> Option<(Alg, PublicKey)> {
    if pk.len() != 32 {
        return None;
    }
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, pk);
    Some((Alg::Ed25519, parse_blob(&blob)?))
}

/// CKK_EC_EDWARDS: the params name edwards25519 (as a PrintableString or
/// the OID 1.3.101.112); the point is the 32-byte key, raw or in an OCTET
/// STRING.
fn ed25519_public(params: &[u8], point: &[u8]) -> Option<(Alg, PublicKey)> {
    const NAME: &[u8] = &[0x13, 0x0c, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9'];
    const OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    if params != NAME && params != OID {
        tracing::info!("PKCS#11: unsupported CKA_EC_PARAMS for an EdDSA key");
        return None;
    }
    let pk = if point.len() == 34 && point[0] == 0x04 && point[1] == 32 { &point[2..] } else { point };
    ed25519_from(pk)
}

/// The public key of an X.509 certificate (its SubjectPublicKeyInfo).
fn x509_public(cert: &[u8]) -> Option<(Alg, PublicKey)> {
    let (0x30, cert, _) = der(cert)? else { return None };
    let (0x30, tbs, _) = der(cert)? else { return None };
    let mut rest = tbs;
    // [0] version, if present.
    if rest.first() == Some(&0xa0) {
        rest = der(rest)?.2;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = der(rest)?.2;
    }
    let (0x30, spki, _) = der(rest)? else { return None };
    let (0x30, alg_id, rest) = der(spki)? else { return None };
    let (0x03, bits, _) = der(rest)? else { return None };
    let key = bits.get(1..)?; // past the unused-bits count
    let (0x06, oid, params) = der(alg_id)? else { return None };
    match oid {
        OID_RSA => {
            let (0x30, seq, _) = der(key)? else { return None };
            let (0x02, n, rest) = der(seq)? else { return None };
            let (0x02, e, _) = der(rest)? else { return None };
            rsa_public(n, e)
        }
        OID_EC_PUBLIC_KEY => {
            let (0x06, curve, _) = der(params)? else { return None };
            ec_from_oid(curve, key)
        }
        OID_ED25519 => ed25519_from(key),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_and_der() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0, 0, 0x80, 1]);
        assert_eq!(out, [0, 0, 0, 3, 0, 0x80, 1]);
        out.clear();
        put_mpint(&mut out, &[0, 0x7f]);
        assert_eq!(out, [0, 0, 0, 1, 0x7f]);
        assert_eq!(der(&[0x04, 0x81, 0x02, 9, 9, 7]), Some((0x04, &[9u8, 9][..], &[7u8][..])));
        assert_eq!(der(&[0x04, 0x05, 1]), None);
    }

    #[test]
    fn ed25519_point_forms() {
        let pk = [7u8; 32];
        let mut wrapped = vec![0x04, 32];
        wrapped.extend_from_slice(&pk);
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let (_, a) = ed25519_public(&oid, &pk).unwrap();
        let (_, b) = ed25519_public(&oid, &wrapped).unwrap();
        assert_eq!(a, b);
        assert!(ed25519_public(&[0x06, 0x01, 0x00], &pk).is_none());
    }
}
