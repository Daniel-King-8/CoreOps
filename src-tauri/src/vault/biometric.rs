//! Opening the vault with something on this device instead of the keychain:
//! the platform's biometric (Windows Hello, Touch ID) or FIDO2 security keys
//! (Settings → Security).
//!
//! Each method produces a key only it can produce, and that key seals a copy
//! of the vault identity's secret key (XChaCha20-Poly1305). The seals live in
//! `vault_unlock.json` next to the identity; nothing stored there opens
//! anything without the method itself.
//!
//! - Windows Hello follows Bitwarden's desktop client
//!   (`desktop_native/biometric/src/windows.rs`): a Hello key credential signs
//!   a fixed random challenge, and the SHA-256 of that signature is the key.
//!   Hello's keys are RSA with PKCS#1 v1.5 signatures, which are
//!   deterministic, so the same challenge always gives the same key.
//! - Touch ID is a gate, not a seal: binding a key to Touch ID in hardware
//!   needs a keychain access group, which only an Apple Developer signing
//!   identity grants, and Reach's macOS builds have none. So a random key in
//!   the login keychain seals the vault key, and Reach reads that key only
//!   after `LAContext` has confirmed the owner's fingerprint.
//! - A security key gives its `hmac-secret` over a stored salt (see
//!   [`super::fido2`]); HKDF-SHA256 turns that into the key.
//!
//! Turning a method on never takes away another way in: a master password must
//! be set first, and the plain copy of the key in the OS keychain is removed
//! only after a method has actually opened the vault once
//! ([`Unlockers::proven`]). Removing the last method puts that copy back.

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::fido2;

const FILE: &str = "vault_unlock.json";

pub const WINDOWS_HELLO: &str = "windows_hello";
pub const TOUCH_ID: &str = "touch_id";
pub const ANDROID_BIOMETRIC: &str = "android_biometric";
pub const FIDO2: &str = "fido2";

/// The Android Keystore alias of the fingerprint key.
pub const ANDROID_KEY_ALIAS: &str = "reach-vault-fingerprint";

/// The keychain service Touch ID's sealing keys live under, one per seal.
const TOUCH_ID_SERVICE: &str = "reach-vault-touch-id";

/// The platform biometric this build offers, if any.
pub fn platform_method() -> Option<&'static str> {
    if cfg!(windows) {
        Some(WINDOWS_HELLO)
    } else if cfg!(target_os = "macos") {
        Some(TOUCH_ID)
    } else if cfg!(target_os = "android") {
        Some(ANDROID_BIOMETRIC)
    } else {
        None
    }
}

fn is_platform(kind: &str) -> bool {
    kind == WINDOWS_HELLO || kind == TOUCH_ID || kind == ANDROID_BIOMETRIC
}

/// Every way this device can open the vault besides the password.
#[derive(Serialize, Deserialize, Clone)]
pub struct Unlockers {
    pub user_uuid: String,
    /// Set once a method has opened the vault for real. Until then the plain
    /// keychain copy stays, in case a seal cannot be opened after all.
    #[serde(default)]
    pub proven: bool,
    /// The salt every security key is asked to HMAC.
    fido_salt: String,
    #[serde(default)]
    seals: Vec<Seal>,
}

/// The identity's secret key, sealed by one method.
#[derive(Serialize, Deserialize, Clone)]
pub struct Seal {
    pub id: String,
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub created: i64,
    /// Windows Hello: the challenge Hello signs.
    #[serde(default)]
    challenge: String,
    /// Security key: the credential it holds for Reach.
    #[serde(default)]
    credential_id: String,
    nonce: String,
    ciphertext: String,
}

/// A seal as Settings lists it.
#[derive(Serialize, Clone)]
pub struct SealInfo {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub created: i64,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Unlockers {
    pub fn new(user_uuid: &str) -> Self {
        let salt: [u8; 32] = rand::random();
        Unlockers { user_uuid: user_uuid.into(), proven: false, fido_salt: BASE64.encode(salt), seals: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.seals.is_empty()
    }

    pub fn has(&self, kind: &str) -> bool {
        self.seals.iter().any(|s| s.kind == kind)
    }

    pub fn list(&self) -> Vec<SealInfo> {
        self.seals
            .iter()
            .map(|s| SealInfo { id: s.id.clone(), kind: s.kind.clone(), label: s.label.clone(), created: s.created })
            .collect()
    }

    /// Add a seal. The platform biometric has one seal at most; a new one
    /// replaces it.
    pub fn add(&mut self, seal: Seal) {
        if is_platform(&seal.kind) {
            self.seals.retain(|s| !is_platform(&s.kind));
        }
        self.seals.push(seal);
    }

    /// Remove a seal; returns what it was, if there was one.
    pub fn remove(&mut self, id: &str) -> Option<Seal> {
        let at = self.seals.iter().position(|s| s.id == id)?;
        Some(self.seals.remove(at))
    }

    fn fido_salt(&self) -> Result<[u8; 32], String> {
        BASE64
            .decode(&self.fido_salt)
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "The security key salt is damaged".to_string())
    }

    fn credential_ids(&self) -> Vec<Vec<u8>> {
        self.seals
            .iter()
            .filter(|s| s.kind == FIDO2)
            .filter_map(|s| BASE64.decode(&s.credential_id).ok())
            .collect()
    }

    fn aad(&self, kind: &str) -> Vec<u8> {
        format!("reach-unlock-v1:{kind}:{}", self.user_uuid).into_bytes()
    }

    fn seal_with(&self, key: &[u8; 32], kind: &str, label: &str, secret: &[u8]) -> Result<Seal, String> {
        let nonce: [u8; 24] = rand::random();
        let ciphertext = XChaCha20Poly1305::new(key.into())
            .encrypt(&XNonce::from(nonce), Payload { msg: secret, aad: &self.aad(kind) })
            .map_err(|e| e.to_string())?;
        Ok(Seal {
            id: uuid::Uuid::new_v4().to_string(),
            kind: kind.into(),
            label: label.into(),
            created: now(),
            challenge: String::new(),
            credential_id: String::new(),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
    }

    fn open_with(&self, key: &[u8; 32], seal: &Seal) -> Result<Zeroizing<Vec<u8>>, String> {
        let nonce: [u8; 24] = BASE64
            .decode(&seal.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(|| "A seal is damaged".to_string())?;
        let ciphertext = BASE64.decode(&seal.ciphertext).map_err(|e| e.to_string())?;
        XChaCha20Poly1305::new(key.into())
            .decrypt(&XNonce::from(nonce), Payload { msg: &ciphertext, aad: &self.aad(&seal.kind) })
            .map(Zeroizing::new)
            .map_err(|_| "The key did not open the vault key".to_string())
    }

    /// Seal `secret` behind the platform biometric. Blocking; shows the
    /// system prompt.
    pub fn seal_with_platform(&self, secret: &[u8]) -> Result<Seal, String> {
        match platform_method() {
            Some(WINDOWS_HELLO) => {
                let challenge: [u8; 32] = rand::random();
                let key = hello::key_for(&challenge, true)?;
                let mut seal = self.seal_with(&key, WINDOWS_HELLO, "Windows Hello", secret)?;
                seal.challenge = BASE64.encode(challenge);
                Ok(seal)
            }
            Some(TOUCH_ID) => {
                touch::verify("turn on Touch ID for your Reach vault")?;
                let key: Zeroizing<[u8; 32]> = Zeroizing::new(rand::random());
                let seal = self.seal_with(&key, TOUCH_ID, "Touch ID", secret)?;
                super::manager::keychain_entry_in(TOUCH_ID_SERVICE, &seal.id)
                    .and_then(|e| {
                        e.set_password(&BASE64.encode(*key))
                            .map_err(|e| super::error::VaultError::KeychainError(e.to_string()))
                    })
                    .map_err(|e| e.to_string())?;
                Ok(seal)
            }
            _ => Err("This device has no biometric unlock".into()),
        }
    }

    /// Open the platform biometric's seal. Blocking; shows the system prompt.
    pub fn open_with_platform(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let seal = self
            .seals
            .iter()
            .find(|s| is_platform(&s.kind))
            .ok_or("Biometric unlock is not turned on")?;
        match seal.kind.as_str() {
            WINDOWS_HELLO => {
                let challenge = BASE64.decode(&seal.challenge).map_err(|e| e.to_string())?;
                let key = hello::key_for(&challenge, false)?;
                self.open_with(&key, seal)
            }
            TOUCH_ID => {
                touch::verify("unlock your Reach vault")?;
                let stored = super::manager::keychain_entry_in(TOUCH_ID_SERVICE, &seal.id)
                    .and_then(|e| e.get_password().map_err(|e| super::error::VaultError::KeychainError(e.to_string())))
                    .map_err(|e| e.to_string())?;
                let key: [u8; 32] = BASE64
                    .decode(stored)
                    .ok()
                    .and_then(|k| k.try_into().ok())
                    .ok_or("The Touch ID key is damaged")?;
                self.open_with(&Zeroizing::new(key), seal)
            }
            _ => Err("Biometric unlock is not turned on".into()),
        }
    }

    /// Seal `secret` behind a security key. Blocking: the user touches the
    /// key twice (and gives its PIN), once to add Reach's credential and once
    /// to get the secret, as systemd-cryptenroll does.
    pub fn seal_with_key(&self, label: &str, secret: &[u8], pin: Option<&str>) -> Result<Seal, String> {
        let user_id = self.user_uuid.as_bytes();
        let credential = fido2::make_credential(user_id, label, &self.credential_ids(), pin)?;
        let (_, output) = fido2::hmac_secret(std::slice::from_ref(&credential), &self.fido_salt()?, pin)?;
        self.seal_with_key_output(label, &credential, &output, secret)
    }

    /// Open with whichever added security key is plugged in. Blocking.
    pub fn open_with_key(&self, pin: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        let (credential, output) = fido2::hmac_secret(&self.credential_ids(), &self.fido_salt()?, pin)?;
        self.open_with_key_output(&credential, &output)
    }

    /// What asking a security key needs: the credentials added so far, and
    /// the salt every key is asked to HMAC.
    pub fn key_request(&self) -> Result<(Vec<Vec<u8>>, [u8; 32]), String> {
        Ok((self.credential_ids(), self.fido_salt()?))
    }

    /// Seal with the `hmac-secret` output a security key gave for `credential`.
    pub fn seal_with_key_output(
        &self,
        label: &str,
        credential: &[u8],
        output: &[u8; 32],
        secret: &[u8],
    ) -> Result<Seal, String> {
        let mut seal = self.seal_with(&fido_key(output), FIDO2, label, secret)?;
        seal.credential_id = BASE64.encode(credential);
        Ok(seal)
    }

    /// Open the seal of `credential` with the output its key gave.
    pub fn open_with_key_output(&self, credential: &[u8], output: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, String> {
        let credential = BASE64.encode(credential);
        let seal = self
            .seals
            .iter()
            .find(|s| s.kind == FIDO2 && s.credential_id == credential)
            .ok_or("This key is not one added to Reach")?;
        self.open_with(&fido_key(output), seal)
    }

    /// An Android fingerprint seal. The Keystore did the sealing, with a key
    /// that never leaves it: what is kept here is its IV and ciphertext.
    pub fn android_seal(&self, iv: &str, ciphertext: &str) -> Seal {
        Seal {
            id: uuid::Uuid::new_v4().to_string(),
            kind: ANDROID_BIOMETRIC.into(),
            label: "Fingerprint".into(),
            created: now(),
            challenge: iv.into(),
            credential_id: String::new(),
            nonce: String::new(),
            ciphertext: ciphertext.into(),
        }
    }

    /// The Android fingerprint seal's IV and ciphertext, if it is on.
    pub fn android_sealed(&self) -> Option<(String, String)> {
        self.seals
            .iter()
            .find(|s| s.kind == ANDROID_BIOMETRIC)
            .map(|s| (s.challenge.clone(), s.ciphertext.clone()))
    }
}

/// The sealing key from a security key's `hmac-secret` output.
fn fido_key(output: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, output)
        .expand(b"reach-fido2-seal-v1", &mut *key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    key
}

/// Whether the platform biometric can be used now (Windows Hello set up,
/// a fingerprint enrolled for Touch ID). Blocking.
pub fn platform_available() -> bool {
    match platform_method() {
        Some(WINDOWS_HELLO) => hello::available(),
        Some(TOUCH_ID) => touch::available(),
        _ => false,
    }
}

/// Clean up after a removed seal: Reach's Windows Hello credential, or the
/// Touch ID key in the keychain. Best-effort; blocking.
pub fn forget(seal: &Seal) {
    match seal.kind.as_str() {
        WINDOWS_HELLO => hello::forget(),
        TOUCH_ID => {
            if let Ok(entry) = super::manager::keychain_entry_in(TOUCH_ID_SERVICE, &seal.id) {
                let _ = entry.delete_credential();
            }
        }
        _ => {}
    }
}

pub fn load(app_dir: &Path) -> Option<Unlockers> {
    let data = std::fs::read(app_dir.join(FILE)).ok()?;
    match serde_json::from_slice(&data) {
        Ok(unlockers) => Some(unlockers),
        Err(e) => {
            tracing::warn!("Ignoring an unreadable {}: {}", FILE, e);
            None
        }
    }
}

pub fn save(app_dir: &Path, unlockers: &Unlockers) -> std::io::Result<()> {
    let tmp = app_dir.join(format!("{FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(unlockers)?)?;
    std::fs::rename(&tmp, app_dir.join(FILE))
}

pub fn remove(app_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(app_dir.join(FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(windows)]
mod hello {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows::core::{s, Array, HSTRING};
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, FindWindowA, GetForegroundWindow, GetWindowThreadProcessId, SetForegroundWindow,
    };
    use zeroize::Zeroizing;

    const CREDENTIAL_NAME: &str = "Reach vault";

    pub fn available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .unwrap_or(false)
    }

    fn status_error(status: KeyCredentialStatus) -> String {
        match status {
            KeyCredentialStatus::UserCanceled => "Windows Hello was cancelled".into(),
            KeyCredentialStatus::UserPrefersPassword => "Windows Hello was declined".into(),
            KeyCredentialStatus::NotFound => "Windows Hello has no key for Reach".into(),
            KeyCredentialStatus::SecurityDeviceLocked => "Windows Hello is locked after too many attempts".into(),
            other => format!("Windows Hello failed (status {})", other.0),
        }
    }

    fn credential(create: bool) -> Result<KeyCredential, String> {
        let name = HSTRING::from(CREDENTIAL_NAME);
        let result = if create {
            with_prompt_in_front(|| {
                KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::FailIfExists)?.join()
            })
        } else {
            KeyCredentialManager::OpenAsync(&name).and_then(|op| op.join())
        }
        .map_err(|e| e.to_string())?;
        match result.Status().map_err(|e| e.to_string())? {
            KeyCredentialStatus::Success => result.Credential().map_err(|e| e.to_string()),
            KeyCredentialStatus::CredentialAlreadyExists if create => credential(false),
            status => Err(status_error(status)),
        }
    }

    /// SHA-256 of Hello's signature over `challenge`.
    pub fn key_for(challenge: &[u8], create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        let credential = credential(create)?;
        let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| e.to_string())?;
        let result = with_prompt_in_front(|| credential.RequestSignAsync(&data)?.join()).map_err(|e| e.to_string())?;
        let status = result.Status().map_err(|e| e.to_string())?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let signature = result.Result().map_err(|e| e.to_string())?;
        let mut bytes = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(|e| e.to_string())?;
        let digest = Sha256::digest(&bytes[..]);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&digest);
        Ok(key)
    }

    pub fn forget() {
        let name = HSTRING::from(CREDENTIAL_NAME);
        if let Err(e) = KeyCredentialManager::DeleteAsync(&name).and_then(|op| op.join()) {
            tracing::debug!("Removing the Windows Hello key: {}", e);
        }
    }

    /// Hello's prompt, asked for by a desktop app, tends to open behind that
    /// app's window. While `f` waits on it, keep bringing it to the front, as
    /// Bitwarden does (`windows_focus.rs`).
    fn with_prompt_in_front<T>(f: impl FnOnce() -> windows::core::Result<T>) -> windows::core::Result<T> {
        let waiting = Arc::new(AtomicBool::new(true));
        let flag = waiting.clone();
        let _ = std::thread::Builder::new().name("hello-focus".into()).spawn(move || {
            while flag.load(Ordering::Relaxed) {
                // SAFETY: plain window lookups and focus calls on handles the
                // system gave us; failures only mean the prompt keeps its place.
                unsafe {
                    if let Ok(prompt) = FindWindowA(s!("Credential Dialog Xaml Host"), None) {
                        if GetForegroundWindow() != prompt {
                            let front = GetWindowThreadProcessId(GetForegroundWindow(), None);
                            let me = GetCurrentThreadId();
                            let attached = front != 0 && front != me && AttachThreadInput(me, front, true).as_bool();
                            let _ = BringWindowToTop(prompt);
                            let _ = SetForegroundWindow(prompt);
                            if attached {
                                let _ = AttachThreadInput(me, front, false);
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        let result = f();
        waiting.store(false, Ordering::Relaxed);
        result
    }
}

/// Touch ID through LocalAuthentication, as a check of the owner.
#[cfg(target_os = "macos")]
mod touch {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::time::Duration;

    pub fn available() -> bool {
        // SAFETY: a fresh context asked whether the policy can be evaluated.
        unsafe { LAContext::new().canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics).is_ok() }
    }

    /// Ask for the owner's fingerprint; `reason` completes the system's
    /// sentence "Reach is trying to …".
    pub fn verify(reason: &str) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
            let result = if ok.as_bool() {
                Ok(())
            } else {
                // SAFETY: LocalAuthentication passes a valid NSError or null.
                Err(unsafe { error.as_ref() }
                    .map(|e| e.localizedDescription().to_string())
                    .unwrap_or_else(|| "Touch ID did not confirm it is you".into()))
            };
            let _ = tx.send(result);
        });
        // SAFETY: the context lives until the reply has arrived (or the wait
        // gave up); the reply block is copied by LocalAuthentication.
        unsafe {
            let context = LAContext::new();
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str(reason),
                &reply,
            );
            rx.recv_timeout(Duration::from_secs(120))
                .unwrap_or_else(|_| Err("Touch ID did not answer".into()))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod touch {
    pub fn available() -> bool {
        false
    }

    pub fn verify(_: &str) -> Result<(), String> {
        Err("Touch ID is only on macOS".into())
    }
}

#[cfg(not(windows))]
mod hello {
    use zeroize::Zeroizing;

    pub fn available() -> bool {
        false
    }

    pub fn key_for(_: &[u8], _: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        Err("Windows Hello is only on Windows".into())
    }

    pub fn forget() {}
}

#[cfg(test)]
impl Unlockers {
    /// Seal with a known key, standing in for a method's prompt.
    pub fn seal_for_test(&self, kind: &str, key: &[u8; 32], secret: &[u8]) -> Seal {
        self.seal_with(key, kind, kind, secret).unwrap()
    }

    pub fn open_for_test(&self, key: &[u8; 32], id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let seal = self.seals.iter().find(|s| s.id == id).ok_or("no such seal")?;
        self.open_with(key, seal)
    }
}

#[cfg(test)]
#[path = "biometric_tests.rs"]
mod tests;
