//! SecurityKeyProvider: signing with FIDO security keys
//! (sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com), the
//! way OpenSSH's ssh-sk.c does it.
//!
//! The key file (id_ed25519_sk, id_ecdsa_sk) holds no secret: only the
//! application ("ssh:"), the key handle and flags. Signing asks the
//! middleware for a FIDO assertion over the data, for that application and
//! key handle, and makes the PROTOCOL.u2f signature from it: the signature,
//! then the flags byte and the counter. The middleware is a library with
//! the sk-api.h functions, or "internal" (the default): on Windows
//! webauthn.dll, as OpenSSH for Windows uses it through libfido2's
//! winhello; on Linux and macOS the USB keys themselves, through
//! ctap-hid-fido2, which Reach already uses for vault unlock, where OpenSSH
//! links libfido2.
//!
//! As sshconnect2.c does: a key that wants user presence shows "Confirm user
//! presence" while it waits for the touch, and a middleware that answers
//! "PIN required" gets the PIN asked once and the signature tried again.
//! ssh runs the middleware in a helper process (ssh-sk-helper); Reach runs
//! it in its own, and an external one only once the user approved its path.

use russh::keys::ssh_key::private::KeypairData;
use russh::keys::{HashAlg, PrivateKey, PublicKey};

use super::pkcs11::{der, put_mpint, put_string};
use super::prompt::{Field, Kind};
use super::userauth::Ui;

/// sk-api.h
const SSH_SK_USER_PRESENCE_REQD: u8 = 0x01;
#[cfg_attr(target_os = "android", allow(dead_code))]
const SSH_SK_USER_VERIFICATION_REQD: u8 = 0x04;
const SSH_SK_ECDSA: u32 = 0x00;
const SSH_SK_ED25519: u32 = 0x01;
const SSH_SK_ERR_UNSUPPORTED: i32 = -2;
const SSH_SK_ERR_PIN_REQUIRED: i32 = -3;
const SSH_SK_ERR_DEVICE_NOT_FOUND: i32 = -4;
const SSH_SK_VERSION_MAJOR: u32 = 0x000a_0000;
const SSH_SK_VERSION_MAJOR_MASK: u32 = 0xffff_0000;

/// What signs for FIDO keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    /// Built in: webauthn.dll on Windows, USB HID on Linux and macOS.
    Internal,
    /// A middleware library implementing sk-api.h.
    Library(String),
}

impl Provider {
    /// SecurityKeyProvider as resolved: "internal" when unset (OpenSSH
    /// built with its own FIDO support), `None` for none, `$VAR` read from
    /// the environment as ssh.c does (unset disables it). A library runs
    /// its code when loaded, so a path waits for approval as a command does.
    pub(crate) fn from_options(o: &super::sshconf::resolve::Options, approved: &[String]) -> Option<Provider> {
        use super::sshconf::keyword::Kw;
        let Some(raw) = o.first(Kw::SecurityKeyProvider) else { return Some(Provider::Internal) };
        let value = match raw.strip_prefix('$').filter(|v| !v.is_empty()) {
            Some(var) => match std::env::var(var) {
                Ok(v) => v,
                Err(_) => {
                    tracing::info!("SecurityKeyProvider: {raw} is not set; disabling");
                    return None;
                }
            },
            None => raw.to_string(),
        };
        if value.eq_ignore_ascii_case("none") {
            None
        } else if value.eq_ignore_ascii_case("internal") {
            Some(Provider::Internal)
        } else if approved.iter().any(|a| a == raw) {
            Some(Provider::Library(value))
        } else {
            tracing::warn!("SecurityKeyProvider {raw} waits for your approval in the session's SSH options; security keys skipped");
            None
        }
    }
}

/// An authenticator-hosted key (sshkey_is_sk).
pub(crate) fn is_sk(public: &PublicKey) -> bool {
    use russh::keys::Algorithm;
    matches!(public.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

/// What sk_sign answers.
struct SignResponse {
    flags: u8,
    counter: u32,
    sig_r: Vec<u8>,
    sig_s: Vec<u8>,
}

#[derive(Debug)]
enum SkError {
    PinRequired,
    Failed(String),
}

impl SkError {
    /// sk-api.h error codes, as skerr_to_ssherr reads them.
    fn from_code(provider: &str, code: i32) -> SkError {
        match code {
            SSH_SK_ERR_PIN_REQUIRED => SkError::PinRequired,
            SSH_SK_ERR_DEVICE_NOT_FOUND => SkError::Failed("device not found".into()),
            SSH_SK_ERR_UNSUPPORTED => SkError::Failed(format!("provider \"{provider}\": feature not supported")),
            _ => SkError::Failed(format!("provider \"{provider}\" failure {code}")),
        }
    }
}

/// An SSH signature blob over `data` from a security key, as sshsk_sign
/// makes it, with the touch notice and the PIN retry of identity_sign.
pub(crate) async fn sign(key: &PrivateKey, data: &[u8], provider: Option<&Provider>, batch_mode: bool, ui: Ui<'_>, label: &str) -> Result<Vec<u8>, String> {
    let provider = provider.ok_or("authenticator-hosted key, but no SecurityKeyProvider")?;
    let (alg, application, key_handle, flags) = match key.key_data() {
        KeypairData::SkEd25519(k) => (SSH_SK_ED25519, k.public().application().to_string(), k.key_handle().to_vec(), k.flags()),
        KeypairData::SkEcdsaSha2NistP256(k) => (SSH_SK_ECDSA, k.public().application().to_string(), k.key_handle().to_vec(), k.flags()),
        _ => return Err("not a security key".into()),
    };
    if application.is_empty() {
        return Err("security key without an application".into());
    }
    let type_name = key.algorithm().as_str().to_string();
    let fp = key.public_key().fingerprint(HashAlg::Sha256);
    let mut pin: Option<String> = None;
    loop {
        let notice = flags & SSH_SK_USER_PRESENCE_REQD != 0 && !batch_mode;
        if notice {
            if let Some(a) = ui.app {
                a.notify_start(ui.host, ui.port, &format!("Confirm user presence for key {type_name} {fp}"));
            }
        }
        let (p, d, app, kh, pn) = (provider.clone(), data.to_vec(), application.clone(), key_handle.clone(), pin.clone());
        let r = tokio::task::spawn_blocking(move || sk_sign(&p, alg, &d, &app, &kh, flags, pn.as_deref()))
            .await
            .unwrap_or_else(|e| Err(SkError::Failed(e.to_string())));
        match r {
            Ok(resp) => {
                if let Some(a) = ui.app.filter(|_| notice) {
                    a.notify_complete(ui.host, ui.port, Some("User presence confirmed"));
                }
                return encode(&type_name, alg, &resp);
            }
            Err(e) => {
                if let Some(a) = ui.app.filter(|_| notice) {
                    a.notify_complete(ui.host, ui.port, None);
                }
                match e {
                    SkError::PinRequired if pin.is_none() && !batch_mode => {
                        let text = format!("Enter PIN for {type_name} key {label}:");
                        let answer = ui.ask(Kind::Passphrase, &text, "", vec![Field { text: text.clone(), echo: false }]).await;
                        pin = Some(answer.and_then(|a| a.into_iter().next()).ok_or("cancelled")?);
                    }
                    SkError::PinRequired => return Err("the security key needs its PIN".into()),
                    SkError::Failed(m) => return Err(m),
                }
            }
        }
    }
}

/// sshsk_ed25519_sig and sshsk_ecdsa_sig.
fn encode(type_name: &str, alg: u32, r: &SignResponse) -> Result<Vec<u8>, String> {
    let mut sig = Vec::new();
    put_string(&mut sig, type_name.as_bytes());
    if alg == SSH_SK_ED25519 {
        if r.sig_r.is_empty() {
            return Err("sk_sign response invalid".into());
        }
        put_string(&mut sig, &r.sig_r);
    } else {
        if r.sig_r.is_empty() || r.sig_s.is_empty() {
            return Err("sk_sign response invalid".into());
        }
        let mut inner = Vec::new();
        put_mpint(&mut inner, &r.sig_r);
        put_mpint(&mut inner, &r.sig_s);
        put_string(&mut sig, &inner);
    }
    sig.push(r.flags);
    sig.extend_from_slice(&r.counter.to_be_bytes());
    Ok(sig)
}

fn sk_sign(provider: &Provider, alg: u32, data: &[u8], application: &str, key_handle: &[u8], flags: u8, pin: Option<&str>) -> Result<SignResponse, SkError> {
    match provider {
        Provider::Library(path) => middleware::sign(path, alg, data, application, key_handle, flags, pin),
        Provider::Internal => internal::sign(alg, data, application, key_handle, flags, pin),
    }
}

/// A FIDO assertion's parts: the flags and counter from the authenticator
/// data, and the signature (raw for Ed25519, DER for ECDSA), as pack_sig
/// splits them.
#[cfg_attr(not(any(windows, target_os = "macos", target_os = "linux")), allow(dead_code))]
fn from_assertion(alg: u32, auth_data: &[u8], signature: &[u8]) -> Result<SignResponse, SkError> {
    if auth_data.len() < 37 {
        return Err(SkError::Failed("authenticator data too short".into()));
    }
    let flags = auth_data[32];
    let counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let (sig_r, sig_s) = if alg == SSH_SK_ED25519 {
        if signature.len() != 64 {
            return Err(SkError::Failed(format!("bad length {}", signature.len())));
        }
        (signature.to_vec(), Vec::new())
    } else {
        let bad = || SkError::Failed("bad ECDSA signature".into());
        let (0x30, seq, _) = der(signature).ok_or_else(bad)? else { return Err(bad()) };
        let (0x02, r, rest) = der(seq).ok_or_else(bad)? else { return Err(bad()) };
        let (0x02, s, _) = der(rest).ok_or_else(bad)? else { return Err(bad()) };
        let trim = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
        (trim(r), trim(s))
    };
    Ok(SignResponse { flags, counter, sig_r, sig_s })
}

/// A middleware library with the sk-api.h ABI, opened for one signature
/// and closed after it, as sshsk_open and sshsk_free do.
mod middleware {
    use std::ffi::{c_char, c_int, c_void, CString};

    use super::{SignResponse, SkError, SSH_SK_VERSION_MAJOR, SSH_SK_VERSION_MAJOR_MASK};

    /// struct sk_sign_response
    #[repr(C)]
    struct SkSignResponse {
        flags: u8,
        counter: u32,
        sig_r: *mut u8,
        sig_r_len: usize,
        sig_s: *mut u8,
        sig_s_len: usize,
    }

    /// struct sk_option; no options are passed when signing.
    #[repr(C)]
    struct SkOption {
        name: *mut c_char,
        value: *mut c_char,
        required: u8,
    }

    type ApiVersion = unsafe extern "C" fn() -> u32;
    type Sign = unsafe extern "C" fn(
        alg: u32,
        data: *const u8,
        data_len: usize,
        application: *const c_char,
        key_handle: *const u8,
        key_handle_len: usize,
        flags: u8,
        pin: *const c_char,
        options: *mut *mut SkOption,
        sign_response: *mut *mut SkSignResponse,
    ) -> c_int;

    extern "C" {
        /// The C library's free: the middleware allocates its answer with
        /// malloc, and ssh frees it with free.
        fn free(p: *mut c_void);
    }

    pub(super) fn sign(
        path: &str,
        alg: u32,
        data: &[u8],
        application: &str,
        key_handle: &[u8],
        flags: u8,
        pin: Option<&str>,
    ) -> Result<SignResponse, SkError> {
        let fail = |m: String| SkError::Failed(m);
        let application = CString::new(application).map_err(|_| fail("bad application".into()))?;
        let pin = pin.map(CString::new).transpose().map_err(|_| fail("bad PIN".into()))?;
        // SAFETY: loading the library the user approved runs its
        // initializers, as dlopen does for ssh. The symbols are cast to the
        // signatures sk-api.h declares; the library stays loaded until the
        // end of this function, after the last call into it.
        unsafe {
            let lib = libloading::Library::new(path).map_err(|e| fail(format!("Provider \"{path}\" dlopen failed: {e}")))?;
            let version: libloading::Symbol<ApiVersion> =
                lib.get(b"sk_api_version\0").map_err(|_| fail(format!("provider {path} is not an OpenSSH FIDO library")))?;
            let v = version();
            tracing::info!("SecurityKeyProvider {path} implements version {v:#010x}");
            if v & SSH_SK_VERSION_MAJOR_MASK != SSH_SK_VERSION_MAJOR {
                return Err(fail(format!(
                    "Provider \"{path}\" implements unsupported version {v:#010x} (supported: {SSH_SK_VERSION_MAJOR:#010x})"
                )));
            }
            for name in ["sk_enroll", "sk_load_resident_keys"] {
                if lib.get::<unsafe extern "C" fn()>(format!("{name}\0").as_bytes()).is_err() {
                    return Err(fail(format!("Provider \"{path}\" dlsym({name}) failed")));
                }
            }
            let sk_sign: libloading::Symbol<Sign> = lib.get(b"sk_sign\0").map_err(|_| fail(format!("Provider \"{path}\" dlsym(sk_sign) failed")))?;
            let mut resp: *mut SkSignResponse = std::ptr::null_mut();
            let r = sk_sign(
                alg,
                data.as_ptr(),
                data.len(),
                application.as_ptr(),
                key_handle.as_ptr(),
                key_handle.len(),
                flags,
                pin.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()),
                std::ptr::null_mut(),
                &mut resp,
            );
            if r != 0 {
                tracing::info!("SecurityKeyProvider: sk_sign failed with code {r}");
                if !resp.is_null() {
                    free_response(resp);
                }
                return Err(SkError::from_code(path, r));
            }
            if resp.is_null() {
                return Err(fail("sk_sign response invalid".into()));
            }
            let take = |p: *mut u8, n: usize| if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, n).to_vec() };
            let out = SignResponse {
                flags: (*resp).flags,
                counter: (*resp).counter,
                sig_r: take((*resp).sig_r, (*resp).sig_r_len),
                sig_s: take((*resp).sig_s, (*resp).sig_s_len),
            };
            free_response(resp);
            drop(lib);
            Ok(out)
        }
    }

    /// sshsk_free_sign_response
    unsafe fn free_response(resp: *mut SkSignResponse) {
        free((*resp).sig_r as *mut c_void);
        free((*resp).sig_s as *mut c_void);
        free(resp as *mut c_void);
    }
}

/// "internal" on Windows: webauthn.dll, which talks to the keys (and asks
/// for the PIN and the touch) itself. As libfido2's winhello does it for
/// OpenSSH: the data goes in as the client data, hashed with SHA-256, the
/// application is the relying party, the key handle the one allowed
/// credential, and user verification is asked for only for a key made with
/// verify-required. Windows always asks for a touch.
#[cfg(windows)]
mod internal {
    use std::sync::OnceLock;

    use windows::core::{w, HRESULT, HSTRING, PCWSTR};
    use windows::Win32::Networking::WindowsWebServices::*;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    use super::{from_assertion, SignResponse, SkError, SSH_SK_USER_VERIFICATION_REQD};

    type Export = unsafe extern "system" fn() -> isize;
    type GetAssertion = unsafe extern "system" fn(
        windows::Win32::Foundation::HWND,
        PCWSTR,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        *mut *mut WEBAUTHN_ASSERTION,
    ) -> HRESULT;
    type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);

    struct Api {
        get_assertion: GetAssertion,
        free_assertion: FreeAssertion,
    }

    fn api() -> Option<&'static Api> {
        static API: OnceLock<Option<Api>> = OnceLock::new();
        API.get_or_init(|| {
            // SAFETY: a system DLL from System32 only, its exports cast to
            // the signatures webauthn.h gives them; it stays loaded.
            unsafe {
                let dll = LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;
                let get = |name: windows::core::PCSTR| GetProcAddress(dll, name);
                Some(Api {
                    get_assertion: std::mem::transmute::<Export, GetAssertion>(get(windows::core::s!("WebAuthNAuthenticatorGetAssertion"))?),
                    free_assertion: std::mem::transmute::<Export, FreeAssertion>(get(windows::core::s!("WebAuthNFreeAssertion"))?),
                })
            }
        })
        .as_ref()
    }

    pub(super) fn sign(alg: u32, data: &[u8], application: &str, key_handle: &[u8], flags: u8, _pin: Option<&str>) -> Result<SignResponse, SkError> {
        let api = api().ok_or_else(|| SkError::Failed("webauthn.dll is not available on this Windows".into()))?;
        let rp_id = HSTRING::from(application);
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: data.len() as u32,
            pbClientDataJSON: data.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut allowed = [WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: key_handle.len() as u32,
            pbId: key_handle.as_ptr() as *mut u8,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        }];
        // SAFETY: all-zero is the documented "unset" for every field.
        let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1;
        options.dwTimeoutMilliseconds = 120_000;
        options.CredentialList = WEBAUTHN_CREDENTIALS { cCredentials: 1, pCredentials: allowed.as_mut_ptr() };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.dwUserVerificationRequirement = if flags & SSH_SK_USER_VERIFICATION_REQD != 0 {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        };
        let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        // SAFETY: every pointer points at locals that outlive the call; the
        // result is freed with the DLL's own function.
        unsafe {
            let hr = (api.get_assertion)(GetForegroundWindow(), PCWSTR(rp_id.as_ptr()), &client, &options, &mut assertion);
            if hr.is_err() || assertion.is_null() {
                return Err(SkError::Failed(match hr.0 as u32 {
                    0x80090036 | 0x800704C7 => "the security key request was cancelled".into(),
                    0x80090011 => "this security key does not hold the key".into(),
                    _ => format!("the security key request failed: {}", windows::core::Error::from(hr).message()),
                }));
            }
            let a = &*assertion;
            let auth_data = std::slice::from_raw_parts(a.pbAuthenticatorData, a.cbAuthenticatorData as usize).to_vec();
            let signature = std::slice::from_raw_parts(a.pbSignature, a.cbSignature as usize).to_vec();
            (api.free_assertion)(assertion);
            from_assertion(alg, &auth_data, &signature)
        }
    }
}

/// "internal" on Linux and macOS: the USB keys, as sk-usbhid.c reaches them
/// through libfido2. The device is the one key present, or among several
/// the one that holds the key handle (a silent probe, as sk_probe does).
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod internal {
    use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
    use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};

    use super::{from_assertion, SignResponse, SkError, SSH_SK_USER_PRESENCE_REQD, SSH_SK_USER_VERIFICATION_REQD};

    /// fidoerr_to_skerr: PIN required, PIN invalid and operation denied
    /// all ask for the PIN.
    fn error(e: impl std::fmt::Display) -> SkError {
        let text = e.to_string();
        if ["0x36", "0x31", "0x27", "PIN_REQUIRED", "PIN_INVALID", "OPERATION_DENIED"].iter().any(|c| text.contains(c)) {
            SkError::PinRequired
        } else {
            SkError::Failed(format!("the security key request failed: {text}"))
        }
    }

    fn holds(key: &FidoKeyHid, application: &str, key_handle: &[u8]) -> bool {
        let args = GetAssertionArgsBuilder::new(application, &[0u8; 32]).credential_id(key_handle).without_up().without_pin_and_uv().build();
        key.get_assertion_with_args(&args).is_ok()
    }

    pub(super) fn sign(alg: u32, data: &[u8], application: &str, key_handle: &[u8], flags: u8, pin: Option<&str>) -> Result<SignResponse, SkError> {
        let cfg = LibCfg::init();
        let mut keys: Vec<FidoKeyHid> = ctap_hid_fido2::get_fidokey_devices()
            .into_iter()
            .filter_map(|d| FidoKeyHidFactory::create_by_params(&[d.param], &cfg).ok())
            .collect();
        let key = match keys.len() {
            0 => return Err(SkError::Failed("device not found".into())),
            1 => keys.remove(0),
            _ => {
                let i = keys.iter().position(|k| holds(k, application, key_handle)).ok_or_else(|| SkError::Failed("device not found".into()))?;
                keys.swap_remove(i)
            }
        };
        let mut args = GetAssertionArgsBuilder::new(application, data).credential_id(key_handle);
        if flags & SSH_SK_USER_PRESENCE_REQD == 0 {
            args = args.without_up();
        }
        if let Some(pin) = pin {
            args = args.pin(pin);
        } else if flags & SSH_SK_USER_VERIFICATION_REQD != 0 {
            // Without a PIN only a key that verifies the user itself
            // (fingerprint) can do it.
            let uv = key.get_info().map_err(error)?.options.iter().any(|(n, v)| n == "uv" && *v);
            if !uv {
                return Err(SkError::PinRequired);
            }
        } else {
            args = args.without_pin_and_uv();
        }
        let assertions = key.get_assertion_with_args(&args.build()).map_err(error)?;
        let a = assertions.first().ok_or_else(|| SkError::Failed("no assertion".into()))?;
        from_assertion(alg, &a.auth_data, &a.signature)
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod internal {
    use super::{SignResponse, SkError};

    pub(super) fn sign(_: u32, _: &[u8], _: &str, _: &[u8], _: u8, _: Option<&str>) -> Result<SignResponse, SkError> {
        Err(SkError::Failed("internal security key support is not available on this platform".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u2f_signature_layout() {
        let r = SignResponse { flags: 0x05, counter: 0x0102_0304, sig_r: vec![0x80, 1], sig_s: vec![0, 2] };
        let sig = encode("sk-ecdsa-sha2-nistp256@openssh.com", SSH_SK_ECDSA, &r).unwrap();
        let name = b"sk-ecdsa-sha2-nistp256@openssh.com";
        let mut want = Vec::new();
        put_string(&mut want, name);
        want.extend_from_slice(&[0, 0, 0, 12, 0, 0, 0, 3, 0, 0x80, 1, 0, 0, 0, 1, 2]);
        want.extend_from_slice(&[0x05, 1, 2, 3, 4]);
        assert_eq!(sig, want);
        let r = SignResponse { flags: 1, counter: 7, sig_r: vec![9; 64], sig_s: Vec::new() };
        let sig = encode("sk-ssh-ed25519@openssh.com", SSH_SK_ED25519, &r).unwrap();
        assert_eq!(&sig[sig.len() - 5..], &[1, 0, 0, 0, 7]);
    }

    #[test]
    fn assertion_parts() {
        let mut auth = vec![0u8; 32];
        auth.extend_from_slice(&[0x01, 0, 0, 1, 0]);
        let der_sig = [0x30, 0x08, 0x02, 0x02, 0x00, 0x81, 0x02, 0x02, 0x01, 0x02];
        let r = from_assertion(SSH_SK_ECDSA, &auth, &der_sig).unwrap();
        assert_eq!((r.flags, r.counter, r.sig_r, r.sig_s), (1, 256, vec![0x81], vec![1, 2]));
        assert!(from_assertion(SSH_SK_ED25519, &auth, &[0; 63]).is_err());
    }

    #[test]
    fn provider_setting() {
        let prov = |text: &str, approved: &[String]| {
            let src = crate::ssh::sshconf::resolve::Source { path: "c".into(), text: Some(text.into()), user: true };
            let env = crate::ssh::sshconf::env::SystemEnv::new(crate::ssh::sshconf::env::ExecPolicy::Never);
            let r = crate::ssh::sshconf::resolve::resolve(&[src], &crate::ssh::sshconf::resolve::Query { host: "h".into(), ..Default::default() }, &env);
            Provider::from_options(&r.options, approved)
        };
        assert_eq!(prov("", &[]), Some(Provider::Internal));
        assert_eq!(prov("SecurityKeyProvider none\n", &[]), None);
        assert_eq!(prov("SecurityKeyProvider internal\n", &[]), Some(Provider::Internal));
        assert_eq!(prov("SecurityKeyProvider /x/sk.so\n", &[]), None);
        assert_eq!(prov("SecurityKeyProvider /x/sk.so\n", &["/x/sk.so".into()]), Some(Provider::Library("/x/sk.so".into())));
        assert_eq!(prov("SecurityKeyProvider $REACH_TEST_UNSET_SK\n", &[]), None);
    }

    /// "internal" with no security key plugged in fails cleanly and at once.
    #[test]
    #[ignore = "needs a machine with no security key plugged in"]
    fn internal_without_a_device() {
        let r = sk_sign(&Provider::Internal, SSH_SK_ED25519, b"data", "ssh:", &[1, 2, 3], SSH_SK_USER_PRESENCE_REQD, None);
        println!("internal, no device: {:?}", r.as_ref().err());
        assert!(matches!(r, Err(SkError::Failed(_))));
    }
}
