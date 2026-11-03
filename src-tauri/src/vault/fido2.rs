//! FIDO2 security keys (YubiKey and the like) through the CTAP2
//! `hmac-secret` extension, for unlocking the vault.
//!
//! The flow is systemd-cryptenroll's (`src/shared/libfido2-util.c`): make a
//! non-resident credential with `hmac-secret` for a fixed relying party, then
//! ask the key for HMAC(its secret for that credential, a stored salt). The
//! key never hands out its secret, so the output can only be had with the key
//! in hand. User verification (the key's PIN) is always required: a key gives
//! a different `hmac-secret` with and without it, and requiring it means a
//! stolen key alone opens nothing.
//!
//! Windows allows programs without admin rights to reach security keys only
//! through `webauthn.dll`, the same API browsers use; it draws its own prompt
//! and asks for the PIN itself. It is loaded at run time, as Firefox does
//! (`dom/webauthn/WinWebAuthnService.cpp`), so Reach still starts on a Windows
//! without it. macOS and Linux talk to the key over USB with `ctap-hid-fido2`,
//! and Reach asks for the PIN.

use zeroize::Zeroizing;

/// The relying party the credentials belong to. Not a web origin: keys only
/// use it to keep Reach's credentials apart from every other site's.
pub const RP_ID: &str = "reach.vault";

/// Whether this build can use security keys here.
pub fn supported() -> bool {
    platform::supported()
}

/// Whether Reach must ask for the key's PIN itself (Windows asks on its own).
pub const fn asks_pin_itself() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux", target_os = "android"))
}

/// Register a credential for Reach on a key, and return its ID. Blocking;
/// the user touches the key (and gives its PIN).
pub fn make_credential(user_id: &[u8], label: &str, exclude: &[Vec<u8>], pin: Option<&str>) -> Result<Vec<u8>, String> {
    platform::make_credential(user_id, label, exclude, pin)
}

/// Ask whichever of `credential_ids` is on the key present for its
/// `hmac-secret` over `salt`. Returns the credential that answered and the
/// 32-byte output. Blocking; the user touches the key (and gives its PIN).
pub fn hmac_secret(
    credential_ids: &[Vec<u8>],
    salt: &[u8; 32],
    pin: Option<&str>,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
    if credential_ids.is_empty() {
        return Err("No security key has been added".into());
    }
    platform::hmac_secret(credential_ids, salt, pin)
}

#[cfg(windows)]
mod platform {
    use super::RP_ID;
    use std::sync::OnceLock;
    use windows::core::{w, BOOL, HRESULT, HSTRING, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Networking::WindowsWebServices::*;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    use zeroize::Zeroizing;

    /// `pHmacSecretSaltValues` and `pHmacSecret` arrived with API version 4.
    const MIN_API: u32 = 4;
    const TIMEOUT_MS: u32 = 120_000;

    /// What GetProcAddress hands back, before it is cast to its signature.
    type Export = unsafe extern "system" fn() -> isize;
    type GetApiVersion = unsafe extern "system" fn() -> u32;
    type MakeCredential = unsafe extern "system" fn(
        HWND,
        *const WEBAUTHN_RP_ENTITY_INFORMATION,
        *const WEBAUTHN_USER_ENTITY_INFORMATION,
        *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
    ) -> HRESULT;
    type GetAssertion = unsafe extern "system" fn(
        HWND,
        PCWSTR,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        *mut *mut WEBAUTHN_ASSERTION,
    ) -> HRESULT;
    type FreeAttestation = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);
    type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);

    struct Api {
        version: u32,
        make_credential: MakeCredential,
        get_assertion: GetAssertion,
        free_attestation: FreeAttestation,
        free_assertion: FreeAssertion,
    }

    fn api() -> Option<&'static Api> {
        static API: OnceLock<Option<Api>> = OnceLock::new();
        API.get_or_init(|| {
            // SAFETY: loading a system DLL from System32 only, and casting
            // exports to the signatures documented in webauthn.h. The DLL
            // stays loaded for the life of the process.
            unsafe {
                let dll = LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;
                let get = |name: windows::core::PCSTR| GetProcAddress(dll, name);
                let version = std::mem::transmute::<Export, GetApiVersion>(get(windows::core::s!("WebAuthNGetApiVersionNumber"))?);
                Some(Api {
                    version: version(),
                    make_credential: std::mem::transmute::<Export, MakeCredential>(get(windows::core::s!(
                        "WebAuthNAuthenticatorMakeCredential"
                    ))?),
                    get_assertion: std::mem::transmute::<Export, GetAssertion>(get(windows::core::s!(
                        "WebAuthNAuthenticatorGetAssertion"
                    ))?),
                    free_attestation: std::mem::transmute::<Export, FreeAttestation>(get(windows::core::s!(
                        "WebAuthNFreeCredentialAttestation"
                    ))?),
                    free_assertion: std::mem::transmute::<Export, FreeAssertion>(get(windows::core::s!(
                        "WebAuthNFreeAssertion"
                    ))?),
                })
            }
        })
        .as_ref()
        .filter(|api| api.version >= MIN_API)
    }

    pub fn supported() -> bool {
        api().is_some()
    }

    fn unavailable() -> String {
        "Security keys need a newer Windows (the WebAuthn API version 4)".into()
    }

    fn describe(hr: HRESULT) -> String {
        // NTE_* codes as webauthn.dll returns them (winerror.h).
        match hr.0 as u32 {
            0x80090036 | 0x800704C7 => "The security key request was cancelled".into(),
            0x8009000F => "This security key is already added".into(),
            0x80090011 => "This key is not one added to Reach".into(),
            0x80090029 => "This security key does not support what unlocking needs (hmac-secret)".into(),
            _ => format!("The security key request failed: {}", windows::core::Error::from(hr).message()),
        }
    }

    /// The client data the key signs: never checked by anyone here (there
    /// is no server), but webauthn.dll requires it.
    fn client_data(kind: &str) -> Vec<u8> {
        let challenge: [u8; 32] = rand::random();
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"https://{RP_ID}"}}"#,
            URL_SAFE_NO_PAD.encode(challenge)
        )
        .into_bytes()
    }

    fn credential(id: &[u8]) -> WEBAUTHN_CREDENTIAL {
        WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_ptr() as *mut u8,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        }
    }

    pub fn make_credential(user_id: &[u8], label: &str, exclude: &[Vec<u8>], _pin: Option<&str>) -> Result<Vec<u8>, String> {
        let api = api().ok_or_else(unavailable)?;
        let rp_id = HSTRING::from(RP_ID);
        let label = HSTRING::from(label);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id.as_ptr()),
            pwszName: w!("CoreOps"),
            pwszIcon: PCWSTR::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_ptr() as *mut u8,
            pwszName: PCWSTR(label.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(label.as_ptr()),
        };
        let mut algorithms = [WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        }];
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: algorithms.len() as u32,
            pCredentialParameters: algorithms.as_mut_ptr(),
        };
        let data = client_data("webauthn.create");
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: data.len() as u32,
            pbClientDataJSON: data.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        // hmac-secret on; credProtect asks the key itself to refuse the
        // credential without user verification, where the key knows it.
        let mut hmac_secret = BOOL::from(true);
        let mut cred_protect = WEBAUTHN_CRED_PROTECT_EXTENSION_IN {
            dwCredProtect: WEBAUTHN_USER_VERIFICATION_REQUIRED,
            bRequireCredProtect: BOOL::from(false),
        };
        let mut extensions = [
            WEBAUTHN_EXTENSION {
                pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
                cbExtension: std::mem::size_of::<BOOL>() as u32,
                pvExtension: &mut hmac_secret as *mut BOOL as *mut _,
            },
            WEBAUTHN_EXTENSION {
                pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT,
                cbExtension: std::mem::size_of::<WEBAUTHN_CRED_PROTECT_EXTENSION_IN>() as u32,
                pvExtension: &mut cred_protect as *mut _ as *mut _,
            },
        ];
        // The keys already added, so the same key is not added twice.
        let mut excluded: Vec<WEBAUTHN_CREDENTIAL> = exclude.iter().map(|id| credential(id)).collect();
        // SAFETY: an all-zero options struct is the documented "unset" for
        // every field; the ones used are filled in below.
        let mut options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = unsafe { std::mem::zeroed() };
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        options.CredentialList = WEBAUTHN_CREDENTIALS { cCredentials: excluded.len() as u32, pCredentials: excluded.as_mut_ptr() };
        options.Extensions = WEBAUTHN_EXTENSIONS { cExtensions: extensions.len() as u32, pExtensions: extensions.as_mut_ptr() };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.bRequireResidentKey = BOOL::from(false);
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

        let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
        // SAFETY: every pointer above points at locals that outlive the call;
        // the result is freed with the DLL's own function.
        unsafe {
            let hr = (api.make_credential)(
                GetForegroundWindow(),
                &rp,
                &user,
                &params,
                &client,
                &options,
                &mut attestation,
            );
            if hr.is_err() || attestation.is_null() {
                return Err(describe(hr));
            }
            let a = &*attestation;
            let id = std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
            (api.free_attestation)(attestation);
            Ok(id)
        }
    }

    pub fn hmac_secret(
        credential_ids: &[Vec<u8>],
        salt: &[u8; 32],
        _pin: Option<&str>,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
        let api = api().ok_or_else(unavailable)?;
        let rp_id = HSTRING::from(RP_ID);
        let data = client_data("webauthn.get");
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: data.len() as u32,
            pbClientDataJSON: data.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut allowed: Vec<WEBAUTHN_CREDENTIAL> = credential_ids.iter().map(|id| credential(id)).collect();
        // One salt for every key: each key's output is still its own, as the
        // HMAC is keyed by that key's secret for its credential.
        let mut salt_copy = *salt;
        let mut global = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: salt_copy.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut global,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: std::ptr::null_mut(),
        };
        // SAFETY: as for make_credential.
        let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        options.CredentialList = WEBAUTHN_CREDENTIALS { cCredentials: allowed.len() as u32, pCredentials: allowed.as_mut_ptr() };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.pHmacSecretSaltValues = &mut salts;

        let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        // SAFETY: as for make_credential.
        unsafe {
            let hr = (api.get_assertion)(GetForegroundWindow(), PCWSTR(rp_id.as_ptr()), &client, &options, &mut assertion);
            if hr.is_err() || assertion.is_null() {
                return Err(describe(hr));
            }
            let a = &*assertion;
            let result = if a.pHmacSecret.is_null() || (*a.pHmacSecret).cbFirst != 32 {
                Err("This security key did not return a secret (does it support hmac-secret?)".to_string())
            } else {
                let out = &*a.pHmacSecret;
                let mut secret = Zeroizing::new([0u8; 32]);
                secret.copy_from_slice(std::slice::from_raw_parts(out.pbFirst, 32));
                let id = std::slice::from_raw_parts(a.Credential.pbId, a.Credential.cbId as usize).to_vec();
                Ok((id, secret))
            };
            (api.free_assertion)(assertion);
            result
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform {
    use super::RP_ID;
    use ctap_hid_fido2::fidokey::credential_management::credential_management_params::CredentialProtectionPolicy;
    use ctap_hid_fido2::fidokey::{AssertionExtension, CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
    use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
    use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};
    use zeroize::Zeroizing;

    pub fn supported() -> bool {
        true
    }

    /// Every FIDO key plugged in, opened.
    fn keys() -> Vec<FidoKeyHid> {
        let cfg = LibCfg::init();
        ctap_hid_fido2::get_fidokey_devices()
            .into_iter()
            .filter_map(|d| FidoKeyHidFactory::create_by_params(&[d.param], &cfg).ok())
            .collect()
    }

    fn pin_of(pin: Option<&str>) -> Result<&str, String> {
        pin.filter(|p| !p.is_empty()).ok_or_else(|| "Enter the security key's PIN".to_string())
    }

    fn describe(e: impl std::fmt::Display) -> String {
        let text = e.to_string();
        if text.contains("0x31") || text.contains("PIN_INVALID") {
            "Wrong PIN for this security key".into()
        } else if text.contains("0x32") || text.contains("PIN_BLOCKED") || text.contains("0x34") {
            "This security key's PIN is blocked; reset it with the key maker's tool".into()
        } else if text.contains("0x2E") || text.contains("NO_CREDENTIALS") {
            "This key is not one added to Reach".into()
        } else if text.contains("0x2F") || text.contains("ACTION_TIMEOUT") {
            "The key was not touched in time".into()
        } else {
            format!("The security key request failed: {text}")
        }
    }

    pub fn make_credential(user_id: &[u8], label: &str, exclude: &[Vec<u8>], pin: Option<&str>) -> Result<Vec<u8>, String> {
        let pin = pin_of(pin)?;
        let mut keys = keys();
        let key = match keys.len() {
            0 => return Err("Plug in the security key to add".into()),
            1 => keys.remove(0),
            _ => return Err("Plug in only the security key you want to add".into()),
        };
        let info = key.get_info().map_err(describe)?;
        if !info.extensions.iter().any(|e| e == "hmac-secret") {
            return Err("This security key does not support hmac-secret, which unlocking needs".into());
        }
        let challenge: [u8; 32] = rand::random();
        let user = PublicKeyCredentialUserEntity::new(Some(user_id), Some(label), Some(label));
        let extensions = [
            CredentialExtension::HmacSecret(Some(true)),
            CredentialExtension::CredProtect(Some(CredentialProtectionPolicy::UserVerificationRequired)),
        ];
        let _ = exclude; // A second credential on the same key is harmless here.
        let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
            .pin(pin)
            .user_entity(&user)
            .extensions(&extensions)
            .build();
        let attestation = key.make_credential_with_args(&args).map_err(describe)?;
        Ok(attestation.credential_descriptor.id)
    }

    pub fn hmac_secret(
        credential_ids: &[Vec<u8>],
        salt: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
        let pin = pin_of(pin)?;
        let keys = keys();
        if keys.is_empty() {
            return Err("Plug in your security key".into());
        }
        let challenge: [u8; 32] = rand::random();
        let mut last = "This key is not one added to Reach".to_string();
        for key in keys {
            let mut args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
                .pin(pin)
                .extensions(&[AssertionExtension::HmacSecret(Some(*salt))]);
            for id in credential_ids {
                args = args.add_credential_id(id);
            }
            match key.get_assertion_with_args(&args.build()) {
                Ok(assertions) => {
                    for a in assertions {
                        for e in &a.extensions {
                            if let AssertionExtension::HmacSecret(Some(out)) = e {
                                return Ok((a.credential_id.clone(), Zeroizing::new(*out)));
                            }
                        }
                    }
                    last = "This security key did not return a secret (does it support hmac-secret?)".into();
                }
                Err(e) => last = describe(e),
            }
        }
        Err(last)
    }
}

/// Android reaches security keys through Reach's Kotlin plugin (see
/// `ipc::vault_commands`), not through these calls.
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod platform {
    use zeroize::Zeroizing;

    pub fn supported() -> bool {
        // The Android plugin can already do it (keyMakeCredential and
        // keyHmacSecret), but nobody has run it with a real phone and key
        // yet, so it is not offered until someone has.
        false
    }

    pub fn make_credential(_: &[u8], _: &str, _: &[Vec<u8>], _: Option<&str>) -> Result<Vec<u8>, String> {
        Err("Security keys are not available on this platform yet".into())
    }

    pub fn hmac_secret(_: &[Vec<u8>], _: &[u8; 32], _: Option<&str>) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
        Err("Security keys are not available on this platform yet".into())
    }
}
