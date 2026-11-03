//! The Android half of Reach's vault unlock. Android offers no Rust API for
//! either piece, so both live in Kotlin (`android/`), and this crate only
//! registers that class and forwards calls to it:
//!
//! - the fingerprint: an AES key in the Android Keystore that needs a strong
//!   biometric check for every use seals the vault key (Android's own
//!   guidance, "Include a cryptographic solution");
//! - FIDO2 security keys over USB and NFC, through Yubico's yubikit-android.
//!
//! On every other platform the plugin registers and does nothing.

use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

#[cfg(target_os = "android")]
use tauri::Manager;

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("reach-unlock")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                let handle = _api.register_android_plugin("com.reach.unlock", "UnlockPlugin")?;
                _app.manage(Unlock(handle));
            }
            Ok(())
        })
        .build()
}

/// The Kotlin side, managed as state on Android.
#[cfg(target_os = "android")]
pub struct Unlock<R: Runtime>(tauri::plugin::PluginHandle<R>);

#[cfg(target_os = "android")]
impl<R: Runtime> Unlock<R> {
    /// Run one of UnlockPlugin's commands. Async, so the webview's thread is
    /// never blocked while Kotlin waits on a fingerprint or a key.
    pub async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        payload: impl serde::Serialize,
    ) -> Result<T, String> {
        self.0
            .run_mobile_plugin_async(method, payload)
            .await
            .map_err(|e| e.to_string())
    }

    /// The same, waiting on this thread. For callers that are not async (the
    /// keychain functions). Never call it from Android's main thread: the
    /// Kotlin side runs there, and would wait on this call forever.
    pub fn call_blocking<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        payload: impl serde::Serialize,
    ) -> Result<T, String> {
        self.0.run_mobile_plugin(method, payload).map_err(|e| e.to_string())
    }
}
