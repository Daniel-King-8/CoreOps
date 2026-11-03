//! Settings, General: the X11 server Reach downloads on Windows when the
//! user turns it on (see `ssh::xserver`). Elsewhere the system's X server
//! is used, so these report it as not needed.

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X11ServerStatus {
    /// Reach brings its own X server here (Windows).
    pub supported: bool,
    pub installed: bool,
    pub version: &'static str,
}

#[cfg(windows)]
fn cancel_flag() -> &'static std::sync::atomic::AtomicBool {
    static F: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    &F
}

#[tauri::command]
pub fn x11server_status() -> X11ServerStatus {
    #[cfg(windows)]
    {
        X11ServerStatus { supported: true, installed: crate::ssh::xserver::installed(), version: crate::ssh::xserver::VERSION }
    }
    #[cfg(not(windows))]
    {
        X11ServerStatus { supported: false, installed: false, version: "" }
    }
}

/// Downloads and sets up the X server, reporting `x11server-progress`
/// events. Resolves when it is ready; rejects with "cancelled" when the
/// user stopped it.
#[tauri::command]
pub async fn x11server_install(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::sync::atomic::Ordering;
        use tauri::Emitter;
        static BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if BUSY.swap(true, Ordering::SeqCst) {
            return Err("the X server is already being set up".into());
        }
        cancel_flag().store(false, Ordering::SeqCst);
        let result = crate::ssh::xserver::install(cancel_flag(), |p| {
            let _ = app.emit("x11server-progress", p);
        })
        .await;
        BUSY.store(false, Ordering::SeqCst);
        result
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("this system's own X server is used".into())
    }
}

#[tauri::command]
pub fn x11server_cancel() {
    #[cfg(windows)]
    cancel_flag().store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Stops Reach's X server and removes it.
#[tauri::command]
pub async fn x11server_remove() -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::ssh::xserver::remove().await
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}
