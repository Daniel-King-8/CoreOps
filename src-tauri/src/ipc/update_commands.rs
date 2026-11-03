//! Telling an Android install that a newer CoreOps is out.
//!
//! Tauri's updater covers Windows, macOS and Linux only. On Android an app
//! that was installed from an APK can never replace itself: Android lets only
//! the installer of record (the browser or file manager it came from) update
//! it without asking, and always shows its own install screen otherwise. So
//! CoreOps reads the same `latest.json` the desktop updater uses and links to
//! the release's APK; Android's installer then checks that the APK is signed
//! with the same key as the installed app before replacing it.
//!
//! The link is built here from a version number that parsed as semver, never
//! taken from the feed, so the feed cannot send the phone anywhere but
//! CoreOps's own GitHub release.

use serde::{Deserialize, Serialize};

const FEED: &str = "https://github.com/Daniel-King-8/CoreOps/releases/latest/download/latest.json";
const RELEASES: &str = "https://github.com/Daniel-King-8/CoreOps/releases";

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AppUpdate {
    pub version: String,
    /// The APK for this phone, or the release page when there is none.
    pub url: String,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
struct Feed {
    version: String,
    #[serde(default)]
    notes: Option<String>,
}

/// The release's APK name for this CPU, as the release workflow names them.
fn apk_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "aarch64" => Some("arm64"),
        "arm" => Some("armv7"),
        _ => None,
    }
}

/// What to offer, given the installed version, the feed and the CPU.
fn decide(current: &str, feed: &str, arch: &str) -> Option<AppUpdate> {
    let feed: Feed = serde_json::from_str(feed).ok()?;
    let latest = semver::Version::parse(feed.version.trim().trim_start_matches('v')).ok()?;
    let current = semver::Version::parse(current.trim().trim_start_matches('v')).ok()?;
    if latest <= current {
        return None;
    }
    let url = match apk_arch(arch) {
        Some(a) => format!("{RELEASES}/download/v{latest}/CoreOps_{latest}_android_{a}.apk"),
        None => format!("{RELEASES}/tag/v{latest}"),
    };
    Some(AppUpdate { version: latest.to_string(), url, notes: feed.notes })
}

/// A newer CoreOps than this one, or `None`. Used on Android, where Tauri's
/// updater does not run; a desktop asks the updater plugin instead.
#[tauri::command]
pub async fn app_update_check(app: tauri::AppHandle) -> Result<Option<AppUpdate>, String> {
    let current = app.package_info().version.to_string();
    let client = crate::http::client_builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let body = client
        .get(FEED)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    Ok(decide(&current, &body, std::env::consts::ARCH))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED_073: &str = r#"{"version":"0.7.3","notes":"VNC and logs","platforms":{}}"#;

    #[test]
    fn offers_a_newer_version_with_the_phones_apk() {
        let u = decide("0.7.2", FEED_073, "aarch64").unwrap();
        assert_eq!(u.version, "0.7.3");
        assert_eq!(u.url, "https://github.com/Daniel-King-8/CoreOps/releases/download/v0.7.3/CoreOps_0.7.3_android_arm64.apk");
        assert_eq!(u.notes.as_deref(), Some("VNC and logs"));
        assert!(decide("0.7.2", FEED_073, "arm").unwrap().url.ends_with("CoreOps_0.7.3_android_armv7.apk"));
    }

    #[test]
    fn same_or_older_is_not_an_update() {
        assert_eq!(decide("0.7.3", FEED_073, "aarch64"), None);
        assert_eq!(decide("0.8.0", FEED_073, "aarch64"), None);
        // Compared as versions, not text: 0.7.10 is newer than 0.7.9.
        assert!(decide("0.7.9", r#"{"version":"0.7.10"}"#, "aarch64").is_some());
        assert_eq!(decide("0.7.10", r#"{"version":"0.7.9"}"#, "aarch64"), None);
    }

    #[test]
    fn a_cpu_without_an_apk_gets_the_release_page() {
        let u = decide("0.7.2", FEED_073, "x86_64").unwrap();
        assert_eq!(u.url, "https://github.com/Daniel-King-8/CoreOps/releases/tag/v0.7.3");
    }

    /// Whatever the feed says, the link stays on CoreOps's own releases.
    #[test]
    fn the_feed_cannot_choose_the_link() {
        for v in [
            "0.9.0/../../evil",
            "1.0.0?x=https://evil.example",
            "https://evil.example/x.apk",
            "9.9.9 ",
            "not a version",
            "",
        ] {
            let feed = serde_json::json!({ "version": v }).to_string();
            if let Some(u) = decide("0.7.2", &feed, "aarch64") {
                assert!(u.url.starts_with("https://github.com/Daniel-King-8/CoreOps/releases/download/v9.9.9/"), "{v}: {}", u.url);
            }
        }
        assert_eq!(decide("0.7.2", "not json", "aarch64"), None);
        assert_eq!(decide("0.7.2", r#"{"notes":"no version"}"#, "aarch64"), None);
    }
}
