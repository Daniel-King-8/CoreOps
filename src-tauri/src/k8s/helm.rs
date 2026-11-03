//! Helm releases, read where Helm keeps them.
//!
//! Helm's default storage driver keeps every revision of a release as a
//! Secret of type `helm.sh/release.v1`, labelled `owner=helm`, named
//! `sh.helm.release.v1.<name>.v<revision>`. Its `release` key holds the
//! release as JSON, gzipped and base64-encoded once more on top of the
//! Secret's own encoding (Helm's `pkg/storage/driver/util.go`). Reading
//! those needs no helm program, so releases, history and values show on a
//! phone too. Changing a release (rollback, upgrade, uninstall) runs `helm`
//! on a host, as Helm's hooks and checks belong to it.

use std::io::Read;

use base64::Engine as _;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use serde::{Deserialize, Serialize};

use super::Cluster;

#[derive(Debug, Deserialize, Default)]
struct RawRelease {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    version: i32,
    #[serde(default)]
    info: RawInfo,
    #[serde(default)]
    chart: RawChart,
    #[serde(default)]
    config: Option<serde_json::Value>,
    #[serde(default)]
    manifest: String,
}

#[derive(Debug, Deserialize, Default)]
struct RawInfo {
    #[serde(default)]
    status: String,
    #[serde(default)]
    last_deployed: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Deserialize, Default)]
struct RawChart {
    #[serde(default)]
    metadata: RawMeta,
    #[serde(default)]
    values: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct RawMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default, rename = "appVersion")]
    app_version: String,
}

/// One revision of a release.
#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Revision {
    pub name: String,
    pub namespace: String,
    pub revision: i32,
    pub status: String,
    pub chart: String,
    pub chart_version: String,
    pub app_version: String,
    pub updated: String,
    pub description: String,
}

/// A revision with what it was installed with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub revision: Revision,
    /// The values the user supplied (`helm get values`), as YAML.
    pub values: String,
    /// The chart's defaults merged under them is not stored; these are the
    /// chart's own defaults, as YAML.
    pub chart_values: String,
    pub manifest: String,
    pub notes: String,
}

/// Decode a release Secret's `release` value (after the Secret's own base64).
pub fn decode(stored: &[u8]) -> Result<serde_json::Value, String> {
    let gz = base64::engine::general_purpose::STANDARD
        .decode(stored.trim_ascii())
        .map_err(|e| format!("Not a Helm release: {e}"))?;
    // Helm gzips when it writes; very old releases may be plain JSON.
    let json = if gz.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(gz.as_slice()).read_to_end(&mut out).map_err(|e| format!("Not a Helm release: {e}"))?;
        out
    } else {
        gz
    };
    serde_json::from_slice(&json).map_err(|e| format!("Not a Helm release: {e}"))
}

fn revision_of(raw: &RawRelease) -> Revision {
    Revision {
        name: raw.name.clone(),
        namespace: raw.namespace.clone(),
        revision: raw.version,
        status: raw.info.status.clone(),
        chart: raw.chart.metadata.name.clone(),
        chart_version: raw.chart.metadata.version.clone(),
        app_version: raw.chart.metadata.app_version.clone(),
        updated: raw.info.last_deployed.clone(),
        description: raw.info.description.clone(),
    }
}

fn yaml_of(v: &Option<serde_json::Value>) -> String {
    match v {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::Object(m)) if m.is_empty() => String::new(),
        Some(v) => serde_saphyr::to_string(v).unwrap_or_default(),
    }
}

impl Cluster {
    async fn release_secrets(&self, ns: Option<&str>, name: Option<&str>) -> Result<Vec<RawRelease>, String> {
        let api: Api<Secret> = match ns {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let mut selector = "owner=helm".to_string();
        if let Some(n) = name {
            selector.push_str(&format!(",name={n}"));
        }
        let list = api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|e| format!("Reading Helm releases: {e}"))?;
        let mut out = Vec::new();
        for s in list.items {
            if s.type_.as_deref() != Some("helm.sh/release.v1") {
                continue;
            }
            let Some(data) = s.data.as_ref().and_then(|d| d.get("release")) else { continue };
            // One unreadable revision must not hide the rest.
            if let Ok(v) = decode(&data.0) {
                if let Ok(raw) = serde_json::from_value::<RawRelease>(v) {
                    out.push(raw);
                }
            }
        }
        Ok(out)
    }

    /// Each release at its newest revision, as `helm list --all`.
    pub async fn releases(&self, ns: Option<&str>) -> Result<Vec<Revision>, String> {
        let mut latest: std::collections::BTreeMap<(String, String), Revision> = Default::default();
        for raw in self.release_secrets(ns, None).await? {
            let r = revision_of(&raw);
            let key = (r.namespace.clone(), r.name.clone());
            if latest.get(&key).is_none_or(|old| old.revision < r.revision) {
                latest.insert(key, r);
            }
        }
        Ok(latest.into_values().collect())
    }

    /// Every revision of one release, newest first, as `helm history`.
    pub async fn release_history(&self, ns: &str, name: &str) -> Result<Vec<Revision>, String> {
        let mut list: Vec<Revision> = self.release_secrets(Some(ns), Some(name)).await?.iter().map(revision_of).collect();
        list.sort_by_key(|r| std::cmp::Reverse(r.revision));
        Ok(list)
    }

    /// One revision's values, chart defaults, manifest and notes.
    pub async fn release_detail(&self, ns: &str, name: &str, revision: i32) -> Result<Detail, String> {
        let raw = self
            .release_secrets(Some(ns), Some(name))
            .await?
            .into_iter()
            .find(|r| r.version == revision)
            .ok_or_else(|| format!("{name} has no revision {revision}"))?;
        Ok(Detail {
            revision: revision_of(&raw),
            values: yaml_of(&raw.config),
            chart_values: yaml_of(&raw.chart.values),
            manifest: raw.manifest.clone(),
            notes: raw.info.notes.clone(),
        })
    }
}

/// The `helm` command line for a change to a release, every value quoted.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HelmAction {
    Rollback,
    Uninstall,
}

pub fn command(action: HelmAction, ns: &str, name: &str, revision: Option<i32>, kube_context: Option<&str>) -> Result<String, String> {
    use crate::container::sh_quote;
    let mut cmd = match action {
        HelmAction::Rollback => {
            let r = revision.ok_or("A rollback needs the revision to go back to")?;
            if r < 1 {
                return Err("Revisions start at 1".into());
            }
            // --wait: done means the rolled-back pods are ready, not just sent.
            format!("helm rollback {} {r} --wait", sh_quote(name))
        }
        HelmAction::Uninstall => format!("helm uninstall {} --wait", sh_quote(name)),
    };
    cmd.push_str(&format!(" --namespace {}", sh_quote(ns)));
    if let Some(c) = kube_context {
        cmd.push_str(&format!(" --kube-context {}", sh_quote(c)));
    }
    Ok(cmd)
}

/// `helm_cmd` run on a POSIX host with the kubeconfig Reach is using, which
/// arrives on stdin: written to a file only its owner can read, used, and
/// removed when the shell exits, whatever happened. The kubeconfig never
/// appears on a command line, where `ps` would show it to every user.
pub fn with_stdin_kubeconfig(helm_cmd: &str) -> String {
    format!(r#"umask 077; f=$(mktemp) || exit 1; trap 'rm -f "$f"' EXIT; cat > "$f" && {helm_cmd} --kubeconfig "$f""#)
}
