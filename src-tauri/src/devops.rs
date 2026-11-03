//! Which DevOps workspaces the user has switched on.
//!
//! Settings → DevOps turns each tool on or off, and off has to mean the tool
//! does nothing, not just that its page is hidden. Every command a workspace
//! exposes calls [`require`] first, so a switched-off tool cannot be driven
//! from a stale page, a script in the webview, or anything else that reaches
//! the IPC layer.
//!
//! The frontend owns the choice (it lives with the other per-device settings)
//! and pushes it here on launch and on every change. Until it does, everything
//! is off: a command that arrives before the settings have loaded is refused
//! rather than guessed at.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Ansible,
    Tofu,
    Databases,
    Containers,
    Kubernetes,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Tool::Ansible => "Ansible",
            Tool::Tofu => "OpenTofu",
            Tool::Databases => "Databases",
            Tool::Containers => "Containers",
            Tool::Kubernetes => "Kubernetes",
        }
    }

    fn flag(self) -> &'static AtomicBool {
        static ANSIBLE: AtomicBool = AtomicBool::new(false);
        static TOFU: AtomicBool = AtomicBool::new(false);
        static DATABASES: AtomicBool = AtomicBool::new(false);
        static CONTAINERS: AtomicBool = AtomicBool::new(false);
        static KUBERNETES: AtomicBool = AtomicBool::new(false);
        match self {
            Tool::Ansible => &ANSIBLE,
            Tool::Tofu => &TOFU,
            Tool::Databases => &DATABASES,
            Tool::Containers => &CONTAINERS,
            Tool::Kubernetes => &KUBERNETES,
        }
    }
}

pub fn set_enabled(tool: Tool, enabled: bool) {
    tool.flag().store(enabled, Ordering::Relaxed);
}

pub fn is_enabled(tool: Tool) -> bool {
    tool.flag().load(Ordering::Relaxed)
}

/// Refuse the call unless `tool` is switched on.
pub fn require(tool: Tool) -> Result<(), String> {
    if is_enabled(tool) {
        Ok(())
    } else {
        Err(format!("{} is turned off. Turn it on in Settings → DevOps.", tool.name()))
    }
}

#[tauri::command]
pub async fn devops_set_enabled(state: tauri::State<'_, crate::state::AppState>, tool: Tool, enabled: bool) -> Result<(), String> {
    set_enabled(tool, enabled);
    // Off means off: open database connections and their SSH tunnels close
    // too, rather than lingering until Reach quits.
    if tool == Tool::Databases && !enabled {
        state.db.lock().await.close_all().await;
    }
    if tool == Tool::Containers && !enabled {
        state.containers.lock().await.close_all();
    }
    if tool == Tool::Kubernetes && !enabled {
        state.k8s.lock().await.close_all();
    }
    Ok(())
}

/// Save text the user asked to download (a log, say). The native Save
/// dialog is opened here, so where the file goes is the user's choice in the
/// system's own dialog, never a path the page names. Returns false when the
/// user cancels.
#[tauri::command]
pub async fn devops_save_text(app: tauri::AppHandle, default_name: String, content: String) -> Result<bool, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let name: String = default_name
        .chars()
        .map(|c| if "<>:\"/\\|?*".contains(c) || c.is_control() { '_' } else { c })
        .collect();
    app.dialog().file().set_file_name(name).add_filter("Text", &["log", "txt"]).save_file(move |picked| {
        let _ = tx.send(picked);
    });
    let Some(picked) = rx.await.map_err(|e| e.to_string())? else { return Ok(false) };
    crate::ipc::vault_commands::picked_file::write(&app, &picked.to_string(), content.as_bytes()).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_tool_has_its_own_switch() {
        set_enabled(Tool::Ansible, true);
        set_enabled(Tool::Tofu, false);
        assert!(require(Tool::Ansible).is_ok());
        let err = require(Tool::Tofu).unwrap_err();
        assert!(err.contains("OpenTofu"), "{err}");

        set_enabled(Tool::Ansible, false);
        assert!(require(Tool::Ansible).is_err());
    }

    #[test]
    fn tool_names_match_the_frontend_ids() {
        let tools: Vec<Tool> = serde_json::from_str(r#"["ansible","tofu","databases","containers","kubernetes"]"#).unwrap();
        assert_eq!(tools, [Tool::Ansible, Tool::Tofu, Tool::Databases, Tool::Containers, Tool::Kubernetes]);
    }
}
