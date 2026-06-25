use std::collections::HashMap;

use crate::toolchain::detect::{check_tool, ToolStatus};
use crate::toolchain::install;
use crate::state::AppState;
use tauri::State;

/// 一次性检查所有外部依赖的状态。供前端启动时调用，避免逐个命令转圈。
#[tauri::command]
pub async fn check_environment(state: State<'_, AppState>) -> Result<HashMap<String, serde_json::Value>, String> {
    let mut result = HashMap::new();

    // 工具链检查（同步但很快，直接查 PATH）
    for tool in &["ansible", "tofu", "python3", "git", "ssh"] {
        let status = check_tool(tool);
        result.insert(tool.to_string(), serde_json::json!({
            "installed": status.installed,
            "version": status.version,
        }));
    }

    // Vault 状态
    let vault_locked = state.vault_manager.lock().await.is_locked();
    result.insert("vault".to_string(), serde_json::json!({
        "locked": vault_locked,
    }));

    // 市场地址
    let market_url = state.marketplace_index_url.read().await.clone();
    result.insert("marketplace".to_string(), serde_json::json!({
        "url": market_url,
    }));

    tracing::info!("Environment check: {:?}", result);
    Ok(result)
}

#[tauri::command]
pub async fn toolchain_check(tool: String) -> Result<ToolStatus, String> {
    Ok(check_tool(&tool))
}

#[tauri::command]
pub async fn toolchain_install(
    tool: String,
    app_handle: tauri::AppHandle,
) -> Result<ToolStatus, String> {
    match tool.as_str() {
        "ansible" => {
            install::install_ansible(&app_handle).await?;
        }
        "tofu" => {
            install::install_tofu(&app_handle).await?;
        }
        _ => {
            return Err(format!("Unknown tool: {}", tool));
        }
    }

    // Re-check after install
    Ok(check_tool(&tool))
}
