//! IPC commands for ssh_config: importing hosts, and what a session's
//! settings do.

use crate::ssh::sshconf::env::SystemEnv;
use crate::ssh::sshconf::import::{self, Scan};
use crate::ssh::sshconf::report::{self, Report};
use crate::ssh::sshconf::session::{resolve_session, SshOptions};

/// Every concrete host in ~/.ssh/config (and what it includes), resolved as
/// ssh would, with a report of each line.
#[tauri::command]
pub async fn sshconfig_scan() -> Result<Scan, String> {
    let user = SystemEnv::user_config().ok_or("No home directory")?;
    let system = SystemEnv::system_config();
    tokio::task::spawn_blocking(move || import::scan(&user, &system)).await.map_err(|e| e.to_string())
}

/// Check if an SSH config file exists.
#[tauri::command]
pub async fn sshconfig_exists() -> Result<bool, String> {
    Ok(SystemEnv::user_config().is_some_and(|p| p.exists()))
}

/// What a session's ssh_config settings do: every line, how it is used,
/// what weakens the connection, what would run.
#[tauri::command]
pub async fn ssh_options_report(
    state: tauri::State<'_, crate::state::AppState>,
    host: String,
    port: u16,
    username: String,
    options: SshOptions,
) -> Result<Report, String> {
    // As a connection would see them: only this person's approvals count.
    let _ = &state;
    let options = options.effective();
    tokio::task::spawn_blocking(move || {
        let res = resolve_session(&options, &host, port, &username);
        let plan = crate::ssh::sshconf::apply::Plan::new(&res.resolved, russh::client::Config::default(), &options.accepted_weakenings, !options.untrusted_lines);
        report::build(&res.resolved, &plan, &res.errors, &res.exec_pending)
    })
    .await
    .map_err(|e| e.to_string())
}
