use std::process::Stdio;

use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};

fn silent_async_command(program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
}

fn silent_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
}

use crate::ssh::client::{exec_on_connection_streaming, SshManager};
use crate::ansible::types::{AnsibleCommand, AnsibleCommandEvent, AnsibleCommandRequest};
use crate::toolchain::detect::windows_to_wsl_path;

/// Build CLI binary name and argument list for an Ansible command.
pub fn build_command_args(request: &AnsibleCommandRequest) -> (String, Vec<String>) {
    let mut args = Vec::new();

    let binary = match request.command {
        AnsibleCommand::Playbook | AnsibleCommand::SyntaxCheck => {
            if let Some(ref playbook) = request.playbook {
                args.push(playbook.clone());
            }
            if let Some(ref inv) = request.inventory_file {
                args.push("-i".to_string());
                args.push(inv.clone());
            }
            if matches!(request.command, AnsibleCommand::SyntaxCheck) {
                args.push("--syntax-check".to_string());
            }
            "ansible-playbook".to_string()
        }
        AnsibleCommand::AdHoc => {
            if let Some(ref pattern) = request.host_pattern {
                args.push(pattern.clone());
            } else {
                args.push("all".to_string());
            }
            if let Some(ref module) = request.module_name {
                args.push("-m".to_string());
                args.push(module.clone());
            }
            if let Some(ref margs) = request.module_args {
                args.push("-a".to_string());
                args.push(margs.clone());
            }
            if let Some(ref inv) = request.inventory_file {
                args.push("-i".to_string());
                args.push(inv.clone());
            }
            "ansible".to_string()
        }
        AnsibleCommand::GalaxyRoleInstall => {
            args.push("role".to_string());
            args.push("install".to_string());
            if let Some(ref name) = request.role_name {
                args.push(name.clone());
            }
            "ansible-galaxy".to_string()
        }
        AnsibleCommand::GalaxyRoleList => {
            args.push("role".to_string());
            args.push("list".to_string());
            "ansible-galaxy".to_string()
        }
        AnsibleCommand::GalaxyRoleRemove => {
            args.push("role".to_string());
            args.push("remove".to_string());
            if let Some(ref name) = request.role_name {
                args.push(name.clone());
            }
            "ansible-galaxy".to_string()
        }
        AnsibleCommand::GalaxyCollectionInstall => {
            args.push("collection".to_string());
            args.push("install".to_string());
            if let Some(ref name) = request.collection_name {
                args.push(name.clone());
            }
            "ansible-galaxy".to_string()
        }
        AnsibleCommand::GalaxyCollectionList => {
            args.push("collection".to_string());
            args.push("list".to_string());
            "ansible-galaxy".to_string()
        }
        AnsibleCommand::VaultEncrypt => {
            args.push("encrypt".to_string());
            if let Some(ref file) = request.vault_file {
                args.push(file.clone());
            }
            "ansible-vault".to_string()
        }
        AnsibleCommand::VaultDecrypt => {
            args.push("decrypt".to_string());
            if let Some(ref file) = request.vault_file {
                args.push(file.clone());
            }
            "ansible-vault".to_string()
        }
        AnsibleCommand::VaultView => {
            args.push("view".to_string());
            if let Some(ref file) = request.vault_file {
                args.push(file.clone());
            }
            "ansible-vault".to_string()
        }
        AnsibleCommand::Inventory => {
            if let Some(ref inv) = request.inventory_file {
                args.push("-i".to_string());
                args.push(inv.clone());
            }
            args.push("--list".to_string());
            "ansible-inventory".to_string()
        }
    };

    // Extra args
    args.extend(request.extra_args.clone());

    (binary, args)
}

/// Execute an Ansible command locally, streaming output via Tauri events.
/// On Windows, tries: native binary → WSL → error.
pub async fn run_local(
    working_dir: &str,
    binary: &str,
    args: &[String],
    run_id: &str,
    app_handle: &tauri::AppHandle,
) -> Result<i32, String> {
    let event_name = format!("ansible-output-{}", run_id);

    // ── 防御性检查链 ──
    // Windows: 优先检查本机二进制，其次 WSL，都没有则立即报错
    #[cfg(windows)]
    let use_wsl = {
        if native_binary_available(binary) {
            false
        } else if should_use_wsl(binary) {
            true
        } else {
            let msg = format!(
                "未检测到工具 [{}]。请确认 Ansible 已安装且路径正确，或手动安装。Windows 用户可通过 WSL 安装。",
                binary
            );
            emit_done(&event_name, run_id, &msg, 1, app_handle);
            return Err(msg);
        }
    };

    #[cfg(not(windows))]
    let use_wsl = false;

    // ── 非 Windows / 本机执行 ──
    #[cfg(not(windows))]
    {
        if which::which(binary).is_err() {
            let msg = format!(
                "未检测到工具 [{}]。请确认 Ansible 已安装且路径正确。",
                binary
            );
            emit_done(&event_name, run_id, &msg, 1, app_handle);
            return Err(msg);
        }
    }

    // ── 执行 ──
    let mut child = if use_wsl {
        let wsl_dir = windows_to_wsl_path(working_dir);
        let escaped_args: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
        let cmd_str = format!(
            "cd {} && ANSIBLE_FORCE_COLOR=0 ANSIBLE_NOCOLOR=1 {} {}",
            shell_escape(&wsl_dir),
            binary,
            escaped_args.join(" ")
        );

        let _ = app_handle.emit(
            &event_name,
            AnsibleCommandEvent {
                run_id: run_id.to_string(),
                stream: "system".to_string(),
                line: format!("Running via WSL: {} {}", binary, args.join(" ")),
                done: false,
                exit_code: None,
            },
        );

        silent_async_command("wsl.exe")
            .args(["--", "bash", "-c", &cmd_str])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("无法启动 wsl.exe: {}", e))?
    } else {
        silent_async_command(binary)
            .args(args)
            .current_dir(working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .env("ANSIBLE_FORCE_COLOR", "0")
            .env("ANSIBLE_NOCOLOR", "1")
            .spawn()
            .map_err(|e| format!("无法启动 {}: {}", binary, e))?
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Stream stdout
    if let Some(stdout) = stdout {
        let event = event_name.clone();
        let handle = app_handle.clone();
        let rid = run_id.to_string();
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = handle.emit(
                    &event,
                    AnsibleCommandEvent {
                        run_id: rid.clone(),
                        stream: "stdout".to_string(),
                        line,
                        done: false,
                        exit_code: None,
                    },
                );
            }
        });
    }

    // Stream stderr
    if let Some(stderr) = stderr {
        let event = event_name.clone();
        let handle = app_handle.clone();
        let rid = run_id.to_string();
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = handle.emit(
                    &event,
                    AnsibleCommandEvent {
                        run_id: rid.clone(),
                        stream: "stderr".to_string(),
                        line,
                        done: false,
                        exit_code: None,
                    },
                );
            }
        });
    }

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Failed to wait for process: {}", e))?;

    let exit_code = status.code().unwrap_or(-1);

    // Emit done event
    let _ = app_handle.emit(
        &event_name,
        AnsibleCommandEvent {
            run_id: run_id.to_string(),
            stream: "system".to_string(),
            line: if exit_code == 0 {
                "Command completed successfully.".to_string()
            } else {
                format!("Command exited with code {}.", exit_code)
            },
            done: true,
            exit_code: Some(exit_code),
        },
    );

    Ok(exit_code)
}

/// On Windows, check if WSL is actually available and the ansible tool
/// exists inside it. Uses a 3-second timeout to prevent hanging.
/// Returns false on any failure (no WSL, tool missing, timeout).
fn should_use_wsl(binary: &str) -> bool {
    #[cfg(not(windows))]
    { let _ = binary; return false; }

    #[cfg(windows)]
    {
        // First check if wsl.exe even exists in PATH — fast early exit.
        if which::which("wsl.exe").is_err() {
            tracing::debug!("WSL not found in PATH, skipping WSL check for {}", binary);
            return false;
        }

        // Run with a 3-second timeout so we don't hang if WSL is broken.
        let mut cmd = silent_command("wsl.exe");
        cmd.args(["--", "bash", "-lc", &format!("which {} 2>/dev/null", binary)]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::null());

        // Spawn and wait with timeout via a separate thread.
        // std::process::Command can't timeout natively, so we use a oneshot.
        let Ok(mut child) = cmd.spawn() else {
            return false;
        };

        let start = std::time::Instant::now();
        const TIMEOUT_MS: u64 = 3000;

        loop {
            if start.elapsed().as_millis() as u64 > TIMEOUT_MS {
                let _ = child.kill();
                tracing::warn!("WSL check timed out after {}ms for {}", TIMEOUT_MS, binary);
                return false;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return true;
                    }
                    return false;
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => return false,
            }
        }
    }
}

/// Check if a binary is available natively on Windows (fast PATH lookup).
fn native_binary_available(binary: &str) -> bool {
    which::which(binary).is_ok()
}

/// Execute an Ansible command on a remote SSH connection, streaming output via Tauri events.
pub async fn run_remote(
    connection_id: &str,
    working_dir: &str,
    binary: &str,
    args: &[String],
    run_id: &str,
    app_handle: &tauri::AppHandle,
    ssh_manager: &mut SshManager,
) -> Result<i32, String> {
    let event_name = format!("ansible-output-{}", run_id);

    // Build the full command string for remote execution
    let cmd = format!(
        "cd {} && {} {}",
        shell_escape(working_dir),
        binary,
        args.join(" ")
    );

    let handle = ssh_manager
        .get_handle(connection_id)
        .map_err(|e| e.to_string())?;

    let exit_code =
        exec_on_connection_streaming(&handle, &cmd, run_id, "ansible-output", app_handle)
            .await
            .map_err(|e| e.to_string())?;

    // Emit done event
    let _ = app_handle.emit(
        &event_name,
        AnsibleCommandEvent {
            run_id: run_id.to_string(),
            stream: "system".to_string(),
            line: if exit_code == 0 {
                "Command completed successfully.".to_string()
            } else {
                format!("Command exited with code {}.", exit_code)
            },
            done: true,
            exit_code: Some(exit_code),
        },
    );

    Ok(exit_code)
}

/// Emit a final "done" event with the given message and exit code.
/// Used by the defensive check chain to report errors to the frontend.
fn emit_done(
    event_name: &str,
    run_id: &str,
    msg: &str,
    exit_code: i32,
    app_handle: &tauri::AppHandle,
) {
    let _ = app_handle.emit(
        event_name,
        AnsibleCommandEvent {
            run_id: run_id.to_string(),
            stream: "stderr".to_string(),
            line: msg.to_string(),
            done: true,
            exit_code: Some(exit_code),
        },
    );
}

/// Basic shell escaping for paths in remote commands.
pub fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}
