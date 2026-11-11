<p align="right">
  <a href="README.md">中文</a>
</p>

<p align="center">
  <img src="src-tauri/icons/128x128.png" alt="CoreOps" width="80" />
</p>

<h1 align="center">CoreOps</h1>

<p align="center">
  A cross-platform SSH client and remote operations workbench for Chinese-speaking DevOps teams
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.8.3-brightgreen?style=flat-square" alt="Version 0.8.3" />
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-333?style=flat-square" alt="Platforms" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Qwen%20%7C%20OpenAI-blueviolet?style=flat-square" alt="AI Support" />
  <img src="https://img.shields.io/badge/stack-Rust%20%2B%20Tauri%20v2-0a84ff?style=flat-square" alt="Rust + Tauri v2" />
</p>

---

## What is CoreOps

CoreOps is a cross-platform SSH client and remote operations workbench built for Chinese-speaking DevOps teams. It is built on the native Rust core of Reach 0.8.8 and brings connections, file transfer, remote desktops, tunnels, automation, containers, Kubernetes, databases, and an AI operations assistant into one application.

No Electron, no subscription, no account. Windows, macOS, Linux, and Android share one codebase. Sessions, keys, and settings stay on your machine by default; encrypted sync is optional when you need multiple devices.

---

## Why CoreOps

- **Native performance**: SSH through Rust and russh, with no OpenSSH dependency and no Electron overhead.
- **One app for daily operations**: SSH, SFTP, RDP/VNC, port tunnels, Ansible, OpenTofu, Docker/K8s, and database workspaces.
- **AI that works with the terminal**: reads the live terminal, generates commands, and injects them into the current session; four execution modes with write confirmation and interactive gates.
- **Better Chinese localisation**: the interface, prompts, errors, and AI panel are fully localised, with nine languages available.
- **Secure by default**: encrypted vault, host-key verification, and log redaction; session sharing and MCP stay off until enabled.
- **Local-first**: no mandatory account or cloud service; turn on encrypted sync only when you need it.

---

## Features

### 1. AI Operations Assistant

The AI panel sits beside the terminal and works with the current session, not as a detached chat window.

- **Reads the live terminal**: the recent terminal output is included automatically, so errors do not need to be copied by hand.
- **Runs code blocks**: shell commands in an AI reply can be injected into the current terminal with one click.
- **Run all commands**: when a reply contains several commands, execute them in order as one batch.
- **SSH / local PTY routing**: automatically uses `sshSend` or `ptyWrite` based on the active tab.
- **Per-tab context**: each tab keeps its own conversation, so switching tabs does not mix histories; closing a tab clears it.
- **Type while it runs**: the input stays editable during execution; Enter only inserts a newline, and you press the red stop button before sending.
- **Abort**: stop a response or an execution at any time.
- **Resizable panel**: drag the panel edge; the width is remembered.
- **Conversation export**: export the current tab's conversation as Markdown, labelled by source (you / auto-run / batch-run / pending / manual run).

#### Four execution modes

| Mode | Behaviour |
|------|-----------|
| **Normal** | The AI can read the terminal and analyse it; commands run only when you click Run |
| **Plan only** | Analysis and plans only; no command can be executed |
| **Auto edit** | The AI may edit configuration files; high-risk commands still ask first |
| **Full auto** | Read-only checks run automatically; writes follow the policy; passwords and interactive commands still require you |

The selected mode is stored locally and survives restarts.

#### Safety boundaries

- **Only shell blocks run**: only blocks explicitly tagged `bash`, `sh`, `shell`, or `zsh` are injected; untagged, `text`, and `console` blocks are display-only.
- **Questions are not actions**: for “what images exist” or “check the status”, only the first read-only command runs, then the client stops instead of expanding into deployment or cleanup.
- **Write confirmation**: in question mode, `mkdir`, `cp`, `rm`, `systemctl`, `docker run/pull` and similar writes become `[待确认]` instead of running automatically.
- **Suggestions and references do not run**: commands under “suggested actions / for reference only / for future use” are not auto-executed; “I’ll run it myself” phrasing is not mistaken for a suggestion.
- **Interactive gate**: `sudo`, password prompts, `[y/N]`, and “press Enter” pauses execution and opens an input dialog.
- **Long-command protection**: waits for the shell prompt to return before typing the next command; pauses with a notice on timeout.
- **Dangerous-command confirmation**: in Auto Edit mode, service restarts, deletions, package management, disk and firewall changes ask first.
- **Round limit**: auto-execution stops after 10 rounds and says so, instead of looping forever.

#### AI configuration

- **Any OpenAI-compatible API**: DeepSeek, Qwen, SiliconFlow, local Ollama, OpenAI, and others.
- **Encrypted API key**: stored in the application vault, never written to a plain-text config file.
- **Model discovery**: fetch the available models from the configured endpoint, with search and filtering.
- **Model details**: context window and price per million tokens.
- **Base-URL handling**: with or without `/v1` both work; DeepSeek's `reasoning_content` is read correctly.
- **Restores after restart**: the key is loaded automatically once the vault is unlocked.

---

### 2. Connections and Terminals

- **SSH terminal**: tabs, split panes, tab groups, and WebGL rendering with xterm.js.
- **Your `~/.ssh/config`, all of it**: ProxyJump, ProxyCommand, ControlMaster, Kerberos (GSSAPI), X11 forwarding, PKCS#11 and FIDO2 keys, and the other keywords — 104 in total.
- **Jump hosts / multi-hop SSH**: imported from ssh_config or configured in the session editor.
- **OpenSSH-style authentication chain**: key → ssh-agent → password.
- **Host-key verification**: fingerprint confirmation on first use, and a clear warning when a known host presents a different key.
- **Reconnect**: dropped SSH tabs show their state and can reconnect with one click.
- **RDP and VNC**: remote desktops in a tab; RDP shares the clipboard, files, and a local folder as a drive.
- **WSL sessions**: open a WSL distribution in a tab on Windows, with user selection.
- **Local shells**: open a local terminal, optionally running a specific program (for example a container shell).
- **Serial console**: COM/TTY access for routers, switches, and embedded devices.
- **Terminal clipboard**: right-click to copy or paste, confirmation before multi-line paste, links open in the system browser.
- **Terminal colours follow the theme**, in dark and light modes.
- **Command palette**: `Ctrl+Shift+P` reaches sessions, tabs, pages, snippets, and actions.
- **Quick Connect**: type `user@host:port` and connect.
- **Start screen**: recent sessions, Quick Connect, and a local shell when no tab is open.

---

### 3. File Transfer and SFTP

- **SFTP explorer**: multi-tab browsing, path navigation, and permission display.
- **Drag and drop**: upload files by dropping them in, download by dragging them out.
- **Folder upload**: send a whole directory, including subfolders, as one transfer with one progress bar.
- **Edit in place**: open a remote file in the CodeMirror editor and save it back.
- **Compress and extract on the server**: no local download required.
- **Transfer queue**: progress, cancel, and retry.
- **Symlinks**: shown with a link icon and their real target; no meaningless size.
- **Real error messages**: download, delete, rename, new file, and new folder failures show the server's own error instead of failing silently.
- **Download integrity**: a dropped connection or a stalled server fails the download instead of leaving a truncated file that looks complete.

---

### 4. Networking and Tunnels

- **Local port forwarding**: map a remote port onto this machine.
- **Remote forwarding**: through `RemoteForward` in ssh_config.
- **Dynamic SOCKS proxy**: create one from the Tunnels panel and route it through the current SSH session.
- **Tunnels are saved with the session** and restored on reconnect.
- **ssh_config forwards**: LocalForward, RemoteForward, and DynamicForward are recognised automatically.
- **Proxy settings**: HTTP/SOCKS proxies can be combined with jump hosts.

---

### 5. Monitoring, Logs, and Audit

- **Live server statistics**: CPU, memory, disk, network, and logged-in users, with no agent installed.
- **Status bar**: connection state, latency, and disconnect/reconnect notices.
- **Session logging**: write terminal output to plain-text files.
- **Log redaction**: hosts, accounts, IPs, session names, and other private values are replaced when logs are shared or a report is generated.
- **Audit trail**: dangerous commands are flagged; AI-driven executions leave their command and output in the conversation.

---

### 6. Automation and DevOps (opt-in, in Settings → DevOps)

#### Ansible

- Playbooks, inventory, and role management.
- Streaming execution output with live task progress.
- On Windows, Ansible runs through WSL; it can also run in a container or on a remote Linux host.
- Built-in playbook templates and inventory generation.

#### OpenTofu / Terraform

- Full Plan / Apply / Destroy workflow.
- State browsing and resource inspection.
- HCL editor with variables, modules, providers, outputs, and locals.
- Visual resource and data-source pickers.
- State encryption, version management, and toolchain installation.
- Supports both OpenTofu and Terraform.

#### Containers and Kubernetes

- Manage Docker, Podman, and Compose.
- Container list, start/stop/remove, logs, file browser, and exec.
- Read file-based logs inside containers (glog, log4j, nginx, and others), including rotation.
- Kubernetes: pods, workloads, events, YAML, logs, and namespace switching.
- Helm support.
- Container and Kubernetes actions use the existing SSH session; no local kubectl is required.

#### Databases

- PostgreSQL, MySQL, MariaDB, SQL Server, SQLite, and Redis.
- Data grid, schema browsing, and a schema-aware SQL editor.
- The table designer shows the `ALTER` statement before it runs.
- Risk-scaled confirmations for destructive operations.
- Connect directly or through an SSH tunnel.
- Database backup and read-only mode.
- Send query results to the AI for analysis.

#### Recipes

- Parameterised scripts with declared parameters and a risk level.
- Built-in and imported recipes.
- Risk checks before execution.
- A reusable button for routine operations.

---

### 7. Security and Credentials

- **Encrypted vault**: sessions, passwords, SSH keys, and secrets are encrypted at rest.
- **Cryptography**: XChaCha20-Poly1305, Argon2id, and X25519.
- **Master password**: optional; unlock with Windows Hello, Touch ID, Android biometrics, or a FIDO2 security key.
- **Auto-lock**: locks when idle or when the system locks.
- **Encrypted cloud sync**: optional sync through Turso/libSQL across devices.
- **Shared vaults**: member invitations and shared sessions/folders.
- **Backup and restore**: encrypted, optionally password-protected backups.
- **Password managers**: Passbolt integration keeps the password out of CoreOps and fetches it only when connecting.
- **Zero-trust defaults**: features that open a door, such as session sharing and the MCP server, stay off until enabled.
- **Host-key verification**: trust on first use and a loud warning when a key changes.
- **Secret redaction**: passwords, tokens, private keys, and sync tokens are kept out of logs.

---

### 8. Collaboration and MCP

- **Session sharing**: two terminals side by side, peer-to-peer and end-to-end encrypted; the owner decides whether the guest can type.
- **MCP server**: hand the current session to Claude Code, Cursor, or any MCP client.
  - Listens on loopback only by default.
  - Guards against blind writes and secret reads.
  - Off by default and enabled manually.
- **Team members**: shared vaults support invitations and permissions.

---

### 9. Interface, Themes, and Plugins

- **Theme system**: built-in dark and light themes, plus third-party themes from the marketplace.
- **Whole-app theming**: title bar, sidebar, tab bar, panels, buttons, and status bar follow the theme, not only the terminal.
- **Terminal colours follow the theme**.
- **Design system**: consistent type scale, spacing, radii, shadows, and colour tokens.
- **Interface zoom**: `Ctrl+=` / `Ctrl+-` scales the whole window, `Ctrl+0` resets; terminal font size is separate.
- **Collapsible sidebar**, draggable width, and a drawer layout on phones.
- **Lua plugins**: sandboxed scripts, a plugin marketplace, and permission declarations.
- **Nine languages**: Chinese, English, German, Spanish, French, Italian, Greek, Bulgarian, and Russian.
- **Language picker** with search.
- **Mobile layout**: Esc/Ctrl/Alt/arrow keys above the keyboard, pinch to zoom, and safe areas for notches, status bars, and the keyboard.

#### Custom appearance

**Settings → Appearance → Custom appearance** lets you pick a local picture as the app background and adjust its visibility. The picture stays on this device and is not synced with the vault.

The terminal keeps the theme's solid colour by default. Turn on **Terminal background** and it shows the picture like the rest of the interface, applying immediately to open terminals.

![Custom background and appearance](Picture/custom-background.png)

---

### 10. Platforms, Updates, and Migration

- **Platforms**: Windows, macOS (Apple Silicon / Intel), Linux, and Android.
- **Installers**: Windows `.exe` / `.msi`, macOS `.dmg`, Linux `.AppImage` / `.deb` / `.rpm`, Android `.apk`.
- **Updates**: signed desktop updates; Android checks the GitHub release for an APK.
- **Upgrades keep your data**: the data directory remains `com.reach.app`, so sessions, vault, and settings survive.
- **Import**:
  - Bulk-import sessions from `~/.ssh/config`.
  - Bulk-import RDP hosts from a Termix export or JSON.
  - Import sessions, folders, and shared vaults.
- **Backup and restore**: full backup and restore.
- **About page**: version, project links, and a manual update check.

---

## Changelog

### v0.8.3

- Added AI conversation export: a new button in the AI panel header, left of the clear button, exports only the current tab's conversation as Markdown
- The update dialog now renders release notes as Markdown: headings, lists, tables, code blocks and images display properly
- Fixed accidental AI auto-execution: only code blocks explicitly tagged `bash` run; untagged blocks, `console` blocks, output examples and config contents are never injected
- Fixed the interaction gate: Chinese password prompts are recognised; Cancel stops execution and sends Ctrl+C; gates are isolated per tab; multi-line interactive commands require confirmation
- Dangerous-command confirmation now covers `sudo`, account/permission changes, `/etc` edits, deletion and shutdown; in full-auto mode only password entry, password changes and interactive commands still ask
- AI command output now filters download/pull progress lines and caps its length, so hundreds of progress updates are not sent to the model
- Commands marked by the AI as “for reference only / for future use” are no longer auto-executed; the client skips them and asks you to run them manually
- AI conversation export now distinguishes You / Auto-run / Batch run / Pending confirmation / Manual run
- The chat input stays editable while the AI is running: type a draft freely, Enter only inserts a newline, and you must press the red stop button before sending
- Fixed Markdown formatting of client-generated pending / auto-run / batch-run / executed messages: multi-line commands now use real code blocks instead of inline backticks
- Fixed garbled terminal echo when a new command was typed while a long command (such as `docker pull`) was still running: the client now waits for the shell prompt and pauses auto-run on timeout
- Full-auto mode no longer asks for confirmation because of error-handling statements such as `exit 1` inside a script; only standalone `exit` / `logout` still require manual handling
- Progress filtering now also removes Docker “Download complete”, “Pull complete” and “Already exists” lines, and collapses repeated blank lines
- Commands placed under “suggested actions / next steps / recommended plan” headings are no longer auto-executed; the client waits for you to press Run
- Auto-run, batch-run and manual-run messages now use a green background and border, distinct from the yellow pending-confirmation message
- Fixed invisible text selection on blue user messages: the highlight was the same blue as the bubble, so a white highlight is now used
- Full-auto / auto-edit now distinguish “asking/inspecting” from “doing/deploying”: for questions, only the first read-only command runs, then the client stops instead of expanding into deployment or cleanup
- Added write-operation detection: in question mode, `mkdir`, `cp`, `rm`, `systemctl`, `docker run/pull` and similar writes become `[待确认]` instead of running automatically
- Raised the auto-execution round limit to 10 and show a clear notice when it is reached
- The “suggested/recommended” guard now recognises “I’ll run it myself” phrasing to avoid false stops
- Version set to 0.8.3

<details>
<summary>Earlier versions</summary>

### v0.8.2

- Added custom appearance: choose a local picture as the app background, adjust its visibility, and override the primary/secondary text and accent colours
- Added a terminal background switch: the terminal keeps the theme's solid colour when off, and shows the picture when on; open terminals update immediately
- Fixed settings, confirmation dialogs, dropdown menus, and the command palette showing the interface behind them
- Session-group dropdown no longer collapses when right-clicking; the rename/delete menu stays above it
- The Windows installer supports Simplified Chinese / English, defaulting to Chinese on Chinese systems
- Version set to 0.8.2

### v0.8.1

- Fixed session drag-and-drop ordering; the order is remembered locally
- Unified the session list on “session group” terminology
- Renamed “Private (this device)” to “Default session group”
- Added a context menu for session groups: rename and delete
- Added “Move session to” for moving sessions between groups
- Added right-click rename for session folders
- Version set to 0.8.1

### v0.8.0

- Rebased on Reach 0.8.8 and gained its new features and fixes
- Upstream additions: RDP / VNC, command palette, split panes and tab groups, WSL sessions, container / Kubernetes workspaces, database management, password-manager integration, theme marketplace, host-key verification, single-file and folder upload, and more
- Kept the CoreOps AI assistant with Normal / Plan only / Auto edit / Full auto modes
- Kept per-tab AI conversation contexts, cleaned up when a tab closes
- Kept the password / confirmation gate for sudo and other interactive commands
- Kept custom API endpoints, model discovery, context window and pricing, and `/v1` handling
- Kept run-all, abort, and panel-width memory
- Version set to 0.8.0; updates and signatures still point to CoreOps' own GitHub release

</details>

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Desktop shell | Tauri v2 |
| Backend | Rust · Tokio · russh (native SSH, no OpenSSH dependency) |
| Frontend | Svelte 5 (runes) · SvelteKit · TypeScript |
| Styling | Tailwind CSS v4 · CSS custom properties |
| Terminal | xterm.js with WebGL |
| Cryptography | XChaCha20-Poly1305 · Argon2id · X25519 |
| Storage | SQLite (libsql) |

---

## Download and install

Download from GitHub Releases:

```text
https://github.com/Daniel-King-8/CoreOps/releases
```

- Windows: `.exe` or `.msi`
- macOS: `.dmg` (Apple Silicon / Intel)
- Linux: `.AppImage` / `.deb` / `.rpm`
- Android: `.apk`

> Installing a new version replaces the old one. Sessions, the vault, and settings live in the `com.reach.app` data directory and are not removed.

---

## Build from source

Requirements: [Rust 1.99+](https://rustup.rs), [Node.js 22.17+](https://nodejs.org), and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
# Clone the repository
git clone https://github.com/Daniel-King-8/CoreOps.git
cd CoreOps

# Install frontend dependencies
npm install

# Development mode (Vite + Tauri)
npm run tauri dev

# Production build
npm run tauri build

# Clear the cache if the version display or build artifacts look stale
Remove-Item -Recurse -Force src-tauri/target/debug/.fingerprint/coreops*, src-tauri/target/debug/coreops* -ErrorAction SilentlyContinue
npm run tauri dev
```

### Configure the AI assistant

1. Open Settings → **AI**
2. Enter the API base URL (default `https://api.deepseek.com/v1`, or any OpenAI-compatible endpoint)
3. Enter the API key and click **Validate and fetch models**
4. Choose a model and enable AI
5. Click the AI icon in the top-right corner of the terminal to open the panel

---

## Acknowledgements

CoreOps is built on [Reach](https://github.com/alexandrosnt/Reach) 0.8.8. Thanks to [@alexandrosnt](https://github.com/alexandrosnt) for creating Reach, and to all upstream contributors.

**Upstream project: [https://github.com/alexandrosnt/Reach](https://github.com/alexandrosnt/Reach)**

CoreOps is an independently maintained branch and does not speak for the Reach project.

---

## Feedback

Found a bug, have a feature request, or just want to talk? Open an issue or send an email:

📮 **Email: [1007887927@qq.com](mailto:1007887927@qq.com)**

Every piece of feedback is read. Thanks for the support.
