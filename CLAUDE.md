# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CoreOps is a Chinese-first fork of the [Reach](https://github.com/alexandrosnt/Reach) SSH client, rebased on **Reach v0.8.8**. It is built with **Tauri v2** (Rust backend) and **Svelte 5** (SvelteKit frontend), and adds:

- An enhanced AI operations assistant (Normal / Plan Only / Auto Edit / Full Auto), per-tab chat contexts, interactive sudo/confirmation gates, custom OpenAI-compatible API endpoints, and model discovery.
- CoreOps branding, Chinese localization, and a manual "About / Check for updates" tab.
- The CoreOps GitHub release channel (`Daniel-King-8/CoreOps`).

Everything else (SSH, SFTP, RDP/VNC, tunnels, WSL, serial, Ansible, OpenTofu, containers, Kubernetes, databases, vault, themes, plugins) comes from upstream Reach 0.8.8.

The bundle identifier intentionally stays `com.reach.desktop`, and the data directory stays `dirs::data_dir()/com.reach.app`, so upgrading from Reach/CoreOps keeps existing sessions and vault data.

## Development Commands

```bash
npm install                  # Install frontend dependencies
npm run tauri dev            # Run app in development mode (Vite + Tauri)
npm run tauri build          # Production build (outputs platform installers)
npm run dev                  # Vite dev server only (no Tauri shell)
npm run build                # Vite build only (outputs to build/)
npm run check                # SvelteKit sync + svelte-check type checking
npm run i18n:check           # Validate every locale has all keys from en.json
```

Rust backend builds are handled by Tauri CLI. To work on Rust independently: `cd src-tauri && cargo check` or `cargo build`.

Prerequisites: Rust (upstream CI uses Rust 1.99+), Node.js 22.17+, and [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/).

## Architecture

### Frontend (`src/`)

- **Single-page SPA** — SSR disabled, `@sveltejs/adapter-static` with `fallback: 'index.html'`.
- **Svelte 5 runes** — `$state`, `$derived`, `$effect`; no Svelte stores.
- **SvelteKit 3 / Vite 8** — the `#lib/*` import alias is defined in `package.json` (`"imports": { "#lib/*": "./src/lib/*" }`); new code should use it (upstream style). `$lib` also still resolves.
- **Tailwind CSS v4** — design tokens in `src/app.css` under `@theme`.
- **Global `__APP_VERSION__`** — injected via `vite.config.ts`, re-exported by `src/lib/version.ts`.

Key directories under `src/lib/`:

| Directory | Purpose |
|-----------|---------|
| `components/` | UI by feature: `ai`, `terminal`, `sessions`, `explorer`, `tunnel`, `vault`, `settings`, `devops`, `db`, `k8s`, `rdp`, `recipes`, ... |
| `state/` | Reactive modules (`.svelte.ts`) exporting getters and mutation helpers |
| `ipc/` | Typed wrappers around Tauri `invoke()`, one file per Rust command module |
| `i18n/` | `t(key, params?)`; locale JSON files in `i18n/locales/` |
| `terminal/` | Split-pane helpers |
| `data/` | Static data (distro icons, community links, MCP clients) |
| `utils/` | Shared utilities |

Layout flow: `+layout.svelte` initializes settings/AI/vault/theme/updater and wraps everything in `AppShell`; `+page.svelte` owns terminal tabs, monitoring polling, and editor overlays.

### Backend (`src-tauri/`)

- Rust + Tokio; SSH via **russh** (no OpenSSH dependency), managed by `SshManager`.
- Centralized `AppState` in `src-tauri/src/state.rs`, passed as Tauri managed state.
- IPC commands in `src-tauri/src/ipc/`, registered in `lib.rs` via `tauri::generate_handler![]`; desktop and mobile blocks are separate.
- Desktop-only features gated with `#[cfg(desktop)]` (PTY, serial, autostart, updater).
- Vault: XChaCha20-Poly1305 + Argon2id + X25519, stored in SQLite via libsql.
- HTTP for AI/marketplace goes through `crate::http::client_builder()` so proxy and TLS settings stay consistent.

### CoreOps AI customization

The AI feature is the main fork-specific code path:

- `src/lib/state/ai-chat.svelte.ts` — per-tab contexts keyed by tab id, execution modes, command extraction, terminal-output capture, sudo/confirmation input gate, abort.
- `src/lib/state/ai.svelte.ts` — AI settings (`enabled`, `apiKey`, `apiUrl`, `selectedModel`), `resolveApiBase()`, model discovery.
- `src/lib/components/ai/AIPanel.svelte` — resizable panel, mode switcher, code-block run buttons, run-all, gate dialog, stop button.
- `src/lib/components/settings/AITab.svelte` — API base URL, encrypted API key, model browser.
- `src-tauri/src/ipc/ai_commands.rs` — `ai_chat` and `ai_fetch_models`; supports arbitrary OpenAI-compatible base URLs and DeepSeek `reasoning_content`.
- `src/lib/state/tabs.svelte.ts` — calls `activateTabContext()` / `removeTabContext()` on tab create, switch, and close.

When changing AI code, keep the `$state` context map out of `$derived` (the current refactor avoids state mutation inside a derived) and keep `executeCommand`'s event names in sync with `ssh-data-{id}` / `pty-data-{id}`.

## Conventions

- **Styling:** Tailwind utilities plus component-scoped `<style>`; use CSS custom properties from `app.css`.
- **i18n:** every user-facing string uses `t('key')`. Add keys to all locale files (or at least `en.json` + `zh.json`) and run `npm run i18n:check`; the checker enforces identical key sets and `{{placeholder}}` parity.
- **IPC naming:** Rust commands `snake_case`; TypeScript wrappers `camelCase`; register both desktop and mobile handlers when applicable.
- **Platform gating:** `#[cfg(desktop)]` for PTY/serial/autostart/updater.
- **Version:** `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json` must stay in sync; `scripts/sync-version.mjs <tag>` updates all three for releases.
- **Do not push** unless the repository owner explicitly asks.
