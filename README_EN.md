<p align="right">
  <a href="README.md">中文</a>
</p>

<p align="center">
  <img src="src-tauri/icons/128x128.png" alt="CoreOps" width="80" />
</p>

<h1 align="center">CoreOps</h1>

<p align="center">
  A personal fork of <a href="https://github.com/alexandrosnt/Reach"><strong>Reach</strong></a> · Deeply customized for Chinese-speaking DevOps engineers
</p>

<p align="center">
  <img src="https://img.shields.io/badge/based_on-Reach-0a84ff?style=flat-square" alt="Based on Reach" />
  <img src="https://img.shields.io/badge/version-0.4.8-brightgreen?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-333?style=flat-square" alt="Platforms" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Qwen%20%7C%20OpenAI-blueviolet?style=flat-square" alt="AI Support" />
</p>

---

## Why Fork Reach?

I've been a loyal user of **Reach** ever since I discovered it. It became the most-opened tool in my daily ops work — no Electron bloat, no monthly subscriptions, a clean interface, and a native Rust + russh SSH implementation that delivers both performance and stability.

After using it for a while, two pain points pushed me to roll up my sleeves:

**1. Language barrier:** Reach is English-only. For someone like me who thinks in Chinese, having all confirmations and error messages in English during high-pressure incidents (say, a 3 AM server alert) adds unnecessary cognitive load. I wanted the interface to speak my native language.

**2. Missing AI workflow:** My workflow increasingly relies on AI assistance — spot an error, paste it to AI, get a fix, verify and run. The original Reach AI module only offers basic command suggestions; it lacks the complete loop of "read terminal context → AI analysis → inject command with one click." I was constantly copy-pasting between the terminal and an AI chat window.

So I built **CoreOps** — keeping every bit of Reach's SSH engine intact, while layering my own workflow customizations on top.

---

## What's Changed vs. Reach

### ① Full Chinese Localization

Completed and thoroughly proofread the Chinese language pack (`zh.json`), covering every piece of UI text:

- All menus, buttons, and tooltips
- Error messages and confirmation dialogs
- All newly added AI panel text (human-translated, not machine-generated)

The entire app can now be switched to Chinese in Settings, with the same reading quality as the original English.

---

### ② Chinese AI Operations Assistant Sidebar (Key Addition)

This is the core addition in CoreOps — an AI chat panel on the right side of the terminal, purpose-built for ops workflows.

**The problem it solves:**

> Before: Spot error → manually copy → open browser / paste to AI tool → read solution → manually copy command → switch back to terminal → paste and run
>
> After: Spot error → AI panel auto-reads the terminal → ask in one line → inject AI's command into the terminal with one click

**Feature overview:**

| Feature | Description |
|---------|-------------|
| Terminal buffer awareness | AI can automatically read the current terminal content — no manual copy needed |
| Streaming output | AI replies appear word-by-word in real time |
| One-click code execution | Shell commands in AI replies can be injected into the terminal with a single click |
| SSH / local PTY routing | Automatically routes to `sshSend` or `ptyWrite` based on the active tab type |
| Draggable panel width | Panel width is resizable and persists across restarts |
| Interrupt generation | Stop AI generation at any time |

**Four execution modes (ordered by trust level):**

```
Chat only     →  Conversation only, AI never touches the terminal
Plan only     →  AI provides commands and a plan; you decide what to run
Assisted      →  AI extracts commands, each requiring your manual confirmation before injection
Full auto     →  AI injects and runs commands automatically (high risk — use with caution)
```

Mode preference is saved locally and survives restarts.

---

### ③ AI Settings Panel

A dedicated **AI Configuration** tab has been added to Settings:

- **Any OpenAI-compatible API**: DeepSeek, Qwen, local Ollama, SiliconFlow, and more — just change the base URL
- **Encrypted API Key storage**: Keys are encrypted via the built-in Vault, never written in plain text
- **Dynamic model list fetching**: Enter your API endpoint and fetch available models with one click; supports search filtering
- **Model info display**: Shows context window size and pricing (cost per million tokens)

---

### ④ Session List Drag-and-Drop Rewrite

The original Reach had compatibility issues with HTML5 native drag-and-drop on Windows (Tauri WebView2). I rewrote it entirely using the Pointer Events API:

- **Reorder within a folder**: Drag up/down freely; drop position snaps precisely (upper half = insert before, lower half = insert after)
- **Move across folders**: Drag onto a folder header to move the session into it — works even with collapsed folders
- **Move to root**: Drag to an empty area to remove a session from its folder
- **Smooth animations**: Powered by Svelte `animate:flip`; surrounding cards glide out of the way

---

## Everything Inherited from Reach (Unchanged)

The following features are carried over **without a single line of modification**:

- **SSH Terminal**: Multi-tab, split pane, WebGL rendering, full xterm.js support
- **SFTP File Browser**: Drag-and-drop upload/download, in-app editing, transfer queue
- **Port Tunneling**: Local / remote / dynamic SOCKS forwarding, saved per session
- **Jump Hosts (ProxyJump)**: Multi-hop SSH, with `~/.ssh/config` import support
- **System Monitoring**: Live CPU / memory / disk metrics from remote hosts, no agent required
- **Ansible Workspace**: Playbook, inventory, and role management with streaming execution output
- **OpenTofu / Terraform**: Plan / Apply / Destroy, state browsing, full IaC workspace
- **Serial Console**: COM/TTY access for routers, switches, and embedded devices
- **Encrypted Vault**: Session credentials, SSH keys, and secrets encrypted at rest with cloud sync support
- **Lua Plugin System**: Sandboxed Lua scripting for extensibility

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop framework | Tauri v2 |
| Backend | Rust · Tokio · russh (native SSH, no OpenSSH dependency) |
| Frontend | Svelte 5 (Runes mode) · SvelteKit · TypeScript |
| Styling | Tailwind CSS v4 · CSS custom properties |
| Terminal rendering | xterm.js + WebGL |
| Encryption | XChaCha20-Poly1305 · Argon2id · X25519 |
| Data storage | SQLite (libsql) |

---

## Building from Source

Requirements: [Rust](https://rustup.rs), [Node.js 22+](https://nodejs.org), and [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

```bash
# Clone the repository
git clone https://github.com/Daniel-King-8/CoreOps.git
cd CoreOps

# Install frontend dependencies
npm install

# Development mode (Vite + Tauri together)
npm run tauri dev

# Production build
npm run tauri build
```

### Configuring the AI Assistant

1. Open the app → Settings → **AI Configuration**
2. Enter your API base URL (defaults to `https://api.deepseek.com/v1`; any OpenAI-compatible endpoint works)
3. Enter your API Key and click "Verify & Fetch Models"
4. Select a model and enable the AI toggle
5. Click the AI icon in the top-right corner of the terminal to open the sidebar

---

## Acknowledgements

A big thank you to **[@alexandrosnt](https://github.com/alexandrosnt)** for building the excellent open-source project Reach. Every bit of CoreOps's SSH capability comes from Reach — this project is simply standing on the shoulders of a giant and adding a few personal touches.

**Original project: [https://github.com/alexandrosnt/Reach](https://github.com/alexandrosnt/Reach)**

---

## A Note from the Author

Honestly, I'm not a particularly skilled programmer. This project inevitably has its share of shortcomings and bugs, and I sincerely ask for your patience and understanding.

The motivation behind CoreOps is simple: **make my own daily work a little smoother, and hopefully help others with similar needs along the way.** If it turns out to be useful to even a handful of people, that's more than enough for me.

If you run into a bug, have a feature suggestion, or just want to chat, feel free to reach out:

📮 **Email: [1007887927@qq.com](mailto:1007887927@qq.com)**

I read every message carefully. Thank you for your support — it genuinely means a lot!

> CoreOps is a personal fork customized for my own ops workflow and does not represent the official Reach project in any way.  
> If you're looking for a solid SSH client, the original Reach is absolutely worth checking out too.
