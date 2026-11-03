<p align="right">
  <a href="README_EN.md">English</a>
</p>

<p align="center">
  <img src="src-tauri/icons/128x128.png" alt="CoreOps" width="80" />
</p>

<h1 align="center">CoreOps</h1>

<p align="center">
  基于 <a href="https://github.com/alexandrosnt/Reach"><strong>Reach</strong></a> 的个人二次开发版本 · 专为中文运维场景深度定制<br>
  A deeply customized fork of Reach SSH client, tailored for Chinese-speaking DevOps engineers.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/基于-Reach%200.8.8-0a84ff?style=flat-square" alt="Based on Reach 0.8.8" />
  <img src="https://img.shields.io/badge/version-0.8.1-brightgreen?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-333?style=flat-square" alt="Platforms" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Qwen%20%7C%20OpenAI-blueviolet?style=flat-square" alt="AI Support" />
</p>

---

## CoreOps 是什么

CoreOps 是一个跨平台的 SSH 客户端与远程运维工具，基于 [Reach](https://github.com/alexandrosnt/Reach) 0.8.8 二次开发。

它保留了 Reach 的完整底层能力：原生 Rust SSH、SFTP、RDP/VNC、端口隧道、Ansible、OpenTofu、容器、Kubernetes、数据库、Vault 加密存储等；同时针对中文运维场景做了两件核心增强：

1. **完整中文化**：界面、提示、错误信息、AI 面板全部中文。
2. **增强版 AI 运维助手**：读取终端现场 → AI 分析 → 生成命令 → 一键注入终端执行，并支持四种执行模式、按标签页隔离上下文、sudo/确认输入门控。

没有 Electron，没有订阅，没有账号；Windows、macOS、Linux、Android 使用同一套代码。

---

## 功能特性

### 一、AI 运维助手（CoreOps 核心增强）

AI 面板位于终端右侧，不是简单的聊天窗口，而是和当前终端联动的运维助手。

- **读取终端现场**：自动读取当前终端最近输出，报错不用手动复制粘贴。
- **代码块一键执行**：AI 回复中的 shell 命令可以直接注入当前终端。
- **一键执行全部命令**：一条回复里有多个命令时，可批量按顺序执行。
- **SSH / 本地 PTY 双路由**：根据当前标签页自动选择 `sshSend` 或 `ptyWrite`。
- **按标签页隔离上下文**：每个标签页有独立的 AI 对话历史，切换标签不会串话；关闭标签自动清理。
- **中止响应**：生成或执行过程中可随时停止。
- **可拖拽宽度**：面板宽度可调整并记忆。
- **sudo / 交互命令门控**：执行 `sudo`、密码确认、`[y/N]`、按回车继续等交互命令时，自动暂停并弹出输入框，等待你输入后继续。
- **危险命令识别**：在“自动编辑”模式下，涉及服务重启、删除、包管理、磁盘/防火墙等高风险命令会先要求确认。

#### 四种执行模式

| 模式 | 行为 |
|------|------|
| **普通对话** | AI 可读取终端并分析，命令需要你手动点击执行 |
| **仅规划** | 只分析和给方案，禁止执行任何命令 |
| **自动编辑** | 可自动修改配置文件；高风险命令仍需确认 |
| **全自动** | AI 自动读取、执行、分析并继续下一轮，适合受控环境 |

模式选择保存在本地，重启不丢失。

#### AI 接口配置

- 兼容任意 **OpenAI 格式 API**：DeepSeek、通义千问、硅基流动、本地 Ollama、OpenAI 等。
- **API Key 加密存储**：通过应用内置 Vault 加密，不明文写入配置文件。
- **模型列表动态拉取**：填入 API 地址和 Key 后，一键获取可用模型，支持搜索筛选。
- **模型信息展示**：上下文窗口大小、每百万 token 计价。
- **API 地址兼容**：带不带 `/v1` 都能自动识别；DeepSeek 的 `reasoning_content` 也能正确读取。
- **重启自动恢复**：Vault 解锁后自动加载 API Key，不需要每次重新验证。

---

### 二、连接与终端

- **SSH 终端**：多标签、分屏、标签组、WebGL 渲染，基于 xterm.js。
- **完整 `~/.ssh/config` 支持**：ProxyJump、ProxyCommand、ControlMaster、Kerberos（GSSAPI）、X11 转发、PKCS#11、FIDO2 密钥等 104 个关键字。
- **跳板机 / 多跳 SSH**：支持从 ssh_config 导入，也支持在会话编辑器里配置。
- **SSH 认证链**：按 OpenSSH 顺序尝试密钥 → ssh-agent → 密码。
- **主机密钥校验**：首次连接显示指纹确认；主机密钥变化时明确警告，防止中间人攻击。
- **断线重连**：SSH 标签页断线有状态提示，可一键重连。
- **RDP / VNC 远程桌面**：在标签页中直接打开；RDP 支持剪贴板、文件传输、本地文件夹映射为磁盘。
- **WSL 会话**：Windows 上直接打开 WSL 发行版终端，支持选择用户。
- **本地 Shell**：在应用内打开本机终端，支持指定启动程序（例如容器内 shell）。
- **串口控制台**：路由器、交换机、嵌入式设备的 COM/TTY 接入。
- **终端剪贴板**：右键复制/粘贴，多行粘贴前确认，链接用系统浏览器打开。
- **终端配色跟随主题**，支持浅色/深色切换。
- **命令面板**：`Ctrl+Shift+P` 搜索会话、标签、页面、片段和动作。
- **快速连接**：输入 `user@host:port` 直接连接。
- **启动页**：无标签时显示最近会话、快速连接和本地终端入口。

---

### 三、文件传输与 SFTP

- **SFTP 文件浏览器**：多标签、路径导航、权限显示。
- **拖拽上传/下载**：文件可直接拖入或拖出窗口。
- **文件夹上传**：整个目录连同子目录一起上传，显示为一个传输任务和一条进度条。
- **在线编辑**：远端文件可直接在 CodeMirror 编辑器中修改并保存。
- **服务器端压缩/解压**：无需先下载到本地。
- **传输队列**：查看进度、取消、重试。
- **符号链接识别**：显示链接图标和真实目标，不显示无意义大小。
- **错误提示**：下载/删除/重命名/新建文件夹失败时显示服务器返回的真实错误，不会静默失败。
- **下载完整性**：连接中断或服务器超时会报错，不会留下“看起来完整”的残缺文件。

---

### 四、网络与隧道

- **本地端口转发**：把远端端口映射到本机。
- **远程端口转发**：通过 ssh_config 的 RemoteForward 使用。
- **动态 SOCKS 代理**：在 Tunnels 面板一键创建，走当前 SSH 会话。
- **隧道随会话保存**：重连后自动恢复。
- **ssh_config 转发**：配置文件里的 LocalForward / RemoteForward / DynamicForward 自动识别。
- **代理设置**：支持 HTTP/SOCKS 代理与跳板机组合。

---

### 五、监控、日志与审计

- **实时系统监控**：远端 CPU、内存、磁盘、网络、登录用户，无需安装 Agent。
- **状态栏**：连接状态、延迟、断线/重连提示。
- **会话日志**：可把终端输出记录为纯文本文件。
- **日志脱敏**：分享日志/生成报告时自动替换主机、账号、IP、会话名等敏感信息。
- **操作审计**：危险命令有明确提示；AI 自动执行会留下执行记录和输出。

---

### 六、自动化与 DevOps（默认关闭，在设置中开启）

#### Ansible

- Playbook、Inventory、Role 管理。
- 流式执行输出，实时看任务进度。
- Windows 上通过 WSL 运行 Ansible；也支持容器或远程 Linux 主机。
- 内置常见 playbook 模板和 inventory 生成。

#### OpenTofu / Terraform

- Plan / Apply / Destroy 完整流程。
- 状态文件浏览、资源查看。
- HCL 编辑器，支持变量、模块、Provider、Output、Locals。
- 资源/数据源可视化选择。
- 状态加密、版本管理、工具链自动安装。
- 支持 OpenTofu 与 Terraform。

#### 容器与 Kubernetes

- Docker、Podman、Compose 管理。
- 容器列表、启动/停止/删除、日志、文件浏览、执行命令。
- 支持读取容器内文件日志（glog、log4j、nginx 等），支持日志轮转。
- Kubernetes：Pod、工作负载、事件、YAML、日志、命名空间切换。
- 支持 Helm。
- 容器/K8s 操作走已有的 SSH 会话，无需在本地安装 kubectl。

#### 数据库

- 支持 PostgreSQL、MySQL、MariaDB、SQL Server、SQLite、Redis。
- 数据网格、表结构浏览、Schema 感知 SQL 编辑器。
- 表设计器会先显示将要执行的 `ALTER` 语句。
- 危险操作按风险等级二次确认。
- 支持直连或通过 SSH 会话转发连接。
- 支持数据库备份、只读模式。
- 查询结果可交给 AI 分析。

#### 配方（Recipes）

- 参数化脚本，执行前声明参数和风险等级。
- 内置/导入配方，执行前检查风险。
- 适合把常用运维操作沉淀成可复用按钮。

---

### 七、安全与凭据

- **加密 Vault**：会话、密码、SSH Key、密钥全部加密存储。
- **加密算法**：XChaCha20-Poly1305、Argon2id、X25519。
- **主密码**：可设置主密码；支持 Windows Hello、Touch ID、Android 生物识别、FIDO2 安全密钥解锁。
- **自动锁定**：空闲或系统锁屏时自动锁定 Vault。
- **云同步**：可选加密同步（Turso/libSQL），多设备共享会话和凭据。
- **共享 Vault**：支持成员邀请、共享会话/文件夹。
- **备份/恢复**：导出加密备份，支持密码保护。
- **密码管理器**：支持 Passbolt，把会话密码指向 Passbolt 条目，不在 CoreOps 里保存副本。
- **零信任默认**：会话共享、MCP Server 等“开门”功能默认关闭，需要手动开启。
- **主机密钥校验**：首次信任、变化告警，不静默接受。
- **日志脱敏**：密码、Token、私钥、同步令牌不会写入日志。

---

### 八、协作与 MCP

- **会话共享**：两个终端点对点连接，端到端加密；共享方可以决定对方是否可输入。
- **MCP Server**：把当前会话交给 Claude Code、Cursor 等 MCP 客户端使用。
  - 默认只监听本机回环地址。
  - 有写入保护、密钥读取保护。
  - 默认关闭，需要手动开启。
- **团队成员**：共享 Vault 支持邀请成员和权限管理。

---

### 九、界面、主题与插件

- **主题系统**：内置深色/浅色主题，支持从主题市场安装第三方主题。
- **整站主题**：主题不只改终端，标题栏、侧边栏、标签栏、面板、按钮、状态栏都会跟随。
- **终端配色跟随主题**。
- **设计系统**：统一字号、间距、圆角、阴影和颜色 token。
- **界面缩放**：`Ctrl+=` / `Ctrl+-` 缩放整个窗口，`Ctrl+0` 恢复；终端字号可单独调整。
- **可折叠侧边栏**、可拖拽宽度、移动端抽屉式布局。
- **Lua 插件系统**：沙盒化脚本扩展，支持插件市场和权限声明。
- **九种语言**：中文、英文、德语、西班牙语、法语、意大利语、希腊语、保加利亚语、俄语。
- **语言选择器**：支持搜索语言名称。
- **移动端适配**：Esc/Ctrl/Alt/方向键工具栏、双指缩放、刘海/状态栏/键盘安全区适配。

---

### 十、平台、更新与迁移

- **平台**：Windows、macOS（Apple Silicon / Intel）、Linux、Android。
- **安装包**：Windows `.exe` / `.msi`，macOS `.dmg`，Linux `.AppImage` / `.deb` / `.rpm`，Android `.apk`。
- **自动更新**：桌面端内置签名更新；Android 检查 GitHub Release 的 APK。
- **版本升级不丢数据**：数据目录保持 `com.reach.app`，会话、Vault、设置原样保留。
- **导入**：
  - 从 `~/.ssh/config` 批量导入会话。
  - 从 Termix 导出或 JSON 批量导入 RDP 主机。
  - 支持会话/文件夹、共享 Vault 导入。
- **备份/恢复**：支持完整备份与恢复。
- **关于页**：查看版本、项目地址、手动检查更新。

---

## 相比原版 Reach 的改动

> 说明：以下为 CoreOps 的历史改造记录。部分能力（如会话拖拽排序、主题系统）后来已被上游 Reach 吸收；CoreOps 0.8.0 继续保留并重点维护的是 **增强版 AI 运维助手** 与 **中文化体验**。

### ① 全面中文界面

补全并深度校对中文语言包，覆盖菜单、按钮、提示、错误信息、确认对话框和新增的 AI 界面文案。

### ② 中文 AI 运维助手（核心）

在终端右侧增加 AI 面板，打通“读取终端现场 → AI 分析 → 一键注入命令”的完整闭环，并加入四种执行模式、按标签页隔离上下文、sudo 输入门控、一键执行全部命令等能力。

### ③ AI 配置面板

在设置页新增独立的 AI 配置 Tab：自定义 API 地址、加密存储 Key、动态拉取模型、展示上下文窗口和计价信息。

### ④ 会话列表拖拽排序

原版在 Windows WebView2 下 HTML5 拖拽存在兼容问题，CoreOps 曾重写为 Pointer Events 实现；该能力后来已被上游吸收。

---

## 完整继承自 Reach 0.8.8 的能力

除 AI 助手外，以下能力均来自上游 Reach 0.8.8：

- SSH 终端、分屏、标签组、WebGL 渲染
- RDP / VNC 远程桌面
- SFTP 文件浏览器、文件夹上传、在线编辑
- 端口转发、SOCKS 代理、跳板机
- 系统监控、会话日志
- 命令面板、启动页、快速连接
- WSL / 本地 Shell / 串口控制台
- Ansible、OpenTofu / Terraform
- 容器、Kubernetes、数据库工作区
- 加密 Vault、云同步、共享 Vault
- 密码管理器（Passbolt）
- 会话共享、MCP Server
- 主题系统、主题市场、Lua 插件
- 九种语言、移动端适配
- 自动更新、备份/恢复、主机密钥校验

---

## 技术栈

| 层级 | 技术 |
|------|------|
| 桌面框架 | Tauri v2 |
| 后端 | Rust · Tokio · russh（原生 SSH，无 OpenSSH 依赖）|
| 前端 | Svelte 5（Runes 模式）· SvelteKit · TypeScript |
| 样式 | Tailwind CSS v4 · CSS 自定义属性 |
| 终端渲染 | xterm.js + WebGL |
| 加密 | XChaCha20-Poly1305 · Argon2id · X25519 |
| 数据存储 | SQLite（libsql）|

---

## 下载与安装

从 GitHub Releases 下载：

```text
https://github.com/Daniel-King-8/CoreOps/releases
```

- Windows：`.exe` 或 `.msi`
- macOS：`.dmg`（Apple Silicon / Intel）
- Linux：`.AppImage` / `.deb` / `.rpm`
- Android：`.apk`

> 安装新版会覆盖旧版本，会话、Vault 和设置保存在 `com.reach.app` 数据目录，不会丢失。

---

## 从源码构建

环境需求：[Rust 1.99+](https://rustup.rs)、[Node.js 22.17+](https://nodejs.org)、以及 [Tauri v2 前置依赖](https://v2.tauri.app/start/prerequisites/)

```bash
# 克隆本仓库
git clone https://github.com/Daniel-King-8/CoreOps.git
cd CoreOps

# 安装前端依赖
npm install

# 开发模式（Vite + Tauri 同时启动）
npm run tauri dev

# 生产构建
npm run tauri build

# 清理缓存（版本号显示异常或编译 artifact 残留时）
Remove-Item -Recurse -Force src-tauri/target/debug/.fingerprint/coreops*, src-tauri/target/debug/coreops* -ErrorAction SilentlyContinue
npm run tauri dev
```

### 配置 AI 助手

1. 打开应用 → 设置 → **AI 配置**
2. 填入 API 地址（默认 `https://api.deepseek.com/v1`，可替换为任意 OpenAI 兼容地址）
3. 填入 API Key，点击「验证并拉取模型列表」
4. 选择模型，开启 AI 开关
5. 终端界面右上角点击 AI 图标，展开侧边栏

---

## 更新日志

### v0.8.1

- 修复会话拖拽排序：可上下拖动会话调整顺序，顺序在本机记忆
- 会话列表统一使用“会话组”用语：下拉标题、搜索框、新建按钮
- “私人（本设备）”改为“默认会话组”
- 会话组支持右键菜单：重命名、删除
- 会话右键新增“转移会话位置”，可移动到其他会话组
- 会话文件夹支持右键重命名
- 版本号更新至 0.8.1

### v0.8.0

同步上游 Reach v0.8.8，并保留 CoreOps 的全部核心自定义。

- 全新底座：从 Reach 0.8.8 重新移植，完整获得上游的新功能与修复
- 上游新增：RDP / VNC 远程桌面、命令面板、分屏与标签组、WSL 会话、容器 / Kubernetes 工作区、数据库管理、密码管理器接入、主题市场、主机密钥校验、单文件与文件夹上传等
- 保留 CoreOps 增强 AI 助手：普通 / 仅规划 / 自动编辑 / 全自动四种执行模式
- 保留按标签页隔离的 AI 对话上下文，关闭标签页自动清理
- 保留 AI 执行 sudo 等交互命令时的密码 / 确认输入门控
- 保留自定义 API 地址（DeepSeek、通义千问、硅基流动、Ollama 等任意 OpenAI 兼容接口）
- 保留模型列表拉取、上下文窗口与价格展示、API 地址带不带 `/v1` 自动识别
- 保留多命令一键执行、执行全部代码块、中止响应、面板宽度记忆
- 版本号同步至 0.8.0，更新源与签名仍指向 CoreOps 自己的 GitHub Release

### 历史版本

更早版本的更新记录见 [CHANGELOG.md](CHANGELOG.md)。

---

## 致谢

感谢 **[@alexandrosnt](https://github.com/alexandrosnt)** 创建了 Reach 这个优秀的开源项目。CoreOps 的所有底层 SSH 能力都来自 Reach，本项目只是站在巨人肩膀上做了一点点个人定制。

**原项目地址：[https://github.com/alexandrosnt/Reach](https://github.com/alexandrosnt/Reach)**

---

## 写在最后

说实话，我并不是一名很厉害的程序员。因此这个项目难免存在不少不足之处，也会有一些 Bug，还望各位用户多多包涵。

做这个项目的初衷很简单——**让自己的工作更顺手，也希望对有相似需求的朋友有所帮助**。能对大家有一点点用处，就已经很值得了。

如果你在使用过程中遇到了 Bug、有功能上的建议、或者只是想聊聊，欢迎通过以下方式联系我：

📮 **邮箱：[1007887927@qq.com](mailto:1007887927@qq.com)**

每一条反馈我都会认真阅读，感谢你的支持与理解！

> CoreOps 是完全为个人运维工作流定制的私有分支，不代表 Reach 官方立场。  
> 如果你在寻找 SSH 客户端，也欢迎直接使用原版 Reach。
