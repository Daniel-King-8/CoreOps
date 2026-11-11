<p align="right">
  <a href="README_EN.md">English</a>
</p>

<p align="center">
  <img src="src-tauri/icons/128x128.png" alt="CoreOps" width="80" />
</p>

<h1 align="center">CoreOps</h1>

<p align="center">
  面向中文运维场景的跨平台 SSH 客户端与远程运维工作台<br>
  A cross-platform SSH client and remote operations workbench for Chinese-speaking DevOps teams.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.8.3-brightgreen?style=flat-square" alt="Version 0.8.3" />
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-333?style=flat-square" alt="Platforms" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Qwen%20%7C%20OpenAI-blueviolet?style=flat-square" alt="AI Support" />
  <img src="https://img.shields.io/badge/stack-Rust%20%2B%20Tauri%20v2-0a84ff?style=flat-square" alt="Rust + Tauri v2" />
</p>

---

## CoreOps 是什么

CoreOps 是一个面向中文运维场景的跨平台 SSH 客户端与远程运维工作台。它基于 Reach 0.8.8 的原生 Rust 内核构建，把日常运维需要的连接、文件传输、远程桌面、隧道、自动化、容器、Kubernetes、数据库和 AI 助手整合在同一个应用里。

没有 Electron，没有订阅，没有账号；Windows、macOS、Linux、Android 使用同一套代码。会话、密钥和配置默认保存在本机，需要多设备时再开启加密同步。

---

## 为什么选择 CoreOps

- **原生性能**：Rust + russh 实现 SSH，不依赖 OpenSSH，也没有 Electron 的额外开销。
- **一个应用覆盖日常运维**：SSH、SFTP、RDP/VNC、端口隧道、Ansible、OpenTofu、Docker/K8s、数据库工作区。
- **AI 与终端真正联动**：读取终端现场、生成命令、注入当前会话；四种执行模式，带写操作确认和交互门控。
- **更好的中文适配**：界面、提示、错误信息和 AI 面板完整中文化，同时提供九种语言。
- **安全默认**：加密 Vault、主机密钥校验、日志脱敏；会话共享、MCP 等能力默认关闭。
- **本地优先**：不强制账号或云服务；需要多设备时再开启加密同步。

---

## 功能特性

### 一、AI 运维助手

AI 面板位于终端右侧，不是独立的聊天窗口，而是和当前终端联动的运维助手。

- **读取终端现场**：自动读取当前终端最近输出，报错不用手动复制粘贴。
- **代码块一键执行**：AI 回复中的 shell 命令可以直接注入当前终端。
- **一键执行全部命令**：一条回复里有多个命令时，可批量按顺序执行。
- **SSH / 本地 PTY 双路由**：根据当前标签页自动选择 `sshSend` 或 `ptyWrite`。
- **按标签页隔离上下文**：每个标签页有独立的 AI 对话历史，切换标签不会串话；关闭标签自动清理。
- **执行中可继续输入**：AI 执行期间输入框保持可编辑，回车只换行；发送前点红色停止按钮终止当前执行。
- **中止响应**：生成或执行过程中可随时停止。
- **可拖拽宽度**：面板宽度可调整并记忆。
- **对话导出**：把当前标签页的对话导出为 Markdown，并按“你 / 自动执行 / 批量执行 / 待确认 / 手动执行”标注来源。

#### 四种执行模式

| 模式 | 行为 |
|------|------|
| **普通对话** | AI 可读取终端并分析，命令需要你手动点击执行 |
| **仅规划** | 只分析和给方案，禁止执行任何命令 |
| **自动编辑** | 可自动修改配置文件；高风险命令仍需确认 |
| **全自动** | 只读检查自动执行；写操作按策略确认；密码/交互命令仍由你处理 |

模式选择保存在本地，重启不丢失。

#### 安全边界

- **只执行 shell 块**：只有明确标记为 `bash` / `sh` / `shell` / `zsh` 的代码块才会注入终端；无标记、`text`、`console` 只展示。
- **询问与执行分离**：问“有哪些镜像 / 查看状态”时，只自动执行第一条只读命令，分析完即停止，不会自行扩展成部署或清理。
- **写操作确认**：询问类请求中遇到 `mkdir`、`cp`、`rm`、`systemctl`、`docker run/pull` 等写操作时，改为 `[待确认]`。
- **建议/参考不执行**：AI 标注“建议动作 / 仅供参考 / 以后重建用”的命令不会自动执行；“我先跑 / 我来执行”不会被误判成建议。
- **交互门控**：执行 `sudo`、密码确认、`[y/N]`、按回车继续等交互命令时，自动暂停并弹出输入框。
- **长命令保护**：等待 shell 提示符重新出现，避免上一条命令未结束时输入下一条；超时则暂停并提示。
- **危险命令确认**：自动编辑模式下，服务重启、删除、包管理、磁盘/防火墙等高风险命令先要求确认。
- **轮次上限**：自动执行最多 10 轮，到达上限会明确提示，避免无限循环。

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

#### 自定义外观

**设置 → 外观 → 自定义外观** 可以选择本机图片作为应用背景，调整背景可见度，背景图只保存在本机，不会随 Vault 同步。

终端默认保持主题纯色背景；打开「终端显示自定义背景」后，终端会像界面其他部分一样透出背景图，已打开的终端实时生效。

![自定义背景与外观](Picture/custom-background.png)

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

## 更新日志

### v0.8.3

- 新增 AI 对话导出：AI 助手面板右上角、垃圾桶按钮左侧新增导出按钮，只导出当前标签页的 AI 对话，支持 Markdown
- 更新弹窗支持 Markdown 渲染：修复此前发行说明不渲染 Markdown 的问题，标题、列表、表格、代码块和图片现在正常显示
- 修复 AI 自动执行误执行：只执行明确标记为 `bash` 的代码块，无标记、`console`、输出示例和配置文件内容不再注入终端
- 修复交互门禁：识别中文密码提示；取消即停止执行并发送 Ctrl+C；门禁按标签页隔离；多行交互命令先确认
- 危险命令确认覆盖 `sudo`、用户/权限变更、`/etc` 修改、删除、关机等；全自动模式除密码输入、修改密码和交互式命令外不再逐条确认
- AI 执行输出会自动过滤下载/拉取进度条，并限制长度，避免把几百行进度发给模型
- AI 标注为“仅供备查 / 仅供参考 / 以后重建用”的命令不会再被自动执行，客户端会跳过并提示手动运行
- AI 对话导出按来源区分“你 / 自动执行 / 批量执行 / 待确认 / 手动执行”
- AI 执行期间聊天输入框保持可编辑：可以先输入草稿，回车只换行；发送前需先点红色停止按钮终止当前执行
- 修复客户端生成的待确认 / 自动执行 / 批量执行 / 已执行消息的 Markdown 格式：多行命令改用独立代码块，不再挤在一行
- 修复长命令（如 `docker pull`）未结束时继续输入下一条命令导致终端回显错乱：现在会等待 shell 提示符，超时则暂停自动执行并提示
- 全自动模式不再因脚本内的 `exit 1` 等错误处理语句误触发确认，只有独立的 `exit` / `logout` 才需要人工处理
- 进度过滤补充 Docker 的 Download complete / Pull complete / Already exists 等行，并压缩连续空行
- AI 把命令写在“建议动作 / 建议进一步排查 / 推荐方案”等小节里时不再自动执行，改为等待用户点击“运行”
- 自动执行、批量执行和手动执行的消息改用绿色底纹与边框，与黄色的“待确认”区分
- 修复蓝色用户消息上的选中高亮与背景同色、看不出是否选中的问题，改为白色高亮
- 全自动/自动编辑区分“询问查看”和“执行部署”：询问类请求只自动执行第一条只读命令，分析完即停止，不再自行扩展成部署或清理
- 新增写操作检测：询问类请求中遇到 mkdir、cp、rm、systemctl、docker run/pull 等写操作时改为 `[待确认]`，不再直接执行
- 自动执行轮次上限提高到 10 轮，到达上限时明确提示后续命令需手动运行
- “建议/推荐”守卫识别“我先跑/我来执行”等自我执行意图，减少误停
- 版本号更新至 0.8.3

<details>
<summary>更早版本</summary>

### v0.8.2

- 新增「自定义外观」：可选择本机图片作为应用背景，调整背景可见度，并覆盖主文字、次要文字与强调色
- 新增「终端显示自定义背景」开关：关闭时终端保持主题纯色背景，开启后终端与界面其他部分一样透出背景图；已打开的终端实时生效
- 修复设置窗口、确认弹窗、下拉菜单和搜索面板等浮层透出后方界面内容的问题
- 会话组下拉：右键分组时列表不再收起，重命名 / 删除菜单浮在上方
- Windows 安装器支持简体中文 / English 语言选择，中文系统默认中文
- 版本号更新至 0.8.2

### v0.8.1

- 修复会话拖拽排序：可上下拖动会话调整顺序，顺序在本机记忆
- 会话列表统一使用“会话组”用语：下拉标题、搜索框、新建按钮
- “私人（本设备）”改为“默认会话组”
- 会话组支持右键菜单：重命名、删除
- 会话右键新增“转移会话位置”，可移动到其他会话组
- 会话文件夹支持右键重命名
- 版本号更新至 0.8.1

### v0.8.0

- 从 Reach 0.8.8 重新移植底座，完整获得上游的新功能与修复
- 上游新增：RDP / VNC 远程桌面、命令面板、分屏与标签组、WSL 会话、容器 / Kubernetes 工作区、数据库管理、密码管理器接入、主题市场、主机密钥校验、单文件与文件夹上传等
- 保留 CoreOps 增强 AI 助手：普通 / 仅规划 / 自动编辑 / 全自动四种执行模式
- 保留按标签页隔离的 AI 对话上下文，关闭标签页自动清理
- 保留 AI 执行 sudo 等交互命令时的密码 / 确认输入门控
- 保留自定义 API 地址、模型列表拉取、上下文窗口与价格展示、API 地址带不带 `/v1` 自动识别
- 保留多命令一键执行、执行全部代码块、中止响应、面板宽度记忆
- 版本号同步至 0.8.0，更新源与签名仍指向 CoreOps 自己的 GitHub Release

</details>

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

## 致谢

CoreOps 基于 [Reach](https://github.com/alexandrosnt/Reach) 0.8.8 构建。感谢 [@alexandrosnt](https://github.com/alexandrosnt) 创建 Reach，以及所有上游贡献者。

**原项目地址：[https://github.com/alexandrosnt/Reach](https://github.com/alexandrosnt/Reach)**

CoreOps 是独立维护的分支，不代表 Reach 官方立场。

---

## 反馈

遇到 Bug、有功能建议，或者只是想聊聊，欢迎提交 Issue 或邮件联系：

📮 **邮箱：[1007887927@qq.com](mailto:1007887927@qq.com)**

每一条反馈我都会认真阅读，感谢你的支持与理解。
