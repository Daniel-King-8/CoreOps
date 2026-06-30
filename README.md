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
  <img src="https://img.shields.io/badge/基于-Reach-0a84ff?style=flat-square" alt="Based on Reach" />
  <img src="https://img.shields.io/badge/version-0.4.8-brightgreen?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-333?style=flat-square" alt="Platforms" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Qwen%20%7C%20OpenAI-blueviolet?style=flat-square" alt="AI Support" />
</p>

---

## 为什么要 Fork Reach？

我是 **Reach** 的忠实用户。自从发现这个项目起，它就成了我日常运维工作中最常打开的工具——没有 Electron 的臃肿，没有月度订阅，界面干净，底层用 Rust + russh 原生实现 SSH，性能和稳定性都让我非常满意。

但用久了之后，我发现两个痛点让我不得不自己动手：

**1. 语言问题**：Reach 是纯英文界面。对于我这样日常习惯用中文思考的工程师来说，在高压运维场景下（比如凌晨三点服务器报警），操作确认、错误提示全是英文，多少会影响判断速度。我希望界面能说"我的母语"。

**2. 功能缺口**：我的工作流越来越依赖大模型辅助——看到报错贴给 AI、AI 给方案、我验证后执行。原版 Reach 的 AI 模块是基础版的命令建议，没有"读取终端现场 → AI 分析 → 一键注入命令"这套完整闭环，我每次都要在终端和 AI 对话框之间来回复制粘贴，效率很低。

所以我在**完整保留 Reach 所有底层 SSH 能力**的基础上，针对自己的使用习惯做了二次开发，命名为 **CoreOps**。

---

## 相比原版 Reach，我改了什么

### ① 全面中文界面

补全并深度校对了中文语言包（`zh.json`），覆盖全部 UI 文案。包括：

- 所有菜单、按钮、提示文字
- 错误信息与确认对话框
- 新增的 AI 相关界面文案（完全原创翻译，非机器直译）

现在整个应用可以在设置中切换为中文，阅读体验与英文原版一致，没有遗漏或截断。

---

### ② 中文 AI 运维助手侧边栏（核心新增）

这是 CoreOps 最核心的改造。在终端界面右侧增加了一个专为运维场景设计的 AI 对话面板。

**解决的核心问题：**

> 以前：发现报错 → 手动复制 → 打开浏览器/其他 AI 工具粘贴 → 看方案 → 手动复制命令 → 回终端执行
>
> 现在：发现报错 → AI 面板自动读取终端内容 → 一句话问 → 一键把 AI 给的命令注入终端

**功能清单：**

| 功能 | 说明 |
|------|------|
| 终端缓冲区感知 | AI 可自动读取当前终端内容，无需手动复制报错 |
| 流式输出 | AI 回复实时逐字显示，不需要等全部生成完 |
| 代码块一键执行 | AI 回复中的 shell 命令，点击即可注入当前终端 |
| SSH / 本地 PTY 双路由 | 根据当前标签页类型，自动选择 `sshSend` 或 `ptyWrite` |
| 可拖拽宽度 | 面板宽度可拖拽调整，记忆上次设置 |
| 中止响应 | 生成过程中可随时打断 |

**四种执行模式（按信任程度递增）：**

```
普通对话   →  仅聊天，AI 不接触终端
仅规划     →  AI 给出操作方案和命令，你自己决定要不要执行
辅助执行   →  AI 提取命令，需逐条手动确认后才注入终端
全自动     →  AI 自动将命令注入终端执行（高风险，谨慎使用）
```

模式选择记忆在本地，重启不丢失。

---

### ③ AI 配置面板

在设置页新增独立的「AI 配置」Tab，支持：

- **兼容 OpenAI 格式的任意 API**：DeepSeek、通义千问、本地 Ollama、硅基流动等均可接入，只需修改 API 地址
- **API Key 加密存储**：通过应用内置的 Vault 加密，不明文写入配置文件
- **模型列表动态拉取**：输入 API 地址后一键拉取可用模型，支持搜索筛选
- **模型信息展示**：显示上下文窗口大小与计价信息（每百万 token 费用）

---

### ④ 会话列表拖拽排序重写

原版 Reach 在 Windows（Tauri WebView2 环境）下 HTML5 原生拖拽存在兼容问题，我将其完全重写为基于 Pointer Events 的实现：

- **同文件夹内排序**：上下拖拽任意调整顺序，松手位置精确判断（上半区插前、下半区插后）
- **跨文件夹移动**：拖到目标文件夹的 Header 上即可归入，支持折叠状态的文件夹
- **拖入根级别**：拖到空白区域可将会话移出文件夹
- **拖拽动画**：基于 Svelte `animate:flip` 实现，其他卡片平滑让位

---

## 保留自原版 Reach 的全部功能

以下功能**一行代码都没改**，完整继承自上游：

- **SSH 终端**：多标签、分屏、WebGL 渲染、完整 xterm.js 支持
- **SFTP 文件浏览器**：拖拽上传下载、在线编辑、传输队列
- **端口隧道**：本地/远程/动态 SOCKS 转发，随会话保存
- **跳板机（ProxyJump）**：多跳 SSH，支持从 `~/.ssh/config` 导入
- **系统监控**：远端 CPU/内存/磁盘实时数据，无需安装 Agent
- **Ansible 工作区**：Playbook、Inventory、角色管理，流式执行输出
- **OpenTofu / Terraform**：Plan/Apply/Destroy，状态浏览，完整 IaC 工作区
- **串口控制台**：路由器、交换机、嵌入式设备 COM/TTY 接入
- **加密 Vault**：会话凭据、SSH Key、密钥加密存储，支持云同步
- **Lua 插件系统**：沙盒化 Lua 脚本扩展

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

## 从源码构建

环境需求：[Rust](https://rustup.rs)、[Node.js 22+](https://nodejs.org)、以及 [Tauri v2 前置依赖](https://v2.tauri.app/start/prerequisites/)

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
```

### 配置 AI 助手

1. 打开应用 → 设置 → **AI 配置**
2. 填入 API 地址（默认 `https://api.deepseek.com/v1`，可替换为任意 OpenAI 兼容地址）
3. 填入 API Key，点击「验证并拉取模型列表」
4. 选择模型，开启 AI 开关
5. 终端界面右上角点击 AI 图标，展开侧边栏

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
