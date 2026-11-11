import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getAISettings, resolveApiBase } from './ai.svelte.js';
import { sshSend } from '#lib/ipc/ssh.js';
import { ptyWrite } from '#lib/ipc/pty.js';
import { readTerminalBuffer } from '#lib/state/terminal-buffer.svelte.js';

// ── 执行模式（全局，不随 Tab 切换） ──
export type ExecutionMode = 'normal' | 'plan-only' | 'auto-edit' | 'full-auto';

const MODE_STORAGE_KEY = 'reach-ai-exec-mode';

let executionMode = $state<ExecutionMode>('normal');

function loadMode(): ExecutionMode {
	if (typeof localStorage !== 'undefined') {
		const saved = localStorage.getItem(MODE_STORAGE_KEY);
		if (saved === 'normal' || saved === 'plan-only' || saved === 'auto-edit' || saved === 'full-auto') return saved;
	}
	return 'normal';
}
executionMode = loadMode();

export function getExecutionMode(): ExecutionMode { return executionMode; }
export function setExecutionMode(mode: ExecutionMode): void {
	executionMode = mode;
	if (typeof localStorage !== 'undefined') localStorage.setItem(MODE_STORAGE_KEY, mode);
}

// ── 消息 ──
export interface AIChatMessage {
	id: string;
	role: 'user' | 'assistant';
	content: string;
	instruction?: string;
	timestamp: number;
}

/** 每个 Tab 的独立 AI 上下文。 */
interface AIContext {
	messages: AIChatMessage[];
	loading: boolean;
	active: boolean;
	error: string | undefined;
	cancelled: boolean;
}

function freshContext(): AIContext {
	return { messages: [], loading: false, active: false, error: undefined, cancelled: false };
}

// ── Tab 隔离核心：Map<tabId, context> ──
let contexts = $state<Record<string, AIContext>>({ default: freshContext() });
let currentContextId = $state<string>('default');

let panelOpen = $state(false);

// ── Human In The Loop：按 Tab 隔离的交互式输入门控 ──
interface GateState {
	pending: boolean;
	label: string;
	type: 'password' | 'confirmation' | 'generic';
	resolver: ((val: string) => void) | null;
	paused: boolean;
	resume: (() => void) | null;
	terminal: TerminalInfo | null;
	sensitiveInput: string;
}

function freshGate(): GateState {
	return { pending: false, label: '', type: 'generic', resolver: null, paused: false, resume: null, terminal: null, sensitiveInput: '' };
}

let gates = $state<Record<string, GateState>>({});

function gateFor(contextId: string): GateState {
	if (!gates[contextId]) gates[contextId] = freshGate();
	return gates[contextId];
}

function interruptTerminal(terminal: TerminalInfo | null): void {
	if (!terminal) return;
	const interrupt = [3];
	if (terminal.tabType === 'ssh' && terminal.connectionId) void sshSend(terminal.connectionId, interrupt);
	else void ptyWrite(terminal.bufferId, interrupt);
}

export function getInputPending(): boolean { return gates[currentContextId]?.pending ?? false; }
export function getInputLabel(): string { return gates[currentContextId]?.label ?? ''; }
export function getInputType(): string { return gates[currentContextId]?.type ?? 'generic'; }

async function waitForInput(contextId: string): Promise<void> {
	const gate = gateFor(contextId);
	if (!gate.pending && !gate.paused) return;
	console.log('[GATE] Execution paused for user input');
	return new Promise<void>((resolve) => { gate.resume = resolve; });
}

function releaseGate(contextId: string): void {
	const gate = gateFor(contextId);
	gate.paused = false;
	if (gate.resume) { const cb = gate.resume; gate.resume = null; cb(); }
}

export function submitUserInput(val: string): void {
	const gate = gateFor(currentContextId);
	if (gate.type === 'password' && val.length >= 3) gate.sensitiveInput = val;
	releaseGate(currentContextId);
	if (gate.resolver) { const r = gate.resolver; gate.resolver = null; gate.pending = false; r(val); }
}

export function cancelInput(): void {
	const contextId = currentContextId;
	const gate = gateFor(contextId);
	// 取消不是“跳过输入”，而是终止当前 Tab 的 AI 执行。
	const c = ctx(contextId);
	c.cancelled = true;
	c.active = false;
	c.loading = false;
	releaseGate(contextId);
	if (gate.resolver) { const r = gate.resolver; gate.resolver = null; gate.pending = false; r(''); }
	// 向终端发送 Ctrl+C，确保 sudo、passwd、read 等交互提示被真正中止。
	interruptTerminal(gate.terminal);
}

function ctx(id: string): AIContext {
	let c = contexts[id];
	if (!c) { c = freshContext(); contexts[id] = c; }
	return c;
}

export function getAIChatState() {
	const c = contexts[currentContextId] ?? contexts.default;
	return {
		messages: c.messages, loading: c.loading,
		active: c.active, error: c.error, panelOpen
	};
}

export function getActive(): boolean { return contexts[currentContextId]?.active ?? false; }

export function activateTabContext(tabId: string): void {
	ctx(tabId);
	currentContextId = tabId;
}
export function getCurrentContextId(): string { return currentContextId; }

export function abortActiveSession(): void {
	const contextId = currentContextId;
	const c = ctx(contextId); c.cancelled = true; c.active = false; c.loading = false;
	c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[操作已打断] 用户手动中止了执行。`, timestamp: Date.now() });
	const gate = gates[contextId];
	if (gate) {
		releaseGate(contextId);
		if (gate.resolver) { const r = gate.resolver; gate.resolver = null; gate.pending = false; r(''); }
		interruptTerminal(gate.terminal);
	}
}

export function removeTabContext(tabId: string): void {
	const c = contexts[tabId];
	if (c) { c.cancelled = true; c.active = false; c.loading = false; }
	const gate = gates[tabId];
	if (gate) {
		if (gate.resolver) { const r = gate.resolver; gate.resolver = null; r(''); }
		delete gates[tabId];
	}
	delete contexts[tabId];
	if (currentContextId === tabId) currentContextId = 'default';
	if (!contexts.default) contexts.default = freshContext();
}
export function toggleAIPanel(): void { panelOpen = !panelOpen; }
export function openAIPanel(): void { panelOpen = true; }
export function closeAIPanel(): void { panelOpen = false; }

export function clearChat(): void {
	const contextId = currentContextId;
	const c = ctx(contextId); c.messages.length = 0; c.error = undefined; c.loading = false; c.cancelled = true;
	const gate = gates[contextId];
	if (gate) {
		releaseGate(contextId);
		if (gate.resolver) { const r = gate.resolver; gate.resolver = null; gate.pending = false; r(''); }
		interruptTerminal(gate.terminal);
	}
}

// ── 工具函数 ──
function buildSystemPrompt(context?: { connectionId?: string; host?: string; username?: string; os?: string; terminalOutput?: string }): string {
	let prompt =
		'你是一位资深 Linux 运维专家，内嵌在 CoreOps SSH 客户端中。请用简洁专业的中文回答用户问题。' +
		'你精通 Linux/Unix 系统管理、Shell 脚本、网络排查、Docker/K8s 容器编排、性能调优等运维领域。' +
		'只有当用户确实需要立即执行某条命令时，才使用 ```bash 代码块；系统只执行回复中的第一个 ```bash 块。' +
		'展示输出、配置内容、文件内容、示例时，必须使用 ```text、```console 或无语言标记的代码块，系统不会执行这些块。' +
		'需要用户执行的命令必须放在 ```bash 块；放在 ```text 块里的命令只是展示，客户端不会执行，也不会显示“运行”按钮。' +
		'任何“仅供备查”“仅供参考”“以后重建用”“示例”或“不要执行”的命令，必须放在 ```text 块；不要把它们放进 ```bash 再声称不会执行——客户端会立即执行第一个 ```bash 块。' +
		'不要编造客户端不存在的按钮或弹窗；确认方式只有两种：高危命令会显示 [待确认] 消息，点代码块右上角的“运行”按钮才会执行；命令执行中出现密码/确认提示时会弹出“需要用户操作”门禁，按钮是“取消”和“继续执行”。' +
		'不要在执行前询问“需要我执行吗”，自动模式下第一个 ```bash 块会被立即执行。' +
		'执行边界：当用户只是询问、查看、检查、分析或让你给建议时，只使用只读命令；不要主动创建目录、修改配置、安装软件、部署服务或清理资源。禁止把 mkdir、cp、rm、systemctl、docker run 等写操作说成“无副作用的准备”。只有用户明确要求执行、部署、安装、修改、删除时，才可以使用写操作。用户询问时，回答完就停，不要自行发起后续操作。' +
		'建议、可选方案、下一步计划必须放在 ```text 块，不要放进 ```bash。' +
		'重要安全规则：自动编辑模式下，sudo、用户/权限变更、主机名/网络变更、修改 /etc、删除、关机、防火墙等危险命令会先请求用户确认；全自动模式下，除密码输入、修改密码、交互式编辑器等需要用户亲自处理的命令外，其余命令直接执行。禁止使用 sudo -n、echo password | sudo -S、su、pkexec 等方式绕过密码。';
	if (context?.host || context?.username || context?.os) {
		prompt += '\n\n当前会话信息：';
		if (context.host) prompt += `\n- 主机：${context.host}`;
		if (context.username) prompt += `\n- 用户：${context.username}`;
		if (context.os) prompt += `\n- 系统：${context.os}`;
	}
	if (context?.terminalOutput) prompt += `\n\n终端最近输出如下：\n\`\`\`\n${context.terminalOutput}\n\`\`\``;
	return prompt;
}

function modeInstruction(mode: ExecutionMode): string {
	switch (mode) {
		case 'plan-only': return '\n\n当前运行模式：纯计划模式。只分析，不执行。';
		case 'auto-edit': return '\n\n当前运行模式：自动编辑模式。你回复中的第一个 ```bash 块会被立即执行；危险命令会先请求用户确认。用户只是询问/查看时只做只读检查，回答后停止，不要自行扩展成部署或清理任务。展示输出、配置或示例请用 ```text。';
		case 'full-auto': return '\n\n当前运行模式：全自动模式。你回复中的第一个 ```bash 块会被立即执行；除密码输入、修改密码、交互式编辑器等需要用户亲自处理的命令外，其余命令会直接执行，不再逐条确认。用户只是询问/查看时只做只读检查，回答后停止，不要自行扩展成部署或清理任务。需要输入时仍会弹出“需要用户操作”门禁。展示输出、配置或示例请用 ```text。';
		default: return '\n\n当前运行模式：普通模式。系统不会自动执行命令，只有用户点击运行按钮时才会执行。命令用 ```bash，展示内容用 ```text。';
	}
}

function toApiMessages(skipId: string, msgs: AIChatMessage[]): { role: string; content: string }[] {
	return msgs.filter((m) => m.id !== skipId).map((m) => ({ role: m.role, content: m.instruction ? `${m.content}\n\n${m.instruction}` : m.content }));
}

async function aiInvoke(apiMessages: { role: string; content: string }[]): Promise<string> {
	const settings = getAISettings();
	if (!settings.enabled || !settings.apiKey || !settings.selectedModel) throw new Error('AI 未配置');
	return invoke<string>('ai_chat', { request: { url: resolveApiBase(settings.apiUrl) + '/chat/completions', apiKey: settings.apiKey, model: settings.selectedModel, messages: apiMessages } });
}

export interface TerminalInfo { bufferId: string; tabType: 'ssh' | 'local'; connectionId?: string; }

const EXECUTABLE_LANGUAGES = new Set(['bash', 'sh', 'shell', 'zsh']);

export function isExecutableLanguage(language: string | undefined): boolean {
	return EXECUTABLE_LANGUAGES.has((language ?? '').trim().toLowerCase());
}

/**
 * 只提取明确标记为 shell 的代码块。
 * 无标记、```text、```console 等都属于展示内容，绝不能注入终端。
 */
interface ExecutableBlock { code: string; index: number; }

function extractExecutableBlocks(content: string): ExecutableBlock[] {
	const blocks: ExecutableBlock[] = [];
	const regex = /```([^\n`]*)\n([\s\S]*?)```/g;
	let match;
	while ((match = regex.exec(content)) !== null) {
		const language = (match[1].trim().split(/\s+/)[0] ?? '').toLowerCase();
		if (!isExecutableLanguage(language)) continue;
		const code = match[2].trim();
		if (code) blocks.push({ code, index: match.index });
	}
	return blocks;
}

function extractCodeBlocks(content: string): string[] { return extractExecutableBlocks(content).map((block) => block.code); }

export function collectCodeBlocks(content: string): string[] { return extractCodeBlocks(content); }

/**
 * AI 有时会把“仅供备查/以后重建用”的命令放进 bash 块，并声称不会执行。
 * 客户端无法读心，只能在自动执行前检查命令块前面的说明文字。
 */
function looksReferenceOnly(prefix: string): boolean {
	const text = prefix.slice(-800);
	const chinese = /(?:仅供(?:备查|参考)|仅供参考|仅作参考|不要(?:执行|运行)|不(?:要|会)?执行|不会自动执行|无需执行|以后(?:再|重建|使用)|日后(?:需要|重建|使用)|备查|示例(?:命令|用)?|展示(?:用|命令)|参考(?:用|命令))/;
	const english = /\b(?:for reference only|reference only|do not (?:run|execute)|don't (?:run|execute)|not (?:to be )?executed|example only|for future use|future reference)\b/i;
	return chinese.test(text) || english.test(text);
}

/**
 * AI 经常把命令写在“建议动作 / 建议进一步排查 / 推荐方案”这类小节里。
 * 这些只是建议，不是用户已经同意执行的下一步，自动模式必须先停下来。
 */
function looksAdvisoryOnly(prefix: string): boolean {
	const text = prefix.slice(-600);
	// AI 明确表示“自己马上要跑”时，不要把“建议”标题当成给用户的建议。
	const lead = text.slice(-220);
	if (/(?:我先(?:跑|执行|运行|试|做)|我来(?:跑|执行|运行|做)|我将(?:执行|运行)|我马上(?:执行|运行)|我直接(?:执行|运行))/.test(lead)) return false;
	const heading = /(?:^|\n)#{1,6}[^\n]{0,80}(?:建议|推荐|suggested|recommended)[^\n]*(?:\n|$)/i;
	const chinese = /(?:建议|推荐)(?:动作|操作|步骤|方案|执行|运行|进一步|排查|如下|以下|先|你|您)/;
	const english = /\b(?:suggested|recommended)\s+(?:actions?|steps?|commands?|next steps?)\b|\bnext steps?\b/i;
	return heading.test(text) || chinese.test(text) || english.test(text);
}

/**
 * 判断用户是在“询问/查看”还是明确要求“执行/变更”。
 * 判不准时按询问处理：宁可少做一步，也不要替用户改系统。
 */
function isActionRequest(prompt: string): boolean {
	const text = prompt.trim();
	if (!text) return false;
	const asksHow = /(?:怎么|如何|教程|步骤|方案|建议|可不可以|能不能|是否需要)/;
	const queryHint = /(?:有哪些|是什么|有什么|多少|查看|看看|检查|列出|分析|状态|有没有|是否|怎么样|为什么|如何|怎么)/;
	const strongAction = /(?:部署|安装|拉取|下载|删除|移除|卸载|启动|停止|重启|修改|更改|配置|设置|创建|新建|清理|升级|更新|禁用|启用|搭建|修复|装一下|跑起来|帮我弄|帮我做|帮我改|给我装)/;
	const weakAction = /(?:运行|执行)/;
	const direct = /(?:直接|立即|现在就|帮我执行|帮我运行|运行一下|执行一下|开始)/;
	// “怎么部署 / 如何安装 / 有什么方案”属于询问，不是执行指令。
	if (strongAction.test(text)) return !(asksHow.test(text) && !direct.test(text));
	// “查看当前运行的容器”里的“运行”是描述，不是动作。
	if (weakAction.test(text)) return !(queryHint.test(text) && !direct.test(text));
	return false;
}

function isInteractiveMultiLine(command: string): boolean {
	if (!command.includes('\n')) return false;
	return /(?:^|\n)\s*(sudo|su|passwd|read|ssh-keygen|visudo|less|more|vi|vim|nano|systemctl\s+edit|mysql|psql|redis-cli)\b/.test(command);
}

/**
 * 全自动模式下仍需用户亲自处理的命令：密码输入/修改、交互式编辑器/终端。
 * 其他危险命令在全自动模式下直接执行，不再逐条确认。
 */
function requiresManualInput(command: string): boolean {
	const cmd = command.trim();
	// 只有独立执行的 exit/logout 才需要确认；脚本里用于错误处理的 `{ ...; exit 1; }`
	// 不应打断全自动执行。
	const firstLine = cmd.split('\n').map((line) => line.trim()).find((line) => line && !line.startsWith('#')) ?? '';
	const standaloneSessionExit = /^(?:exit|logout)(?:\s+\d+)?\s*$/.test(firstLine);
	return (
		standaloneSessionExit ||
		/(?:^|[;&|]\s*|\n\s*)(passwd\b(?!\s+-S\b)|chpasswd|chage|visudo|read|su|ssh-keygen|vi|vim|nano|less|more|mysql|psql|redis-cli|systemctl\s+edit)\b/.test(cmd) ||
		/\bopenssl\s+passwd\b/.test(cmd) ||
		/\bmkpasswd\b/.test(cmd) ||
		/\bsudo\s+(?:-S|-i|-s|su)\b/.test(cmd)
	);
}

function isDangerousCommand(command: string): boolean {
	const cmd = command.trim();
	const patterns = [
		// 提权与会话身份
		/(?:^|[;&|]\s*|\n\s*)(sudo|su|doas|pkexec)\b/,
		/^\s*(exit|logout)\s*$/,
		/(?:^|[;&|]\s*|\n\s*)(usermod|useradd|userdel|groupadd|groupdel|gpasswd|passwd|chpasswd|chage|visudo)\b/,
		/\b(sudoers(?:\.d)?|authorized_keys)\b/,
		// 服务与系统状态
		/\b(systemctl|service|supervisorctl)\s+(?!status\b|show\b|is-active\b|is-enabled\b|list-|cat\b|--status-all\b)/,
		/\b(reboot|shutdown|halt|poweroff|init\s+[0-6])\b/,
		/\b(kill|pkill|killall)\b/,
		// 主机名、网络与会话身份变更
		/\b(hostnamectl|localectl|timedatectl)\s+(?:set-|set\b)/,
		/\bhostname\s+(?!-|$)/,
		/\bexec\b/,
		/\b(nmcli|ip)\s+(connection\s+(up|down|modify|delete|add)|addr\s+(add|del|flush)|route\s+(add|del|replace|flush)|link\s+(set|up|down))\b/,
		// 文件系统与磁盘
		/\brm\b/, /\b(mkfs|mke2fs|fdisk|parted|wipefs|dd)\b/, /\b(mount|umount|swapoff)\b/,
		// 包管理与远程脚本
		/\b(apt|apt-get|yum|dnf|zypper|pacman|apk)\s+(install|remove|erase|purge|update|upgrade|dist-upgrade|autoremove|downgrade|groupinstall|groupremove|distro-sync)\b/,
		/\b(dpkg|rpm)\s+.*(--?[ie]|--?erase|--?install)\b/,
		/\b(pip\d*)\s+(install|uninstall)\b/,
		/\b(snap|flatpak|brew)\s+(install|remove|uninstall|upgrade)\b/,
		/\b(curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b/,
		// 网络与防火墙
		/\b(iptables|ip6tables|nft|firewall-cmd|ufw)\b/,
		// 容器与 Kubernetes 的变更操作
		/\b(docker|podman)\s+(stop|rm|rmi|kill|restart|down|prune|system\s+prune)\b/,
		/\bkubectl\s+(delete|drain|cordon|scale|apply|replace|edit|patch)\b/,
		// 对系统路径做变更
		/\b(mv|cp|rm|sed\s+-i|tee|truncate|chmod|chown|chattr|install)\b[^\n]*\s(?:\/etc\/|\/root\/|\/boot\/|\/usr\/|\/var\/lib\/|[^\s]*\/\.ssh\/)/
	];
	return patterns.some((pattern) => pattern.test(cmd));
}

/** 是否会修改文件、服务或系统状态。询问类请求只允许自动执行只读命令。 */
function containsWriteOperation(command: string): boolean {
	const cmd = command.trim();
	const at = '(?:^|[;&|]\\s*|\\n\\s*)';
	const patterns = [
		new RegExp(`${at}(?:mkdir|rmdir|touch|cp|mv|rm|ln|chmod|chown|chattr|tee|truncate|dd|install)\\b`),
		/\bsed\s+-i\b/,
		new RegExp(`${at}(?:systemctl|service)\\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\\b`),
		new RegExp(`${at}(?:docker|podman)\\s+(?:run|create|start|stop|restart|rm|rmi|pull|push|build|tag|prune|load|import|commit|exec)\\b`),
		new RegExp(`${at}(?:apt|apt-get|yum|dnf|zypper|pacman|apk)\\s+(?:install|remove|erase|purge|update|upgrade|dist-upgrade|autoremove|downgrade)\\b`),
		new RegExp(`${at}(?:pip\\d*|npm|pnpm|yarn)\\s+(?:install|uninstall|add|remove)\\b`),
		new RegExp(`${at}(?:useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd|visudo|chage)\\b`),
		new RegExp(`${at}kubectl\\s+(?:apply|delete|patch|scale|edit|replace|create|drain|cordon|taint)\\b`),
		new RegExp(`${at}(?:iptables|ip6tables|nft|firewall-cmd|ufw|mount|umount|swapoff|mkfs|mke2fs|fdisk|parted|wipefs)\\b`),
		/\b(?:curl|wget)\b[^\n|]*(?:\s-o\s|\s-O\b)/,
		/(?:^|[^>])>{1,2}\s*(?!['"&]|\/dev\/(?:null|stdout|stderr)\b)\S/,
		new RegExp(`${at}(?:crontab|hostnamectl|timedatectl|localectl)\\b`)
	];
	return patterns.some((pattern) => pattern.test(cmd));
}

const MAX_AUTO_ROUNDS = 10;

function decodePayload(payload: unknown): string {
	if (payload instanceof Uint8Array) return new TextDecoder().decode(payload);
	if (Array.isArray(payload)) return new TextDecoder().decode(new Uint8Array(payload));
	if (typeof payload === 'string') return payload;
	return '';
}

function stripAnsi(str: string): string {
	return str.replace(/\x1b\[[\d;?]*[A-Za-z]/g, '').replace(/\x1b\].*?(\x07|\x1b\\)/g, '')
		.replace(/\x1b[PX^_].*?\x1b\\/g, '').replace(/\x1b[=>]/g, '').replace(/\x1b[^\[\]]/g, '')
		.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

const MAX_AI_OUTPUT_LINES = 200;
const MAX_AI_OUTPUT_CHARS = 16_000;

/** 进度条、下载动画等对 AI 没有信息量的重复行。 */
function isProgressLine(line: string): boolean {
	const s = line.trim();
	if (!s) return false;
	// 错误、警告、最终状态必须保留。
	if (/\b(?:error|failed|fatal|denied|not found|warning)\b/i.test(s)) return false;
	if (/\b(?:Downloading|Download complete|Pulling|Pull complete|Pulling fs layer|Already exists|Waiting|Extracting|Verifying Checksum)\b/i.test(s)) return true;
	if (/\b\d+(?:\.\d+)?\s*(?:B|kB|MB|GB)\s*\/\s*\d+(?:\.\d+)?\s*(?:B|kB|MB|GB)\b/i.test(s)) return true;
	if (/\[[=>#\-\s]{3,}\]/.test(s) && /\d+(?:\.\d+)?\s*(?:B|kB|MB|GB|%)/i.test(s)) return true;
	if (/\b\d{1,3}%\b/.test(s) && /(?:download|upload|receiv|resolv|connect|pull|extract|build|progress)/i.test(s)) return true;
	return false;
}

/** 控制发给 AI 的输出体积，避免几千行日志撑爆上下文。 */
function limitAiOutput(text: string): string {
	let lines = text.split('\n');
	let truncated = false;
	if (lines.length > MAX_AI_OUTPUT_LINES) {
		lines = lines.slice(-MAX_AI_OUTPUT_LINES);
		truncated = true;
	}
	let result = lines.join('\n');
	if (result.length > MAX_AI_OUTPUT_CHARS) {
		result = result.slice(-MAX_AI_OUTPUT_CHARS);
		truncated = true;
	}
	return truncated ? `[输出过长，已截断，仅保留最后部分]\n${result}` : result;
}

/** 生成 Markdown 代码块；内容本身含有 ``` 时自动加长围栏。 */
function mdCode(text: string, language: string): string {
	const fence = text.includes('```') ? '````' : '```';
	return `${fence}${language}\n${text}\n${fence}`;
}

/**
 * 判断终端最后一行是不是 shell 提示符。
 * 用于确认上一条命令是否真的结束，避免把新命令输入到仍在运行的终端里。
 */
function isIdlePromptLine(line: string): boolean {
	const s = stripAnsi(line).trimEnd();
	if (!s || s.length > 300) return false;
	// `>` 是续行提示符，不是空闲状态。
	if (/^(?:>|\+)\s*$/.test(s)) return false;
	// [root@King ~]# / [user@host path]$
	if (/^\[[^\]\n]{1,120}\][#$]\s*$/.test(s)) return true;
	// user@host:~$ / user@192.168.1.10:/path# / (venv) user@host:~$
	if (/[^\s@]+@[^\s:/]+[^\n]{0,160}[#$%]\s*$/.test(s)) return true;
	// oh-my-zsh 等以 ➜ 开头的提示符（后面可能跟着 git 分支/状态）。
	if (/^➜\s/.test(s)) return true;
	if (/^(?:\$|#|%|❯|➜)\s*$/.test(s)) return true;
	if (/[❯➜]\s*$/.test(s)) return true;
	return false;
}

const IDLE_WAIT_TIMEOUT_MS = 5 * 60_000;
/** 提示符格式无法识别时，终端安静这么久就认为命令已结束。 */
const IDLE_QUIET_FALLBACK_MS = 10_000;

/** 等终端回到提示符，最多等 timeoutMs。缓冲区读不到时直接放行。 */
async function waitUntilTerminalIdle(terminal: TerminalInfo, timeoutMs = IDLE_WAIT_TIMEOUT_MS): Promise<boolean> {
	const key = terminal.tabType === 'ssh' && terminal.connectionId ? terminal.connectionId : terminal.bufferId;
	let snapshot = readTerminalBuffer(key, 30);
	if (!snapshot.trim()) return true;
	const deadline = Date.now() + timeoutMs;
	let unchangedSince = Date.now();
	while (Date.now() < deadline) {
		const lastLine = snapshot.trimEnd().split('\n').pop() ?? '';
		if (isIdlePromptLine(lastLine)) {
			// 提示符还要保持一小段时间不变，避免命令刚开始输出时误判。
			await new Promise((resolve) => setTimeout(resolve, 500));
			const again = readTerminalBuffer(key, 30);
			if (again === snapshot) return true;
			snapshot = again;
			unchangedSince = Date.now();
			continue;
		}
		// 进度条输出意味着命令仍在运行，不能靠“安静”判断。
		if (isProgressLine(lastLine)) unchangedSince = Date.now();
		await new Promise((resolve) => setTimeout(resolve, 500));
		const again = readTerminalBuffer(key, 30) || snapshot;
		if (again !== snapshot) {
			snapshot = again;
			unchangedSince = Date.now();
		} else if (Date.now() - unchangedSince >= IDLE_QUIET_FALLBACK_MS) {
			// 自定义提示符可能无法识别；终端长时间没有新输出，视为空闲。
			return true;
		}
	}
	return false;
}


interface CommandResult {
	output: string;
	/** 是否在超时前等到了 shell 提示符（或会话结束）。 */
	completed: boolean;
	/** 终端连接是否已断开。 */
	sessionClosed: boolean;
}

async function captureCommandOutput(command: string, terminal: TerminalInfo, contextId: string): Promise<CommandResult> {
	const gate = gateFor(contextId);
	gate.terminal = terminal;
	try {
		return await captureCommandOutputInner(command, terminal, contextId);
	} finally {
		if (gate.terminal === terminal) gate.terminal = null;
	}
}

async function captureCommandOutputInner(command: string, terminal: TerminalInfo, contextId: string): Promise<CommandResult> {
	const gate = gateFor(contextId);
	const eventId = terminal.tabType === 'ssh' && terminal.connectionId ? terminal.connectionId : terminal.bufferId;
	const eventName = terminal.tabType === 'ssh' ? `ssh-data-${eventId}` : `pty-data-${eventId}`;
	const isSsh = terminal.tabType === 'ssh' && !!terminal.connectionId;
	const chunks: string[] = [];
	let outputBuffer = '';
	let unlisten: UnlistenFn | undefined;

	unlisten = await listen<unknown>(eventName, (event) => {
		const text = decodePayload(event.payload);
		if (!text) return;
		if (text.includes('sudo') || text.includes('password') || text.includes('密码')) {
			console.log('[AI_SSH_RAW]', JSON.stringify(text.slice(0, 200)));
		}
		chunks.push(text);
		outputBuffer += text;
		// Interaction Gate: detect prompts in real-time
		if (outputBuffer.length > 8) {
			const cleaned = stripAnsi(outputBuffer);
			const lines = cleaned.split('\n');
			const lastLine = lines.filter(l => l.trim()).pop() || '';
			const shellPromptVisible = /(?:^|\n)[^\n]*[#$]\s*$/.test(cleaned);
			if (!gate.pending) {
				if (/\[sudo\].*?(?:password|密码).*[:：]/i.test(cleaned) ||
					/^(?:新的密码|重新输入新的密码|密码|口令)\s*[:：]\s*$/m.test(cleaned)) {
					gate.type = 'password'; gate.label = '密码认证'; gate.pending = true; gate.paused = true;
				} else if (/^.*password\s*[:：]/i.test(lastLine)) {
					gate.type = 'password'; gate.label = '密码'; gate.pending = true; gate.paused = true;
				} else if (/\[y\/n\]|\(y\/n\)/i.test(lastLine)) {
					gate.type = 'confirmation'; gate.label = '确认 [y/N]'; gate.pending = true; gate.paused = true;
				} else if (/(?:press|按).*(?:enter|any key|回车|任意键)/i.test(lastLine)) {
					gate.type = 'generic'; gate.label = '按回车继续'; gate.pending = true; gate.paused = true;
				} else if (/^(?:enter choice|请选择|请输入).*[:：]/im.test(lastLine)) {
					gate.type = 'generic'; gate.label = '输入'; gate.pending = true; gate.paused = true;
				}
			}
			if (gate.pending && shellPromptVisible) {
				// 终端已经回到 shell 提示符，说明交互提示消失了，门禁必须同步关闭。
				gate.pending = false;
				releaseGate(contextId);
				if (gate.resolver) { const r = gate.resolver; gate.resolver = null; r(''); }
			}
		}
	});

	let sessionClosed = false;
	const exitName = terminal.tabType === 'ssh' ? `ssh-exit-${eventId}` : `pty-exit-${eventId}`;
	const unlistenExit = await listen<unknown>(exitName, () => { sessionClosed = true; });

	const encoded = Array.from(new TextEncoder().encode(command + '\n'));
	if (isSsh) await sshSend(terminal.connectionId!, encoded);
	else await ptyWrite(terminal.bufferId, encoded);

	let completed = false;
	let lastLength = 0, stableCount = 0, hadData = false;
	// docker pull 等命令可能跑好几分钟。等待提示符最长 10 分钟；
	// 连续 60 秒无任何输出且没有提示符时提前结束，并标记为“未确认完成”。
	const maxTicks = 1200;
	const stableBreakTicks = 120;
	for (let i = 0; i < maxTicks; i++) {
		await new Promise((r) => setTimeout(r, 500));
		if (ctx(contextId).cancelled) break;
		if (sessionClosed) { completed = true; break; }
		if (gate.pending && !gate.resolver) {
			// 保留 chunks（提示符之前的输出），只清空提示检测缓冲，避免重复识别同一个提示符。
			outputBuffer = "";
			const val = await new Promise<string>((resolve) => { gate.resolver = resolve; });
			if (!val) break;
			const payload = Array.from(new TextEncoder().encode(val + '\n'));
			if (isSsh) await sshSend(terminal.connectionId!, payload);
			else await ptyWrite(terminal.bufferId, payload);
			lastLength = 0; stableCount = 0;
		}
		if (chunks.length > 0) hadData = true;
		if (chunks.length > lastLength) { lastLength = chunks.length; stableCount = 0; }
		else if (hadData) {
			stableCount++;
			if (stableCount >= 6) {
				// 输出稳定不代表命令结束：docker pull 这类命令在下载期间会先稳定地回显命令，
				// 必须等到 shell 提示符重新出现。
				const tail = stripAnsi(chunks.join('')).trimEnd();
				const tailLine = tail.split('\n').pop() ?? '';
				const bufferLine = (readTerminalBuffer(eventId, 3).trimEnd().split('\n').pop() ?? '').trimEnd();
				if (isIdlePromptLine(tailLine) || isIdlePromptLine(bufferLine)) { completed = true; break; }
				if (stableCount >= stableBreakTicks) break;
			}
		}
	}
	unlisten?.();
	unlistenExit?.();

	let cleanOutput = stripAnsi(chunks.join(''))
		.replace(/\[sudo\].*(?:password|密码).*[:：]?\n?/g, '')
		.replace(/^(?:新的密码|重新输入新的密码|密码|口令)\s*[:：]\s*\n?/gm, '')
		.replace(/^(?:password|passwd)\s*[:：].*$/gim, '')
		.trim();
	if (gate.sensitiveInput) {
		cleanOutput = cleanOutput.split(gate.sensitiveInput).join('[已隐藏]');
	}
	const lines = cleanOutput.split('\n');
	const cmdLines = command.split('\n').map((line) => line.trim()).filter(Boolean);
	const firstCmdLine = cmdLines[0] ?? '';
	const firstToken = firstCmdLine.split(/\s+/)[0] ?? '';
	let startIdx = 0;
	let foundCommand = false;

	// 先尝试完整匹配第一行命令。
	for (let i = 0; i < Math.min(lines.length, 20); i++) {
		if (firstCmdLine && lines[i].includes(firstCmdLine)) {
			foundCommand = true;
			startIdx = i + 1;
			break;
		}
	}
	// 终端可能给命令行加提示符前缀或换行，退化为“提示符行 + 命令首词”。
	if (!foundCommand && firstToken && /^\[[^\]]+\][#$]\s*/.test(lines[0] ?? '') && (lines[0] ?? '').includes(firstToken)) {
		foundCommand = true;
		startIdx = 1;
	}
	if (foundCommand) {
		// 跳过终端对多行命令的回显：逐行粘贴时每一行都会带提示符前缀，
		// 某些终端则使用 `>` 续行提示符。
		const expected = new Set(cmdLines);
		let skipped = 0;
		while (startIdx < lines.length && skipped <= cmdLines.length + 8) {
			const raw = lines[startIdx];
			const stripped = raw
				.replace(/^\[[^\]]*\][#$]\s*/, '')
				.replace(/^[^\s]+@[^\s]+[#$]\s*/, '')
				.replace(/^>\s?/, '')
				.trim();
			if (stripped === '' || expected.has(stripped) || /^(?:\[[^\]]*\][#$]\s*)?>\s?/.test(raw)) {
				startIdx++;
				skipped++;
				continue;
			}
			break;
		}
	}
	let endIdx = lines.length;
	while (endIdx > startIdx && (
		/^[^a-zA-Z0-9]*[$#>]\s*$/.test(lines[endIdx - 1]) ||
		/^\[[^\]]+\][#$]\s*$/.test(lines[endIdx - 1])
	)) endIdx--;
	const outputLines = lines.slice(startIdx, endIdx);
	let progressFiltered = 0;
	const filteredLines = outputLines.filter((line) => {
		if (isProgressLine(line)) { progressFiltered++; return false; }
		return true;
	});
	if (progressFiltered > 0) filteredLines.unshift(`[已过滤 ${progressFiltered} 行进度输出]`);
	let result = filteredLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
	if (!result) {
		result = progressFiltered > 0
			? `[已过滤 ${progressFiltered} 行进度输出，无其他输出]`
			: (foundCommand ? '（无输出）' : (cleanOutput.trim() || '（无输出）'));
	}
	if (!completed && !sessionClosed && !ctx(contextId).cancelled) {
		result += '\n\n[注意] 等待 shell 提示符超时，命令可能仍在执行，以上输出可能不完整。';
	}
	return { output: limitAiOutput(result), completed: completed || sessionClosed, sessionClosed };
}

function runCommandInTerminal(command: string, terminal: TerminalInfo, contextId: string): Promise<CommandResult> { return captureCommandOutput(command, terminal, contextId); }
function canAutoExec(): boolean { return executionMode === 'auto-edit' || executionMode === 'full-auto'; }

/** 用户发送聊天消息（主入口）。 */
export async function sendMessage(
	prompt: string,
	context?: { connectionId?: string; host?: string; username?: string; os?: string; terminalOutput?: string },
	terminal?: TerminalInfo
): Promise<void> {
	const settings = getAISettings();
	const contextId = currentContextId;
	if (!settings.enabled || !settings.apiKey || !settings.selectedModel) { ctx(contextId).error = 'AI 未配置'; return; }
	const c = ctx(contextId);
	const actionRequest = isActionRequest(prompt);
	c.messages.push({ id: crypto.randomUUID(), role: 'user', content: prompt, timestamp: Date.now() });
	const assistantId = crypto.randomUUID();
	c.messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });
	c.loading = true; c.active = true; c.error = undefined; c.cancelled = false;

	try {
		const systemPrompt = buildSystemPrompt(context) + modeInstruction(executionMode);
		let hint = '';
		if (terminal) {
			if (executionMode === 'full-auto') {
				hint = '\n\n已接入终端且处于全自动模式。你回复中的第一个 ```bash 块会被立即执行；除密码输入、修改密码、交互式编辑器等需要用户亲自处理的命令外，其余命令不再逐条确认。需要输入时仍会弹出“需要用户操作”门禁。展示输出、配置或示例请用 ```text。';
			} else if (executionMode === 'auto-edit') {
				hint = '\n\n已接入终端且处于自动编辑模式。你回复中的第一个 ```bash 块会被立即执行；危险命令会先请求用户确认。展示输出、配置或示例请用 ```text。';
			} else if (executionMode === 'normal') {
				hint = '\n\n已接入终端。系统不会自动执行命令；命令请用 ```bash，展示内容请用 ```text。';
			}
		}
		const apiMessages = [{ role: 'system', content: systemPrompt + hint }, ...toApiMessages(assistantId, c.messages)];
		const content = await aiInvoke(apiMessages);
		if (c.cancelled) return;
		const idx = c.messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1) c.messages[idx].content = content;

		if (terminal && canAutoExec() && !c.cancelled) {
			let lastResponse = content; let rounds = 0; let lastCommand = '';
			while (rounds < MAX_AUTO_ROUNDS && !c.cancelled) {
				await waitForInput(contextId);
				const codeBlocks = extractExecutableBlocks(lastResponse);
				if (codeBlocks.length === 0) break;
				const firstBlock = codeBlocks[0];
				const leadIn = lastResponse.slice(0, firstBlock.index);
				if (looksReferenceOnly(leadIn) || looksAdvisoryOnly(leadIn)) {
					c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[未自动执行] AI 将这段命令标注为“建议/参考”内容，已跳过自动执行。需要时请手动点代码块上的“运行”。`, timestamp: Date.now() });
					break;
				}
				const cmd = firstBlock.code;
				if (cmd === lastCommand) break;
				lastCommand = cmd;
				// 用户只是询问/查看时，第一条只读命令可以自动执行；
				// 任何写操作都必须先确认，避免 AI 擅自建目录、改配置或部署服务。
				const queryWrite = !actionRequest && containsWriteOperation(cmd);
				const needsConfirmation = executionMode === 'full-auto'
					? (requiresManualInput(cmd) || queryWrite)
					: (isDangerousCommand(cmd) || isInteractiveMultiLine(cmd) || queryWrite);
				if (needsConfirmation) {
					const reason = queryWrite ? '该命令会修改系统' : '高危命令';
					c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[待确认] ${reason}：\n\n${mdCode(cmd, 'bash')}`, timestamp: Date.now() });
					break;
				}
				if (!(await waitUntilTerminalIdle(terminal))) {
					c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 终端上一条命令仍在运行（未出现 shell 提示符）。为避免把新命令输入到运行中的终端，自动执行已暂停；请等待命令结束后重试。`, timestamp: Date.now() });
					break;
				}
				const result = await runCommandInTerminal(cmd, terminal, contextId);
				if (c.cancelled) return;
				c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[自动执行]\n\n${mdCode(cmd, 'bash')}\n\n输出：\n\n${mdCode(result.output, 'text')}`, instruction: '分析以上输出。', timestamp: Date.now() });
				if (result.sessionClosed) {
					c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[会话已结束] 终端连接已断开，自动执行已停止。`, timestamp: Date.now() });
					break;
				}
				if (!result.completed) {
					c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 上一条命令在等待时间内没有返回 shell 提示符，可能仍在运行。为避免把新命令输入到运行中的终端，自动执行已暂停；请等待命令结束或手动处理后重试。`, timestamp: Date.now() });
					break;
				}
				const nextId = crypto.randomUUID();
				c.messages.push({ id: nextId, role: 'assistant', content: '', timestamp: Date.now() });
				const nextMessages = [{ role: 'system', content: systemPrompt + hint + '\n\n继续。' }, ...toApiMessages(nextId, c.messages)];
				lastResponse = await aiInvoke(nextMessages);
				if (c.cancelled) return;
				const nIdx = c.messages.findIndex((m) => m.id === nextId);
				if (nIdx !== -1) c.messages[nIdx].content = lastResponse;
				rounds++;
				// 询问类请求：拿到 AI 对第一条只读命令的分析后就停，不再自动执行后续块。
				if (!actionRequest) break;
			}
			if (actionRequest && !c.cancelled && rounds >= MAX_AUTO_ROUNDS && extractExecutableBlocks(lastResponse).length > 0) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 已达到自动执行轮次上限（${MAX_AUTO_ROUNDS} 轮），后续命令请手动点击“运行”。`, timestamp: Date.now() });
			}
		}
	} catch (e) { if (c.cancelled) return; c.error = String(e); const idx = c.messages.findIndex((m) => m.id === assistantId); if (idx !== -1 && !c.messages[idx].content) c.messages.splice(idx, 1); }
	finally { c.loading = false; c.active = false; }
}

/** 点击代码块执行按钮。 */
export async function executeCommand(command: string, bufferId: string, tabType: 'ssh' | 'local', connectionId?: string, context?: { host?: string; username?: string; os?: string }): Promise<void> {
	const contextId = currentContextId;
	if (executionMode === 'plan-only') { ctx(contextId).error = '纯计划模式，禁止执行。'; return; }
	if (gateFor(contextId).pending) return;
	const c = ctx(contextId);
	const terminal: TerminalInfo = { bufferId, tabType, connectionId };
	if (!(await waitUntilTerminalIdle(terminal, 60_000))) {
		c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[未执行] 终端上一条命令仍在运行（未出现 shell 提示符）。为避免把新命令输入到运行中的终端，本次执行已取消；请等待命令结束后重试。`, timestamp: Date.now() });
		return;
	}
	const userMsgId = crypto.randomUUID();
	c.messages.push({ id: userMsgId, role: 'user', content: `执行命令：\n\n${mdCode(command, 'bash')}`, timestamp: Date.now() });
	c.loading = true; c.active = true; c.error = undefined; c.cancelled = false;
	try {
		const result = await captureCommandOutput(command, terminal, contextId);
		if (c.cancelled) return;
		const output = result.output;
		const userMsgIdx = c.messages.findIndex((m) => m.id === userMsgId);
		if (userMsgIdx !== -1) c.messages[userMsgIdx].content = `已执行：\n\n${mdCode(command, 'bash')}\n\n输出：\n\n${mdCode(output, 'text')}`;
		if (result.sessionClosed) {
			c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[会话已结束] 终端连接已断开。`, timestamp: Date.now() });
			return;
		}
		if (!result.completed) {
			c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 命令在等待时间内没有返回 shell 提示符，可能仍在运行。自动继续已停止；请等待命令结束或手动处理后重试。`, timestamp: Date.now() });
			return;
		}
		const assistantId = crypto.randomUUID();
		c.messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });
		const sysPrompt = buildSystemPrompt(context ? { ...context, terminalOutput: output } : { terminalOutput: output }) + modeInstruction(executionMode);
		const apiMessages = [{ role: 'system', content: sysPrompt }, ...toApiMessages(assistantId, c.messages)];
		const content = await aiInvoke(apiMessages);
		if (c.cancelled) return;
		const idx = c.messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1) c.messages[idx].content = content;
		if (!canAutoExec()) return;
		// 手动运行只读命令时，只分析这一次的结果，不再自动串联后续写操作。
		// 只有用户点的是写操作，才允许 AI 继续多轮执行。
		if (!containsWriteOperation(command)) return;
		let lastResponse = content; let rounds = 0; let lastCommand = '';
		while (rounds < MAX_AUTO_ROUNDS && !c.cancelled) {
			await waitForInput(contextId);
			const moreCmds = extractExecutableBlocks(lastResponse);
			if (moreCmds.length === 0) break;
			const firstBlock = moreCmds[0];
			const leadIn = lastResponse.slice(0, firstBlock.index);
			if (looksReferenceOnly(leadIn) || looksAdvisoryOnly(leadIn)) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[未自动执行] AI 将这段命令标注为“建议/参考”内容，已跳过自动执行。需要时请手动点代码块上的“运行”。`, timestamp: Date.now() });
				break;
			}
			const cmd = firstBlock.code;
			if (cmd === lastCommand) break;
			lastCommand = cmd;
			const needsConfirmation = executionMode === 'full-auto'
				? requiresManualInput(cmd)
				: (isDangerousCommand(cmd) || isInteractiveMultiLine(cmd));
			if (needsConfirmation) { c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[待确认] 高危命令：\n\n${mdCode(cmd, 'bash')}`, timestamp: Date.now() }); break; }
			if (!(await waitUntilTerminalIdle(terminal))) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 终端上一条命令仍在运行（未出现 shell 提示符）。为避免把新命令输入到运行中的终端，自动执行已暂停；请等待命令结束后重试。`, timestamp: Date.now() });
				break;
			}
			const result = await runCommandInTerminal(cmd, terminal, contextId);
			if (c.cancelled) return;
			c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[自动执行]\n\n${mdCode(cmd, 'bash')}\n\n输出：\n\n${mdCode(result.output, 'text')}`, instruction: '分析输出。', timestamp: Date.now() });
			if (result.sessionClosed) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[会话已结束] 终端连接已断开，自动执行已停止。`, timestamp: Date.now() });
				break;
			}
			if (!result.completed) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 上一条命令在等待时间内没有返回 shell 提示符，可能仍在运行。为避免把新命令输入到运行中的终端，自动执行已暂停；请等待命令结束或手动处理后重试。`, timestamp: Date.now() });
				break;
			}
			const nextId = crypto.randomUUID();
			c.messages.push({ id: nextId, role: 'assistant', content: '', timestamp: Date.now() });
			const nextMessages = [{ role: 'system', content: sysPrompt + '\n\n继续。' }, ...toApiMessages(nextId, c.messages)];
			lastResponse = await aiInvoke(nextMessages);
			if (c.cancelled) return;
			const nIdx = c.messages.findIndex((m) => m.id === nextId);
			if (nIdx !== -1) c.messages[nIdx].content = lastResponse;
			rounds++;
		}
		if (!c.cancelled && rounds >= MAX_AUTO_ROUNDS && extractExecutableBlocks(lastResponse).length > 0) {
			c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 已达到自动执行轮次上限（${MAX_AUTO_ROUNDS} 轮），后续命令请手动点击“运行”。`, timestamp: Date.now() });
		}
	} catch (e) { if (c.cancelled) return; c.error = String(e); }
	finally { c.loading = false; c.active = false; }
}

/** 一键执行全部命令。 */
export async function executeAllCommands(content: string, bufferId: string, tabType: 'ssh' | 'local', connectionId?: string): Promise<void> {
	const contextId = currentContextId;
	if (executionMode === 'plan-only') { ctx(contextId).error = '纯计划模式，禁止执行。'; return; }
	const commands = extractCodeBlocks(content);
	if (commands.length === 0) return;
	const c = ctx(contextId);
	const terminal: TerminalInfo = { bufferId, tabType, connectionId };
	c.loading = true; c.active = true; c.error = undefined; c.cancelled = false;
	let allOutput = '';
	let paused = false;
	try {
		for (let i = 0; i < commands.length && !c.cancelled && !gateFor(contextId).pending; i++) {
			await waitForInput(contextId);
			const cmd = commands[i];
			const needsConfirmation = executionMode === 'full-auto'
				? requiresManualInput(cmd)
				: (isDangerousCommand(cmd) || isInteractiveMultiLine(cmd));
			if (needsConfirmation) {
				c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[待确认] 高危命令：\n\n${mdCode(cmd, 'bash')}`, timestamp: Date.now() });
				break;
			}
			if (!(await waitUntilTerminalIdle(terminal))) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 终端上一条命令仍在运行（未出现 shell 提示符）。为避免把新命令输入到运行中的终端，批量执行已暂停；请等待命令结束后重试。`, timestamp: Date.now() });
				paused = true;
				break;
			}
			c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[批量执行 ${i + 1}/${commands.length}]\n\n${mdCode(cmd, 'bash')}`, timestamp: Date.now() });
			const result = await captureCommandOutput(cmd, terminal, contextId);
			if (c.cancelled) return;
			const output = result.output;
			c.messages[c.messages.length - 1].content = `[批量执行 ${i + 1}/${commands.length}]\n\n${mdCode(cmd, 'bash')}\n\n输出：\n\n${mdCode(output, 'text')}`;
			allOutput += `\n### 命令 ${i + 1}: \`${cmd}\`\n\n${mdCode(output, 'text')}\n`;
			if (result.sessionClosed) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[会话已结束] 终端连接已断开，批量执行已停止。`, timestamp: Date.now() });
				paused = true;
				break;
			}
			if (!result.completed) {
				c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[已暂停] 第 ${i + 1} 条命令在等待时间内没有返回 shell 提示符，可能仍在运行。为避免继续输入，批量执行已停止；请等待命令结束或手动处理后重试。`, timestamp: Date.now() });
				paused = true;
				break;
			}
		}
		if (paused) return;
		const assistantId = crypto.randomUUID();
		c.messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });
		const sysPrompt = buildSystemPrompt({ terminalOutput: allOutput }) + modeInstruction(executionMode);
		const apiMessages = [{ role: 'system', content: sysPrompt }, ...toApiMessages(assistantId, c.messages)];
		const analysis = await aiInvoke(apiMessages);
		if (c.cancelled) return;
		const aidx = c.messages.findIndex((m) => m.id === assistantId);
		if (aidx !== -1) c.messages[aidx].content = analysis;
	} catch (e) { if (c.cancelled) return; c.error = String(e); }
	finally { c.loading = false; c.active = false; }
}
