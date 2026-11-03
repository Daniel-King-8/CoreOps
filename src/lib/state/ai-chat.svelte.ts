import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getAISettings, resolveApiBase } from './ai.svelte.js';
import { sshSend } from '#lib/ipc/ssh.js';
import { ptyWrite } from '#lib/ipc/pty.js';

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

// ── Human In The Loop：交互式命令输入门控 ──
let inputPending = $state(false);
let inputLabel = $state('');
let inputType: 'password' | 'confirmation' | 'generic' = 'generic';
let inputResolver: ((val: string) => void) | null = null;
let gatePaused = false;
let gateResume: (() => void) | null = null;

export function getInputPending(): boolean { return inputPending; }
export function getInputLabel(): string { return inputLabel; }
export function getInputType(): string { return inputType; }

async function waitForInput(): Promise<void> {
	if (!inputPending && !gatePaused) return;
	console.log('[GATE] Execution paused for user input');
	return new Promise<void>((resolve) => { gateResume = resolve; });
}

function releaseGate(): void {
	gatePaused = false;
	if (gateResume) { const cb = gateResume; gateResume = null; cb(); }
}

export function submitUserInput(val: string): void {
	releaseGate();
	if (inputResolver) { const r = inputResolver; inputResolver = null; inputPending = false; r(val); }
}

export function cancelInput(): void {
	releaseGate();
	if (inputResolver) { const r = inputResolver; inputResolver = null; inputPending = false; r(''); }
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
	const c = ctx(currentContextId); c.cancelled = true; c.active = false; c.loading = false;
	c.messages.push({ id: crypto.randomUUID(), role: 'assistant', content: `[操作已打断] 用户手动中止了执行。`, timestamp: Date.now() });
}

export function removeTabContext(tabId: string): void {
	delete contexts[tabId];
	if (currentContextId === tabId) currentContextId = 'default';
	if (!contexts.default) contexts.default = freshContext();
}
export function toggleAIPanel(): void { panelOpen = !panelOpen; }
export function openAIPanel(): void { panelOpen = true; }
export function closeAIPanel(): void { panelOpen = false; }

export function clearChat(): void {
	const c = ctx(currentContextId); c.messages.length = 0; c.error = undefined; c.loading = false; c.cancelled = true;
}

// ── 工具函数 ──
function buildSystemPrompt(context?: { connectionId?: string; host?: string; username?: string; os?: string; terminalOutput?: string }): string {
	let prompt =
		'你是一位资深 Linux 运维专家，内嵌在 CoreOps SSH 客户端中。请用简洁专业的中文回答用户问题。' +
		'你精通 Linux/Unix 系统管理、Shell 脚本、网络排查、Docker/K8s 容器编排、性能调优等运维领域。' +
		'当需要建议用户执行命令时，务必使用 ```bash 代码块包裹，以便系统自动提取并注入终端执行。' +
		'重要安全规则：如果命令需要 sudo 权限，只需在 ```bash 代码块中给出标准命令（如 sudo apt update），系统会自动检测并暂停等待用户授权。禁止使用 sudo -n、echo password | sudo -S、su、pkexec 等方式绕过密码。';
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
		case 'auto-edit': return '\n\n当前运行模式：自动编辑模式。可修改配置文件，危险命令需用户确认。';
		case 'full-auto': return '\n\n当前运行模式：全自动模式。可自由执行，但遇到交互提示时会暂停等待用户授权。';
		default: return '';
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

function extractCodeBlocks(content: string): string[] {
	const blocks: string[] = [];
	const regex = /```(?:bash|sh|shell|zsh|console|terminal)?\n([\s\S]*?)```/g;
	let match;
	while ((match = regex.exec(content)) !== null) { const code = match[1].trim(); if (code) blocks.push(code); }
	return blocks;
}

export function collectCodeBlocks(content: string): string[] { return extractCodeBlocks(content); }

function isDangerousCommand(command: string): boolean {
	const d = [/\b(systemctl|service|supervisorctl)\s/, /\b(apt|apt-get|yum|dnf|pacman|zypper|apk|brew|pip\d*|npm|cargo|snap|flatpak)\s/,
		/\b(kill|pkill|killall|reboot|shutdown|halt|poweroff)\b/, /\brm\s+-rf\b/,
		/\b(docker|podman)\s+(stop|rm|kill|restart|down|compose\s+down)\b/, /\bkubectl\s+delete\b/,
		/\b(iptables|firewall-cmd|ufw)\s/, /\b(mount|umount|mkfs|fdisk|parted|wipefs)\b/,
		/\b(init)\s+[0-6]\b/, /\bdpkg\s/, /\brpm\s.*(--?e|--?erase)\b/];
	return d.some((r) => r.test(command.trim()));
}

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

async function captureCommandOutput(command: string, terminal: TerminalInfo): Promise<string> {
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
		if (isSsh && !inputPending && outputBuffer.length > 8) {
			const cleaned = stripAnsi(outputBuffer);
			const lines = cleaned.split('\n');
			const lastLine = lines.filter(l => l.trim()).pop() || '';
			if (/\[sudo\].*?(?:password|密码).*[:：]/.test(cleaned)) {
				inputType = 'password'; inputLabel = 'sudo 密码认证'; inputPending = true; gatePaused = true;
			} else if (/^.*password\s*[:：]/i.test(lastLine)) {
				inputType = 'password'; inputLabel = '密码'; inputPending = true; gatePaused = true;
			} else if (/\[y\/n\]|\(y\/n\)/i.test(lastLine)) {
				inputType = 'confirmation'; inputLabel = '确认 [y/N]'; inputPending = true; gatePaused = true;
			} else if (/(?:press|按).*(?:enter|any key|回车|任意键)/i.test(lastLine)) {
				inputType = 'generic'; inputLabel = '按回车继续'; inputPending = true; gatePaused = true;
			} else if (/^(?:enter choice|请选择|请输入).*[:：]/im.test(lastLine)) {
				inputType = 'generic'; inputLabel = '输入'; inputPending = true; gatePaused = true;
			}
		}
	});

	const encoded = Array.from(new TextEncoder().encode(command + '\n'));
	if (isSsh) await sshSend(terminal.connectionId!, encoded);
	else await ptyWrite(terminal.bufferId, encoded);

	let lastLength = 0, stableCount = 0, hadData = false;
	for (let i = 0; i < 120; i++) {
		await new Promise((r) => setTimeout(r, 500));
		if (isSsh && inputPending && !inputResolver) {
			chunks.length = 0;
			outputBuffer = "";
			const val = await new Promise<string>((resolve) => { inputResolver = resolve; });
			if (!val) break;
			await sshSend(terminal.connectionId!, Array.from(new TextEncoder().encode(val + '\n')));
			lastLength = 0; stableCount = 0;
		}
		if (chunks.length > 0) hadData = true;
		if (chunks.length > lastLength) { lastLength = chunks.length; stableCount = 0; }
		else if (hadData) { stableCount++; if (stableCount >= 6) break; }
	}
	unlisten?.();

	const cleanOutput = stripAnsi(chunks.join('')).replace(/\[sudo\].*(?:password|密码).*[:：]?\n?/g, '').trim();
	const lines = cleanOutput.split('\n');
	const cmdTrimmed = command.trim();
	let startIdx = 0;
	for (let i = 0; i < Math.min(lines.length, 8); i++) { if (lines[i].includes(cmdTrimmed)) { startIdx = i + 1; break; } }
	let endIdx = lines.length;
	while (endIdx > startIdx && /^[^a-zA-Z0-9]*[$#>]\s*$/.test(lines[endIdx - 1])) endIdx--;
	const extracted = lines.slice(startIdx, endIdx).join('\n').trim();
	return extracted.length >= 3 ? extracted : cleanOutput.trim() || '（无输出）';
}

function runCommandInTerminal(command: string, terminal: TerminalInfo): Promise<string> { return captureCommandOutput(command, terminal); }
function canAutoExec(): boolean { return executionMode === 'auto-edit' || executionMode === 'full-auto'; }

/** 用户发送聊天消息（主入口）。 */
export async function sendMessage(
	prompt: string,
	context?: { connectionId?: string; host?: string; username?: string; os?: string; terminalOutput?: string },
	terminal?: TerminalInfo
): Promise<void> {
	const settings = getAISettings();
	if (!settings.enabled || !settings.apiKey || !settings.selectedModel) { ctx(currentContextId).error = 'AI 未配置'; return; }
	const c = ctx(currentContextId);
	c.messages.push({ id: crypto.randomUUID(), role: 'user', content: prompt, timestamp: Date.now() });
	const assistantId = crypto.randomUUID();
	c.messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });
	c.loading = true; c.active = true; c.error = undefined; c.cancelled = false;

	try {
		const systemPrompt = buildSystemPrompt(context) + modeInstruction(executionMode);
		let hint = '';
		if (terminal) {
			if (executionMode === 'full-auto') hint = '\n\n已接入终端且处于全自动模式。遇到交互提示时系统会自动暂停等待用户授权。';
			else hint = '\n\n已接入终端。建议命令用 ```bash 包裹。';
		}
		const apiMessages = [{ role: 'system', content: systemPrompt + hint }, ...toApiMessages(assistantId, c.messages)];
		const content = await aiInvoke(apiMessages);
		if (c.cancelled) return;
		const idx = c.messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1) c.messages[idx].content = content;

		if (terminal && canAutoExec() && !c.cancelled) {
			let lastResponse = content; let rounds = 0;
			while (rounds < 6 && !c.cancelled) {
				await waitForInput();
				const codeBlocks = extractCodeBlocks(lastResponse);
				if (codeBlocks.length === 0) break;
				const cmd = codeBlocks[0];
				if (executionMode === 'auto-edit' && isDangerousCommand(cmd)) {
					c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[待确认] 高危命令：\`\`\`bash\n${cmd}\n\`\`\``, timestamp: Date.now() });
					break;
				}
				const output = await runCommandInTerminal(cmd, terminal);
				if (c.cancelled) return;
				c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[自动执行] \`${cmd}\`\n\n输出：\n\`\`\`\n${output}\n\`\`\``, instruction: '分析以上输出。', timestamp: Date.now() });
				const nextId = crypto.randomUUID();
				c.messages.push({ id: nextId, role: 'assistant', content: '', timestamp: Date.now() });
				const nextMessages = [{ role: 'system', content: systemPrompt + hint + '\n\n继续。' }, ...toApiMessages(nextId, c.messages)];
				lastResponse = await aiInvoke(nextMessages);
				if (c.cancelled) return;
				const nIdx = c.messages.findIndex((m) => m.id === nextId);
				if (nIdx !== -1) c.messages[nIdx].content = lastResponse;
				rounds++;
			}
		}
	} catch (e) { if (c.cancelled) return; c.error = String(e); const idx = c.messages.findIndex((m) => m.id === assistantId); if (idx !== -1 && !c.messages[idx].content) c.messages.splice(idx, 1); }
	finally { c.loading = false; c.active = false; }
}

/** 点击代码块执行按钮。 */
export async function executeCommand(command: string, bufferId: string, tabType: 'ssh' | 'local', connectionId?: string, context?: { host?: string; username?: string; os?: string }): Promise<void> {
	if (executionMode === 'plan-only') { ctx(currentContextId).error = '纯计划模式，禁止执行。'; return; }
	if (inputPending) return;
	const c = ctx(currentContextId);
	const terminal: TerminalInfo = { bufferId, tabType, connectionId };
	const userMsgId = crypto.randomUUID();
	c.messages.push({ id: userMsgId, role: 'user', content: `执行命令：\`${command}\``, timestamp: Date.now() });
	c.loading = true; c.active = true; c.error = undefined; c.cancelled = false;
	try {
		const output = await captureCommandOutput(command, terminal);
		if (c.cancelled) return;
		const userMsgIdx = c.messages.findIndex((m) => m.id === userMsgId);
		if (userMsgIdx !== -1) c.messages[userMsgIdx].content = `已执行：\`${command}\`\n\`\`\`\n${output}\n\`\`\``;
		const assistantId = crypto.randomUUID();
		c.messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });
		const sysPrompt = buildSystemPrompt(context ? { ...context, terminalOutput: output } : { terminalOutput: output }) + modeInstruction(executionMode);
		const apiMessages = [{ role: 'system', content: sysPrompt }, ...toApiMessages(assistantId, c.messages)];
		const content = await aiInvoke(apiMessages);
		if (c.cancelled) return;
		const idx = c.messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1) c.messages[idx].content = content;
		if (!canAutoExec()) return;
		let lastResponse = content; let rounds = 0;
		while (rounds < 5 && !c.cancelled) {
			await waitForInput();
			const moreCmds = extractCodeBlocks(lastResponse);
			if (moreCmds.length === 0) break;
			const cmd = moreCmds[0];
			if (executionMode === 'auto-edit' && isDangerousCommand(cmd)) { c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[待确认] \`\`\`bash\n${cmd}\n\`\`\``, timestamp: Date.now() }); break; }
			const cmdOutput = await runCommandInTerminal(cmd, terminal);
			if (c.cancelled) return;
			c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[自动执行] \`${cmd}\`\n\`\`\`\n${cmdOutput}\n\`\`\``, instruction: '分析输出。', timestamp: Date.now() });
			const nextId = crypto.randomUUID();
			c.messages.push({ id: nextId, role: 'assistant', content: '', timestamp: Date.now() });
			const nextMessages = [{ role: 'system', content: sysPrompt + '\n\n继续。' }, ...toApiMessages(nextId, c.messages)];
			lastResponse = await aiInvoke(nextMessages);
			if (c.cancelled) return;
			const nIdx = c.messages.findIndex((m) => m.id === nextId);
			if (nIdx !== -1) c.messages[nIdx].content = lastResponse;
			rounds++;
		}
	} catch (e) { if (c.cancelled) return; c.error = String(e); }
	finally { c.loading = false; c.active = false; }
}

/** 一键执行全部命令。 */
export async function executeAllCommands(content: string, bufferId: string, tabType: 'ssh' | 'local', connectionId?: string): Promise<void> {
	if (executionMode === 'plan-only') { ctx(currentContextId).error = '纯计划模式，禁止执行。'; return; }
	const commands = extractCodeBlocks(content);
	if (commands.length === 0) return;
	const c = ctx(currentContextId);
	const terminal: TerminalInfo = { bufferId, tabType, connectionId };
	c.loading = true; c.active = true; c.error = undefined; c.cancelled = false;
	let allOutput = '';
	try {
		for (let i = 0; i < commands.length && !c.cancelled && !inputPending; i++) {
			await waitForInput();
			const cmd = commands[i];
			c.messages.push({ id: crypto.randomUUID(), role: 'user', content: `[批量执行 ${i + 1}/${commands.length}] \`${cmd}\``, timestamp: Date.now() });
			const output = await captureCommandOutput(cmd, terminal);
			if (c.cancelled) return;
			c.messages[c.messages.length - 1].content = `[批量执行 ${i + 1}/${commands.length}] \`${cmd}\`\n\`\`\`\n${output}\n\`\`\``;
			allOutput += `\n### 命令 ${i + 1}: \`${cmd}\`\n\`\`\`\n${output}\n\`\`\`\n`;
		}
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
