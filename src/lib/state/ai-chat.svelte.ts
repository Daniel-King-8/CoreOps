import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getAISettings } from './ai.svelte';
import { readTerminalBuffer } from './terminal-buffer.svelte';
import { sshSend } from '$lib/ipc/ssh';
import { ptyWrite } from '$lib/ipc/pty';

// ── 执行模式 ──
export type ExecutionMode = 'normal' | 'plan-only' | 'auto-edit' | 'full-auto';

const MODE_STORAGE_KEY = 'reach-ai-exec-mode';

let executionMode = $state<ExecutionMode>('normal');

function loadMode(): ExecutionMode {
	if (typeof localStorage !== 'undefined') {
		const saved = localStorage.getItem(MODE_STORAGE_KEY);
		if (saved === 'normal' || saved === 'plan-only' || saved === 'auto-edit' || saved === 'full-auto') {
			return saved;
		}
	}
	return 'normal';
}
executionMode = loadMode();

export function getExecutionMode(): ExecutionMode {
	return executionMode;
}

export function setExecutionMode(mode: ExecutionMode): void {
	executionMode = mode;
	if (typeof localStorage !== 'undefined') {
		localStorage.setItem(MODE_STORAGE_KEY, mode);
	}
}

// ── 聊天消息 ──
export interface AIChatMessage {
	id: string;
	role: 'user' | 'assistant';
	content: string;
	instruction?: string;
	timestamp: number;
}

let messages = $state<AIChatMessage[]>([]);
let loading = $state(false);
let active = $state(false);
let error = $state<string | undefined>();
let panelOpen = $state(false);

let cancelled = false;

export function getAIChatState() {
	return { messages, loading, active, error, panelOpen };
}

export function getActive(): boolean {
	return active;
}

export function abortActiveSession(): void {
	cancelled = true;
	active = false;
	loading = false;
	messages.push({
		id: crypto.randomUUID(),
		role: 'assistant',
		content: `[操作已打断] 用户手动中止了执行。`,
		timestamp: Date.now()
	});
}

export function toggleAIPanel(): void {
	panelOpen = !panelOpen;
}

export function openAIPanel(): void {
	panelOpen = true;
}

export function closeAIPanel(): void {
	panelOpen = false;
}

export function clearChat(): void {
	messages.length = 0;
	error = undefined;
	loading = false;
	cancelled = true;
}

/** 构建中文高级 Linux 运维专家的 system prompt。 */
function buildSystemPrompt(context?: {
	connectionId?: string;
	host?: string;
	username?: string;
	os?: string;
	terminalOutput?: string;
}): string {
	let prompt =
		'你是一位资深 Linux 运维专家，内嵌在 CoreOps SSH 客户端中。请用简洁专业的中文回答用户问题。' +
		'你精通 Linux/Unix 系统管理、Shell 脚本、网络排查、Docker/K8s 容器编排、性能调优等运维领域。' +
		'当需要建议用户执行命令时，务必使用 ```bash 代码块包裹，以便系统自动提取并注入终端执行。';

	if (context?.host || context?.username || context?.os) {
		prompt += '\n\n当前会话信息：';
		if (context.host) prompt += `\n- 主机：${context.host}`;
		if (context.username) prompt += `\n- 用户：${context.username}`;
		if (context.os) prompt += `\n- 系统：${context.os}`;
	}

	if (context?.terminalOutput) {
		prompt += `\n\n终端最近输出如下：\n\`\`\`\n${context.terminalOutput}\n\`\`\``;
	}

	return prompt;
}

/** 根据执行模式追加系统指令。 */
function modeInstruction(mode: ExecutionMode): string {
	switch (mode) {
		case 'plan-only':
			return '\n\n当前运行模式：纯计划模式。你只能分析问题、诊断原因、制定排查方案。绝对不能建议任何命令，即使用 ```bash 代码块给出命令也不行。请在分析完成后用中文总结你的排查计划。';
		case 'auto-edit':
			return '\n\n当前运行模式：自动编辑模式。你可以自由读取系统状态并自动修改配置文件（如 nginx.conf、/etc/hosts 等），但不得重启服务或运行可能影响线上服务的危险命令。当需要执行涉及服务启停的命令时，请先显式询问用户确认。';
		case 'full-auto':
			return '\n\n当前运行模式：全自动模式。你拥有完整权限，可以自由读取系统信息、修改配置、执行任何命令，全程无需用户确认。';
		default:
			return '';
	}
}

/**
 * 将 messages 数组转换为发送给大模型的 API 消息列表。
 * 会把 instruction 字段拼接到 content 末尾（仅对 AI 可见）。
 */
function toApiMessages(skipId: string): { role: string; content: string }[] {
	return messages
		.filter((m) => m.id !== skipId)
		.map((m) => ({
			role: m.role,
			content: m.instruction ? `${m.content}\n\n${m.instruction}` : m.content
		}));
}

/** 调用 AI API（通过 Tauri invoke 转发到 Rust 后端 HTTP 客户端）。 */
async function aiInvoke(apiMessages: { role: string; content: string }[]): Promise<string> {
	const settings = getAISettings();
	if (!settings.enabled || !settings.apiKey || !settings.selectedModel) {
		throw new Error('AI 未配置，请前往 设置 → AI 填写 API Key 和模型。');
	}

	return invoke<string>('ai_chat', {
		request: {
			url: settings.apiUrl + '/chat/completions',
			apiKey: settings.apiKey,
			model: settings.selectedModel,
			messages: apiMessages
		}
	});
}

export interface TerminalInfo {
	bufferId: string;
	tabType: 'ssh' | 'local';
	connectionId?: string;
}

/** 从 AI 回复中提取 ```bash 代码块，供自动执行使用。 */
function extractCodeBlocks(content: string): string[] {
	const blocks: string[] = [];
	const regex = /```(?:bash|sh|shell|zsh|console|terminal)?\n([\s\S]*?)```/g;
	let match;
	while ((match = regex.exec(content)) !== null) {
		const code = match[1].trim();
		if (code) blocks.push(code);
	}
	return blocks;
}

/** 从消息内容中提取所有可执行 bash 代码块（供一键执行面板使用）。 */
export function collectCodeBlocks(content: string): string[] {
	return extractCodeBlocks(content);
}

/** 判断命令是否属于高危险操作（服务控制 / 包管理 / 重启 / 删除等）。 */
function isDangerousCommand(command: string): boolean {
	const cmd = command.trim();
	const dangerous = [
		/\b(systemctl|service|supervisorctl)\s/,
		/\b(apt|apt-get|yum|dnf|pacman|zypper|apk|brew|pip\d*|npm|cargo|snap|flatpak)\s/,
		/\b(kill|pkill|killall|reboot|shutdown|halt|poweroff)\b/,
		/\brm\s+-rf\b/,
		/\b(docker|podman)\s+(stop|rm|kill|restart|down|compose\s+down)\b/,
		/\bkubectl\s+delete\b/,
		/\b(iptables|firewall-cmd|ufw)\s/,
		/\b(mount|umount|mkfs|fdisk|parted|wipefs)\b/,
		/\b(init)\s+[0-6]\b/,
		/\bdpkg\s/,
		/\brpm\s.*(--?e|--?erase)\b/,
	];
	return dangerous.some((r) => r.test(cmd));
}

function decodePayload(payload: unknown): string {
	if (payload instanceof Uint8Array) return new TextDecoder().decode(payload);
	if (Array.isArray(payload)) return new TextDecoder().decode(new Uint8Array(payload));
	if (typeof payload === 'string') return payload;
	return '';
}

function stripAnsi(str: string): string {
	return str
		.replace(/\x1b\[[\d;?]*[A-Za-z]/g, '')
		.replace(/\x1b\].*?(\x07|\x1b\\)/g, '')
		.replace(/\x1b[PX^_].*?\x1b\\/g, '')
		.replace(/\x1b[=>]/g, '')
		.replace(/\x1b[^\[\]]/g, '')
		.replace(/\r\n/g, '\n')
		.replace(/\r/g, '\n');
}

/** 将命令注入终端并捕获输出结果。最长等待 60 秒，3 秒无新数据判定结束。 */
async function captureCommandOutput(command: string, terminal: TerminalInfo): Promise<string> {
	const eventId =
		terminal.tabType === 'ssh' && terminal.connectionId
			? terminal.connectionId
			: terminal.bufferId;
	const eventName = terminal.tabType === 'ssh' ? `ssh-data-${eventId}` : `pty-data-${eventId}`;

	const chunks: string[] = [];
	let unlisten: UnlistenFn | undefined;

	unlisten = await listen<unknown>(eventName, (event) => {
		const text = decodePayload(event.payload);
		if (text) chunks.push(text);
	});

	const encoded = Array.from(new TextEncoder().encode(command + '\n'));
	if (terminal.tabType === 'ssh' && terminal.connectionId) {
		await sshSend(terminal.connectionId, encoded);
	} else {
		await ptyWrite(terminal.bufferId, encoded);
	}

	let lastLength = 0;
	let stableCount = 0;
	let hadData = false;

	for (let i = 0; i < 120; i++) {
		await new Promise((r) => setTimeout(r, 500));
		const currentLength = chunks.length;
		if (currentLength > 0) hadData = true;
		if (currentLength > lastLength) {
			lastLength = currentLength;
			stableCount = 0;
		} else if (hadData) {
			stableCount++;
			if (stableCount >= 6) break;
		}
	}

	unlisten?.();

	const rawOutput = chunks.join('');
	const cleanOutput = stripAnsi(rawOutput);

	const lines = cleanOutput.split('\n');
	const cmdTrimmed = command.trim();

	let startIdx = 0;
	for (let i = 0; i < Math.min(lines.length, 8); i++) {
		if (lines[i].includes(cmdTrimmed)) {
			startIdx = i + 1;
			break;
		}
	}

	let endIdx = lines.length;
	while (endIdx > startIdx && /^[^a-zA-Z0-9]*[$#>]\s*$/.test(lines[endIdx - 1])) {
		endIdx--;
	}

	const outputLines = lines.slice(startIdx, endIdx);
	const extracted = outputLines.join('\n').trim();

	if (extracted.length < 3) {
		return cleanOutput.trim() || '（无输出）';
	}

	return extracted;
}

async function runCommandInTerminal(command: string, terminal: TerminalInfo): Promise<string> {
	return captureCommandOutput(command, terminal);
}

/** 当前模式是否允许自动执行。 */
function canAutoExec(): boolean {
	return executionMode === 'auto-edit' || executionMode === 'full-auto';
}

/** 用户发送聊天消息（主入口）。 */
export async function sendMessage(
	prompt: string,
	context?: {
		connectionId?: string;
		host?: string;
		username?: string;
		os?: string;
		terminalOutput?: string;
	},
	terminal?: TerminalInfo
): Promise<void> {
	const settings = getAISettings();
	if (!settings.enabled || !settings.apiKey || !settings.selectedModel) {
		error = 'AI 未配置，请前往 设置 → AI 填写 API Key 和模型。';
		return;
	}

	messages.push({
		id: crypto.randomUUID(),
		role: 'user',
		content: prompt,
		timestamp: Date.now()
	});

	const assistantId = crypto.randomUUID();
	messages.push({
		id: assistantId,
		role: 'assistant',
		content: '',
		timestamp: Date.now()
	});

	loading = true;
	active = true;
	error = undefined;
	cancelled = false;

	try {
		const systemPrompt = buildSystemPrompt(context) + modeInstruction(executionMode);
		let autoExecHint = '';

		if (terminal) {
			if (executionMode === 'plan-only') {
				// 纯计划模式：不带终端上下文
			} else if (executionMode === 'full-auto') {
				autoExecHint = '\n\n你已接入真实终端且处于全自动模式。建议命令时请用 ```bash 包裹，系统会自动执行。';
			} else if (executionMode === 'auto-edit') {
				autoExecHint = '\n\n你已接入真实终端且处于自动编辑模式。系统会自动执行配置修改类命令，运行/重启服务类命令请等待用户确认。';
			} else {
				// normal：不带自动执行提示
				autoExecHint = '\n\n你已接入真实终端。建议命令时请用 ```bash 包裹，用户可以手动选择执行。';
			}
		}

		const apiMessages = [
			{ role: 'system', content: systemPrompt + autoExecHint },
			...toApiMessages(assistantId)
		];

		const content = await aiInvoke(apiMessages);
		if (cancelled) return;

		const idx = messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1) messages[idx].content = content;

		// 自动执行：仅在 auto-edit / full-auto 模式下且存在终端时
		if (terminal && canAutoExec() && !cancelled) {
			let lastResponse = content;
			let rounds = 0;

			while (rounds < 6 && !cancelled) {
				const codeBlocks = extractCodeBlocks(lastResponse);
				if (codeBlocks.length === 0) break;

				const command = codeBlocks[0];

				// 自动编辑模式：危险命令阻断，改为待确认
				if (executionMode === 'auto-edit' && isDangerousCommand(command)) {
					messages.push({
						id: crypto.randomUUID(),
						role: 'user',
						content: `[待确认] AI 建议执行以下命令（涉及系统服务/包管理，请手动确认）：\n\`\`\`bash\n${command}\n\`\`\``,
						timestamp: Date.now()
					});
					break; // 停止自动执行，等待用户手动点击 Run
				}

				const output = await runCommandInTerminal(command, terminal);
				if (cancelled) return;

				messages.push({
					id: crypto.randomUUID(),
					role: 'user',
					content: `[自动执行] \`${command}\`\n\n输出结果：\n\`\`\`\n${output}\n\`\`\``,
					instruction:
						'请分析以上输出。如果还需要进一步排查，请在 ```bash 代码块中给出下一条命令；如果问题已解决，请用中文总结排查结论，不要包含代码块。',
					timestamp: Date.now()
				});

				const nextId = crypto.randomUUID();
				messages.push({ id: nextId, role: 'assistant', content: '', timestamp: Date.now() });

				const nextMessages = [
					{
						role: 'system',
						content:
							systemPrompt + autoExecHint +
							'\n\n你正在真实终端上执行命令并接收输出。请分析输出结果。如果需要继续，用 ```bash 代码块给出下一条命令（每次一条）；如果任务已完成，请用中文总结，不要包含代码块。'
					},
					...toApiMessages(nextId)
				];

				lastResponse = await aiInvoke(nextMessages);
				if (cancelled) return;

				const nIdx = messages.findIndex((m) => m.id === nextId);
				if (nIdx !== -1) messages[nIdx].content = lastResponse;
				rounds++;
			}
		}
	} catch (e) {
		if (cancelled) return;
		error = String(e);
		const idx = messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1 && !messages[idx].content) messages.splice(idx, 1);
	} finally {
		loading = false;
			active = false;
	}
}

/** 用户点击代码块「执行」按钮后触发：注入命令 → 捕获输出 → AI 分析。 */
export async function executeCommand(
	command: string,
	bufferId: string,
	tabType: 'ssh' | 'local',
	connectionId?: string,
	context?: { host?: string; username?: string; os?: string }
): Promise<void> {
	// 纯计划模式：阻止执行
	if (executionMode === 'plan-only') {
		error = '当前处于纯计划模式，不允许执行命令。请切换到其他模式。';
		return;
	}

	const terminal: TerminalInfo = { bufferId, tabType, connectionId };

	const userMsgId = crypto.randomUUID();
	messages.push({
		id: userMsgId,
		role: 'user',
		content: `执行命令：\`${command}\`\n\n正在等待输出...`,
		timestamp: Date.now()
	});

	loading = true;
	active = true;
	error = undefined;
	cancelled = false;

	try {
		const output = await captureCommandOutput(command, terminal);
		if (cancelled) return;

		const userMsgIdx = messages.findIndex((m) => m.id === userMsgId);
		if (userMsgIdx !== -1) messages[userMsgIdx].content = `已执行：\`${command}\`\n\n输出结果：\n\`\`\`\n${output}\n\`\`\``;

		const assistantId = crypto.randomUUID();
		messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });

		const sysPrompt = buildSystemPrompt(
			context ? { ...context, terminalOutput: output } : { terminalOutput: output }
		) + modeInstruction(executionMode);

		const apiMessages = [
			{ role: 'system', content: sysPrompt },
			...toApiMessages(assistantId)
		];

		const content = await aiInvoke(apiMessages);
		if (cancelled) return;

		const idx = messages.findIndex((m) => m.id === assistantId);
		if (idx !== -1) messages[idx].content = content;

		// 自动执行后续命令：仅 auto-edit / full-auto
		if (!canAutoExec()) return;

		let lastResponse = content;
		let rounds = 0;
		while (rounds < 5 && !cancelled) {
			const moreCmds = extractCodeBlocks(lastResponse);
			if (moreCmds.length === 0) break;

			const cmd = moreCmds[0];

			// 自动编辑模式：危险命令阻断，改为待确认
			if (executionMode === 'auto-edit' && isDangerousCommand(cmd)) {
				messages.push({
					id: crypto.randomUUID(),
					role: 'user',
					content: `[待确认] AI 建议执行以下命令（涉及系统服务/包管理，请手动确认）：\n\`\`\`bash\n${cmd}\n\`\`\``,
					timestamp: Date.now()
				});
				break;
			}

			const cmdOutput = await runCommandInTerminal(cmd, terminal);
			if (cancelled) return;

			messages.push({
				id: crypto.randomUUID(),
				role: 'user',
				content: `[自动执行] \`${cmd}\`\n\n输出结果：\n\`\`\`\n${cmdOutput}\n\`\`\``,
				instruction: '请分析以上输出。如果还需要继续，用 ```bash 代码块给出下一条命令；如果已完成，请用中文总结，不要包含代码块。',
				timestamp: Date.now()
			});

			const nextId = crypto.randomUUID();
			messages.push({ id: nextId, role: 'assistant', content: '', timestamp: Date.now() });

			const nextMessages = [
				{
					role: 'system',
					content:
						sysPrompt +
						'\n\n请分析命令输出。如果还需要继续，用 ```bash 代码块给出下一条命令；如果已完成，请用中文总结，不要包含代码块。'
				},
				...toApiMessages(nextId)
			];

			lastResponse = await aiInvoke(nextMessages);
			if (cancelled) return;

			const nIdx = messages.findIndex((m) => m.id === nextId);
			if (nIdx !== -1) messages[nIdx].content = lastResponse;
			rounds++;
		}
	} catch (e) {
		if (cancelled) return;
		error = String(e);
	} finally {
		loading = false;
		active = false;
	}
}

/** 一键执行：从消息内容中提取所有 bash 代码块，顺次注入终端执行。供普通模式一键面板调用。 */
export async function executeAllCommands(
	content: string,
	bufferId: string,
	tabType: 'ssh' | 'local',
	connectionId?: string
): Promise<void> {
	const commands = extractCodeBlocks(content);
	if (commands.length === 0) return;

	const terminal: TerminalInfo = { bufferId, tabType, connectionId };
	loading = true;
	active = true;
	error = undefined;
	cancelled = false;

	let allOutput = '';

	try {
		for (let i = 0; i < commands.length && !cancelled; i++) {
			const cmd = commands[i];
			messages.push({
				id: crypto.randomUUID(),
				role: 'user',
				content: `[批量执行 ${i + 1}/${commands.length}] \`${cmd}\``,
				timestamp: Date.now()
			});

			const output = await captureCommandOutput(cmd, terminal);
			if (cancelled) return;

			const idx = messages.length - 1;
			messages[idx].content = `[批量执行 ${i + 1}/${commands.length}] \`${cmd}\`\n\`\`\`\n${output}\n\`\`\``;
			allOutput += `\n### 命令 ${i + 1}: \`${cmd}\`\n\`\`\`\n${output}\n\`\`\`\n`;
		}

		// 全部执行完毕后，让 AI 分析汇总结果
		const assistantId = crypto.randomUUID();
		messages.push({ id: assistantId, role: 'assistant', content: '', timestamp: Date.now() });

		const sysPrompt = buildSystemPrompt({ terminalOutput: allOutput }) + modeInstruction(executionMode);
		const apiMessages = [
			{ role: 'system', content: sysPrompt },
			...toApiMessages(assistantId)
		];

		const analysis = await aiInvoke(apiMessages);
		if (cancelled) return;

		const aidx = messages.findIndex((m) => m.id === assistantId);
		if (aidx !== -1) messages[aidx].content = analysis;
	} catch (e) {
		if (cancelled) return;
		error = String(e);
	} finally {
		loading = false;
		active = false;
	}
}
