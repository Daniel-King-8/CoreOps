<script lang="ts">
	import { getAIChatState, sendMessage, executeCommand, executeAllCommands, collectCodeBlocks, closeAIPanel, clearChat, getExecutionMode, setExecutionMode, getActive, abortActiveSession, type ExecutionMode, type TerminalInfo } from '$lib/state/ai-chat.svelte';
	import { getAISettings } from '$lib/state/ai.svelte';
	import { getSessionList } from '$lib/state/sessions.svelte';
	import { readTerminalBuffer } from '$lib/state/terminal-buffer.svelte';
	import { t } from '$lib/state/i18n.svelte';

	interface Props {
		connectionId?: string;
		activeTabId?: string;
		activeTabType?: 'local' | 'ssh';
	}

	let { connectionId, activeTabId, activeTabType }: Props = $props();

	let chatState = $derived(getAIChatState());
	let aiSettings = $derived(getAISettings());
	let isConfigured = $derived(aiSettings.enabled && aiSettings.apiKey && aiSettings.selectedModel);

	let inputValue = $state('');
	let modeMenuOpen = $state(false);

	// 执行模式
	const modeOptions: { value: ExecutionMode; key: string }[] = [
		{ value: 'normal', key: 'ai.mode.normal' },
		{ value: 'plan-only', key: 'ai.mode.plan_only' },
		{ value: 'auto-edit', key: 'ai.mode.auto_edit' },
		{ value: 'full-auto', key: 'ai.mode.full_auto' }
	];

	function modeLabel(mode: ExecutionMode): string {
		const m = modeOptions.find((o) => o.value === mode);
		return m ? t(m.key) : mode;
	}

	function selectMode(mode: ExecutionMode): void {
		setExecutionMode(mode);
		modeMenuOpen = false;
	}

	/** AI 消息是否包含可执行代码块（供一键执行面板判断）。 */
	function hasCommands(content: string): boolean {
		return collectCodeBlocks(content).length > 0;
	}

	/** 点击「一键执行」按钮。 */
	function handleRunAll(content: string): void {
		const bufferId = activeTabType === 'ssh' && connectionId ? connectionId : activeTabId;
		if (!bufferId) return;
		executeAllCommands(content, bufferId, activeTabType ?? 'local', connectionId);
	}
	let messagesContainer: HTMLDivElement | undefined = $state();
	let copiedId = $state<string | undefined>();

	// ── 可拖拽宽度 ──
	const PANEL_STORAGE_KEY = 'reach-ai-panel-width';
	const MIN_WIDTH = 280;
	const MAX_WIDTH = 800;
	const DEFAULT_WIDTH = 350;

	let panelWidth = $state(DEFAULT_WIDTH);

	$effect(() => {
		if (typeof localStorage !== 'undefined') {
			const saved = localStorage.getItem(PANEL_STORAGE_KEY);
			if (saved) {
				const w = parseInt(saved, 10);
				if (w >= MIN_WIDTH && w <= MAX_WIDTH) panelWidth = w;
			}
		}
	});

	let resizing = $state(false);
	let resizeStartX = 0;
	let resizeStartWidth = 0;

	function onResizeMouseDown(e: MouseEvent): void {
		resizing = true;
		resizeStartX = e.clientX;
		resizeStartWidth = panelWidth;
		e.preventDefault();
	}

	function onResizeMouseMove(e: MouseEvent): void {
		if (!resizing) return;
		const dx = resizeStartX - e.clientX;
		panelWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, resizeStartWidth + dx));
	}

	function onResizeMouseUp(): void {
		if (!resizing) return;
		resizing = false;
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem(PANEL_STORAGE_KEY, String(panelWidth));
		}
	}

	// ── 自动执行消息检测 ──
	function isAutoExec(msg: { role: string; content: string; instruction?: string }): boolean {
		if (msg.role !== 'user') return false;
		if (msg.instruction !== undefined) return true;
		return msg.content.startsWith('[自动执行]') ||
		       msg.content.startsWith('已执行：') ||
		       msg.content.startsWith('执行命令：') ||
		       msg.content.startsWith('[待确认]') ||
		       msg.content.startsWith('[批量执行');
	}

	// ── 原有逻辑 ──

	function copyMessage(id: string, content: string): void {
		navigator.clipboard.writeText(content);
		copiedId = id;
		setTimeout(() => { copiedId = undefined; }, 1500);
	}

	$effect(() => {
		if (chatState.messages.length && messagesContainer) {
			messagesContainer.scrollTop = messagesContainer.scrollHeight;
		}
	});

	$effect(() => {
		const el = messagesContainer;
		if (!el) return;
		const handler = (e: MouseEvent) => {
			const target = e.target as HTMLElement;
			if (target.classList.contains('copy-btn')) {
				const code = decodeURIComponent(target.dataset.code ?? '');
				navigator.clipboard.writeText(code);
			} else if (target.classList.contains('run-btn')) {
				const command = decodeURIComponent(target.dataset.code ?? '');
				const bufferId = activeTabType === 'ssh' && connectionId ? connectionId : activeTabId;
				if (bufferId) {
					let ctx: { host?: string; username?: string; os?: string } | undefined;
					if (connectionId) {
						const sessions = getSessionList();
						const session = sessions.find((s) => s.id === connectionId);
						if (session) {
							ctx = { host: session.host, username: session.username, os: session.detected_os ?? undefined };
						}
					}
					executeCommand(command, bufferId, activeTabType ?? 'local', connectionId, ctx);
				} else {
					navigator.clipboard.writeText(command);
				}
			}
		};
		el.addEventListener('click', handler);
		return () => el.removeEventListener('click', handler);
	});

	function handleSend(): void {
		if (getActive()) return;
		const text = inputValue.trim();
		if (!text) return;
		inputValue = '';

		let context: { connectionId?: string; host?: string; username?: string; os?: string; terminalOutput?: string } | undefined;
		let terminal: TerminalInfo | undefined;

		if (connectionId || activeTabId) {
			context = { connectionId };

			if (connectionId) {
				const sessions = getSessionList();
				const session = sessions.find((s) => s.id === connectionId);
				if (session) {
					context.host = session.host;
					context.username = session.username;
					context.os = session.detected_os ?? undefined;
				}
			}

			const bufferId = activeTabType === 'ssh' && connectionId ? connectionId : activeTabId;
			if (bufferId) {
				context.terminalOutput = readTerminalBuffer(bufferId);

				terminal = {
					bufferId,
					tabType: activeTabType ?? 'local',
					connectionId
				};
			}
		}

		sendMessage(text, context, terminal);
	}

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			handleSend();
		}
	}

	function renderContent(content: string, showRun: boolean = true): string {
		// 1. XSS 防护：转义 HTML 特殊字符
		let text = content
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;');

		const mode = getExecutionMode();
		const hasTerminal = !!(activeTabId || connectionId) && showRun && mode !== 'plan-only';
		const placeholders: string[] = [];

		// 2. 提取并保护代码块
		text = text.replace(
			/```(\w*)\n?([\s\S]*?)```/g,
			(_, lang, code) => {
				const idx = placeholders.length;
				const actions = hasTerminal
					? `<button class="run-btn" data-code="${encodeURIComponent(code.trim())}">${t('ai.run')}</button>`
					: '';
				placeholders.push(
					`<div class="code-block"><div class="code-header"><span>${lang || 'code'}</span><div class="code-actions">${actions}<button class="copy-btn" data-code="${encodeURIComponent(code.trim())}">${t('ai.copy')}</button></div></div><pre><code>${code.trim()}</code></pre></div>`
				);
				return `\x00CB${idx}\x00`;
			}
		);

		// 3. Markdown 粗体 **text**
		text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

		// 4. Markdown 斜体 *text*（避开 ** 残留）
		text = text.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

		// 5. 行内代码
		text = text.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

		// 6. 无序列表 "- item" 或 "* item"
		text = text.replace(/(^|<br>)[-*]\s(.+?)(?=<br>|$)/gm, '$1<li>$2</li>');

		// 7. 换行
		text = text.replace(/\n/g, '<br>');

		// 8. 还原代码块
		text = text.replace(/\x00CB(\d+)\x00/g, (_, idx) => placeholders[parseInt(idx)] || '');

		return text;
	}

</script>

<svelte:window onmousemove={onResizeMouseMove} onmouseup={onResizeMouseUp} />

{#if chatState.panelOpen}
	<aside
		class="ai-panel"
		class:resizing
		style:width="{panelWidth}px"
		style:min-width="{panelWidth}px"
	>
		<div class="resize-handle" role="separator" aria-label="拖拽调整面板宽度" onmousedown={onResizeMouseDown}></div>

		<div class="panel-header">
			<span class="panel-title">{t('ai.title')}</span>
			<div class="header-actions">
				<button class="icon-btn" onclick={clearChat} aria-label={t('ai.clear_chat')} title={t('ai.clear_chat')}>
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
					</svg>
				</button>
				<button class="icon-btn" onclick={closeAIPanel} aria-label={t('ai.close_panel')} title={t('ai.close_panel')}>
					<svg width="14" height="14" viewBox="0 0 10 10" fill="none">
						<path d="M1 1L9 9M9 1L1 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
					</svg>
				</button>
			</div>
		</div>

		{#if !isConfigured}
			<div class="panel-disabled">
				<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 2a10 10 0 1010 10A10 10 0 0012 2zm1 15h-2v-2h2zm0-4h-2V7h2z" />
				</svg>
				<p>{t('ai.not_configured')}</p>
				<p class="hint">{t('ai.go_to_settings')}</p>
			</div>
		{:else}
			<div class="messages" bind:this={messagesContainer}>
				{#if chatState.messages.length === 0}
					<div class="empty-state">
						<p>{t('ai.empty_hint')}</p>
					</div>
				{/if}
				{#each chatState.messages as msg (msg.id)}
					<div class="message-wrapper" class:auto-exec={isAutoExec(msg)}>
						<div class="message message-{msg.role}">
							{@html renderContent(msg.content, !isAutoExec(msg))}
							{#if msg.role === 'assistant' && !msg.content && chatState.loading}
								<span class="typing-indicator">
									<span></span><span></span><span></span>
								</span>
							{/if}
						</div>
						{#if msg.content}
							<button
								class="msg-copy-btn"
								class:copied={copiedId === msg.id}
								onclick={() => copyMessage(msg.id, msg.content)}
								title={t('ai.copy_message')}
							>
								{#if copiedId === msg.id}
									<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
										<polyline points="20 6 9 17 4 12" />
									</svg>
								{:else}
									<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
										<rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
									</svg>
								{/if}
							</button>
						{/if}

						<!-- 普通模式：AI 消息含代码块 → 一键执行面板 -->
						{#if msg.role === 'assistant' && !isAutoExec(msg) && (getExecutionMode() === 'normal' || getExecutionMode() === 'auto-edit') && hasCommands(msg.content)}
							<button class="run-all-btn" onclick={() => handleRunAll(msg.content)}>
								<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<polygon points="5 3 19 12 5 21 5 3" />
								</svg>
								<span>{t('ai.run_all')}</span>
							</button>
						{/if}
					</div>
				{/each}
				{#if chatState.error}
					<div class="message message-error">{chatState.error}</div>
				{/if}
			</div>

			<div class="input-area">
				<div class="mode-switcher">
					<button
						class="mode-btn mode-{getExecutionMode()}"
						onclick={() => (modeMenuOpen = !modeMenuOpen)}
						title={modeLabel(getExecutionMode())}
					>
						<span class="mode-short">{modeLabel(getExecutionMode())}</span>
					</button>
					{#if modeMenuOpen}
						<!-- svelte-ignore a11y_no_static_element_interactions -->
						<div class="mode-backdrop" onclick={() => (modeMenuOpen = false)}></div>
						<div class="mode-dropdown">
							{#each modeOptions as opt}
								<button
									class="mode-option"
									class:selected={getExecutionMode() === opt.value}
									onclick={() => selectMode(opt.value)}
								>
									<span class="mode-option-name">{t(opt.key)}</span>
									<span class="mode-option-desc">{t(opt.key + '_desc')}</span>
								</button>
							{/each}
						</div>
					{/if}
				</div>
				<textarea
					class="chat-input"
					bind:value={inputValue}
					onkeydown={handleKeydown}
					placeholder={getActive() ? t('ai.generating') : t('ai.placeholder')}
					rows="1"
					disabled={getActive()}
				></textarea>
				{#if getActive()}
					<button class="stop-btn" onclick={abortActiveSession} aria-label={t('ai.stop')} title={t('ai.stop')}>
						<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
							<rect x="4" y="4" width="16" height="16" rx="2" />
						</svg>
					</button>
				{:else}
					<button class="send-btn" onclick={handleSend} disabled={!inputValue.trim()} aria-label={t('ai.send')}>
						<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" />
						</svg>
					</button>
				{/if}
			</div>
		{/if}
	</aside>
{/if}

<style>
	.ai-panel {
		position: relative;
		height: 100%;
		display: flex;
		flex-direction: column;
		background-color: var(--color-bg-elevated);
		border-left: 1px solid var(--color-border);
		animation: slideInPanel 200ms var(--ease-default);
	}

	.ai-panel.resizing {
		user-select: none;
	}

	/* ── 拖拽手柄 ── */
	.resize-handle {
		position: absolute;
		left: 0;
		top: 0;
		bottom: 0;
		width: 5px;
		cursor: col-resize;
		z-index: 10;
		transition: background-color 150ms ease;
	}

	.resize-handle:hover,
	.ai-panel.resizing .resize-handle {
		background-color: var(--color-accent);
	}

	.panel-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 12px;
		border-bottom: 1px solid var(--color-border);
		flex-shrink: 0;
	}

	.panel-title {
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--color-text-primary);
	}

	.header-actions {
		display: flex;
		gap: 4px;
	}

	.icon-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 28px;
		height: 28px;
		border: none;
		border-radius: var(--radius-btn);
		background: transparent;
		color: var(--color-text-secondary);
		cursor: pointer;
		transition: background-color 150ms ease;
	}

	.icon-btn:hover {
		background-color: rgba(255, 255, 255, 0.08);
		color: var(--color-text-primary);
	}

	.panel-disabled {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 8px;
		padding: 24px;
		color: var(--color-text-secondary);
		text-align: center;
	}

	.panel-disabled p {
		margin: 0;
		font-size: 0.8125rem;
	}

	.hint {
		opacity: 0.6;
		font-size: 0.75rem !important;
	}

	.messages {
		flex: 1;
		overflow-y: auto;
		overflow-x: hidden;
		padding: 12px;
		display: flex;
		flex-direction: column;
		gap: 8px;
		min-width: 0;
	}

	.empty-state {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--color-text-secondary);
		font-size: 0.75rem;
		text-align: center;
		padding: 24px;
	}

	.empty-state p {
		margin: 0;
	}

	.message-wrapper {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		max-width: 100%;
		min-width: 0;
	}

	/* ── 对齐规则 ── */
	/* 用户发言：居右 */
	.message-wrapper:has(.message-user):not(.auto-exec) {
		align-self: flex-end;
		align-items: flex-end;
	}

	/* AI 回复 & 自动执行面板：统一居左 */
	.message-wrapper.auto-exec,
	.message-wrapper:has(.message-assistant) {
		align-self: flex-start;
		align-items: flex-start;
	}

	.msg-copy-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 22px;
		height: 22px;
		border: none;
		border-radius: 4px;
		background: transparent;
		color: var(--color-text-secondary);
		cursor: pointer;
		opacity: 0;
		transition: opacity 150ms ease, background-color 150ms ease;
	}

	.message-wrapper:hover .msg-copy-btn {
		opacity: 1;
	}

	.msg-copy-btn:hover {
		background-color: rgba(255, 255, 255, 0.08);
		color: var(--color-text-primary);
	}

	.msg-copy-btn.copied {
		opacity: 1;
		color: var(--color-success, #30d158);
	}

	/* ── 气泡基础 ── */
	.message {
		padding: 8px 12px;
		border-radius: 12px;
		font-size: 0.8125rem;
		line-height: 1.5;
		word-break: break-word;
		overflow-wrap: break-word;
		max-width: 100%;
		box-sizing: border-box;
		user-select: text;
	}

	/* ── 气泡配色 ── */
	/* 用户发言：纯正科技蓝（跟随系统 accent），居右 */
	.message-user {
		background-color: var(--color-accent);
		color: #fff;
	}

	/* AI 回复：跟随系统暗色主题背景，居左，自适应边框 */
	.message-assistant {
		background-color: var(--color-bg-secondary);
		color: var(--color-text-primary);
		border: 1px solid var(--color-border);
	}

	/* 自动执行面板：与 AI 同阵营，跟随系统主题色，居左 */
	.message-wrapper.auto-exec .message-user {
		background-color: var(--color-bg-secondary);
		color: var(--color-text-primary);
		border: 1px solid var(--color-border);
	}

	.message-error {
		background-color: rgba(255, 59, 48, 0.1);
		color: var(--color-danger);
		font-size: 0.75rem;
		text-align: center;
	}

	/* ── 代码块防溢出 + 可选中 ── */
	.message :global(.code-block) {
		margin: 6px 0;
		border-radius: 6px;
		overflow: hidden;
		background-color: var(--color-bg-primary);
		border: 1px solid var(--color-border);
		box-sizing: border-box;
		width: 100%;
		max-width: 100%;
		user-select: text;
	}

	.message :global(.code-header) {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 4px 8px;
		font-size: 0.6875rem;
		color: var(--color-text-secondary);
		border-bottom: 1px solid var(--color-border);
	}

	.message :global(.code-actions) {
		display: flex;
		gap: 4px;
	}

	.message :global(.copy-btn) {
		border: none;
		background: transparent;
		color: var(--color-accent);
		cursor: pointer;
		font-size: 0.6875rem;
		padding: 2px 6px;
		border-radius: 4px;
	}

	.message :global(.copy-btn:hover) {
		background-color: rgba(255, 255, 255, 0.06);
	}

	.message :global(.run-btn) {
		border: none;
		background: transparent;
		color: var(--color-success, #30d158);
		cursor: pointer;
		font-size: 0.6875rem;
		padding: 2px 6px;
		border-radius: 4px;
	}

	.message :global(.run-btn:hover) {
		background-color: rgba(48, 209, 88, 0.1);
	}

	/* 自动执行面板：CSS 级强制隐藏执行按钮 */
	.message-wrapper.auto-exec :global(.run-btn) {
		display: none;
	}

	/* 一键执行按钮 */
	.run-all-btn {
		display: flex;
		align-items: center;
		gap: 5px;
		padding: 5px 10px;
		margin-top: 4px;
		border: 1px dashed var(--color-accent);
		border-radius: 8px;
		background: color-mix(in srgb, var(--color-accent) 8%, transparent);
		color: var(--color-accent);
		font-family: var(--font-sans);
		font-size: 0.6875rem;
		font-weight: 600;
		cursor: pointer;
		transition: background-color 150ms ease;
		align-self: flex-end;
	}

	.run-all-btn:hover {
		background: color-mix(in srgb, var(--color-accent) 18%, transparent);
	}

	.message :global(pre) {
		margin: 0;
		padding: 8px;
		overflow-x: auto;
		overflow-y: hidden;
		max-width: 100%;
		box-sizing: border-box;
		user-select: text;
	}

	.message :global(pre code) {
		white-space: pre-wrap;
		word-break: break-all;
		user-select: text;
	}

	.message :global(code) {
		font-family: var(--font-mono, monospace);
		font-size: 0.75rem;
		user-select: text;
	}

	.message :global(.inline-code) {
		padding: 1px 4px;
		border-radius: 3px;
		background-color: var(--color-bg-primary);
		font-size: 0.75rem;
		word-break: break-all;
		user-select: text;
	}

	.typing-indicator {
		display: inline-flex;
		gap: 3px;
		padding: 4px 0;
	}

	.typing-indicator span {
		width: 5px;
		height: 5px;
		border-radius: 50%;
		background-color: var(--color-text-secondary);
		animation: typingBounce 1s infinite;
	}

	.typing-indicator span:nth-child(2) { animation-delay: 0.15s; }
	.typing-indicator span:nth-child(3) { animation-delay: 0.3s; }

	/* ── 模式切换器 ── */
	.mode-switcher {
		position: relative;
		flex-shrink: 0;
	}

	.mode-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 28px;
		height: 28px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-bg-primary);
		color: var(--color-text-secondary);
		cursor: pointer;
		font-size: 0.6875rem;
		font-weight: 700;
		font-family: var(--font-sans);
		padding: 0;
		transition: color 150ms ease, border-color 150ms ease, background-color 150ms ease;
	}

	.mode-btn:hover {
		border-color: var(--color-accent);
		color: var(--color-accent);
	}

	/* 全自动模式：危险警告色 */
	.mode-btn.mode-full-auto {
		border-color: rgba(255, 69, 58, 0.5);
		color: var(--color-danger, #ff453a);
		background-color: rgba(255, 69, 58, 0.1);
	}

	.mode-btn.mode-full-auto:hover {
		border-color: var(--color-danger, #ff453a);
		background-color: rgba(255, 69, 58, 0.18);
	}

	.mode-backdrop {
		position: fixed;
		inset: 0;
		z-index: 50;
	}

	.mode-dropdown {
		position: absolute;
		bottom: calc(100% + 8px);
		left: 0;
		width: 220px;
		background-color: var(--color-bg-elevated);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
		z-index: 51;
		overflow: hidden;
		padding: 4px;
	}

	.mode-option {
		display: flex;
		flex-direction: column;
		gap: 1px;
		width: 100%;
		padding: 8px 10px;
		border: none;
		border-radius: 6px;
		background: transparent;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		transition: background-color 120ms ease;
	}

	.mode-option:hover {
		background-color: var(--color-bg-secondary);
	}

	.mode-option.selected {
		background-color: color-mix(in srgb, var(--color-accent) 12%, transparent);
	}

	.mode-option-name {
		font-size: 0.75rem;
		font-weight: 600;
		color: var(--color-text-primary);
	}

	.mode-option-desc {
		font-size: 0.625rem;
		color: var(--color-text-secondary);
		line-height: 1.3;
	}

	/* ── 输入区 ── */
	.input-area {
		display: flex;
		gap: 6px;
		align-items: center;
		padding: 10px 12px;
		border-top: 1px solid var(--color-border);
		flex-shrink: 0;
	}

	.chat-input {
		flex: 1;
		padding: 8px 12px;
		font-size: 0.8125rem;
		font-family: inherit;
		color: var(--color-text-primary);
		background-color: var(--color-bg-primary);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		outline: none;
		resize: none;
		line-height: 1.4;
		transition: border-color 150ms ease;
	}

	.chat-input:focus {
		border-color: var(--color-accent);
	}

	.chat-input::placeholder {
		color: var(--color-text-secondary);
		opacity: 0.5;
	}

	.send-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 34px;
		height: 34px;
		border: none;
		border-radius: 50%;
		background-color: var(--color-accent);
		color: #fff;
		cursor: pointer;
		flex-shrink: 0;
		transition: opacity 150ms ease;
	}

	.send-btn:disabled {
		opacity: 0.4;
		cursor: default;
	}

	.stop-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 34px;
		height: 34px;
		border: none;
		border-radius: 50%;
		background-color: var(--color-danger, #ff453a);
		color: #fff;
		cursor: pointer;
		flex-shrink: 0;
		transition: opacity 150ms ease;
	}

	.stop-btn:hover {
		opacity: 0.85;
	}

	@keyframes slideInPanel {
		from { transform: translateX(100%); }
		to { transform: translateX(0); }
	}

	@keyframes typingBounce {
		0%, 60%, 100% { transform: translateY(0); }
		30% { transform: translateY(-4px); }
	}
</style>
