<script lang="ts">
	import { openUrl } from '@tauri-apps/plugin-opener';
	import { t } from '#lib/state/i18n.svelte.js';
	import {
		getUpdaterState,
		checkForUpdate,
		downloadAndInstall,
		relaunchNow
	} from '#lib/state/updater.svelte.js';
	import { __APP_VERSION__ } from '#lib/version.js';

	const updater = getUpdaterState();

	type Status = 'idle' | 'checking' | 'available' | 'latest' | 'downloading' | 'ready' | 'error';

	let localStatus = $state<Status>('idle');

	let status = $derived.by(() => {
		if (localStatus === 'checking') return 'checking';
		if (updater.downloading) return 'downloading' as Status;
		if (updater.readyToRelaunch) return 'ready' as Status;
		if (updater.error && localStatus !== 'idle') return 'error' as Status;
		if (localStatus === 'latest') return 'latest';
		if (updater.updateAvailable) return 'available' as Status;
		return localStatus;
	});

	async function openGitHub() {
		await openUrl('https://github.com/Daniel-King-8/CoreOps');
	}
	async function openDocs() {
		await openUrl("https://blog.king818.xyz/archives/coreops#%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%EF%BC%9A");
	}

	async function handleCheckUpdate() {
		localStatus = 'checking';
		const found = await checkForUpdate();
		if (found) {
			localStatus = 'available';
		} else if (updater.error) {
			localStatus = 'error';
		} else {
			localStatus = 'latest';
			setTimeout(() => { if (localStatus === 'latest') localStatus = 'idle'; }, 3000);
		}
	}

	async function handleInstallUpdate() {
		localStatus = 'downloading';
		await downloadAndInstall();
	}
</script>

<div class="about-wrap">
	<div class="about-logo">
		<svg width="48" height="48" viewBox="0 0 24 24" fill="none">
			<rect width="24" height="24" rx="6" fill="rgba(255,255,255,0.08)" />
			<path
				d="M4 17V7l8-4 8 4v10l-8 4-8-4z"
				stroke="currentColor"
				stroke-width="1.5"
				stroke-linejoin="round"
			/>
			<path d="M12 3v18M4 7l8 4 8-4" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
		</svg>
	</div>

	<h2 class="about-name">CoreOps</h2>
	<p class="about-version">v{__APP_VERSION__}</p>

	<div class="about-meta">
		<div class="meta-row">
			<span class="meta-label">{t('about.author')}</span>
			<span class="meta-value">Daniel-King-8</span>
		</div>
		<div class="meta-row">
			<span class="meta-label">{t('about.based_on')}</span>
			<span class="meta-value">Reach (alexandrosnt)</span>
		</div>
		<div class="meta-row">
			<span class="meta-label">GitHub</span>
			<button class="link-btn" onclick={openGitHub}>
				github.com/Daniel-King-8/CoreOps
				<svg width="12" height="12" viewBox="0 0 24 24" fill="none">
					<path
						d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
					/>
				</svg>
			</button>
		</div>
		<div class="meta-row">
				<span class="meta-label">使用说明</span>
				<button class="link-btn" onclick={openDocs}>
					blog.king818.xyz
					<svg width="12" height="12" viewBox="0 0 24 24" fill="none">
						<path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
					</svg>
				</button>
			</div>
	</div>

	<!-- 检查更新区域 -->
	<div class="updater-section">
		{#if status === 'idle' || status === 'latest' || status === 'error'}
			{#if status === 'latest'}
				<p class="update-msg success">{t('about.is_latest')}</p>
			{/if}
			{#if status === 'error'}
				<p class="update-msg error">{updater.error || t('about.update_failed')}</p>
			{/if}
			<button
				class="update-btn"
				onclick={handleCheckUpdate}
			>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none">
					<path d="M21 2v6h-6M3 12a9 9 0 0115-6.7L21 8M3 22v-6h6M21 12a9 9 0 01-15 6.7L3 16"
						stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				{status === 'error' ? t('about.retry') : t('about.check_update')}
			</button>

		{:else if status === 'checking'}
			<button class="update-btn" disabled>
				<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none">
					<path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="2" stroke-dasharray="30 10"/>
				</svg>
				{t('about.checking')}
			</button>

		{:else if status === 'available'}
			<p class="update-msg info">{t('about.update_available')}：v{updater.updateVersion}</p>
			<button class="update-btn primary" onclick={handleInstallUpdate}>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none">
					<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"
						stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				{t('about.install_update')}
			</button>

		{:else if status === 'downloading'}
			<p class="update-msg info">{t('about.downloading')} {updater.downloadProgress > 0 ? `${updater.downloadProgress}%` : '...'}</p>
			<div class="progress-bar">
				<div class="progress-fill" style="width: {updater.downloadProgress}%"></div>
			</div>

		{:else if status === 'ready'}
			<p class="update-msg success">{t('about.restart_hint')}</p>
			<button class="update-btn primary" onclick={relaunchNow}>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none">
					<path d="M1 4v6h6M23 20v-6h-6M20.49 9A9 9 0 005.64 5.64L1 10M23 14l-4.64 4.36A9 9 0 013.51 15"
						stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				{t('about.restart')}
			</button>
		{/if}
	</div>
</div>

<style>
	.about-wrap {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 24px 16px 16px;
		gap: 6px;
	}

	.about-logo {
		color: var(--color-text-secondary);
		margin-bottom: 8px;
	}

	.about-name {
		font-size: 1.25rem;
		font-weight: 600;
		color: var(--color-text-primary);
		margin: 0;
	}

	.about-version {
		font-size: 0.8rem;
		color: var(--color-text-muted, var(--color-text-secondary));
		margin: 0 0 16px;
	}

	.about-meta {
		width: 100%;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		overflow: hidden;
	}

	.meta-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 14px;
		border-bottom: 1px solid var(--color-border);
		font-size: 0.8125rem;
	}

	.meta-row:last-child {
		border-bottom: none;
	}

	.meta-label {
		color: var(--color-text-secondary);
	}

	.meta-value {
		color: var(--color-text-primary);
		font-weight: 500;
	}

	.link-btn {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		background: none;
		border: none;
		padding: 0;
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--color-accent, #58a6ff);
		cursor: pointer;
		text-decoration: underline;
		text-underline-offset: 2px;
	}

	.link-btn:hover {
		opacity: 0.8;
	}

	/* 更新区域 */
	.updater-section {
		width: 100%;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 8px;
		margin-top: 10px;
	}

	.update-btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 7px 16px;
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--color-text-primary);
		background: rgba(255, 255, 255, 0.07);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		cursor: pointer;
		transition: background 0.15s;
	}

	.update-btn:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.12);
	}

	.update-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.update-btn.primary {
		color: #fff;
		background: var(--color-accent, #238636);
		border-color: transparent;
	}

	.update-btn.primary:hover:not(:disabled) {
		opacity: 0.88;
	}

	.update-msg {
		font-size: 0.8rem;
		margin: 0;
		text-align: center;
	}

	.update-msg.success { color: #3fb950; }
	.update-msg.error   { color: #f85149; }
	.update-msg.info    { color: var(--color-text-secondary); }

	.progress-bar {
		width: 100%;
		height: 4px;
		background: rgba(255, 255, 255, 0.1);
		border-radius: 2px;
		overflow: hidden;
	}

	.progress-fill {
		height: 100%;
		background: var(--color-accent, #58a6ff);
		border-radius: 2px;
		transition: width 0.2s ease;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.spin {
		animation: spin 1s linear infinite;
	}
</style>
