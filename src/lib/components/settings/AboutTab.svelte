<script lang="ts">
	import { open } from '@tauri-apps/plugin-shell';
	import { t } from '$lib/state/i18n.svelte';

	declare const APP_VERSION: string;

	async function openGitHub() {
		await open('https://github.com/Daniel-King-8/CoreOps');
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
	<p class="about-version">v{APP_VERSION}</p>

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
</style>
