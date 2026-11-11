<script lang="ts">
	import { getUpdaterState, downloadAndInstall, skipStartupUpdate } from '#lib/state/updater.svelte.js';
	import { t } from '#lib/state/i18n.svelte.js';
	import { marked } from 'marked';
	import DOMPurify from 'dompurify';
	import { openUrl } from '@tauri-apps/plugin-opener';

	interface Props {
		open: boolean;
	}

	let { open }: Props = $props();

	const updater = getUpdaterState();

	let buttonLabel = $derived.by(() => {
		if (updater.installing) return t('updater.installing');
		if (updater.downloading) return t('updater.downloading', { progress: updater.downloadProgress });
		if (updater.error) return t('updater.retry');
		return t('updater.update_now');
	});

	let buttonDisabled = $derived(updater.downloading || updater.installing);
	let showEscapeHatch = $derived(updater.downloadAttempts >= 3 && !!updater.error);

	function handleUpdate() {
		downloadAndInstall();
	}

	function handleSkip() {
		skipStartupUpdate();
	}

	/** Release notes are Markdown; render them, then clean the result. */
	let notesHtml = $derived.by(() => {
		const notes = updater.updateNotes;
		if (!notes) return '';
		try {
			const html = marked.parse(notes, { async: false, gfm: true, breaks: true }) as string;
			return DOMPurify.sanitize(html);
		} catch {
			// A malformed note should still be readable, never inject HTML.
			return DOMPurify.sanitize(`<pre>${escapeHtml(notes)}</pre>`);
		}
	});

	function escapeHtml(value: string): string {
		return value.replace(/[&<>"']/g, (character) => {
			switch (character) {
				case '&': return '&amp;';
				case '<': return '&lt;';
				case '>': return '&gt;';
				case '"': return '&quot;';
				default: return '&#39;';
			}
		});
	}

	/** Links in a release note open outside the app, not inside the WebView. */
	function handleNotesClick(event: MouseEvent): void {
		const target = event.target;
		if (!(target instanceof Element)) return;
		const anchor = target.closest('a');
		const href = anchor?.getAttribute('href');
		if (!href || href.startsWith('#')) return;
		event.preventDefault();
		event.stopPropagation();
		try {
			void openUrl(new URL(href, window.location.href).toString()).catch(() => {});
		} catch {
			// Not a URL the webview can resolve; leave it alone.
		}
	}
</script>

{#if open}
	<div class="update-backdrop" role="presentation">
		<div class="update-card" role="alertdialog" aria-modal="true" aria-label={t('updater.title')}>
			<div class="card-header">
				<div class="icon-container">
					<svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
						<path d="M16 3L17.5 8.5L20 6L19 11L24 9.5L20.5 13L26 13.5L21 16L26 18.5L20.5 19L24 22.5L19 21L20 26L17.5 23.5L16 29L14.5 23.5L12 26L13 21L8 22.5L11.5 19L6 18.5L11 16L6 13.5L11.5 13L8 9.5L13 11L12 6L14.5 8.5L16 3Z" fill="var(--color-accent)" fill-opacity="0.15" stroke="var(--color-accent)" stroke-width="1.5" stroke-linejoin="round"/>
						<path d="M16 10V18M16 18L12.5 14.5M16 18L19.5 14.5" stroke="var(--color-accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
						<line x1="12" y1="21" x2="20" y2="21" stroke="var(--color-accent)" stroke-width="1.5" stroke-linecap="round"/>
					</svg>
				</div>
				<h2 class="title">{t('updater.title')}</h2>
				{#if updater.updateVersion}
					<span class="version-badge">v{updater.updateVersion}</span>
				{/if}
			</div>

			{#if updater.updateNotes}
				<div class="release-notes">
					<h3 class="release-notes-heading">{t('updater.release_notes')}</h3>
					<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
					<div class="release-notes-content" onclick={handleNotesClick}>
						<div class="release-notes-text">{@html notesHtml}</div>
					</div>
				</div>
			{/if}

			{#if updater.downloading || updater.installing}
				<div class="progress-container">
					<div class="progress-track">
						<div
							class="progress-fill"
							class:installing={updater.installing}
							style="width: {updater.installing ? 100 : updater.downloadProgress}%"
						></div>
					</div>
					{#if updater.installing}
						<p class="progress-label">{t('updater.installing_desc')}</p>
					{/if}
				</div>
			{/if}

			{#if updater.error}
				<div class="error-message">
					<svg width="14" height="14" viewBox="0 0 14 14" fill="none">
						<circle cx="7" cy="7" r="6" stroke="var(--color-danger)" stroke-width="1.2"/>
						<path d="M7 4V7.5M7 9.5V10" stroke="var(--color-danger)" stroke-width="1.2" stroke-linecap="round"/>
					</svg>
					<span>{updater.error}</span>
				</div>
			{/if}

			<div class="actions">
				<!-- Always a way past: an update is offered, never forced. A .deb
				     or a build from source cannot install it in place (#87). -->
				<button class="btn-ghost" onclick={handleSkip} disabled={updater.installing}>
					{showEscapeHatch ? t('updater.continue_without') : t('updater.later')}
				</button>
				<button
					class="btn-primary"
					disabled={buttonDisabled}
					onclick={handleUpdate}
				>
					{#if updater.downloading}
						<svg class="spinner" width="16" height="16" viewBox="0 0 16 16" fill="none">
							<circle cx="8" cy="8" r="6" stroke="rgba(255,255,255,0.25)" stroke-width="2"/>
							<path d="M14 8A6 6 0 0 0 8 2" stroke="white" stroke-width="2" stroke-linecap="round"/>
						</svg>
					{/if}
					{buttonLabel}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.update-backdrop {
		position: fixed;
		inset: 0;
		/* Clear of the phone's status and navigation bars (0 on a desktop). */
		padding: var(--safe-top) var(--safe-right) var(--safe-bottom) var(--safe-left);
		z-index: 300;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--color-surface-sunken);
		backdrop-filter: blur(8px);
		-webkit-backdrop-filter: blur(8px);
		animation: fadeIn var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1));
	}

	.update-card {
		background-color: var(--color-bg-elevated, var(--color-bg-elevated));
		border: 1px solid var(--color-border, var(--color-border));
		border-radius: var(--radius-modal, 16px);
		box-shadow: var(--shadow-elevated, 0 8px 32px rgba(0, 0, 0, 0.25));
		width: 90%;
		max-width: 440px;
		display: flex;
		flex-direction: column;
		overflow: hidden;
		animation: scaleIn var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1));
		font-family: var(--font-sans, 'Inter', system-ui, -apple-system, sans-serif);
	}

	.card-header {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		padding: 28px 24px 16px;
	}

	.icon-container {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 56px;
		height: 56px;
		border-radius: 14px;
		background: rgba(10, 132, 255, 0.1);
	}

	.title {
		font-size: 1.125rem;
		font-weight: 600;
		color: var(--color-text-primary, var(--color-text-primary));
		margin: 0;
		letter-spacing: -0.01em;
	}

	.version-badge {
		display: inline-flex;
		align-items: center;
		padding: 3px 10px;
		border-radius: 20px;
		font-size: 0.75rem;
		font-weight: 500;
		color: var(--color-accent, var(--color-accent));
		background: rgba(10, 132, 255, 0.12);
		letter-spacing: 0.01em;
	}

	.release-notes {
		padding: 0 24px 16px;
	}

	.release-notes-heading {
		font-size: 0.75rem;
		font-weight: 500;
		color: var(--color-text-secondary, var(--color-text-secondary));
		margin: 0 0 8px 0;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.release-notes-content {
		max-height: 200px;
		overflow-y: auto;
		overflow-x: auto;
		border-radius: 8px;
		background: var(--color-surface-hover);
		border: 1px solid var(--color-border, var(--color-border));
	}

	.release-notes-text {
		margin: 0;
		padding: 12px;
		font-family: var(--font-sans, 'Inter', system-ui, -apple-system, sans-serif);
		font-size: 0.8125rem;
		line-height: 1.55;
		color: var(--color-text-secondary, var(--color-text-secondary));
		word-wrap: break-word;
	}

	.release-notes-text :global(h1),
	.release-notes-text :global(h2),
	.release-notes-text :global(h3),
	.release-notes-text :global(h4) {
		margin: 12px 0 6px;
		color: var(--color-text-primary);
		font-weight: 600;
		line-height: 1.35;
	}

	.release-notes-text :global(h1:first-child),
	.release-notes-text :global(h2:first-child),
	.release-notes-text :global(h3:first-child),
	.release-notes-text :global(h4:first-child) {
		margin-top: 0;
	}

	.release-notes-text :global(h1) { font-size: 1rem; }
	.release-notes-text :global(h2) { font-size: 0.9375rem; }
	.release-notes-text :global(h3) { font-size: 0.875rem; }
	.release-notes-text :global(h4) { font-size: 0.8125rem; }

	.release-notes-text :global(p) {
		margin: 0 0 8px;
	}

	.release-notes-text :global(p:last-child) {
		margin-bottom: 0;
	}

	.release-notes-text :global(ul),
	.release-notes-text :global(ol) {
		margin: 0 0 8px;
		padding-left: 20px;
	}

	.release-notes-text :global(li) {
		margin: 2px 0;
	}

	.release-notes-text :global(strong) {
		color: var(--color-text-primary);
		font-weight: 600;
	}

	.release-notes-text :global(a) {
		color: var(--color-accent);
		text-decoration: none;
	}

	.release-notes-text :global(a:hover) {
		text-decoration: underline;
	}

	.release-notes-text :global(code) {
		padding: 1px 4px;
		border-radius: 4px;
		background: var(--color-surface-active);
		font-family: var(--font-mono, 'JetBrains Mono', monospace);
		font-size: 0.75rem;
	}

	.release-notes-text :global(pre) {
		margin: 8px 0;
		padding: 8px;
		overflow-x: auto;
		border-radius: 6px;
		background: var(--color-surface-active);
	}

	.release-notes-text :global(pre code) {
		padding: 0;
		background: transparent;
	}

	.release-notes-text :global(table) {
		width: 100%;
		margin: 8px 0;
		border-collapse: collapse;
		font-size: 0.75rem;
	}

	.release-notes-text :global(th),
	.release-notes-text :global(td) {
		padding: 4px 6px;
		border: 1px solid var(--color-border);
		text-align: left;
		vertical-align: top;
	}

	.release-notes-text :global(th) {
		color: var(--color-text-primary);
		font-weight: 600;
		background: var(--color-surface-hover);
	}

	.release-notes-text :global(img) {
		display: block;
		max-width: 100%;
		height: auto;
		margin: 8px 0;
		border-radius: 6px;
	}

	.release-notes-text :global(hr) {
		margin: 10px 0;
		border: none;
		border-top: 1px solid var(--color-border);
	}

	.release-notes-text :global(blockquote) {
		margin: 8px 0;
		padding-left: 10px;
		border-left: 2px solid var(--color-border);
	}

	.release-notes-content::-webkit-scrollbar {
		width: 6px;
	}

	.release-notes-content::-webkit-scrollbar-track {
		background: transparent;
	}

	.release-notes-content::-webkit-scrollbar-thumb {
		background: var(--color-surface-active);
		border-radius: 3px;
	}

	.progress-container {
		padding: 0 24px 16px;
	}

	.progress-track {
		height: 6px;
		border-radius: 3px;
		background: var(--color-surface-active);
		overflow: hidden;
	}

	.progress-fill {
		height: 100%;
		border-radius: 3px;
		background: var(--color-accent, var(--color-accent));
		transition: width 300ms var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1));
	}

	.progress-fill.installing {
		animation: pulse 1.5s ease-in-out infinite;
	}

	.progress-label {
		margin: 8px 0 0 0;
		font-size: 0.75rem;
		color: var(--color-text-secondary, var(--color-text-secondary));
		text-align: center;
	}

	.error-message {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		margin: 0 24px 16px;
		padding: 10px 12px;
		border-radius: 8px;
		background: rgba(255, 69, 58, 0.08);
		border: 1px solid rgba(255, 69, 58, 0.15);
		font-size: 0.8125rem;
		color: var(--color-danger, var(--color-danger));
		line-height: 1.4;
	}

	.error-message svg {
		flex-shrink: 0;
		margin-top: 1px;
	}

	.actions {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 8px;
		padding: 16px 24px 24px;
	}

	.btn-primary {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
		padding: 10px 20px;
		border-radius: 10px;
		border: none;
		font-family: var(--font-sans, 'Inter', system-ui, -apple-system, sans-serif);
		font-size: 0.875rem;
		font-weight: 500;
		color: #fff;
		background-color: var(--color-accent, var(--color-accent));
		cursor: pointer;
		transition:
			background-color var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1)),
			opacity var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1)),
			transform var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1));
		user-select: none;
		white-space: nowrap;
	}

	.btn-primary:hover:not(:disabled) {
		background-color: var(--color-accent-hover, var(--color-accent-hover));
	}

	.btn-primary:active:not(:disabled) {
		transform: scale(0.97);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-ghost {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: 10px 16px;
		border-radius: 10px;
		border: none;
		font-family: var(--font-sans, 'Inter', system-ui, -apple-system, sans-serif);
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--color-text-secondary, var(--color-text-secondary));
		background: transparent;
		cursor: pointer;
		transition:
			background-color var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1)),
			color var(--duration-default, 200ms) var(--ease-default, cubic-bezier(0.25, 0.1, 0.25, 1));
		user-select: none;
		white-space: nowrap;
	}

	.btn-ghost:hover {
		background: var(--color-surface-hover);
		color: var(--color-text-primary, var(--color-text-primary));
	}

	.btn-ghost:active {
		transform: scale(0.97);
	}

	.spinner {
		animation: spin 0.8s linear infinite;
	}

	@keyframes fadeIn {
		from {
			opacity: 0;
		}
		to {
			opacity: 1;
		}
	}

	@keyframes scaleIn {
		from {
			opacity: 0;
			transform: scale(0.95);
		}
		to {
			opacity: 1;
			transform: scale(1);
		}
	}

	@keyframes pulse {
		0%, 100% {
			opacity: 1;
		}
		50% {
			opacity: 0.6;
		}
	}

	@keyframes spin {
		from {
			transform: rotate(0deg);
		}
		to {
			transform: rotate(360deg);
		}
	}
</style>
