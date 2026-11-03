<script lang="ts">
	/** The tabs of a detail pane; arrow keys move between them. */
	interface Props {
		tabs: { id: string; label: string }[];
		active: string;
		onchange: (id: string) => void;
	}

	let { tabs, active, onchange }: Props = $props();

	function onKeydown(e: KeyboardEvent): void {
		if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
		const i = tabs.findIndex((x) => x.id === active);
		const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
		onchange(next.id);
		(e.currentTarget as HTMLElement).querySelector<HTMLButtonElement>(`[data-id="${next.id}"]`)?.focus();
	}
</script>

<div class="tabs" role="tablist" tabindex="-1" onkeydown={onKeydown}>
	{#each tabs as tab (tab.id)}
		<button
			type="button"
			role="tab"
			data-id={tab.id}
			aria-selected={tab.id === active}
			tabindex={tab.id === active ? 0 : -1}
			class:on={tab.id === active}
			onclick={() => onchange(tab.id)}>{tab.label}</button
		>
	{/each}
</div>

<style>
	.tabs {
		display: flex;
		gap: 2px;
		padding: 0 10px;
		border-bottom: 1px solid var(--color-border);
		overflow-x: auto;
		scrollbar-width: none;
		flex-shrink: 0;
	}

	button {
		min-height: 36px;
		padding: 0 12px;
		border: none;
		border-bottom: 2px solid transparent;
		background: none;
		color: var(--color-text-secondary);
		font: inherit;
		font-size: var(--text-sm);
		white-space: nowrap;
		cursor: pointer;
	}

	button:hover {
		color: var(--color-text-primary);
	}

	button.on {
		color: var(--color-text-primary);
		border-bottom-color: var(--color-accent);
	}

	button:focus-visible {
		outline: 2px solid var(--color-accent);
		outline-offset: -2px;
	}

	@media (pointer: coarse) {
		button {
			min-height: 44px;
		}
	}
</style>
