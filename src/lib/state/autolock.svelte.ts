/**
 * Locking Reach by itself: after a stretch without keyboard or mouse use, and
 * when the computer's own session locks or sleeps. Both are off until switched
 * on in Settings → Security. A lock holds the vault (see `vaultState.held`), so
 * it stays locked until the user opens it from the lock screen; terminals and
 * remote desktops that are already open keep running behind it.
 */
import { listen } from '@tauri-apps/api/event';
import { getSettings } from './settings.svelte';
import { lock, vaultState } from './vault.svelte';

const ACTIVITY = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'] as const;
const CHECK_EVERY_MS = 15_000;

const settings = getSettings();
let lastActivity = Date.now();
let started = false;

function noteActivity(): void {
	lastActivity = Date.now();
}

async function lockNow(reason: string): Promise<void> {
	if (vaultState.locked || !vaultState.hasIdentity) return;
	console.info(`Locking Reach: ${reason}`);
	try {
		await lock();
	} catch (err) {
		console.error('Auto-lock failed:', err);
	}
}

/** Start watching. Safe to call more than once. */
export function startAutoLock(): void {
	if (started) return;
	started = true;

	// Capture phase, so keys typed into a terminal count as activity too.
	for (const kind of ACTIVITY) {
		window.addEventListener(kind, noteActivity, { capture: true, passive: true });
	}

	setInterval(() => {
		const minutes = settings.autoLockMinutes;
		if (minutes > 0 && Date.now() - lastActivity >= minutes * 60_000) {
			void lockNow(`${minutes} minutes without activity`);
		}
	}, CHECK_EVERY_MS);

	// Sent by the backend when the OS session locks or the machine sleeps.
	void listen('system-locked', () => {
		if (settings.lockOnSystemLock) void lockNow('the computer locked');
	});

	// On Android, and when the window is hidden, time away counts as idle.
	// Timers may not run while Reach is in the background, so on the way back
	// the time away is checked before it counts as activity.
	document.addEventListener('visibilitychange', () => {
		if (document.hidden) return;
		const minutes = settings.autoLockMinutes;
		if (minutes > 0 && Date.now() - lastActivity >= minutes * 60_000) {
			void lockNow(`away for more than ${minutes} minutes`);
		} else {
			noteActivity();
		}
	});
}
