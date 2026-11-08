/**
 * Keep the wallpaper inside floating panels aligned with the page wallpaper.
 *
 * The page paints one fixed, cover-scaled picture behind everything. A panel
 * that shows the picture itself must show the same crop at the same scale;
 * otherwise a small menu shows a shrunken copy of the whole picture. CSS
 * `background-attachment: fixed` is not reliable inside the webview (a
 * transformed or composited element falls back to an element-relative image),
 * so the cover geometry is computed against the viewport and written per
 * panel.
 */

import { getCustomAppearance } from '#lib/state/custom-theme.svelte.js';

const SURFACE_SELECTOR = '.wallpaper-surface, .select-menu';

interface ImageSize {
	width: number;
	height: number;
}

const imageSizes = new Map<string, Promise<ImageSize | null>>();

function loadImageSize(url: string): Promise<ImageSize | null> {
	const cached = imageSizes.get(url);
	if (cached) return cached;

	const size = new Promise<ImageSize | null>((resolve) => {
		const image = new Image();
		image.onload = () =>
			resolve(
				image.naturalWidth > 0 && image.naturalHeight > 0
					? { width: image.naturalWidth, height: image.naturalHeight }
					: null
			);
		image.onerror = () => resolve(null);
		image.src = url;
	});

	imageSizes.set(url, size);
	return size;
}

let started: (() => void) | null = null;

/** Start (once) and return a stop function. Safe in a non-browser context. */
export function startWallpaperSurfaceTracking(): () => void {
	if (typeof window === 'undefined' || typeof document === 'undefined') return () => {};
	if (started) return started;

	let frame = 0;
	let disposed = false;
	let url = '';
	let imageSize: ImageSize | null = null;

	const apply = (): void => {
		if (disposed) return;

		const nextUrl = getCustomAppearance().backgroundImage;
		if (nextUrl !== url) {
			url = nextUrl;
			imageSize = null;
			if (url) {
				void loadImageSize(url).then((size) => {
					if (disposed || url !== nextUrl) return;
					imageSize = size;
					schedule();
				});
			}
		}

		const surfaces = document.querySelectorAll<HTMLElement>(SURFACE_SELECTOR);
		if (!url || !imageSize) {
			for (const surface of surfaces) {
				surface.style.removeProperty('--wallpaper-image-size');
				surface.style.removeProperty('--wallpaper-image-position');
			}
			return;
		}

		// The page's picture is `background-size: cover; background-position:
		// center` on the viewport. Reproduce that geometry for every panel, then
		// shift it by the panel's own position so the crop matches its place.
		const viewportWidth = window.innerWidth;
		const viewportHeight = window.innerHeight;
		const scale = Math.max(viewportWidth / imageSize.width, viewportHeight / imageSize.height);
		const width = imageSize.width * scale;
		const height = imageSize.height * scale;
		const left = (viewportWidth - width) / 2;
		const top = (viewportHeight - height) / 2;

		for (const surface of surfaces) {
			const rect = surface.getBoundingClientRect();
			if (rect.width <= 0 || rect.height <= 0) continue;
			surface.style.setProperty('--wallpaper-image-size', `${width}px ${height}px`);
			surface.style.setProperty(
				'--wallpaper-image-position',
				`${left - rect.left}px ${top - rect.top}px`
			);
		}
	};

	const schedule = (): void => {
		if (disposed) return;
		cancelAnimationFrame(frame);
		frame = requestAnimationFrame(apply);
	};

	// New menus, dropdowns and select popups are inserted on demand; catch them.
	const observer = new MutationObserver(schedule);
	observer.observe(document.documentElement, { childList: true, subtree: true });

	// A panel's pop-in/drop animation transforms it while it opens, so measure
	// again once the motion finishes. Ignore unrelated transitions elsewhere.
	const onMotionEnd = (event: Event): void => {
		const target = event.target;
		if (target instanceof Element && (target.matches(SURFACE_SELECTOR) || target.closest(SURFACE_SELECTOR))) {
			schedule();
		}
	};

	window.addEventListener('resize', schedule);
	window.addEventListener('scroll', schedule, true);
	window.addEventListener('coreops:custom-appearance', schedule);
	document.addEventListener('animationend', onMotionEnd, true);
	document.addEventListener('transitionend', onMotionEnd, true);

	schedule();

	const stop = (): void => {
		disposed = true;
		cancelAnimationFrame(frame);
		observer.disconnect();
		window.removeEventListener('resize', schedule);
		window.removeEventListener('scroll', schedule, true);
		window.removeEventListener('coreops:custom-appearance', schedule);
		document.removeEventListener('animationend', onMotionEnd, true);
		document.removeEventListener('transitionend', onMotionEnd, true);
		started = null;
	};

	started = stop;
	return stop;
}
