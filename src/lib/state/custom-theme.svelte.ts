/**
 * Optional user appearance on top of a theme.
 *
 * A theme is a fixed palette. This layer lets a user put their own picture
 * behind the interface and override the text/accent colours without writing a
 * theme file. It is deliberately local to this device: a picture is data, not
 * a theme, and should not travel with a shared vault.
 */

export interface CustomAppearance {
	/** A data: URL of the picture, or empty for none. */
	backgroundImage: string;
	/** How strongly the picture shows through the app, 0–100. */
	backgroundOpacity: number;
	/** Draw the picture behind the terminal too, instead of its solid colour. */
	terminalBackground: boolean;
	/** Empty means "use the theme's colour". */
	textPrimary: string;
	textSecondary: string;
	accent: string;
}

const STORAGE_KEY = 'coreops-custom-appearance';

const DEFAULTS: CustomAppearance = {
	backgroundImage: '',
	backgroundOpacity: 45,
	terminalBackground: false,
	textPrimary: '',
	textSecondary: '',
	accent: ''
};

function load(): CustomAppearance {
	if (typeof localStorage === 'undefined') return { ...DEFAULTS };
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (!raw) return { ...DEFAULTS };
		const parsed = JSON.parse(raw) as Partial<CustomAppearance>;
		return {
			backgroundImage: typeof parsed.backgroundImage === 'string' ? parsed.backgroundImage : '',
			backgroundOpacity:
				typeof parsed.backgroundOpacity === 'number'
					? Math.min(100, Math.max(0, parsed.backgroundOpacity))
					: DEFAULTS.backgroundOpacity,
			terminalBackground: parsed.terminalBackground === true,
			textPrimary: typeof parsed.textPrimary === 'string' ? parsed.textPrimary : '',
			textSecondary: typeof parsed.textSecondary === 'string' ? parsed.textSecondary : '',
			accent: typeof parsed.accent === 'string' ? parsed.accent : ''
		};
	} catch {
		return { ...DEFAULTS };
	}
}

let custom = $state<CustomAppearance>(load());

export function getCustomAppearance(): CustomAppearance {
	return custom;
}

function save(): void {
	if (typeof localStorage === 'undefined') return;
	try {
		localStorage.setItem(STORAGE_KEY, JSON.stringify(custom));
	} catch {
		// A picture can exceed the quota. It still applies for this run.
	}
}

export function setCustomBackgroundImage(dataUrl: string): void {
	custom.backgroundImage = dataUrl;
	save();
	applyCustomAppearance();
}

export function setCustomBackgroundOpacity(value: number): void {
	custom.backgroundOpacity = Math.min(100, Math.max(0, value));
	save();
	applyCustomAppearance();
}

export function setCustomTerminalBackground(value: boolean): void {
	custom.terminalBackground = value;
	save();
	applyCustomAppearance();
}

export function setCustomColor(key: 'textPrimary' | 'textSecondary' | 'accent', value: string): void {
	custom[key] = value;
	save();
	applyCustomAppearance();
}

export function resetCustomAppearance(): void {
	custom = { ...DEFAULTS };
	save();
	applyCustomAppearance();
}

function setOrRemove(root: HTMLElement, name: string, value: string): void {
	if (value) root.style.setProperty(name, value);
	else root.style.removeProperty(name);
}

/**
 * Re-apply the custom layer. Called after every theme change because applying
 * a theme writes the same CSS variables this layer overrides.
 */
export function applyCustomAppearance(): void {
	if (typeof document === 'undefined') return;
	const root = document.documentElement;

	// Fall back to the theme's own value rather than removing the property:
	// the theme writes these inline too, and removing them would leave the
	// built-in dark palette behind a light or marketplace theme.
	setOrRemove(root, '--color-text-primary', custom.textPrimary || 'var(--theme-text-primary)');
	setOrRemove(root, '--color-text-secondary', custom.textSecondary || 'var(--theme-text-secondary)');
	setOrRemove(root, '--color-accent', custom.accent || 'var(--theme-accent)');
	setOrRemove(
		root,
		'--color-accent-hover',
		custom.accent ? `color-mix(in srgb, ${custom.accent} 82%, white)` : 'var(--theme-accent-hover)'
	);

	if (custom.backgroundImage) {
		// applyTheme writes these tokens inline, which beats a stylesheet
		// override, so the translucent values have to be inline too.
		//
		// The picture itself stays opaque and the interface fades instead. Dimming
		// both multiplied the two opacities: at the default 45% the picture only
		// reached the eye at about 10%, which a white surface hid completely in a
		// light theme. Keeping the picture opaque makes the slider mean what it
		// says, in light and dark themes alike.
		const visibility = custom.backgroundOpacity / 100;
		const surface = (token: 'primary' | 'secondary' | 'elevated', keep: number): string =>
			`color-mix(in srgb, var(--theme-bg-${token}) ${100 - visibility * keep}%, transparent)`;

		// The page fades in step with the slider, so 100% shows the picture
		// unobscured. Panels keep some of the theme colour, so text sitting on
		// them stays readable however visible the picture is.
		root.style.setProperty('--color-bg-primary', surface('primary', 100));
		root.style.setProperty('--color-bg-secondary', surface('secondary', 85));
		root.style.setProperty('--color-bg-elevated', surface('elevated', 70));
		root.style.setProperty('--custom-appearance-image', `url("${custom.backgroundImage}")`);
		root.style.setProperty('--custom-appearance-opacity', '1');
		root.classList.add('custom-appearance');
	} else {
		root.classList.remove('custom-appearance');
		root.style.setProperty('--color-bg-primary', 'var(--theme-bg-primary)');
		root.style.setProperty('--color-bg-secondary', 'var(--theme-bg-secondary)');
		root.style.setProperty('--color-bg-elevated', 'var(--theme-bg-elevated)');
		root.style.removeProperty('--custom-appearance-image');
		root.style.removeProperty('--custom-appearance-opacity');
	}

	// The terminal switch only makes sense with a picture to show; without one,
	// or with the switch off, the terminal keeps its theme's solid colour.
	root.classList.toggle(
		'custom-terminal-background',
		Boolean(custom.backgroundImage && custom.terminalBackground)
	);

	// Floating panels compute the picture's cover geometry from this layer.
	if (typeof window !== 'undefined') {
		window.dispatchEvent(new Event('coreops:custom-appearance'));
	}
}
