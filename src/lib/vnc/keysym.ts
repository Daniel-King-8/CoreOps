/**
 * Browser keyboard events → X11 keysyms, for VNC.
 *
 * A VNC server is sent the character a key produced, not the key's position:
 * it then types that character on its own keyboard map. So printable keys
 * are taken from `KeyboardEvent.key`, which follows the local layout, and
 * only keys that produce no character are taken from `code`.
 *
 * Values are from X11's keysymdef.h. A character outside Latin-1 is
 * 0x01000000 + its code point, the Unicode keysym range every current server
 * understands.
 */

/** Keys that produce no character, by `KeyboardEvent.key` (and by `code`, where the names agree). */
const NAMED: Record<string, number> = {
	Backspace: 0xff08, Tab: 0xff09, Enter: 0xff0d, Escape: 0xff1b, Delete: 0xffff, Insert: 0xff63,
	Home: 0xff50, End: 0xff57, PageUp: 0xff55, PageDown: 0xff56,
	ArrowLeft: 0xff51, ArrowUp: 0xff52, ArrowRight: 0xff53, ArrowDown: 0xff54,
	PrintScreen: 0xff61, ScrollLock: 0xff14, Pause: 0xff13, ContextMenu: 0xff67,
	CapsLock: 0xffe5, NumLock: 0xff7f, Clear: 0xff0b,
	F1: 0xffbe, F2: 0xffbf, F3: 0xffc0, F4: 0xffc1, F5: 0xffc2, F6: 0xffc3,
	F7: 0xffc4, F8: 0xffc5, F9: 0xffc6, F10: 0xffc7, F11: 0xffc8, F12: 0xffc9,
};

/** Modifiers, by `code`: which side matters to some programs. */
const MODIFIERS: Record<string, number> = {
	ShiftLeft: 0xffe1, ShiftRight: 0xffe2, ControlLeft: 0xffe3, ControlRight: 0xffe4,
	AltLeft: 0xffe9, AltRight: 0xffea, MetaLeft: 0xffeb, MetaRight: 0xffec,
	OSLeft: 0xffeb, OSRight: 0xffec,
};

/** The keypad, by what it typed, so NumLock on gives keypad digits. */
const KEYPAD: Record<string, number> = {
	'0': 0xffb0, '1': 0xffb1, '2': 0xffb2, '3': 0xffb3, '4': 0xffb4,
	'5': 0xffb5, '6': 0xffb6, '7': 0xffb7, '8': 0xffb8, '9': 0xffb9,
	'.': 0xffae, ',': 0xffac, '+': 0xffab, '-': 0xffad, '*': 0xffaa, '/': 0xffaf,
};

/** The keysym for one character. */
export function keysymForChar(ch: string): number | null {
	const cp = ch.codePointAt(0);
	if (cp === undefined || cp < 0x20 || cp === 0x7f) return null;
	if (cp < 0x7f || (cp >= 0xa0 && cp <= 0xff)) return cp;
	return 0x01000000 + cp;
}

/** The keysym for a key by its position alone: the phone key bar's keys. */
export function keysymForCode(code: string): number | null {
	if (code in MODIFIERS) return MODIFIERS[code];
	if (code in NAMED) return NAMED[code];
	if (code === 'Space') return 0x20;
	if (code === 'NumpadEnter') return 0xff8d;
	const letter = /^Key([A-Z])$/.exec(code);
	if (letter) return letter[1].toLowerCase().charCodeAt(0);
	const digit = /^Digit([0-9])$/.exec(code);
	if (digit) return digit[1].charCodeAt(0);
	return null;
}

/**
 * The keysym for a key event, or null for one that should not be sent:
 * a dead key (the character it makes arrives with the next key), an IME
 * composition, AltGr itself (see the panel).
 *
 * With Ctrl, Alt or the Windows key held, a letter or digit is sent as the
 * Latin one in that position: on a Greek or Cyrillic layout Ctrl+C must be
 * Ctrl+C, not Ctrl+ψ.
 */
export function keysymForEvent(e: Pick<KeyboardEvent, 'code' | 'key' | 'ctrlKey' | 'altKey' | 'metaKey'>): number | null {
	if (e.key === 'Dead' || e.key === 'Process' || e.key === 'Unidentified' || e.key === 'AltGraph') return null;
	if (e.code in MODIFIERS) return MODIFIERS[e.code];
	if (e.code === 'NumpadEnter') return 0xff8d;
	if (e.code.startsWith('Numpad') && e.key in KEYPAD) return KEYPAD[e.key];
	if (e.key in NAMED) return NAMED[e.key];
	if ([...e.key].length === 1) {
		const shortcut = e.ctrlKey || e.altKey || e.metaKey;
		if (shortcut && /^(Key[A-Z]|Digit[0-9])$/.test(e.code) && !/^[\x20-\x7e]$/.test(e.key)) {
			return keysymForCode(e.code);
		}
		return keysymForChar(e.key);
	}
	return null;
}
