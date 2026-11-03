/**
 * Validates that all locale files have every key from en.json (the base locale),
 * and that every message's placeholders are right: written `{{name}}`, as t()
 * fills them, and the same ones in every language as in English. A `{name}`
 * is shown to the user as it is; that shipped once, in 0.7.2.
 * Run: node scripts/i18n-check.js
 */

import { readdir, readFile } from 'fs/promises';
import { join, basename } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const LOCALES_DIR = join(__dirname, '..', 'src', 'lib', 'i18n', 'locales');

/** `{{name}}` placeholders in a message, sorted. */
function placeholders(value) {
	return [...value.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort().join(',');
}

/** `{name}` with single braces: never filled in, shown as written. */
function singleBraces(value) {
	return [...value.matchAll(/(?<!\{)\{(\w+)\}(?!\})/g)].map((m) => m[0]);
}

/** Problems with the placeholders of one locale against English. */
function placeholderProblems(content, base) {
	const problems = [];
	for (const [key, value] of Object.entries(content)) {
		if (typeof value !== 'string') continue;
		const single = singleBraces(value);
		if (single.length > 0) problems.push(`${key}: ${single.join(' ')} should be {{...}}`);
		if (key in base && placeholders(value) !== placeholders(base[key])) {
			problems.push(`${key}: placeholders {{${placeholders(value)}}} differ from English {{${placeholders(base[key])}}}`);
		}
	}
	return problems;
}

async function main() {
	const baseFile = join(LOCALES_DIR, 'en.json');
	const baseContent = JSON.parse(await readFile(baseFile, 'utf-8'));
	const baseKeys = Object.keys(baseContent).sort();

	console.log(`Base locale (en.json): ${baseKeys.length} keys\n`);

	const files = await readdir(LOCALES_DIR);
	const localeFiles = files.filter((f) => f.endsWith('.json') && f !== 'en.json');

	let hasErrors = false;

	const baseProblems = placeholderProblems(baseContent, baseContent);
	if (baseProblems.length > 0) {
		hasErrors = true;
		console.log('  en: PLACEHOLDERS');
		baseProblems.forEach((p) => console.log(`      ! ${p}`));
	}

	for (const file of localeFiles) {
		const locale = basename(file, '.json');
		const content = JSON.parse(await readFile(join(LOCALES_DIR, file), 'utf-8'));
		const localeKeys = new Set(Object.keys(content));

		const missing = baseKeys.filter((k) => !localeKeys.has(k));
		const extra = Object.keys(content).filter((k) => !baseKeys.includes(k));

		const problems = placeholderProblems(content, baseContent);

		if (missing.length === 0 && extra.length === 0 && problems.length === 0) {
			console.log(`  ${locale}: OK (${localeKeys.size} keys)`);
		} else {
			hasErrors = true;
			console.log(`  ${locale}: ISSUES`);
			if (missing.length > 0) {
				console.log(`    Missing (${missing.length}):`);
				missing.forEach((k) => console.log(`      - ${k}`));
			}
			if (extra.length > 0) {
				console.log(`    Extra (${extra.length}):`);
				extra.forEach((k) => console.log(`      + ${k}`));
			}
			if (problems.length > 0) {
				console.log(`    Placeholders (${problems.length}):`);
				problems.forEach((p) => console.log(`      ! ${p}`));
			}
		}
	}

	if (hasErrors) {
		console.log('\nSome locale files have issues.');
		process.exit(1);
	} else {
		console.log('\nAll locale files are valid.');
	}
}

main().catch((err) => {
	console.error('Error:', err.message);
	process.exit(1);
});
