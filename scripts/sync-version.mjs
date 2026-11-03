/**
 * 把发布 tag 的版本号同步写入三处版本文件。
 *
 * 由 .github/workflows/release.yml 在打包前调用：
 *   node scripts/sync-version.mjs 0.4.20
 *
 * 背景：此前版本号文件不会跟随 tag 更新，导致安装包内部版本号始终是旧值，
 * 用户更新后应用仍自报旧版本，形成「反复提示更新」的死循环。
 *
 * 设计要点：采用正则替换而非 JSON 重新序列化，只改动 version 字段那一行，
 * 保留原文件的缩进与格式，避免产生整文件 diff。
 */

import { readFileSync, writeFileSync } from 'fs';

const version = (process.argv[2] ?? '').trim().replace(/^v/, '');

if (!version) {
	console.error('用法: node scripts/sync-version.mjs <版本号>');
	process.exit(1);
}

if (!/^\d+\.\d+\.\d+/.test(version)) {
	console.error(`版本号格式不合法: ${version}`);
	process.exit(1);
}

/** 替换 JSON 顶层 2 空格缩进的 version 字段，保留原格式。 */
function patchJson(path) {
	const raw = readFileSync(path, 'utf8');
	// 顶层字段是 2 空格缩进；依赖对象的 version 是更深缩进，不会误伤
	const pattern = /^(\s{2}"version"\s*:\s*)"[^"]*"/m;

	if (!pattern.test(raw)) {
		throw new Error(`未找到顶层 version 字段: ${path}`);
	}

	// 注意：即使新旧版本号相同，replace 结果也与原文一致，
	// 因此必须用 test() 判断字段是否存在，不能用「结果是否变化」来判断。
	writeFileSync(path, raw.replace(pattern, `$1"${version}"`));
	console.log(`  ✓ ${path}`);
}

/** 替换 Cargo.toml 中 [package] 段的行首 version，不触碰依赖版本。 */
function patchCargoToml(path) {
	const raw = readFileSync(path, 'utf8');
	const pattern = /^version\s*=\s*"[^"]*"/m;

	if (!pattern.test(raw)) {
		throw new Error(`未找到 [package] version 字段: ${path}`);
	}

	writeFileSync(path, raw.replace(pattern, `version = "${version}"`));
	console.log(`  ✓ ${path}`);
}

console.log(`同步版本号到: ${version}`);

try {
	patchJson('package.json'); // 前端 APP_VERSION 来源
	patchJson('src-tauri/tauri.conf.json'); // 安装包版本号来源
	patchCargoToml('src-tauri/Cargo.toml'); // Rust crate 版本
} catch (e) {
	console.error(`同步失败: ${e.message}`);
	process.exit(1);
}

console.log('版本号同步完成');
