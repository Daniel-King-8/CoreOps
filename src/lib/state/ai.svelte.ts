import { invoke } from '@tauri-apps/api/core';
import {
	getOpenRouterApiKey,
	setOpenRouterApiKey,
	getDefaultAiModel,
	setDefaultAiModel,
	loadSecureSettings
} from './settings.svelte.js';

export interface AISettings {
	enabled: boolean;
	apiKey: string;
	apiUrl: string;
	selectedModel: string;
}

export interface OpenRouterModel {
	id: string;
	name: string;
	description: string;
	context_length: number;
	pricing: { prompt: string; completion: string };
}

const STORAGE_KEY = 'reach-ai-settings';

/**
 * 归一化 API 基础地址，让「带 /v1」与「不带 /v1」两种写法都能正常工作。
 *
 * 规则：
 * - 去掉首尾空白与末尾斜杠
 * - 若末尾不是版本号段（/v1、/v1beta、/v4 等），自动补上 /v1
 *
 * 例：
 *   https://api.siliconflow.cn            → https://api.siliconflow.cn/v1
 *   https://api.siliconflow.cn/v1         → 保持不变
 *   https://open.bigmodel.cn/api/paas/v4  → 保持不变（尊重服务商自有版本号）
 */
export function resolveApiBase(rawUrl?: string): string {
	let base = (rawUrl ?? '').trim().replace(/\/+$/, '');
	if (!base) return base;
	const lastSegment = base.slice(base.lastIndexOf('/') + 1);
	// 末尾已是 v1 / v1beta / v4 这类版本号段则不再追加
	if (!/^v\d/i.test(lastSegment)) base += '/v1';
	return base;
}

let aiSettings = $state<AISettings>({
	enabled: false,
	apiKey: '',
	apiUrl: 'https://api.deepseek.com/v1',
	// `deepseek-chat` was retired on 2026-07-24 and now 404s; `deepseek-flash`
	// is the current DeepSeek model name.
	selectedModel: 'deepseek-flash'
});
let models = $state<OpenRouterModel[]>([]);
let modelsLoading = $state(false);
let modelsError = $state<string | undefined>();
let secureLoaded = $state(false);

export function getAISettings(): AISettings {
	return aiSettings;
}

/** 更新 AI 设置项。API Key 加密存入 Vault，其余字段存 localStorage。 */
export async function updateAISetting<K extends keyof AISettings>(
	key: K,
	value: AISettings[K]
): Promise<void> {
	aiSettings[key] = value;

	if (key === 'apiKey') {
		await setOpenRouterApiKey(value as string);
	} else if (key === 'selectedModel') {
		await setDefaultAiModel(value as string);
		saveLocalSettings();
	} else {
		saveLocalSettings();
	}
}

/** 从 localStorage 加载非敏感设置（enabled、apiUrl、selectedModel）。 */
export function loadAISettings(): void {
	if (typeof localStorage === 'undefined') return;

	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (raw) {
			const parsed = JSON.parse(raw) as Partial<{
				enabled: boolean;
				apiUrl: string;
				selectedModel: string;
			}>;
			aiSettings.enabled = parsed.enabled ?? false;
			if (parsed.apiUrl) aiSettings.apiUrl = parsed.apiUrl;
			if (!aiSettings.selectedModel && parsed.selectedModel) {
				aiSettings.selectedModel = parsed.selectedModel;
			}
		}
	} catch {
		// 数据损坏 — 保持默认值
	}
}

/**
 * 从 Vault 加载加密的敏感设置（API Key + 模型名）。
 *
 * 只有真正读到 API Key 才置位 `secureLoaded`。此前只要调用过一次就无条件
 * 置位，于是当 Vault 尚未解锁（解锁是异步的，启动时常常慢一拍）时读到
 * null 也会把 `secureLoaded` 设为 true，导致后续解锁了也不再重试 —— 表现
 * 为每次重启 AI 都「未配置」，必须进设置页手动触发一次。
 */
export async function loadSecureAISettings(): Promise<void> {
	if (secureLoaded) return;

	await loadSecureSettings();

	const apiKey = getOpenRouterApiKey();
	const model = getDefaultAiModel();

	if (apiKey) {
		aiSettings.apiKey = apiKey;
		// 读到 Key 才认为加载完成；否则保持 false，等 Vault 解锁后重试。
		secureLoaded = true;
	}
	if (model) aiSettings.selectedModel = model;
}

/** 清空加密设置（Vault 锁定时调用）。 */
export function clearSecureAISettings(): void {
	aiSettings.apiKey = '';
	secureLoaded = false;
}

/** 将非敏感设置持久化到 localStorage。 */
function saveLocalSettings(): void {
	if (typeof localStorage === 'undefined') return;
	try {
		localStorage.setItem(
			STORAGE_KEY,
			JSON.stringify({
				enabled: aiSettings.enabled,
				apiUrl: aiSettings.apiUrl,
				selectedModel: aiSettings.selectedModel
			})
		);
	} catch {
		// Storage 不可用
	}
}

/** @deprecated 请使用异步的 updateAISetting。 */
export function saveAISettings(): void {
	saveLocalSettings();
}

export function getModels(): OpenRouterModel[] {
	return models;
}

export function getModelsLoading(): boolean {
	return modelsLoading;
}

export function getModelsError(): string | undefined {
	return modelsError;
}

/** 从配置的 API 地址拉取可用模型列表。 */
export async function fetchModels(): Promise<void> {
	if (!aiSettings.apiKey) return;
	modelsLoading = true;
	modelsError = undefined;
	try {
		const result = await invoke<
			Array<{
				id: string;
				name: string;
				description: string;
				context_length: number;
				pricing: { prompt: string; completion: string };
			}>
		>('ai_fetch_models', {
			request: {
				apiKey: aiSettings.apiKey,
				baseUrl: resolveApiBase(aiSettings.apiUrl)
			}
		});
		models = result.map((m) => ({
			id: m.id,
			name: m.name,
			description: m.description,
			context_length: m.context_length,
			pricing: {
				prompt: m.pricing.prompt,
				completion: m.pricing.completion
			}
		}));
	} catch (e) {
		modelsError = String(e);
	} finally {
		modelsLoading = false;
	}
}

export function getSelectedModelInfo(): OpenRouterModel | undefined {
	return models.find((m) => m.id === aiSettings.selectedModel);
}
