use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiChatRequest {
    pub url: String,
    pub api_key: String,
    pub model: String,
    pub messages: Vec<AiMessage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<AiMessage>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterResponse {
    choices: Option<Vec<Choice>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Option<ChoiceMessage>,
}

#[derive(Debug, Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
    /// DeepSeek 新模型将推理过程/思考内容放在此字段，
    /// content 可能为空字符串，需降级读取此字段。
    reasoning_content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: Option<String>,
}

#[tauri::command]
pub async fn ai_chat(request: AiChatRequest) -> Result<String, String> {
    tracing::info!(
        "ai_chat called: model={}, url={}, messages={}",
        request.model,
        request.url,
        request.messages.len()
    );

    let client = crate::http::client_builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let body = OpenRouterRequest {
        model: request.model,
        messages: request.messages,
    };

    let res = client
        .post(&request.url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", request.api_key))
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("HTTP request failed: {}", e);
            format!("HTTP request failed: {}", e)
        })?;

    let status = res.status();
    tracing::info!("ai_chat response status: {}", status);

    if !status.is_success() {
        let text = res.text().await.unwrap_or_default();
        tracing::error!("ai_chat API error {}: {}", status.as_u16(), text);
        return Err(format!("API error {}: {}", status.as_u16(), text));
    }

    let raw = res.text().await.map_err(|e| {
        tracing::error!("Failed to read response body: {}", e);
        format!("Failed to read response body: {}", e)
    })?;

    tracing::info!("ai_chat response length: {} bytes", raw.len());

    let data: OpenRouterResponse = serde_json::from_str(&raw).map_err(|e| {
        tracing::error!(
            "Failed to parse response: {} — raw: {}",
            e,
            preview(&raw, 500)
        );
        format!("Failed to parse response: {}", e)
    })?;

    if let Some(err) = data.error {
        let msg = err
            .message
            .unwrap_or_else(|| "Unknown API error".to_string());
        tracing::error!("ai_chat API returned error: {}", msg);
        return Err(msg);
    }

    let content = data
        .choices
        .and_then(|c| c.into_iter().next())
        .and_then(|c| c.message)
        .map(|m| {
            let text = m.content.as_deref().unwrap_or("");
            if text.trim().is_empty() {
                m.reasoning_content.as_deref().unwrap_or("").to_string()
            } else {
                text.to_string()
            }
        })
        .unwrap_or_default();

    if content.trim().is_empty() {
        tracing::error!("ai_chat returned empty content");
        return Err("Empty response from AI model".to_string());
    }

    tracing::info!("ai_chat success: {} chars", content.len());
    Ok(content)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiFetchModelsRequest {
    pub api_key: String,
    pub base_url: String,
}

#[derive(Debug, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub context_length: u64,
    pub pricing: ModelPricing,
}

#[derive(Debug, Serialize)]
pub struct ModelPricing {
    pub prompt: String,
    pub completion: String,
}

#[derive(Debug, Deserialize)]
struct ModelsResponse {
    data: Vec<ModelEntry>,
}

#[derive(Debug, Deserialize)]
struct ModelEntry {
    id: String,
    name: Option<String>,
    description: Option<String>,
    context_length: Option<u64>,
    pricing: Option<ModelEntryPricing>,
}

#[derive(Debug, Deserialize)]
struct ModelEntryPricing {
    prompt: Option<String>,
    completion: Option<String>,
}

/// 安全截断字符串用于日志/错误信息，避免在多字节 UTF-8 字符（如中文）处切断导致 panic。
fn preview(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// 拼接模型列表接口地址，兼容用户填写带或不带版本号段的 base URL。
///
/// 例：
///   https://api.siliconflow.cn      → https://api.siliconflow.cn/v1/models
///   https://api.siliconflow.cn/v1   → https://api.siliconflow.cn/v1/models
///   https://open.bigmodel.cn/api/paas/v4 → .../v4/models
fn build_models_url(base_url: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let last_segment = base.rsplit('/').next().unwrap_or("");
    // 末尾是 v1 / v1beta / V4 这类版本号段则不再追加，与前端 resolveApiBase 保持一致
    let mut chars = last_segment.chars();
    let is_version_segment = matches!(chars.next(), Some('v') | Some('V'))
        && chars.next().is_some_and(|c| c.is_ascii_digit());
    if is_version_segment {
        format!("{}/models", base)
    } else {
        format!("{}/v1/models", base)
    }
}

#[tauri::command]
pub async fn ai_fetch_models(request: AiFetchModelsRequest) -> Result<Vec<ModelInfo>, String> {
    let models_url = build_models_url(&request.base_url);
    tracing::info!(
        "ai_fetch_models: base_url={}, full_url={}",
        request.base_url,
        models_url
    );

    let client = crate::http::client_builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let res = client
        .get(&models_url)
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {}", request.api_key))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("ai_fetch_models: request failed: {:?}", e);
            format!("网络请求失败: {}", e)
        })?;

    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(unknown)")
        .to_string();

    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    tracing::info!(
        "ai_fetch_models: status={}, content_type={}, body_len={}",
        status,
        content_type,
        body.len()
    );
    tracing::debug!("ai_fetch_models: body_preview={}", preview(&body, 500));

    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status.as_u16(), body));
    }

    if !content_type.starts_with("application/json") {
        tracing::error!(
            "ai_fetch_models: expected JSON but got content-type={}, body_preview={:?}",
            content_type,
            preview(&body, 100)
        );
        return Err(format!(
            "API 接口返回了 {} 格式的数据（期望 JSON）。请检查 API 地址是否正确。返回内容前 100 字节: {:?}",
            content_type,
            preview(&body, 100)
        ));
    }

    let data: ModelsResponse = serde_json::from_str(&body).map_err(|e| {
        tracing::error!(
            "ai_fetch_models: JSON parse error: {} — raw: {}",
            e,
            preview(&body, 300)
        );
        format!(
            "API 响应 JSON 解析失败: {}。响应前 200 字符: {}",
            e,
            preview(&body, 200)
        )
    })?;

    Ok(data
        .data
        .into_iter()
        .map(|m| ModelInfo {
            id: m.id,
            name: m.name.unwrap_or_default(),
            description: m.description.unwrap_or_default(),
            context_length: m.context_length.unwrap_or(0),
            pricing: ModelPricing {
                prompt: m
                    .pricing
                    .as_ref()
                    .and_then(|p| p.prompt.clone())
                    .unwrap_or_else(|| "0".to_string()),
                completion: m
                    .pricing
                    .as_ref()
                    .and_then(|p| p.completion.clone())
                    .unwrap_or_else(|| "0".to_string()),
            },
        })
        .collect())
}
