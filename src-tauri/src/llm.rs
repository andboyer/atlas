use crate::types::ScanResult;
use anyhow::Result;
use serde::{Deserialize, Serialize};

// ── Prompt building ───────────────────────────────────────────────────────────

/// Build the user prompt from a scan result.  We only include aggregated
/// metrics — never raw hostnames, SSIDs, or other PII unless the user has
/// confirmed.  (Full redaction UI is a follow-up feature.)
fn build_prompt(scan: &ScanResult) -> String {
    let link = &scan.link;
    let reach = &scan.reachability;

    let mut lines = vec![
        "You are an expert network engineer helping a small-business owner or IT admin.".to_string(),
        "Here is a structured WiFi diagnostic. Explain each finding in plain language,".to_string(),
        "give 2-3 specific actionable steps per issue, and end with a one-sentence priority.".to_string(),
        String::new(),
        "## WiFi Link".to_string(),
        format!("  Band: {}", link.band.as_deref().unwrap_or("unknown")),
        format!("  RSSI: {} dBm", link.rssi_dbm.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string())),
        format!("  SNR: {} dB", link.snr_db.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string())),
        format!("  Tx rate: {} Mbps", link.tx_rate_mbps.map(|v| format!("{v:.0}")).unwrap_or_else(|| "n/a".to_string())),
        String::new(),
        "## Reachability".to_string(),
        format!("  Gateway latency: {} ms", reach.gateway_latency_ms.map(|v| format!("{v:.1}")).unwrap_or_else(|| "n/a".to_string())),
        format!("  Internet latency: {} ms", reach.internet_latency_ms.map(|v| format!("{v:.1}")).unwrap_or_else(|| "n/a".to_string())),
        format!("  DNS latency: {} ms", reach.dns_latency_ms.map(|v| format!("{v:.1}")).unwrap_or_else(|| "n/a".to_string())),
        format!("  Packet loss: {}%", reach.packet_loss_pct.map(|v| format!("{v:.1}")).unwrap_or_else(|| "n/a".to_string())),
        String::new(),
        format!("## Devices: {} online / {}", scan.devices.iter().filter(|d| d.online).count(), scan.devices.len()),
        String::new(),
    ];

    if scan.findings.is_empty() {
        lines.push("## Findings: none — network appears healthy.".to_string());
    } else {
        lines.push("## Findings".to_string());
        for (i, f) in scan.findings.iter().enumerate() {
            lines.push(format!(
                "{}. [{}] {} (confidence {:.0}%)",
                i + 1,
                f.severity.as_str().to_uppercase(),
                f.title,
                f.confidence * 100.0
            ));
            for ev in &f.evidence {
                lines.push(format!("   - {ev}"));
            }
        }
    }

    lines.push(String::new());
    lines.push("Please respond in 3–5 short paragraphs, one per finding. Be direct and jargon-free.".to_string());

    lines.join("\n")
}

/// A single message in a chat conversation.
#[derive(Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

// ── OpenAI ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OaiRequest<'a> {
    model: &'a str,
    messages: Vec<OaiMessageOwned>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize)]
struct OaiMessageOwned {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OaiResponse {
    choices: Vec<OaiChoice>,
}

#[derive(Deserialize)]
struct OaiChoice {
    message: OaiChoiceMessage,
}

#[derive(Deserialize)]
struct OaiChoiceMessage {
    content: String,
}

async fn call_openai(api_key: &str, model: &str, base_url: Option<&str>, messages: &[ChatMessage]) -> Result<String> {
    let url = format!(
        "{}/v1/chat/completions",
        base_url.unwrap_or("https://api.openai.com")
    );
    let body = OaiRequest {
        model,
        messages: messages.iter().map(|m| OaiMessageOwned { role: m.role.clone(), content: m.content.clone() }).collect(),
        max_tokens: 800,
        temperature: 0.4,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json::<OaiResponse>()
        .await?;

    Ok(resp
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default())
}

// ── Anthropic ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AnthropicRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessageOwned>,
}

#[derive(Serialize)]
struct AnthropicMessageOwned {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: String,
}

async fn call_anthropic(api_key: &str, model: &str, messages: &[ChatMessage]) -> Result<String> {
    // Anthropic uses a top-level `system` field; user/assistant messages go in `messages`.
    let system = messages
        .iter()
        .find(|m| m.role == "system")
        .map(|m| m.content.clone())
        .unwrap_or_default();
    let chat_messages: Vec<AnthropicMessageOwned> = messages
        .iter()
        .filter(|m| m.role != "system")
        .map(|m| AnthropicMessageOwned { role: m.role.clone(), content: m.content.clone() })
        .collect();

    let body = AnthropicRequest {
        model,
        max_tokens: 800,
        system,
        messages: chat_messages,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json::<AnthropicResponse>()
        .await?;

    Ok(resp
        .content
        .into_iter()
        .next()
        .map(|c| c.text)
        .unwrap_or_default())
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Build the chat messages list for a one-shot diagnostic explanation.
fn explain_messages(scan: &ScanResult) -> Vec<ChatMessage> {
    vec![ChatMessage { role: "user".into(), content: build_prompt(scan) }]
}

/// Build the system message that embeds diagnostic context for interactive chat.
fn chat_system_message(scan: &ScanResult) -> ChatMessage {
    let mut sys = "You are an expert network engineer assistant helping a user troubleshoot their WiFi and LAN.\n".to_string();
    sys.push_str("Here is the current diagnostic context:\n\n");
    sys.push_str(&build_prompt(scan));
    sys.push_str("\n\nAnswer the user's follow-up questions concisely and precisely, referencing the above data.");
    ChatMessage { role: "system".into(), content: sys }
}

/// Dispatch to the correct LLM provider with a messages list.
async fn dispatch(provider: &str, api_key: &str, model: &str, base_url: Option<&str>, messages: &[ChatMessage]) -> Result<String> {
    match provider {
        "anthropic" => call_anthropic(api_key, model, messages).await,
        _ => call_openai(api_key, model, base_url, messages).await,
    }
}

/// Call the configured LLM with a structured summary of the scan and return
/// a plain-language explanation.
pub async fn explain(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    scan: &ScanResult,
) -> Result<String> {
    let messages = explain_messages(scan);
    tracing::debug!("LLM explain ({} chars)", messages[0].content.len());
    dispatch(provider, api_key, model, base_url, &messages).await
}

/// Answer a follow-up question in the context of the current scan result.
/// `history` is alternating user/assistant messages (not including the new question).
pub async fn chat_query(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    scan: &ScanResult,
    history: Vec<ChatMessage>,
    question: &str,
) -> Result<String> {
    let mut messages = vec![chat_system_message(scan)];
    messages.extend(history);
    messages.push(ChatMessage { role: "user".into(), content: question.to_string() });
    tracing::debug!("LLM chat ({} msgs)", messages.len());
    dispatch(provider, api_key, model, base_url, &messages).await
}

// ── Payload preview (returned to frontend before sending) ────────────────────

/// Return the prompt that *would* be sent, so the user can review it before
/// confirming.  Nothing is sent to any server by this function.
pub fn preview_payload(scan: &ScanResult) -> String {
    build_prompt(scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, LinkStats, ReachabilityStats, ScanResult, Severity};
    use chrono::Utc;
    use uuid::Uuid;

    fn empty_scan() -> ScanResult {
        ScanResult {
            run_id: Uuid::new_v4().to_string(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            link: LinkStats {
                ssid: None, bssid: None, band: Some("5".to_string()),
                channel: Some(36), channel_width_mhz: Some(80),
                rssi_dbm: Some(-55), noise_dbm: Some(-95),
                snr_db: Some(40), tx_rate_mbps: Some(400.0),
                rx_rate_mbps: None, security: Some("WPA2".to_string()),
            },
            reachability: ReachabilityStats {
                gateway_ip: Some("192.168.1.1".to_string()),
                gateway_latency_ms: Some(2.0),
                internet_latency_ms: Some(15.0),
                dns_latency_ms: Some(10.0),
                packet_loss_pct: Some(0.0),
            },
            devices: vec![],
            findings: vec![],
            recommendations: vec![],
            service_reachability: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
            nearby_aps: vec![],
            speed_mbps: None,
        }
    }

    #[test]
    fn prompt_contains_key_fields() {
        let scan = empty_scan();
        let prompt = build_prompt(&scan);
        assert!(prompt.contains("5"), "band missing");
        assert!(prompt.contains("-55"), "rssi missing");
        assert!(prompt.contains("healthy"), "healthy state missing");
    }

    #[test]
    fn prompt_lists_findings() {
        let mut scan = empty_scan();
        scan.findings = vec![Finding {
            id: "f1".to_string(),
            rule_id: "link.weak_signal".to_string(),
            title: "Weak signal strength".to_string(),
            severity: Severity::High,
            confidence: 0.9,
            evidence: vec!["RSSI -78 dBm".to_string()],
            affected_devices: vec![],
            recommendation_id: None,
            observed_at: Utc::now(),
        }];
        let prompt = build_prompt(&scan);
        assert!(prompt.contains("Weak signal strength"));
        assert!(prompt.contains("HIGH"));
        assert!(prompt.contains("90%"));
    }
}
