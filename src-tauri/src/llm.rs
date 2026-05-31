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

// ── OpenAI ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OaiRequest<'a> {
    model: &'a str,
    messages: Vec<OaiMessage<'a>>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize)]
struct OaiMessage<'a> {
    role: &'a str,
    content: &'a str,
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

async fn call_openai(api_key: &str, model: &str, base_url: Option<&str>, prompt: &str) -> Result<String> {
    let url = format!(
        "{}/v1/chat/completions",
        base_url.unwrap_or("https://api.openai.com")
    );
    let body = OaiRequest {
        model,
        messages: vec![OaiMessage { role: "user", content: prompt }],
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
    messages: Vec<AnthropicMessage<'a>>,
}

#[derive(Serialize)]
struct AnthropicMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: String,
}

async fn call_anthropic(api_key: &str, model: &str, prompt: &str) -> Result<String> {
    let body = AnthropicRequest {
        model,
        max_tokens: 800,
        messages: vec![AnthropicMessage { role: "user", content: prompt }],
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

// ── Public entry point ────────────────────────────────────────────────────────

/// Call the configured LLM with a structured summary of the scan and return
/// a plain-language explanation.
pub async fn explain(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    scan: &ScanResult,
) -> Result<String> {
    let prompt = build_prompt(scan);
    tracing::debug!("LLM prompt ({} chars):\n{}", prompt.len(), &prompt[..prompt.len().min(200)]);

    match provider {
        "anthropic" => call_anthropic(api_key, model, &prompt).await,
        _ => call_openai(api_key, model, base_url, &prompt).await,
    }
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
