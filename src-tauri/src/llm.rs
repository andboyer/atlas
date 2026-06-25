use crate::store::MetricSample;
use crate::types::{AvDiagnosticsResult, ScanResult};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Prompt building ───────────────────────────────────────────────────────────

/// One series of recent metric samples sent into the prompt (oldest-first).
pub type MetricHistory = Vec<(String, Vec<MetricSample>)>;

/// Build the user prompt from a scan result + optional time-series history.
///
/// We deliberately include the full advanced-analytics surface (bufferbloat,
/// interference, PHY efficiency, roaming, rogue APs) plus a compact summary
/// of the last hour of RSSI / latency / loss samples so the model can reason
/// about *trends*, not just the current instant. The trade-off is prompt
/// length (~1.5-3 KB typical) — well under any model's context limit and
/// well worth the diagnostic quality.
///
/// We never include raw hostnames or device MACs.
fn build_prompt(scan: &ScanResult, history: Option<&MetricHistory>) -> String {
    let link = &scan.link;
    let reach = &scan.reachability;

    let mut lines = vec![
        "You are an expert network engineer helping a small-business owner or IT admin."
            .to_string(),
        "Below is a structured WiFi diagnostic, including bufferbloat, channel".to_string(),
        "interference, PHY-rate efficiency, roaming history, and (if present)".to_string(),
        "potential rogue APs. Explain each finding in plain language, give 2-3".to_string(),
        "specific actionable steps per issue, and end with a one-sentence priority.".to_string(),
        String::new(),
        "## WiFi Link".to_string(),
        format!("  Band: {}", link.band.as_deref().unwrap_or("unknown")),
        format!(
            "  Channel: {} ({} MHz)",
            link.channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "n/a".into()),
            link.channel_width_mhz
                .map(|w| w.to_string())
                .unwrap_or_else(|| "n/a".into())
        ),
        format!(
            "  PHY mode: {}",
            link.phy_mode.as_deref().unwrap_or("unknown")
        ),
        format!(
            "  Wi-Fi generation: {}",
            link.wifi_generation.as_deref().unwrap_or("unknown")
        ),
        format!(
            "  AP vendor (OUI): {}",
            link.vendor.as_deref().unwrap_or("unknown")
        ),
        format!(
            "  Security: {}",
            link.security.as_deref().unwrap_or("unknown")
        ),
        format!(
            "  RSSI: {} dBm",
            link.rssi_dbm
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "  SNR: {} dB",
            link.snr_db
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "  Tx rate: {} Mbps",
            link.tx_rate_mbps
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "n/a".to_string())
        ),
        String::new(),
        "## Reachability".to_string(),
        format!(
            "  Gateway latency: {} ms",
            reach
                .gateway_latency_ms
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "  Internet latency: {} ms",
            reach
                .internet_latency_ms
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "  DNS latency: {} ms",
            reach
                .dns_latency_ms
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "  Packet loss: {}%",
            reach
                .packet_loss_pct
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "n/a".to_string())
        ),
    ];

    if let Some(speed) = scan.speed_mbps {
        lines.push(format!("  HTTP download: {speed:.1} Mbps"));
    }
    if let Some(mtu) = scan.mtu_bytes {
        lines.push(format!("  Path MTU: {mtu} bytes"));
    }
    if scan.captive_portal {
        lines.push("  ⚠ Captive portal detected.".into());
    }
    if scan.dns_leak {
        lines.push("  ⚠ DNS leak detected — queries going outside the configured resolver.".into());
    }

    // ── Bufferbloat / responsiveness ──
    if let Some(q) = &scan.quality {
        lines.push(String::new());
        lines.push("## Bufferbloat (networkQuality)".to_string());
        if let Some(rpm) = q.responsiveness_rpm {
            let label = q.responsiveness_label.as_deref().unwrap_or("");
            lines.push(format!("  Responsiveness: {rpm} RPM ({label})"));
        }
        if let Some(dl) = q.dl_throughput_mbps {
            lines.push(format!("  Downlink: {dl:.1} Mbps"));
        }
        if let Some(ul) = q.ul_throughput_mbps {
            lines.push(format!("  Uplink: {ul:.1} Mbps"));
        }
        if let Some(idle) = q.idle_latency_ms {
            lines.push(format!("  Idle latency: {idle:.1} ms"));
        }
    }

    // ── PHY efficiency ──
    if let Some(p) = &scan.phy_efficiency {
        lines.push(String::new());
        lines.push("## PHY-rate efficiency".to_string());
        lines.push(format!("  Mode: {}", p.phy_mode));
        lines.push(format!(
            "  Actual / theoretical: {:.0} / {:.0} Mbps ({:.0}% — {})",
            p.actual_mbps,
            p.theoretical_max_mbps,
            p.efficiency * 100.0,
            p.grade
        ));
        lines.push(format!("  Diagnostic: {}", p.diagnostic));
    }

    // ── Channel interference ──
    if let Some(intf) = &scan.interference {
        lines.push(String::new());
        lines.push("## Channel interference".to_string());
        if let Some(score) = intf.current_channel_score {
            lines.push(format!(
                "  Current channel score: {score:.0}/100 (lower is better)"
            ));
        }
        if let Some(ch) = intf.recommended_24 {
            lines.push(format!("  Recommended 2.4 GHz channel: {ch}"));
        }
        if let Some(ch) = intf.recommended_5 {
            lines.push(format!("  Recommended 5 GHz channel: {ch}"));
        }
        // Top 3 most-congested channels for context.
        let mut sorted = intf.channels.clone();
        sorted.sort_by(|a, b| {
            b.interference_score
                .partial_cmp(&a.interference_score)
                .unwrap()
        });
        let worst: Vec<String> = sorted
            .iter()
            .take(3)
            .map(|c| {
                format!(
                    "ch {} ({} GHz, {:.0})",
                    c.channel, c.band, c.interference_score
                )
            })
            .collect();
        if !worst.is_empty() {
            lines.push(format!("  Most congested: {}", worst.join(", ")));
        }
    }

    // ── Roaming ──
    if let Some(r) = &scan.roaming {
        lines.push(String::new());
        lines.push("## Roaming history".to_string());
        lines.push(format!("  Roams (last hour): {}", r.events_last_hour));
        lines.push(format!("  Roams (last 24h): {}", r.events_last_24h));
        if let Some(d) = r.avg_dwell_secs {
            lines.push(format!("  Average dwell time: {} s", d));
        }
        if r.sticky_warning {
            lines.push("  ⚠ Sticky-client suspected: weak RSSI but no recent roam.".into());
        }
    }

    // ── Rogue APs ──
    if !scan.rogue_aps.is_empty() {
        lines.push(String::new());
        lines.push("## Potential rogue / evil-twin APs".to_string());
        for r in &scan.rogue_aps {
            lines.push(format!(
                "  [{sev}] SSID '{ssid}' — {reason}",
                sev = r.severity.as_str().to_uppercase(),
                ssid = r.ssid,
                reason = r.reason,
            ));
        }
    }

    // ── Internet egress (WAN / ISP) ──
    if let Some(w) = &scan.wan {
        lines.push(String::new());
        lines.push("## Internet egress".to_string());
        if let Some(ip) = &w.public_ipv4 {
            lines.push(format!("  Public IPv4: {ip}"));
        }
        if let Some(ip) = &w.public_ipv6 {
            lines.push(format!("  Public IPv6: {ip}"));
        }
        lines.push(format!(
            "  Dual-stack (v4+v6): {}",
            if w.dual_stack { "yes" } else { "no" }
        ));
        if let Some(isp) = &w.isp {
            let asn = w.asn.map(|a| format!(" (AS{a})")).unwrap_or_default();
            lines.push(format!("  ISP: {isp}{asn}"));
        }
        if let Some(country) = &w.country {
            let region = w
                .region
                .as_deref()
                .map(|r| format!(", {r}"))
                .unwrap_or_default();
            lines.push(format!("  Location: {country}{region}"));
        }
    }

    // ── Trend vs previous hour ──
    if let Some(t) = &scan.trends {
        if !t.deltas.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "## Trend vs previous hour ({} prior samples)",
                t.samples_considered
            ));
            for d in &t.deltas {
                let arrow = match d.direction.as_str() {
                    "improved" => "↑",
                    "degraded" => "↓",
                    _ => "·",
                };
                lines.push(format!(
                    "  {arrow} {label}: {current:.1} (prev hr avg {prev:.1}, Δ {delta:+.1}) — {dir}",
                    arrow = arrow,
                    label = d.label,
                    current = d.current,
                    prev = d.prev_hour_avg,
                    delta = d.delta,
                    dir = d.direction,
                ));
            }
        }
    }

    // ── Roaming suggestion ──
    if let Some(a) = &scan.alternate_ap {
        lines.push(String::new());
        lines.push("## Roaming suggestion".to_string());
        lines.push(format!(
            "  Current AP on SSID '{ssid}' is at {cur} dBm; a stronger AP ({alt_bssid}) \
             on the same SSID is visible at {alt} dBm — {imp} dB improvement.",
            ssid = a.ssid,
            cur = a.current_rssi_dbm,
            alt_bssid = a.alternate_bssid,
            alt = a.alternate_rssi_dbm,
            imp = a.improvement_db,
        ));
        if let Some(ch) = a.alternate_channel {
            let band = a.alternate_band.as_deref().unwrap_or("?");
            lines.push(format!("  Alternate is on channel {ch} ({band} GHz)."));
        }
    }

    // ── Devices ──
    lines.push(String::new());
    lines.push(format!(
        "## Devices: {} online / {}",
        scan.devices.iter().filter(|d| d.online).count(),
        scan.devices.len()
    ));

    // ── Findings ──
    lines.push(String::new());
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

    // ── Time-series history (optional) ──
    if let Some(hist) = history {
        let non_empty: Vec<_> = hist.iter().filter(|(_, s)| !s.is_empty()).collect();
        if !non_empty.is_empty() {
            lines.push(String::new());
            lines.push("## Recent metric history (oldest → newest)".to_string());
            for (label, samples) in non_empty {
                lines.push(format!("  {label}: {}", summarise_samples(samples)));
            }
        }
    }

    lines.push(String::new());
    lines.push(
        "Respond in 3-5 short paragraphs prioritised by severity. Be direct, jargon-free, \
         and reference concrete numbers from the data above."
            .to_string(),
    );

    lines.join("\n")
}

/// Compress a sample series into a compact `min/avg/max (n)` summary plus
/// the last few raw values so the model can see the immediate trend.
fn summarise_samples(samples: &[MetricSample]) -> String {
    if samples.is_empty() {
        return "no data".into();
    }
    let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let tail: Vec<String> = samples
        .iter()
        .rev()
        .take(5)
        .map(|s| format!("{:.1}", s.value))
        .collect::<Vec<_>>();
    let tail_rev: Vec<String> = tail.into_iter().rev().collect();
    format!(
        "min {:.1}, avg {:.1}, max {:.1} (n={}) — recent: {}",
        min,
        avg,
        max,
        values.len(),
        tail_rev.join(", ")
    )
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

/// Shared HTTP client for LLM calls. A finite timeout is essential: a
/// local Ollama daemon that is up but loading a cold model (or a stalled
/// socket) will otherwise hang the request forever — which surfaces in the
/// UI as a permanently "Thinking…" button and looks like the app froze.
/// The short connect timeout fails fast when nothing is listening on the
/// host:port; `overall_secs` bounds slow CPU-bound local generations, which
/// can take several minutes for an 8B model on an Intel Mac.
fn llm_http_client(overall_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(overall_secs))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Overall request timeout for remote, fast-streaming providers (OpenAI,
/// Anthropic).
const REMOTE_TIMEOUT_SECS: u64 = 120;
/// Overall request timeout for local Ollama. CPU-only generation of a large
/// prompt can take minutes, so this is deliberately generous.
const OLLAMA_TIMEOUT_SECS: u64 = 600;

async fn call_openai(
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    messages: &[ChatMessage],
) -> Result<String> {
    let url = format!(
        "{}/v1/chat/completions",
        base_url.unwrap_or("https://api.openai.com")
    );
    let body = OaiRequest {
        model,
        messages: messages
            .iter()
            .map(|m| OaiMessageOwned {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect(),
        max_tokens: 800,
        temperature: 0.4,
    };
    // Local Ollama (any non-default base URL) gets a long timeout for slow
    // CPU generation; remote OpenAI uses the shorter remote timeout.
    let timeout_secs = if base_url.is_some() {
        OLLAMA_TIMEOUT_SECS
    } else {
        REMOTE_TIMEOUT_SECS
    };
    let client = llm_http_client(timeout_secs);
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

// ── OpenAI-compatible tool-calling (agentic chat) ─────────────────────────────

/// Single round-trip against an OpenAI-compatible `/v1/chat/completions`
/// endpoint (OpenAI itself or a local Ollama server) with optional `tools`.
///
/// `messages` are raw OpenAI message objects (so the caller can include
/// `tool` role results and assistant messages carrying `tool_calls`).
/// Returns the assistant `message` object verbatim so the orchestrator can
/// inspect `content` and `tool_calls`. Used by the chat agent loop; the
/// orchestration (executing tool calls, looping) lives in `commands.rs`
/// because it needs the device-execution `AppState`.
pub async fn chat_completion_raw(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    messages: Vec<Value>,
    tools: Option<Value>,
) -> Result<Value> {
    // Resolve the endpoint base the same way `dispatch` does for the
    // OpenAI-compatible providers.
    let (base, is_ollama) = match provider {
        "ollama" => (base_url.unwrap_or("http://127.0.0.1:11434"), true),
        _ => (base_url.unwrap_or("https://api.openai.com"), false),
    };
    let url = format!("{base}/v1/chat/completions");

    let mut body = serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": 800,
        "temperature": 0.3,
    });
    if let Some(t) = tools {
        body["tools"] = t;
        body["tool_choice"] = Value::String("auto".into());
    }

    let timeout_secs = if is_ollama {
        OLLAMA_TIMEOUT_SECS
    } else {
        REMOTE_TIMEOUT_SECS
    };
    let client = llm_http_client(timeout_secs);

    let send = async {
        let resp = client
            .post(&url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok::<Value, anyhow::Error>(resp)
    };

    let resp = match send.await {
        Ok(v) => v,
        Err(e) if is_ollama => return Err(friendly_ollama_error(base, model, &e)),
        Err(e) => return Err(e),
    };

    // choices[0].message — the assistant turn (content and/or tool_calls).
    let message = resp
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("LLM response missing choices[0].message"))?;
    Ok(message)
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
        .map(|m| AnthropicMessageOwned {
            role: m.role.clone(),
            content: m.content.clone(),
        })
        .collect();

    let body = AnthropicRequest {
        model,
        max_tokens: 800,
        system,
        messages: chat_messages,
    };
    let client = llm_http_client(REMOTE_TIMEOUT_SECS);
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
fn explain_messages(scan: &ScanResult, history: Option<&MetricHistory>) -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: "user".into(),
        content: build_prompt(scan, history),
    }]
}

/// Build the system message that embeds diagnostic context for interactive chat.
/// `av` (optional) folds the most recent AV-over-IP diagnostics — Dante/AES67
/// devices, multicast joins, PTP/IGMP/DSCP/LLDP/SAP deep probes, and AV
/// warnings — into the same grounding context so the assistant can reason
/// about audio-network issues, not just general Wi-Fi/LAN.
fn chat_system_message(
    scan: &ScanResult,
    history: Option<&MetricHistory>,
    av: Option<&AvDiagnosticsResult>,
) -> ChatMessage {
    let mut sys = "You are an expert network engineer assistant helping a user troubleshoot their WiFi and LAN.\n".to_string();
    sys.push_str("Here is the current diagnostic context:\n\n");
    sys.push_str(&build_prompt(scan, history));
    if let Some(av) = av {
        sys.push_str("\n\n# AV-over-IP diagnostics (Dante / AES67 / PTP / multicast)\n");
        sys.push_str(&build_av_context(av));
    }
    sys.push_str("\n\nAnswer the user's follow-up questions concisely and precisely, referencing the above data.");
    ChatMessage {
        role: "system".into(),
        content: sys,
    }
}

/// Public accessor for the interactive-chat system prompt content. The chat
/// agent loop in `commands.rs` builds its own message list (with tool
/// schemas) and needs the same diagnostic context string.
pub fn chat_system_prompt(
    scan: &ScanResult,
    history: Option<&MetricHistory>,
    av: Option<&AvDiagnosticsResult>,
) -> String {
    chat_system_message(scan, history, av).content
}

/// Public wrapper around [`dispatch`] for callers outside this module that
/// need to send an arbitrary message list (e.g. the causal narrator).
pub async fn dispatch_public(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    messages: &[ChatMessage],
) -> Result<String> {
    dispatch(provider, api_key, model, base_url, messages).await
}

/// Dispatch to the correct LLM provider with a messages list.
///
/// Ollama exposes an OpenAI-compatible endpoint at `<base_url>/v1/chat/completions`,
/// so we reuse `call_openai` for it. The bearer token is ignored by the Ollama
/// server; we pass an empty string when no key is configured.
async fn dispatch(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    messages: &[ChatMessage],
) -> Result<String> {
    match provider {
        "anthropic" => call_anthropic(api_key, model, messages).await,
        "ollama" => {
            let url = base_url.unwrap_or("http://127.0.0.1:11434");
            call_openai(api_key, model, Some(url), messages)
                .await
                .map_err(|e| friendly_ollama_error(url, model, &e))
        }
        _ => call_openai(api_key, model, base_url, messages).await,
    }
}

/// Translate a raw reqwest error from the Ollama OpenAI-compatible endpoint into
/// an actionable message. The default reqwest text ("error sending request for
/// url …") doesn't tell the user that Ollama itself isn't running.
fn friendly_ollama_error(url: &str, model: &str, err: &anyhow::Error) -> anyhow::Error {
    // Walk the error chain looking for the underlying reqwest error.
    let mut req_err: Option<&reqwest::Error> = None;
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err.as_ref());
    while let Some(s) = source {
        if let Some(r) = s.downcast_ref::<reqwest::Error>() {
            req_err = Some(r);
            break;
        }
        source = s.source();
    }

    if let Some(r) = req_err {
        if r.is_timeout() {
            return anyhow::anyhow!(
                "Ollama timed out while generating a response with `{model}` at {url}. \
                 Local models can be slow on CPU-only machines — try a smaller/faster \
                 model (e.g. `ollama pull llama3.2:3b`) or ask a shorter question."
            );
        }
        if r.is_connect() {
            return anyhow::anyhow!(
                "Cannot reach Ollama at {url}. Make sure the Ollama app is running \
                 (`ollama serve`) and that a model is installed (e.g. `ollama pull {model}`)."
            );
        }
        if let Some(status) = r.status() {
            if status.as_u16() == 404 {
                return anyhow::anyhow!(
                    "Ollama responded 404 at {url}. The model `{model}` is probably \
                     not installed — run `ollama pull {model}` and try again."
                );
            }
            return anyhow::anyhow!("Ollama returned HTTP {status} for model `{model}` at {url}.");
        }
    }
    anyhow::anyhow!("Ollama request failed: {err}")
}

/// Call the configured LLM with a structured summary of the scan and return
/// a plain-language explanation. `history` (optional) seeds the prompt with
/// recent metric trends so the model can comment on changes over time.
pub async fn explain(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    scan: &ScanResult,
    history: Option<&MetricHistory>,
) -> Result<String> {
    let messages = explain_messages(scan, history);
    tracing::debug!("LLM explain ({} chars)", messages[0].content.len());
    dispatch(provider, api_key, model, base_url, &messages).await
}

/// Ask the LLM to enumerate **radio-specific** issues + suggestions from the
/// most recent scan, focusing on RF data (band/channel/width/RSSI/SNR/PHY
/// efficiency, the airspace scan, and roaming history). Returned text is
/// parsed by the frontend into a list of items.
pub async fn radio_insights(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    scan: &ScanResult,
) -> Result<String> {
    let prompt = build_radio_prompt(scan);
    tracing::debug!("LLM radio_insights ({} chars)", prompt.len());
    let messages = vec![ChatMessage {
        role: "user".into(),
        content: prompt,
    }];
    dispatch(provider, api_key, model, base_url, &messages).await
}

/// Build a focused prompt around the RF / airspace surface only. Returns
/// JSON-shaped output (list of `{severity, title, detail, suggestion}`)
/// so the UI can render structured cards without parsing free prose.
fn build_radio_prompt(scan: &ScanResult) -> String {
    let link = &scan.link;
    let mut lines = vec![
        "You are an expert WiFi RF engineer.".to_string(),
        "Analyze the radio data below and identify concrete issues AND specific suggestions."
            .to_string(),
        "Focus ONLY on radio / airspace topics: band, channel, channel width, RSSI, SNR,"
            .to_string(),
        "PHY efficiency, neighbor congestion, co-channel overlap, roaming behavior, and rogue APs."
            .to_string(),
        "Ignore DNS, captive portal, MTU, or upstream/ISP issues.".to_string(),
        String::new(),
        "## Current link".to_string(),
        format!("  SSID: {}", link.ssid.as_deref().unwrap_or("?")),
        format!(
            "  Band/channel/width: {} / {} / {} MHz",
            link.band.as_deref().unwrap_or("?"),
            link.channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            link.channel_width_mhz
                .map(|w| w.to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        format!(
            "  PHY mode: {} ({})",
            link.phy_mode.as_deref().unwrap_or("?"),
            link.wifi_generation.as_deref().unwrap_or("?")
        ),
        format!(
            "  RSSI: {} dBm  SNR: {} dB  Tx rate: {} Mbps",
            link.rssi_dbm
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            link.snr_db
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            link.tx_rate_mbps
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "?".into())
        ),
        format!("  AP vendor: {}", link.vendor.as_deref().unwrap_or("?")),
        format!("  Security: {}", link.security.as_deref().unwrap_or("?")),
    ];

    // PHY efficiency
    if let Some(p) = &scan.phy_efficiency {
        lines.push(String::new());
        lines.push("## PHY-rate efficiency".to_string());
        lines.push(format!(
            "  Actual {:.0} / Theoretical {:.0} Mbps = {:.0}% ({})",
            p.actual_mbps,
            p.theoretical_max_mbps,
            p.efficiency * 100.0,
            p.grade,
        ));
        lines.push(format!("  Diagnostic: {}", p.diagnostic));
    }

    // Channel interference (summary + top 3 worst)
    if let Some(intf) = &scan.interference {
        lines.push(String::new());
        lines.push("## Channel interference (rules-engine view)".to_string());
        if let Some(s) = intf.current_channel_score {
            lines.push(format!(
                "  Current channel score: {s:.0}/100 (lower is better)"
            ));
        }
        if let Some(ch) = intf.recommended_24 {
            lines.push(format!("  Recommended 2.4 GHz channel: {ch}"));
        }
        if let Some(ch) = intf.recommended_5 {
            lines.push(format!("  Recommended 5 GHz channel: {ch}"));
        }
        let mut sorted = intf.channels.clone();
        sorted.sort_by(|a, b| {
            b.interference_score
                .partial_cmp(&a.interference_score)
                .unwrap()
        });
        for c in sorted.iter().take(5) {
            lines.push(format!(
                "  ch {} ({} GHz): score {:.0}",
                c.channel, c.band, c.interference_score,
            ));
        }
    }

    // Nearby APs — the strongest 10, since RSSI dictates congestion impact.
    if !scan.nearby_aps.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "## Nearby APs ({} total — top 10 by RSSI shown)",
            scan.nearby_aps.len()
        ));
        let mut sorted = scan.nearby_aps.clone();
        sorted.sort_by_key(|a| -a.rssi_dbm.unwrap_or(-127));
        for ap in sorted.iter().take(10) {
            let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
            let band = ap.band.as_deref().unwrap_or("?");
            let ch = ap
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into());
            let width = ap
                .width_mhz
                .map(|w| format!("{w}MHz"))
                .unwrap_or_else(|| "?".into());
            let rssi = ap
                .rssi_dbm
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into());
            let phy = ap.phy_mode.as_deref().unwrap_or("?");
            lines.push(format!(
                "  '{ssid}' — {band}GHz ch{ch} {width} {phy} @ {rssi} dBm",
            ));
        }
    }

    // Roaming
    if let Some(r) = &scan.roaming {
        lines.push(String::new());
        lines.push("## Roaming".to_string());
        lines.push(format!(
            "  Events: {} last hour / {} last 24h",
            r.events_last_hour, r.events_last_24h,
        ));
        if let Some(d) = r.avg_dwell_secs {
            lines.push(format!("  Avg dwell: {d} s"));
        }
        if r.sticky_warning {
            lines.push("  ⚠ Sticky-client suspected.".into());
        }
    }

    // Roaming suggestion (alternate AP available)
    if let Some(a) = &scan.alternate_ap {
        lines.push(String::new());
        lines.push("## Alternate AP".to_string());
        lines.push(format!(
            "  Stronger AP on same SSID '{}': {} dBm (Δ {} dB vs current {} dBm)",
            a.ssid, a.alternate_rssi_dbm, a.improvement_db, a.current_rssi_dbm,
        ));
    }

    // Rogue APs
    if !scan.rogue_aps.is_empty() {
        lines.push(String::new());
        lines.push("## Potential rogue / evil-twin APs".to_string());
        for r in &scan.rogue_aps {
            lines.push(format!(
                "  [{}] '{}' — {}",
                r.severity.as_str().to_uppercase(),
                r.ssid,
                r.reason,
            ));
        }
    }

    lines.push(String::new());
    lines.push(
        "Respond with STRICT JSON only (no markdown, no prose outside JSON). \
         Schema: { \"items\": [ { \"severity\": \"info|warn|critical\", \
         \"title\": string, \"detail\": string, \"suggestion\": string } ] }. \
         Cap at 6 items. Order by severity (critical first). If everything looks \
         healthy, return { \"items\": [ { \"severity\": \"info\", \"title\": \
         \"Radio looks healthy\", \"detail\": \"<2-sentence rationale referencing \
         concrete numbers above>\", \"suggestion\": \"\" } ] }."
            .to_string(),
    );

    lines.join("\n")
}
/// Ask the LLM to enumerate AV-over-IP issues + suggestions from a Dante /
/// multicast / PTP snapshot. The prompt is deliberately scoped to AV topics
/// (Dante, IGMP/multicast, PTP, QoS, AV-on-Wi-Fi) and intentionally NOT
/// to general Wi-Fi tuning, which has its own `radio_insights` entry point.
///
/// Returns raw model text; the frontend parses the JSON envelope.
pub async fn av_insights(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    av: &AvDiagnosticsResult,
    scan: Option<&ScanResult>,
) -> Result<String> {
    let prompt = build_av_prompt(av, scan);
    tracing::debug!("LLM av_insights ({} chars)", prompt.len());
    let messages = vec![ChatMessage {
        role: "user".into(),
        content: prompt,
    }];
    dispatch(provider, api_key, model, base_url, &messages).await
}

/// Build an AV-over-IP-focused prompt. We include the most recent Wi-Fi link
/// info (when available) so the model can correlate symptoms — e.g. \"Dante on
/// Wi-Fi via Ubiquiti AP\" should always escalate to critical regardless of
/// what mDNS shows. Output schema matches `radio_insights` plus a `category`
/// field so the UI can group/colour by domain (dante / multicast / ptp / wifi / qos).
fn build_av_prompt(av: &AvDiagnosticsResult, scan: Option<&ScanResult>) -> String {
    let mut lines = vec![
        "You are an expert AV-over-IP network engineer specialising in Dante,".to_string(),
        "AES67, multicast / IGMP snooping, and IEEE 1588 PTP synchronisation.".to_string(),
        "Analyze the snapshot below and enumerate concrete issues AND specific suggestions."
            .to_string(),
        "Focus on: Dante device health, sample-rate/latency alignment, redundancy,".to_string(),
        "multicast plumbing (IGMP querier presence, snooping, switch forwarding),".to_string(),
        "PTP master / sync quality, AV-on-Wi-Fi anti-patterns, and DSCP/QoS markings.".to_string(),
        "Ignore general Wi-Fi tuning unless it directly affects audio.".to_string(),
        String::new(),
    ];

    // Wi-Fi cross-reference (when available).
    if let Some(s) = scan {
        lines.push("## Host Wi-Fi context".to_string());
        lines.push(format!(
            "  SSID: '{}'  band/ch/width: {}/{}/{} MHz  vendor: {}",
            s.link.ssid.as_deref().unwrap_or("?"),
            s.link.band.as_deref().unwrap_or("?"),
            s.link
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            s.link
                .channel_width_mhz
                .map(|w| w.to_string())
                .unwrap_or_else(|| "?".into()),
            s.link.vendor.as_deref().unwrap_or("?"),
        ));
        lines.push(format!(
            "  RSSI: {} dBm  SNR: {} dB",
            s.link
                .rssi_dbm
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            s.link
                .snr_db
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
        ));
        lines.push(String::new());
    }

    // Shared AV context block (snapshot summary, deep probes, Dante devices,
    // multicast joins, and heuristic warnings). Reused verbatim by the
    // interactive-chat system prompt so the assistant is grounded in the
    // exact same AV facts the dedicated AV-insights panel sees.
    lines.push(build_av_context(av));

    lines.push(String::new());
    lines.push(
        "Respond with STRICT JSON only (no markdown, no prose outside JSON). \
         Schema: { \"items\": [ { \"severity\": \"info|warn|critical\", \
         \"category\": \"dante|multicast|ptp|wifi|qos|general\", \
         \"title\": string, \"detail\": string, \"suggestion\": string } ] }. \
         Cap at 8 items. Order by severity (critical first). Do NOT just repeat the \
         heuristic warnings verbatim — synthesise across categories and recommend \
         concrete switch/AP/DSP configuration changes when supportable from the data. \
         If everything looks healthy, return one info item explaining why in 2 sentences."
            .to_string(),
    );

    lines.join("\n")
}

/// Build the provider-neutral AV-over-IP context block: snapshot summary,
/// every available deep-probe result (IGMP / PTP / DSCP / LLDP / link audit /
/// SAP), the Dante/AES67 device inventory, local multicast joins, and any
/// heuristic warnings already flagged. Shared by both the dedicated
/// `build_av_prompt` (AV-insights panel) and the interactive-chat system
/// prompt so the assistant is grounded in identical AV facts. No output-format
/// instructions are included here — callers append their own.
fn build_av_context(av: &AvDiagnosticsResult) -> String {
    let mut lines = vec![
        "## AV-over-IP snapshot".to_string(),
        format!("  Dante devices found: {}", av.dante_devices.len()),
        format!("  Dante Domain Manager seen: {}", av.ddm_seen),
        format!("  AES67-capable devices: {}", av.aes67_seen),
    ];

    // Deep-probe results (privileged + unprivileged listeners). Each section
    // is independently optional.
    if let Some(dp) = &av.deep_probe {
        // IGMP querier / snooping health.
        if let Some(igmp) = &dp.igmp {
            lines.push(String::new());
            lines.push("## IGMP probe (multicast querier)".to_string());
            lines.push(format!(
                "  iface={} listen={}s verdict='{}' queriers={} reports={} leaves={}",
                igmp.iface,
                igmp.listen_secs,
                igmp.verdict,
                igmp.queriers_seen.len(),
                igmp.reports_seen,
                igmp.leaves_seen,
            ));
            for q in igmp.queriers_seen.iter().take(4) {
                lines.push(format!(
                    "    - querier {} (IGMPv{}, max_resp={}ds, group {})",
                    q.from, q.version, q.max_resp_ds, q.group,
                ));
            }
            if let Some(d) = &igmp.detail {
                lines.push(format!("  interpretation: {d}"));
            }
            if let Some(e) = &igmp.error {
                lines.push(format!("    error: {e}"));
            }
        }

        // PTP grandmaster / sync quality.
        if let Some(ptp) = &dp.ptp {
            lines.push(String::new());
            lines.push("## PTP probe (IEEE 1588 sync)".to_string());
            lines.push(format!(
                "  iface={} listen={}s verdict='{}' grandmasters={} competing_gm={}",
                ptp.iface,
                ptp.listen_secs,
                ptp.verdict,
                ptp.grandmaster_count,
                ptp.competing_gm_observed,
            ));
            for dom in ptp.domains.iter().take(4) {
                let jitter = dom
                    .sync_jitter_us
                    .map(|j| format!("{j:.0}µs"))
                    .unwrap_or_else(|| "?".into());
                lines.push(format!(
                    "    - domain {} (PTPv{}, {} profile, {}): {} GM(s), sync_arrivals={}, jitter={}",
                    dom.domain_number,
                    dom.version,
                    dom.profile,
                    dom.transport,
                    dom.grandmasters.len(),
                    dom.sync_arrivals,
                    jitter,
                ));
                for gm in dom.grandmasters.iter().take(3) {
                    lines.push(format!(
                        "        GM {} class={} prio1={} prio2={} announces={} from {}",
                        gm.clock_identity,
                        gm.clock_class,
                        gm.priority1,
                        gm.priority2,
                        gm.announces_seen,
                        gm.source_ip,
                    ));
                }
            }
            if let Some(e) = &ptp.error {
                lines.push(format!("    error: {e}"));
            }
        }

        // DSCP / QoS marking audit.
        if let Some(dscp) = &dp.dscp {
            lines.push(String::new());
            lines.push("## DSCP / QoS audit".to_string());
            lines.push(format!(
                "  iface={} listen={}s verdict='{}'",
                dscp.iface, dscp.listen_secs, dscp.verdict,
            ));
            for o in dscp.observations.iter().take(8) {
                let mark = if o.dscp_median == o.dscp_expected {
                    "ok"
                } else {
                    "MISMATCH"
                };
                lines.push(format!(
                    "    - {} ({}): dscp {}→expected {} [{}], ttl med={} min={}, {} pkts",
                    o.stream_kind,
                    o.dst_group,
                    o.dscp_median,
                    o.dscp_expected,
                    mark,
                    o.ttl_median,
                    o.ttl_min,
                    o.packets,
                ));
            }
            if let Some(e) = &dscp.error {
                lines.push(format!("    error: {e}"));
            }
        }

        // LLDP / CDP upstream switch identification.
        if let Some(lldp) = &dp.lldp {
            lines.push(String::new());
            lines.push("## LLDP / CDP neighbours (upstream switch)".to_string());
            lines.push(format!(
                "  iface={} mechanism={} verdict='{}' neighbours={}",
                lldp.iface,
                lldp.mechanism,
                lldp.verdict,
                lldp.neighbors.len(),
            ));
            for n in lldp.neighbors.iter().take(4) {
                lines.push(format!(
                    "    - {} via {} | port={} | vlan={} | name={} | desc={}",
                    n.source_mac,
                    n.via,
                    n.port_id.as_deref().unwrap_or("?"),
                    n.vlan_id
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    n.system_name.as_deref().unwrap_or("?"),
                    n.system_description.as_deref().unwrap_or("?"),
                ));
            }
            if let Some(e) = &lldp.error {
                lines.push(format!("    error: {e}"));
            }
        }

        // Per-NIC link audit (EEE / duplex / flow-control / MTU).
        if let Some(la) = &dp.link_audit {
            lines.push(String::new());
            lines.push("## NIC link audit".to_string());
            lines.push(format!(
                "  iface={} verdict='{}' speed={} duplex={} eee={} flow_rx={} flow_tx={} mtu={}",
                la.iface,
                la.verdict,
                la.link_speed_mbps
                    .map(|s| format!("{s}Mb"))
                    .unwrap_or_else(|| "?".into()),
                la.duplex.as_deref().unwrap_or("?"),
                la.eee_enabled
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "?".into()),
                la.flow_control_rx
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "?".into()),
                la.flow_control_tx
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "?".into()),
                la.mtu.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
            ));
            for issue in la.issues.iter().take(6) {
                lines.push(format!("    - {issue}"));
            }
        }

        // SAP/SDP advertised AES67 streams.
        if let Some(sap) = &dp.sap {
            lines.push(String::new());
            lines.push("## SAP/SDP advertised streams (AES67)".to_string());
            lines.push(format!(
                "  iface={} listen={}s verdict='{}' streams={}",
                sap.iface,
                sap.listen_secs,
                sap.verdict,
                sap.streams.len(),
            ));
            for st in sap.streams.iter().take(8) {
                lines.push(format!(
                    "    - '{}' grp={}:{} sr={} ch={} ptime={} from {}",
                    st.session_name,
                    st.multicast_group.as_deref().unwrap_or("?"),
                    st.port.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                    st.sample_rate_hz
                        .map(|r| format!("{r}Hz"))
                        .unwrap_or_else(|| "?".into()),
                    st.channels
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "?".into()),
                    st.ptime_ms
                        .map(|p| format!("{p}ms"))
                        .unwrap_or_else(|| "?".into()),
                    st.source_ip,
                ));
            }
            if let Some(e) = &sap.error {
                lines.push(format!("    error: {e}"));
            }
        }
    }

    // Dante / AES67 device inventory (cap at 20 to keep tokens bounded).
    if !av.dante_devices.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "## Dante / AES67 devices ({} total — top 20 by IP)",
            av.dante_devices.len()
        ));
        for d in av.dante_devices.iter().take(20) {
            let model = d.model.as_deref().unwrap_or("?");
            let host = d.hostname.as_deref().unwrap_or("?");
            let sr = d
                .sample_rate_hz
                .map(|r| format!("{:.1} kHz", r as f32 / 1000.0))
                .unwrap_or_else(|| "?".into());
            let lat = d
                .latency_profile_ms
                .map(|l| format!("{l} ms"))
                .unwrap_or_else(|| "?".into());
            let chans = match (d.tx_channels, d.rx_channels) {
                (Some(tx), Some(rx)) => format!("{tx}tx/{rx}rx"),
                _ => "?ch".into(),
            };
            let ports = if d.control_ports_open.is_empty() {
                "none open".to_string()
            } else {
                d.control_ports_open
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let wifi_flag = if d.on_wifi { " [ON WI-FI]" } else { "" };
            lines.push(format!(
                "  {} ({})  model='{}'  {}  sr={}  lat={}  redundancy={}  ports=[{}]{}",
                d.ip, host, model, chans, sr, lat, d.redundancy, ports, wifi_flag,
            ));
        }
    }

    // Multicast snapshot.
    if !av.multicast.is_empty() {
        lines.push(String::new());
        lines.push("## Local multicast joins (per interface)".to_string());
        for i in &av.multicast {
            lines.push(format!(
                "  {}: {} groups total | dante_audio={} | ptp={}",
                i.iface, i.group_count, i.dante_audio_groups, i.ptp_groups,
            ));
            // List up to 8 specific groups per interface for diagnostic value.
            for g in i.groups.iter().take(8) {
                lines.push(format!("    - {} ({})", g.group, g.purpose));
            }
        }
    }

    // Heuristic warnings we already detected — give the LLM something to
    // build on rather than re-derive.
    if !av.warnings.is_empty() {
        lines.push(String::new());
        lines.push("## Heuristic AV warnings already flagged".to_string());
        for w in &av.warnings {
            lines.push(format!("  [{}/{}] {}", w.severity, w.category, w.message));
        }
    }

    lines.join("\n")
}

/// Answer a follow-up question in the context of the current scan result.
/// `history` is alternating user/assistant messages (not including the new question).
#[allow(clippy::too_many_arguments)]
pub async fn chat_query(
    provider: &str,
    api_key: &str,
    model: &str,
    base_url: Option<&str>,
    scan: &ScanResult,
    metric_history: Option<&MetricHistory>,
    av: Option<&AvDiagnosticsResult>,
    history: Vec<ChatMessage>,
    question: &str,
) -> Result<String> {
    let mut messages = vec![chat_system_message(scan, metric_history, av)];
    messages.extend(history);
    messages.push(ChatMessage {
        role: "user".into(),
        content: question.to_string(),
    });
    tracing::debug!("LLM chat ({} msgs)", messages.len());
    dispatch(provider, api_key, model, base_url, &messages).await
}

// ── Payload preview (returned to frontend before sending) ────────────────────

/// Return the prompt that *would* be sent, so the user can review it before
/// confirming.  Nothing is sent to any server by this function.
pub fn preview_payload(scan: &ScanResult) -> String {
    build_prompt(scan, None)
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
                ssid: None,
                bssid: None,
                band: Some("5".to_string()),
                channel: Some(36),
                channel_width_mhz: Some(80),
                rssi_dbm: Some(-55),
                noise_dbm: Some(-95),
                snr_db: Some(40),
                tx_rate_mbps: Some(400.0),
                rx_rate_mbps: None,
                security: Some("WPA2".to_string()),
                phy_mode: Some("802.11ac".to_string()),
                wifi_generation: Some("Wi-Fi 5".to_string()),
                vendor: None,
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
            quality: None,
            interference: None,
            phy_efficiency: None,
            roaming: None,
            rogue_aps: vec![],
            wan: None,
            trends: None,
            alternate_ap: None,
        }
    }

    #[test]
    fn prompt_contains_key_fields() {
        let scan = empty_scan();
        let prompt = build_prompt(&scan, None);
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
        let prompt = build_prompt(&scan, None);
        assert!(prompt.contains("Weak signal strength"));
        assert!(prompt.contains("HIGH"));
        assert!(prompt.contains("90%"));
    }

    #[test]
    fn prompt_includes_advanced_sections_when_present() {
        use crate::types::{
            ChannelScore, InterferenceReport, PhyEfficiency, QualityStats, RoamingStats,
            RogueApFinding,
        };
        let mut scan = empty_scan();
        scan.quality = Some(QualityStats {
            dl_throughput_mbps: Some(100.0),
            ul_throughput_mbps: Some(40.0),
            responsiveness_rpm: Some(80),
            idle_latency_ms: Some(35.0),
            responsiveness_label: Some("Low".into()),
        });
        scan.interference = Some(InterferenceReport {
            channels: vec![ChannelScore {
                channel: 6,
                band: "2.4".into(),
                interference_score: 75.0,
                co_channel_count: 3,
                adjacent_channel_count: 2,
                strongest_interferer_dbm: Some(-45),
            }],
            recommended_24: Some(11),
            recommended_5: Some(36),
            current_channel_score: Some(75.0),
        });
        scan.phy_efficiency = Some(PhyEfficiency {
            phy_mode: "802.11ac @ 80 MHz".into(),
            theoretical_max_mbps: 866.0,
            actual_mbps: 200.0,
            efficiency: 0.23,
            grade: "poor".into(),
            diagnostic: "Likely interference.".into(),
        });
        scan.roaming = Some(RoamingStats {
            events_last_hour: 5,
            events_last_24h: 50,
            avg_dwell_secs: Some(120),
            sticky_warning: false,
            recent_events: vec![],
        });
        scan.rogue_aps = vec![RogueApFinding {
            ssid: "Office".into(),
            bssids: vec!["aa:bb:cc:dd:ee:ff".into()],
            security_modes: vec!["Open".into(), "WPA2".into()],
            reason: "evil-twin".into(),
            severity: Severity::High,
        }];
        let prompt = build_prompt(&scan, None);
        assert!(prompt.contains("Bufferbloat"));
        assert!(prompt.contains("80 RPM"));
        assert!(prompt.contains("Channel interference"));
        assert!(prompt.contains("Recommended 2.4 GHz channel: 11"));
        assert!(prompt.contains("PHY-rate efficiency"));
        assert!(prompt.contains("poor"));
        assert!(prompt.contains("Roaming history"));
        assert!(prompt.contains("Potential rogue"));
    }

    #[test]
    fn prompt_includes_history_when_provided() {
        use crate::store::MetricSample;
        let scan = empty_scan();
        let now = Utc::now();
        let history: MetricHistory = vec![(
            "RSSI (dBm)".into(),
            vec![
                MetricSample {
                    metric: "link.rssi_dbm".into(),
                    value: -55.0,
                    sampled_at: now,
                    label: None,
                },
                MetricSample {
                    metric: "link.rssi_dbm".into(),
                    value: -60.0,
                    sampled_at: now,
                    label: None,
                },
                MetricSample {
                    metric: "link.rssi_dbm".into(),
                    value: -75.0,
                    sampled_at: now,
                    label: None,
                },
            ],
        )];
        let prompt = build_prompt(&scan, Some(&history));
        assert!(prompt.contains("Recent metric history"));
        assert!(prompt.contains("RSSI (dBm)"));
        assert!(prompt.contains("min -75.0"));
    }
}
