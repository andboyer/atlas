//! In-app Ollama installer.
//!
//! Atlas talks to Ollama over HTTP (`http://localhost:11434`); it does not
//! bundle the daemon (Ollama plus a single model is multiple gigabytes,
//! ships its own auto-updater, and would conflict with any existing
//! install). This module gives the UI three building blocks so the user
//! doesn't have to leave Atlas to get Ollama running:
//!
//!   * [`check_ollama_status`] — non-erroring health probe; tells the UI
//!     whether to render "Ollama running ✓", "Installed but not running",
//!     or "Not installed, install it for me".
//!   * [`install_ollama`] — downloads the official release artifact
//!     (`Ollama-darwin.zip` / `OllamaSetup.exe`) from `ollama.com`,
//!     verifies SHA256 against the publisher's own `sha256sum.txt` release
//!     manifest (which lists every asset), extracts (macOS) or launches
//!     the elevated installer (Windows), and emits streaming progress over
//!     a [`tauri::ipc::Channel`].
//!   * [`launch_ollama`] — opens the menu-bar app / starts `ollama serve`
//!     for the "installed but not running" case.
//!
//! The SHA256 manifest approach matches what Ollama themselves publish for
//! the same release and is the same trust boundary as the canonical
//! `curl … | sh` install. We do NOT pin a hash at Atlas build time
//! because Ollama ships an auto-update every few weeks and a hard pin
//! would silently break the installer the moment they cut a new release.

#[cfg(any(target_os = "macos", target_os = "windows"))]
use anyhow::Context;
use anyhow::{anyhow, Result};
use serde::Serialize;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;
use std::time::Duration;
use tauri::ipc::Channel;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::process_util::NoConsoleExt;

/// Snapshot of Ollama health on the local box. Returned to the UI so it
/// can render the right install/run/pull affordances. Never errors —
/// "can't reach it" surfaces as `reachable: false`.
#[derive(Debug, Clone, Serialize)]
pub struct OllamaStatus {
    /// True iff `<base_url>/api/version` answered 200 within the timeout.
    pub reachable: bool,
    /// Daemon version when reachable (e.g. `"0.30.4"`). `None` otherwise.
    pub version: Option<String>,
    /// Names of `ollama pull`-ed models the daemon currently knows about
    /// (e.g. `["llama3:latest", "mistral:7b"]`). Empty when the daemon
    /// is reachable but has no models installed.
    pub models: Vec<String>,
    /// True iff the Ollama application binary exists on disk. Lets the UI
    /// distinguish "installed but not running" from "not installed at all"
    /// — different affordances (Launch vs Install).
    pub app_installed: bool,
    /// Base URL we probed (mirrors back the caller's setting so the UI
    /// can caption the status row with the same host:port).
    pub base_url: String,
}

/// Streaming progress event for [`install_ollama`]. Coalesced to ≤ 4
/// `Progress` messages per second so the IPC channel doesn't get flooded
/// on fast connections.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
pub enum InstallProgress {
    /// Resolved download URL + expected size in bytes (from
    /// `Content-Length`). Fires before the download starts so the UI can
    /// render "Downloading 177 MB from github.com/ollama/ollama …".
    Starting { url: String, total_bytes: u64 },
    /// Periodic bytes-downloaded ping. `total_bytes` may be 0 if the
    /// server didn't send `Content-Length` (rare for GitHub releases).
    Progress {
        downloaded_bytes: u64,
        total_bytes: u64,
    },
    /// Hash verification step. UI usually just shows "Verifying…".
    Verifying { expected: String, actual: String },
    /// Extraction / installer-launch step with a human-readable label.
    Installing { step: String },
    /// Terminal success. UI should re-poll [`check_ollama_status`].
    Done,
    /// Terminal failure with an operator-friendly message.
    Failed { message: String },
}

/// Tauri command: probe Ollama at `base_url` (defaults to localhost:11434)
/// and return a one-shot health snapshot. Never errors at the IPC layer —
/// failures show up in the returned struct's `reachable` field.
#[tauri::command]
pub async fn check_ollama_status(base_url: Option<String>) -> OllamaStatus {
    let base = base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("http://127.0.0.1:11434")
        .trim_end_matches('/')
        .to_string();

    // Short timeout — a not-running daemon refuses the TCP connect
    // immediately on localhost; we don't want this probe to ever block
    // the Settings panel open.
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return OllamaStatus {
                reachable: false,
                version: None,
                models: vec![],
                app_installed: ollama_app_installed(),
                base_url: base,
            };
        }
    };

    let version = client
        .get(format!("{base}/api/version"))
        .send()
        .await
        .ok()
        .filter(|r| r.status().is_success());

    let version = match version {
        Some(r) => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("version").and_then(|s| s.as_str()).map(String::from)),
        None => None,
    };

    let reachable = version.is_some();

    let mut models = Vec::new();
    if reachable {
        if let Ok(resp) = client.get(format!("{base}/api/tags")).send().await {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<serde_json::Value>().await {
                    if let Some(arr) = v.get("models").and_then(|m| m.as_array()) {
                        for m in arr {
                            if let Some(n) = m.get("name").and_then(|n| n.as_str()) {
                                models.push(n.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    OllamaStatus {
        reachable,
        version,
        models,
        app_installed: ollama_app_installed(),
        base_url: base,
    }
}

/// Tauri command: download + install Ollama from the official upstream.
/// macOS extracts `Ollama-darwin.zip` to `/Applications/Ollama.app` and
/// launches the menu-bar app. Windows runs `OllamaSetup.exe` (UAC will
/// prompt for elevation; we can't avoid that — Ollama's NSIS installer
/// doesn't support `/S` silent mode). Linux is intentionally unsupported
/// here because the upstream installer is a `curl … | sudo sh` flow that
/// needs root.
#[tauri::command]
pub async fn install_ollama(progress: Channel<InstallProgress>) -> Result<(), String> {
    match install_ollama_impl(&progress).await {
        Ok(()) => {
            let _ = progress.send(InstallProgress::Done);
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = progress.send(InstallProgress::Failed {
                message: msg.clone(),
            });
            Err(msg)
        }
    }
}

/// Tauri command: bring an existing Ollama install up if it's installed
/// but not currently running. Wraps `open /Applications/Ollama.app` on
/// macOS and spawns `ollama.exe serve` on Windows. UI should re-poll
/// [`check_ollama_status`] after ~2 seconds.
#[tauri::command]
pub async fn launch_ollama() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        Command::new("/usr/bin/open")
            .arg("/Applications/Ollama.app")
            .no_console()
            .spawn()
            .map_err(|e| format!("Failed to launch /Applications/Ollama.app: {e}"))?;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        for path in windows_ollama_candidates() {
            if path.exists() {
                Command::new(&path)
                    .arg("serve")
                    .no_console()
                    .spawn()
                    .map_err(|e| format!("Failed to launch {}: {e}", path.display()))?;
                return Ok(());
            }
        }
        Err("Ollama executable not found. Try reinstalling.".into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(
            "In-app launch is unsupported on this platform; run `ollama serve` in a terminal."
                .into(),
        )
    }
}

#[cfg(target_os = "windows")]
fn windows_ollama_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        out.push(
            std::path::PathBuf::from(local)
                .join("Programs")
                .join("Ollama")
                .join("ollama.exe"),
        );
    }
    out.push(std::path::PathBuf::from(
        r"C:\Program Files\Ollama\ollama.exe",
    ));
    out
}

fn ollama_app_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/Applications/Ollama.app/Contents/MacOS/Ollama",
            "/Applications/Ollama.app",
            "/opt/homebrew/bin/ollama",
            "/usr/local/bin/ollama",
        ];
        candidates.iter().any(|p| Path::new(p).exists())
    }
    #[cfg(target_os = "windows")]
    {
        windows_ollama_candidates().iter().any(|p| p.exists())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        ["/usr/local/bin/ollama", "/usr/bin/ollama"]
            .iter()
            .any(|p| Path::new(p).exists())
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn install_ollama_impl(progress: &Channel<InstallProgress>) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    // Ollama does NOT publish per-asset `.zip.sha256` sidecars — those 404.
    // Instead each GitHub release ships one `sha256sum.txt` listing every
    // asset as `<hash>  ./<filename>`. We fetch that via the same
    // `ollama.com/download/…` redirect so the checksum stays pinned to the
    // exact release version the zip download resolves to.
    #[cfg(target_os = "macos")]
    let (url, sha_url, filename) = (
        "https://ollama.com/download/Ollama-darwin.zip",
        "https://ollama.com/download/sha256sum.txt",
        "Ollama-darwin.zip",
    );
    #[cfg(target_os = "windows")]
    let (url, sha_url, filename) = (
        "https://ollama.com/download/OllamaSetup.exe",
        "https://ollama.com/download/sha256sum.txt",
        "OllamaSetup.exe",
    );

    // reqwest follows redirects by default, so both URLs above land on
    // the right GitHub Release asset for the current Ollama version.
    // Generous timeout: the Windows installer is ~1.4 GB and even on a
    // gigabit connection takes ~15s; on slower links 5 minutes is the
    // realistic ceiling before we bail.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .context("build http client")?;

    // 1. Fetch the release checksum manifest and pull out our asset's line.
    let sha_body = client
        .get(sha_url)
        .send()
        .await
        .with_context(|| format!("fetch sha256 manifest at {sha_url}"))?
        .error_for_status()
        .with_context(|| format!("sha256 manifest HTTP error at {sha_url}"))?
        .text()
        .await
        .context("read sha256 manifest body")?;
    // Each line is `<64-hex-hash>  ./<filename>` (or `*<filename>`). Match the
    // line whose final path component equals our asset and take its hash.
    let expected_sha = sha_body
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            let name = parts.next()?;
            let base = name.trim_start_matches('*').rsplit('/').next()?;
            (base == filename).then(|| hash.to_lowercase())
        })
        .ok_or_else(|| anyhow!("no sha256 entry for {filename} in manifest at {sha_url}"))?;
    if expected_sha.len() != 64 || !expected_sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "sha256 manifest at {sha_url} had a malformed hash for {filename}: {:?}",
            expected_sha.chars().take(80).collect::<String>()
        ));
    }

    // 2. Begin streaming download.
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("start download at {url}"))?
        .error_for_status()
        .with_context(|| format!("download HTTP error at {url}"))?;
    let total = resp.content_length().unwrap_or(0);

    let tmp_dir = std::env::temp_dir().join("atlas-ollama-install");
    std::fs::create_dir_all(&tmp_dir).context("mktmpdir for ollama install")?;
    let dl_path = tmp_dir.join(filename);

    let _ = progress.send(InstallProgress::Starting {
        url: url.to_string(),
        total_bytes: total,
    });

    let mut file = std::fs::File::create(&dl_path).context("create download file")?;
    let mut hasher = Sha256::new();
    let mut got: u64 = 0;
    let mut next_emit = std::time::Instant::now() + Duration::from_millis(250);
    let mut stream = resp;
    loop {
        let chunk = stream.chunk().await.context("download chunk")?;
        let Some(chunk) = chunk else { break };
        file.write_all(&chunk).context("write download chunk")?;
        hasher.update(&chunk);
        got += chunk.len() as u64;
        let now = std::time::Instant::now();
        if now >= next_emit {
            let _ = progress.send(InstallProgress::Progress {
                downloaded_bytes: got,
                total_bytes: total,
            });
            next_emit = now + Duration::from_millis(250);
        }
    }
    file.sync_all().ok();
    drop(file);
    let _ = progress.send(InstallProgress::Progress {
        downloaded_bytes: got,
        total_bytes: total,
    });

    // 3. Verify SHA256 (we hashed inline while writing).
    let actual_sha = format!("{:x}", hasher.finalize());
    let _ = progress.send(InstallProgress::Verifying {
        expected: expected_sha.clone(),
        actual: actual_sha.clone(),
    });
    if actual_sha != expected_sha {
        let _ = std::fs::remove_file(&dl_path);
        return Err(anyhow!(
            "Downloaded Ollama installer failed SHA256 verification. \
             Expected {expected_sha}, got {actual_sha}. \
             The download may have been tampered with — \
             install manually from https://ollama.com/download instead."
        ));
    }

    // 4. Extract (macOS) or launch (Windows).
    #[cfg(target_os = "macos")]
    {
        let _ = progress.send(InstallProgress::Installing {
            step: "Extracting to /Applications/Ollama.app".into(),
        });
        // `unzip` ships with every macOS install. We use -o to overwrite an
        // existing Ollama.app (the user might be reinstalling) and -q to
        // avoid spamming a few thousand stdout lines.
        let output = Command::new("/usr/bin/unzip")
            .arg("-o")
            .arg("-q")
            .arg(&dl_path)
            .arg("-d")
            .arg("/Applications")
            .no_console()
            .output()
            .context("run /usr/bin/unzip")?;
        if !output.status.success() {
            return Err(anyhow!(
                "Failed to extract Ollama-darwin.zip to /Applications. \
                 You may need to grant Atlas Full Disk Access. \
                 unzip stderr: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let _ = progress.send(InstallProgress::Installing {
            step: "Launching Ollama".into(),
        });
        Command::new("/usr/bin/open")
            .arg("/Applications/Ollama.app")
            .no_console()
            .spawn()
            .context("launch /Applications/Ollama.app")?;
        // Give the menu-bar daemon ~2s to bind :11434 before the UI re-polls.
        tokio::time::sleep(Duration::from_secs(2)).await;
        // Once the daemon is up, pull the default `llama3` model so the
        // user has a working LLM the moment install finishes. Best-effort:
        // a network hiccup here shouldn't fail the (already-completed)
        // install — we just leave a note and let the user pull it later.
        if let Err(e) = pull_default_model(progress).await {
            let _ = progress.send(InstallProgress::Installing {
                step: format!(
                    "Ollama installed. Couldn't auto-pull llama3 ({e}); \
                     run `ollama pull llama3` once the daemon is up."
                ),
            });
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = progress.send(InstallProgress::Installing {
            step: "Launching OllamaSetup.exe (Windows will prompt for elevation)".into(),
        });
        // Ollama's NSIS installer does not support `/S` silent mode, so
        // the user has to click through. We just spawn it and let
        // Windows handle UAC. Installation typically takes 1-3 minutes.
        Command::new(&dl_path)
            .no_console()
            .spawn()
            .context("spawn OllamaSetup.exe")?;
    }

    Ok(())
}

/// After the daemon comes up, run the equivalent of `ollama pull llama3`
/// over the HTTP API so the user has a working model immediately. Waits
/// up to ~30s for the daemon to bind `:11434`, then streams the pull and
/// emits coarse progress as `InstallProgress::Installing` steps (≤4/sec).
#[cfg(target_os = "macos")]
async fn pull_default_model(progress: &Channel<InstallProgress>) -> Result<()> {
    const MODEL: &str = "llama3";
    const BASE: &str = "http://127.0.0.1:11434";

    // 1. Wait for the daemon to answer /api/version (up to ~30s).
    let probe = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .context("build daemon probe client")?;
    let mut ready = false;
    for _ in 0..30 {
        if probe
            .get(format!("{BASE}/api/version"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !ready {
        return Err(anyhow!("daemon not reachable at {BASE} within 30s"));
    }

    // 2. Stream the pull. `/api/pull` returns newline-delimited JSON
    //    status objects; the download lines carry `total`/`completed`
    //    byte counters we surface as a percentage. The model is several
    //    GB, so we give this request a generous 1-hour ceiling.
    let _ = progress.send(InstallProgress::Installing {
        step: format!("Downloading {MODEL} model…"),
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3600))
        .build()
        .context("build model-pull client")?;
    let mut stream = client
        .post(format!("{BASE}/api/pull"))
        .json(&serde_json::json!({ "model": MODEL, "stream": true }))
        .send()
        .await
        .with_context(|| format!("start pull of {MODEL}"))?
        .error_for_status()
        .with_context(|| format!("pull {MODEL} HTTP error"))?;

    let mut buf = String::new();
    let mut next_emit = std::time::Instant::now();
    loop {
        let chunk = stream.chunk().await.context("pull stream chunk")?;
        let Some(chunk) = chunk else { break };
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(nl) = buf.find('\n') {
            let line: String = buf.drain(..=nl).collect();
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                return Err(anyhow!("Ollama failed to pull {MODEL}: {err}"));
            }
            let now = std::time::Instant::now();
            if now >= next_emit {
                let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("downloading");
                let total = v.get("total").and_then(|n| n.as_u64()).unwrap_or(0);
                let completed = v.get("completed").and_then(|n| n.as_u64()).unwrap_or(0);
                let step = if total > 0 {
                    let pct = ((completed as f64 / total as f64) * 100.0).round() as u64;
                    format!("Pulling {MODEL}: {status} ({pct}%)")
                } else {
                    format!("Pulling {MODEL}: {status}")
                };
                let _ = progress.send(InstallProgress::Installing { step });
                next_emit = now + Duration::from_millis(250);
            }
        }
    }

    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn install_ollama_impl(_progress: &Channel<InstallProgress>) -> Result<()> {
    Err(anyhow!(
        "In-app install is only supported on macOS and Windows. \
         Run `curl -fsSL https://ollama.com/install.sh | sh` from a terminal."
    ))
}
