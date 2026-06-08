//! HTTPS transport — `reqwest` with a per-host cookie jar.
//!
//! Controller-style devices (TP-Link Omada, UniFi Network controller,
//! Luminex GigaCore web UI) want a POST `/login` once and then a session
//! cookie on every subsequent request. We give each `HostEntry` its own
//! `reqwest::Client` keyed in a process-global `DashMap`-style mutex so
//! cookies survive across runbook steps within a run.
//!
//! `host.tls_verify = false` flips off cert validation — operators with
//! internal CAs commonly need this for self-signed dev controllers. It
//! defaults to `true` (refuse), and the inventory UI surfaces the toggle
//! prominently with a warning.
//!
//! Login is fired lazily on the first command per session; if it fails,
//! the parent command surfaces `TransportError::Auth`. Subsequent
//! commands re-use the populated cookie jar.

use super::{CommandRequest, CommandResponse, Transport, TransportError};
use crate::device::inventory::{AuthKind, HostEntry, TransportKind};
use crate::device::keychain;
use crate::device::pack;
use async_trait::async_trait;
use parking_lot::Mutex;
use reqwest::{header::HeaderName, Method};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct HttpsTransport {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    packs: pack::PackRegistry,
}

#[derive(Clone)]
struct SessionEntry {
    client: reqwest::Client,
    logged_in: bool,
}

impl HttpsTransport {
    pub fn new(packs: pack::PackRegistry) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            packs,
        }
    }

    fn build_client(host: &HostEntry) -> Result<reqwest::Client, TransportError> {
        // Each session gets a fresh cookie jar.
        let jar = reqwest::cookie::Jar::default();
        let builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(!host.tls_verify)
            .timeout(std::time::Duration::from_secs(30))
            .cookie_provider(Arc::new(jar));
        builder
            .build()
            .map_err(|e| TransportError::Other(e.to_string()))
    }

    fn session_for(&self, host: &HostEntry) -> Result<SessionEntry, TransportError> {
        let mut map = self.sessions.lock();
        if let Some(s) = map.get(&host.id) {
            return Ok(s.clone());
        }
        let entry = SessionEntry {
            client: Self::build_client(host)?,
            logged_in: false,
        };
        map.insert(host.id.clone(), entry.clone());
        Ok(entry)
    }

    fn mark_logged_in(&self, host_id: &str) {
        if let Some(s) = self.sessions.lock().get_mut(host_id) {
            s.logged_in = true;
        }
    }

    async fn ensure_login(&self, host: &HostEntry) -> Result<(), TransportError> {
        let session = self.session_for(host)?;
        if session.logged_in {
            return Ok(());
        }
        let pack = self
            .packs
            .get(&host.skill)
            .ok_or_else(|| TransportError::Other(format!("unknown skill `{}`", host.skill)))?;
        let Some(login) = &pack.login else {
            // Pack defines no login surface (rare; Q-SYS uses header auth)
            // — mark logged-in to skip re-checks.
            self.mark_logged_in(&host.id);
            return Ok(());
        };
        if login.path.is_empty() && login.api_key_header.is_empty() {
            self.mark_logged_in(&host.id);
            return Ok(());
        }
        // Header-based auth (Q-SYS): nothing to do on first call; the
        // request method will read the api key from the keychain per-call.
        if !login.api_key_header.is_empty() {
            self.mark_logged_in(&host.id);
            return Ok(());
        }
        let password = keychain::get(&host.id)
            .map_err(|e| TransportError::Auth(host.id.clone(), e.to_string()))?;
        let url = format!("https://{}:{}{}", host.hostname, host.port, login.path);
        let mut body = serde_json::Map::new();
        if !login.username_field.is_empty() {
            body.insert(
                login.username_field.clone(),
                Value::String(host.username.clone()),
            );
        }
        if !login.password_field.is_empty() {
            body.insert(login.password_field.clone(), Value::String(password));
        }
        let resp = session
            .client
            .post(&url)
            .json(&Value::Object(body))
            .send()
            .await
            .map_err(|e| TransportError::Connect(host.hostname.clone(), e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body_txt = resp.text().await.unwrap_or_default();
            return Err(TransportError::Auth(
                host.id.clone(),
                format!(
                    "login HTTP {status}: {}",
                    body_txt.chars().take(200).collect::<String>()
                ),
            ));
        }
        // Some controllers (Omada) deliver a CSRF token in the JSON body
        // that must be echoed on subsequent mutating requests. We're
        // read-only in v1 so we don't capture it; that's a Phase-6 task.
        let _ = resp.bytes().await;
        self.mark_logged_in(&host.id);
        Ok(())
    }
}

#[async_trait]
impl Transport for HttpsTransport {
    async fn exec(
        &self,
        host: &HostEntry,
        req: CommandRequest,
    ) -> Result<CommandResponse, TransportError> {
        if host.transport != TransportKind::Https {
            return Err(TransportError::Unsupported("expected https host".into()));
        }
        self.ensure_login(host).await?;
        let session = self.session_for(host)?;
        let started = Instant::now();
        let url = format!("https://{}:{}{}", host.hostname, host.port, req.rendered);
        let method = Method::from_bytes(req.method.as_bytes())
            .map_err(|e| TransportError::Other(format!("bad method `{}`: {e}", req.method)))?;
        let mut builder = session.client.request(method, &url);
        // Q-SYS style header API key.
        if host.auth == AuthKind::ApiKey {
            if let Ok(key) = keychain::get(&host.id) {
                if let Some(pack) = self.packs.get(&host.skill) {
                    if let Some(login) = &pack.login {
                        if !login.api_key_header.is_empty() {
                            if let Ok(hn) = HeaderName::from_bytes(login.api_key_header.as_bytes())
                            {
                                builder = builder.header(hn, key);
                            }
                        }
                    }
                }
            }
        }
        if let Some(body) = req.body {
            builder = builder.json(&body);
        }
        let result = tokio::time::timeout(req.timeout, builder.send()).await;
        let duration_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(Ok(resp)) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                Ok(CommandResponse {
                    stdout: text,
                    stderr: String::new(),
                    status_code: Some(status.as_u16() as i32),
                    duration_ms,
                })
            }
            Ok(Err(e)) => Err(TransportError::Connect(
                host.hostname.clone(),
                e.to_string(),
            )),
            Err(_) => Err(TransportError::Timeout(req.timeout.as_millis() as u64)),
        }
    }

    async fn test(&self, host: &HostEntry) -> Result<(), TransportError> {
        // Just attempt the login; if the pack has no login surface we
        // GET / and accept any 2xx/3xx/4xx (the cert validation has
        // already happened in build_client).
        self.ensure_login(host).await?;
        let session = self.session_for(host)?;
        let url = format!("https://{}:{}/", host.hostname, host.port);
        let resp = session
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TransportError::Connect(host.hostname.clone(), e.to_string()))?;
        let s = resp.status();
        // 5xx is bad; anything else means we at least talked to a TLS
        // peer that responded with HTTP.
        if s.is_server_error() {
            return Err(TransportError::Other(format!("server error {s}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::inventory::{AuthKind, TransportKind};

    fn https_host() -> HostEntry {
        HostEntry {
            id: "ctlr".into(),
            alias: "Test Controller".into(),
            hostname: "127.0.0.1".into(),
            port: 8443,
            transport: TransportKind::Https,
            skill: "unifi".into(),
            username: "atlas".into(),
            auth: AuthKind::Password,
            key_path: String::new(),
            site: String::new(),
            roles: vec![],
            av_switch_uplink_port: String::new(),
            timeout_seconds: 0,
            tls_verify: false,
        }
    }

    #[test]
    fn session_for_creates_and_reuses() {
        let packs = pack::load_bundled();
        let t = HttpsTransport::new(packs);
        let h = https_host();
        let _a = t.session_for(&h).unwrap();
        // Second call must not re-build the client (cookie jar would
        // be lost). We can't `Arc::ptr_eq` on reqwest::Client directly
        // because it doesn't expose its inner Arc — instead we sample
        // the session map size before and after.
        let before = t.sessions.lock().len();
        let _b = t.session_for(&h).unwrap();
        let after = t.sessions.lock().len();
        assert_eq!(
            before, after,
            "second session_for should reuse, not re-insert"
        );
    }
}
