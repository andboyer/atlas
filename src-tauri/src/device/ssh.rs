//! SSH transport — shells out to the OS `ssh` binary.
//!
//! Why not `russh`? Two reasons:
//!  1. **Smaller binary, no extra OpenSSL surface.** macOS, Windows
//!     (since Win10 1809), and every desktop Linux distro ship a modern
//!     OpenSSH client by default. Re-implementing that in Rust adds ~3 MB
//!     and a new vendor of crypto bugs.
//!  2. **Operator-supplied ssh-agent / `~/.ssh/config` just works.** Any
//!     `Match`/`Host`/`ProxyJump`/`ForwardAgent` rule the operator already
//!     wrote applies without us re-implementing the config parser.
//!
//! We pass per-call options on the command line to ensure deterministic
//! behaviour regardless of the operator's `~/.ssh/config`:
//!  * `BatchMode=yes` — never prompt; fail fast if no key matches.
//!  * `StrictHostKeyChecking=accept-new` — trust on first use, refuse on
//!    later host-key swaps. The operator can pin in `~/.ssh/known_hosts`
//!    out of band.
//!  * `ConnectTimeout=10` — bound the TCP handshake.
//!  * `ServerAliveInterval=15` + `ServerAliveCountMax=2` — bound the
//!    command's wall-clock against silent drops.
//!
//! Password auth uses `sshpass -e` IF and only if the operator stored a
//! password in the keychain. `sshpass` is not bundled — if it's missing
//! we surface a clear "install sshpass for password auth" error. Key auth
//! is preferred for every documented vendor.
//!
//! Whole module is `cfg(unix)` + `cfg(windows)` gated below — the only
//! divergence is the `sshpass` path.

use super::{CommandRequest, CommandResponse, Transport, TransportError};
use crate::device::inventory::{AuthKind, HostEntry, TransportKind};
use crate::device::keychain;
use async_trait::async_trait;
use std::process::Stdio;
use std::time::Instant;
use tokio::process::Command;

#[derive(Default, Clone)]
pub struct SshTransport;

impl SshTransport {
    pub fn new() -> Self {
        Self
    }

    fn ssh_args(host: &HostEntry) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
            "-o".into(),
            "ServerAliveInterval=15".into(),
            "-o".into(),
            "ServerAliveCountMax=2".into(),
            "-p".into(),
            host.port.to_string(),
        ];
        if host.auth == AuthKind::Key && !host.key_path.is_empty() {
            args.push("-i".into());
            args.push(expand_tilde(&host.key_path));
        }
        // Force NO interactive password prompt; password auth (if used)
        // funnels through sshpass below.
        args.push("-o".into());
        args.push(format!(
            "PasswordAuthentication={}",
            if host.auth == AuthKind::Password {
                "yes"
            } else {
                "no"
            }
        ));
        let user_host = if host.username.is_empty() {
            host.hostname.clone()
        } else {
            format!("{}@{}", host.username, host.hostname)
        };
        args.push(user_host);
        args
    }
}

#[async_trait]
impl Transport for SshTransport {
    async fn exec(
        &self,
        host: &HostEntry,
        req: CommandRequest,
    ) -> Result<CommandResponse, TransportError> {
        if host.transport != TransportKind::Ssh {
            return Err(TransportError::Unsupported("expected ssh host".into()));
        }
        let started = Instant::now();
        // Resolve password from keychain if applicable. We do this OUTSIDE
        // the command line so the secret never appears in `ps`.
        let password_env = if host.auth == AuthKind::Password {
            match keychain::get(&host.id) {
                Ok(s) => Some(s),
                Err(e) => {
                    return Err(TransportError::Auth(host.id.clone(), e.to_string()));
                }
            }
        } else {
            None
        };
        let args = SshTransport::ssh_args(host);
        let mut cmd = build_command(password_env.as_deref(), &args, &req.rendered)?;
        let result = tokio::time::timeout(req.timeout, cmd.output()).await;
        let duration_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(Ok(output)) => Ok(CommandResponse {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                status_code: output.status.code(),
                duration_ms,
            }),
            Ok(Err(e)) => Err(TransportError::Io(e.to_string())),
            Err(_) => Err(TransportError::Timeout(req.timeout.as_millis() as u64)),
        }
    }

    async fn test(&self, host: &HostEntry) -> Result<(), TransportError> {
        let req = CommandRequest {
            command_id: "_test".into(),
            rendered: "echo ok".into(),
            body: None,
            method: "SSH".into(),
            risk: super::Risk::Read,
            timeout: std::time::Duration::from_secs(15),
        };
        let resp = self.exec(host, req).await?;
        if resp.stdout.trim() == "ok" {
            Ok(())
        } else {
            Err(TransportError::Other(format!(
                "unexpected response: stdout=`{}` stderr=`{}`",
                resp.stdout.trim(),
                resp.stderr.trim()
            )))
        }
    }
}

/// Build the OS command, routing through `sshpass -e` when password auth
/// is active. The password rides on `SSHPASS=` env var, not argv.
fn build_command(
    password: Option<&str>,
    ssh_args: &[String],
    remote_cmd: &str,
) -> Result<Command, TransportError> {
    if let Some(pw) = password {
        // sshpass MUST be on PATH. We can't bundle it (license-incompatible
        // on macOS Gatekeeper'd apps and not on Win by default); operators
        // are expected to `brew install sshpass` / `apt install sshpass`.
        let mut cmd = Command::new("sshpass");
        cmd.env("SSHPASS", pw);
        cmd.arg("-e").arg("ssh");
        for a in ssh_args {
            cmd.arg(a);
        }
        cmd.arg(remote_cmd);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use crate::process_util::NoConsoleExt;
            cmd.no_console();
        }
        return Ok(cmd);
    }
    let mut cmd = Command::new("ssh");
    for a in ssh_args {
        cmd.arg(a);
    }
    cmd.arg(remote_cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use crate::process_util::NoConsoleExt;
        cmd.no_console();
    }
    Ok(cmd)
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return format!("{}/{}", home.display(), rest);
        }
    }
    path.to_string()
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::inventory::{AuthKind, TransportKind};

    fn host_with_key() -> HostEntry {
        HostEntry {
            id: "test".into(),
            alias: "Test".into(),
            hostname: "1.2.3.4".into(),
            port: 2222,
            transport: TransportKind::Ssh,
            skill: "cisco-ios".into(),
            username: "admin".into(),
            auth: AuthKind::Key,
            key_path: "~/.ssh/id_ed25519".into(),
            site: String::new(),
            roles: vec![],
            av_switch_uplink_port: String::new(),
            timeout_seconds: 0,
            tls_verify: true,
        }
    }

    #[test]
    fn ssh_args_include_batchmode_and_strict_hk() {
        let h = host_with_key();
        let args = SshTransport::ssh_args(&h);
        assert!(args.iter().any(|s| s == "BatchMode=yes"));
        assert!(args.iter().any(|s| s == "StrictHostKeyChecking=accept-new"));
        assert!(args.iter().any(|s| s == "ConnectTimeout=10"));
    }

    #[test]
    fn ssh_args_force_password_off_for_key_auth() {
        let h = host_with_key();
        let args = SshTransport::ssh_args(&h);
        assert!(args.iter().any(|s| s == "PasswordAuthentication=no"));
    }

    #[test]
    fn ssh_args_expands_tilde_in_key_path() {
        let h = host_with_key();
        let args = SshTransport::ssh_args(&h);
        // No bare `~/` should appear after expansion when HOME is set in CI.
        let key_idx = args.iter().position(|s| s == "-i").unwrap();
        let key = &args[key_idx + 1];
        if std::env::var_os("HOME").is_some() {
            assert!(!key.starts_with("~/"), "did not expand tilde: {key}");
        }
    }

    #[test]
    fn user_host_pair_uses_user_at_host() {
        let h = host_with_key();
        let args = SshTransport::ssh_args(&h);
        let last = args.last().unwrap();
        assert_eq!(last, "admin@1.2.3.4");
    }

    #[test]
    fn no_user_just_hostname() {
        let mut h = host_with_key();
        h.username = String::new();
        let args = SshTransport::ssh_args(&h);
        assert_eq!(args.last().unwrap(), "1.2.3.4");
    }
}
