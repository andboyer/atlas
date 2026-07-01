//! Session-scoped privileged probe agent (macOS).
//!
//! Each privileged probe normally re-execs the binary under a fresh
//! `osascript ... with administrator privileges` prompt, and macOS only
//! caches the admin right *within a single authorization session* — so
//! separate `osascript` invocations don't share it and every run
//! re-prompts. To prompt only ONCE per app launch we instead spawn a
//! single long-lived elevated *agent* process on first privileged use.
//! The agent listens on a locked-down Unix-domain socket and runs every
//! subsequent probe in-process as root, so there are no further prompts
//! for the lifetime of the app.
//!
//! Security model:
//!   - The agent runs ONLY a fixed allowlist of passive listener probes
//!     (`igmp-listen` / `ptp-listen` / `stp-listen`) with validated
//!     interface names and clamped listen windows. There is no arbitrary
//!     command / file / shell surface.
//!   - The socket lives in a per-session `0700` directory owned by the
//!     invoking user; the socket itself is chowned to that user and
//!     chmod `0600`, so only that uid can connect.
//!   - Every request must carry a 256-bit random session token delivered
//!     to the agent through a `0600` file (never argv, so it can't leak
//!     via `ps`).
//!   - The agent self-terminates when the parent app exits (PID watch) or
//!     after an idle timeout, so it never lingers as a stray root process.
//!
//! On Windows / Linux this module is a thin pass-through to the existing
//! one-shot `elevate_and_run_probe` (UAC always prompts; polkit caches
//! only briefly) — the persistent agent is a macOS-specific optimisation.

use std::sync::OnceLock;

/// Allowlisted probe kinds the agent will run as root. Anything else is
/// rejected before dispatch (and routed to the one-shot helper instead).
#[cfg(target_os = "macos")]
const ALLOWED_KINDS: &[&str] = &["igmp-listen", "ptp-listen", "stp-listen"];

/// Idle ceiling: if no request arrives for this long (and none is in
/// flight) the root agent exits so it can't linger after the operator
/// stops using the privileged tools.
#[cfg(target_os = "macos")]
const MAX_IDLE_SECS: u64 = 900;

/// Process-wide handle to the session privileged agent. A single shared
/// instance is correct because there is exactly one app process / one
/// user session.
pub struct AgentClient {
    #[cfg(target_os = "macos")]
    inner: tokio::sync::Mutex<Option<macos::RunningAgent>>,
}

impl AgentClient {
    fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            inner: tokio::sync::Mutex::new(None),
        }
    }

    /// Run a privileged probe, prompting for admin at most once per app
    /// launch (macOS). Returns the probe's JSON payload as a string, or a
    /// human-readable `Err`. On Windows / Linux this delegates straight to
    /// the one-shot elevation helper.
    pub async fn run_probe(
        &self,
        exe: &str,
        kind: &str,
        iface: &str,
        secs: u32,
    ) -> Result<String, String> {
        #[cfg(target_os = "macos")]
        {
            self.run_probe_macos(exe, kind, iface, secs).await
        }
        #[cfg(not(target_os = "macos"))]
        {
            crate::probes::elevate::elevate_and_run_probe(exe, kind, iface, secs).await
        }
    }
}

/// Shared, process-wide privileged-agent client.
pub fn shared() -> &'static AgentClient {
    static SHARED: OnceLock<AgentClient> = OnceLock::new();
    SHARED.get_or_init(AgentClient::new)
}

/// Entry point for the elevated `--probe-agent` mode. Invoked from
/// `try_handle_probe_args` BEFORE the GUI initialises, in a process that
/// is already running as root (spawned via osascript). Returns the
/// process exit code. Only meaningful on macOS.
#[cfg(target_os = "macos")]
pub fn run_agent(args: &[String]) -> i32 {
    macos::run_agent(args)
}

#[cfg(target_os = "macos")]
impl AgentClient {
    async fn run_probe_macos(
        &self,
        exe: &str,
        kind: &str,
        iface: &str,
        secs: u32,
    ) -> Result<String, String> {
        // Kinds the agent doesn't handle fall straight through to the
        // one-shot helper (keeps the agent's privileged surface minimal).
        if !ALLOWED_KINDS.contains(&kind) {
            return crate::probes::elevate::elevate_and_run_probe(exe, kind, iface, secs).await;
        }

        let mut guard = self.inner.lock().await;

        // Reuse the running agent only if it still answers on its socket.
        // We deliberately do NOT look at the spawning `osascript` child's
        // exit status: the agent daemonises itself, so `osascript` returns
        // as soon as the prompt is satisfied and the (long-lived) root
        // daemon carries on independently. A liveness ping is the only
        // reliable signal.
        let alive = match guard.as_ref() {
            None => false,
            Some(a) => macos::send_request(
                &a.socket,
                &a.token,
                "ping",
                "",
                "",
                0,
                std::time::Duration::from_secs(2),
            )
            .await
            .map(|r| r.ok)
            .unwrap_or(false),
        };
        if !alive {
            if let Some(old) = guard.take() {
                old.cleanup();
            }
            tracing::info!(target: "elevate", "launching session privileged agent (one auth prompt)");
            match macos::ensure_agent(exe).await {
                Ok(a) => *guard = Some(a),
                Err(e) => {
                    tracing::warn!(
                        target: "elevate",
                        "session privileged agent unavailable ({e}); using one-shot elevation"
                    );
                    drop(guard);
                    return crate::probes::elevate::elevate_and_run_probe(exe, kind, iface, secs)
                        .await;
                }
            }
        } else {
            tracing::info!(target: "elevate", "reusing session privileged agent (no prompt)");
        }

        let (socket, token) = {
            let a = guard.as_ref().expect("agent present after ensure");
            (a.socket.clone(), a.token.clone())
        };

        // Watchdog mirrors the one-shot helper: listen window + 30 s slack.
        let req_timeout = std::time::Duration::from_secs(secs as u64 + 30);
        match macos::send_request(&socket, &token, "probe", kind, iface, secs, req_timeout).await {
            Ok(resp) if resp.ok => resp
                .json
                .ok_or_else(|| "privileged agent returned no payload".to_string()),
            Ok(resp) => Err(resp
                .error
                .unwrap_or_else(|| "privileged agent reported an error".to_string())),
            Err(e) => {
                // The connection broke mid-session (agent crashed / was
                // killed). Drop it and fall back to a one-shot run so the
                // operator still gets a result.
                if let Some(old) = guard.take() {
                    old.cleanup();
                }
                drop(guard);
                tracing::warn!(
                    target: "elevate",
                    "privileged agent request failed ({e}); using one-shot elevation"
                );
                crate::probes::elevate::elevate_and_run_probe(exe, kind, iface, secs).await
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{ALLOWED_KINDS, MAX_IDLE_SECS};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(serde::Serialize, serde::Deserialize)]
    pub(super) struct AgentRequest {
        pub token: String,
        pub op: String,
        #[serde(default)]
        pub kind: String,
        #[serde(default)]
        pub iface: String,
        #[serde(default)]
        pub secs: u32,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub(super) struct AgentResponse {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub json: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    impl AgentResponse {
        fn ok_empty() -> Self {
            Self {
                ok: true,
                json: None,
                error: None,
            }
        }
        fn ok_json(json: String) -> Self {
            Self {
                ok: true,
                json: Some(json),
                error: None,
            }
        }
        fn err(msg: impl Into<String>) -> Self {
            Self {
                ok: false,
                json: None,
                error: Some(msg.into()),
            }
        }
    }

    /// A live elevated agent daemon + the socket the app talks to it on.
    /// The spawning `osascript` has already exited (the agent daemonises),
    /// so there is no child handle to hold — lifetime is governed by the
    /// agent's own parent-PID / idle watchdog plus the `shutdown` message.
    pub(super) struct RunningAgent {
        pub socket: PathBuf,
        pub token: String,
        pub dir: PathBuf,
    }

    impl RunningAgent {
        /// Best-effort teardown: ask the daemon to exit and remove the
        /// session directory.
        pub fn cleanup(self) {
            if let Ok(mut s) = UnixStream::connect(&self.socket) {
                let req = AgentRequest {
                    token: self.token.clone(),
                    op: "shutdown".into(),
                    kind: String::new(),
                    iface: String::new(),
                    secs: 0,
                };
                if let Ok(mut line) = serde_json::to_string(&req) {
                    line.push('\n');
                    let _ = s.write_all(line.as_bytes());
                    let _ = s.flush();
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// 256 bits of entropy (two v4 UUIDs) — comfortably unguessable for a
    /// local-only, owner-restricted socket.
    fn random_token() -> String {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    }

    fn arg_value(args: &[String], key: &str) -> Option<String> {
        let idx = args.iter().position(|a| a == key)?;
        args.get(idx + 1).cloned()
    }

    /// Constant-time byte comparison so token checking can't be timed.
    fn constant_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// Same rule as `elevate::validate_iface` — kernel-style names only.
    fn iface_ok(iface: &str) -> bool {
        !iface.is_empty()
            && iface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
    }

    // ── Client side (runs in the unprivileged app process) ──────────────

    pub(super) async fn ensure_agent(exe: &str) -> Result<RunningAgent, String> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Per-session 0700 directory the user owns. Root (the agent) drops
        // the socket inside it; the dir perms alone already gate access.
        //
        // The names are kept SHORT because a Unix-domain socket path must
        // fit in `sockaddr_un.sun_path` (104 bytes on macOS). The default
        // per-user temp dir (`/var/folders/…`) is already ~49 chars, so a
        // long dir/file name overflows; if the resulting socket path is
        // still too long we fall back to `/tmp` (5 chars).
        let short = uuid::Uuid::new_v4().simple().to_string();
        let short = &short[..12];
        let dir_name = format!("atlas-{short}");
        let mut dir = std::env::temp_dir().join(&dir_name);
        let mut socket = dir.join("s");
        if socket.as_os_str().len() >= 100 {
            dir = std::path::PathBuf::from("/tmp").join(&dir_name);
            socket = dir.join("s");
        }
        std::fs::create_dir_all(&dir).map_err(|e| format!("create agent dir: {e}"))?;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));

        let token = random_token();
        let token_file = dir.join("t");
        std::fs::write(&token_file, &token).map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            format!("write token file: {e}")
        })?;
        let _ = std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600));

        let parent_pid = std::process::id();
        let socket_str = socket.to_string_lossy();
        let token_file_str = token_file.to_string_lossy();
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let shell_cmd = format!(
            "\"{exe}\" --probe-agent --socket \"{sock}\" --token-file \"{tf}\" \
             --uid {uid} --gid {gid} --parent-pid {pp}",
            exe = esc(exe),
            sock = esc(&socket_str),
            tf = esc(&token_file_str),
            pp = parent_pid,
        );
        let apple_script = format!(
            "do shell script \"{}\" with administrator privileges",
            esc(&shell_cmd)
        );

        let mut child = tokio::process::Command::new("osascript")
            .arg("-e")
            .arg(&apple_script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&dir);
                format!("spawn osascript: {e}")
            })?;

        // The agent daemonises itself, so `osascript` returns (exit 0) as
        // soon as the auth prompt is satisfied — that is SUCCESS, not a
        // failure. A NON-zero exit means the user cancelled or the launch
        // failed. Either way we keep polling the socket until the daemon
        // binds it (or the deadline lapses).
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut launched = false;
        loop {
            if !launched {
                if let Ok(Some(status)) = child.try_wait() {
                    launched = true;
                    if !status.success() {
                        let mut msg = String::new();
                        if let Some(mut se) = child.stderr.take() {
                            use tokio::io::AsyncReadExt;
                            let _ = se.read_to_string(&mut msg).await;
                        }
                        let _ = std::fs::remove_dir_all(&dir);
                        if msg.contains("User canceled")
                            || msg.contains("canceled")
                            || msg.contains("cancelled")
                        {
                            return Err("Administrator authorisation was cancelled.".into());
                        }
                        return Err(format!(
                            "privileged agent launch failed (status {:?}): {}",
                            status.code(),
                            msg.trim()
                        ));
                    }
                }
            }
            if socket.exists() {
                if let Ok(resp) =
                    send_request(&socket, &token, "ping", "", "", 0, Duration::from_secs(3)).await
                {
                    if resp.ok {
                        return Ok(RunningAgent { socket, token, dir });
                    }
                }
            }
            if Instant::now() >= deadline {
                let _ = std::fs::remove_dir_all(&dir);
                return Err("privileged agent did not become ready in time".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub(super) async fn send_request(
        socket: &Path,
        token: &str,
        op: &str,
        kind: &str,
        iface: &str,
        secs: u32,
        timeout: Duration,
    ) -> Result<AgentResponse, String> {
        let req = AgentRequest {
            token: token.to_string(),
            op: op.to_string(),
            kind: kind.to_string(),
            iface: iface.to_string(),
            secs,
        };
        let mut line =
            serde_json::to_string(&req).map_err(|e| format!("serialise request: {e}"))?;
        line.push('\n');

        let fut = async {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
            let mut stream = tokio::net::UnixStream::connect(socket)
                .await
                .map_err(|e| format!("connect agent: {e}"))?;
            stream
                .write_all(line.as_bytes())
                .await
                .map_err(|e| format!("write request: {e}"))?;
            stream.flush().await.ok();
            let mut reader = TokioBufReader::new(stream);
            let mut resp_line = String::new();
            reader
                .read_line(&mut resp_line)
                .await
                .map_err(|e| format!("read response: {e}"))?;
            if resp_line.trim().is_empty() {
                return Err("agent closed the connection without responding".to_string());
            }
            serde_json::from_str::<AgentResponse>(resp_line.trim())
                .map_err(|e| format!("parse agent response: {e}"))
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err("agent request timed out".to_string()),
        }
    }

    // ── Server side (runs in the elevated agent process, as root) ───────

    pub(super) fn run_agent(args: &[String]) -> i32 {
        let socket = match arg_value(args, "--socket") {
            Some(s) => PathBuf::from(s),
            None => {
                eprintln!("agent: --socket required");
                return 2;
            }
        };
        let token_file = match arg_value(args, "--token-file") {
            Some(s) => s,
            None => {
                eprintln!("agent: --token-file required");
                return 2;
            }
        };
        let uid: u32 = arg_value(args, "--uid")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let gid: u32 = arg_value(args, "--gid")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let parent_pid: i32 = arg_value(args, "--parent-pid")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Read + immediately consume the one-shot token file.
        let token = std::fs::read_to_string(&token_file)
            .unwrap_or_default()
            .trim()
            .to_string();
        let _ = std::fs::remove_file(&token_file);
        if token.is_empty() {
            eprintln!("agent: empty or missing token");
            return 2;
        }

        let _ = std::fs::remove_file(&socket);
        let listener = match UnixListener::bind(&socket) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("agent: bind {}: {e}", socket.display());
                return 1;
            }
        };
        // Lock the socket to the invoking user only.
        if let Ok(c) = std::ffi::CString::new(socket.as_os_str().as_bytes()) {
            unsafe {
                libc::chown(c.as_ptr(), uid, gid);
            }
        }
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));

        // Detach from the spawning `osascript` / `do shell script` so that
        // the AppleScript call returns as soon as the auth prompt is
        // satisfied, leaving this process running as an independent root
        // daemon. The socket is bound ABOVE first, so any bind error is
        // still reported through osascript's exit status before we detach.
        //
        // fork() MUST happen before any threads are created — we are still
        // single-threaded here because `--probe-agent` is dispatched before
        // the Tauri / tokio runtime starts. The bound listener fd survives
        // fork (CLOEXEC only affects exec, not fork).
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                eprintln!("agent: fork failed");
                return 1;
            }
            if pid > 0 {
                // The process osascript is waiting on exits → `do shell
                // script` returns success and the prompt clears.
                std::process::exit(0);
            }
            // Daemon child: new session, detach controlling terminal.
            libc::setsid();
            // Redirect std fds to /dev/null so a closed osascript pipe
            // can't deliver SIGPIPE / spurious EOF to the daemon.
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::dup2(devnull, 2);
                if devnull > 2 {
                    libc::close(devnull);
                }
            }
        }

        let last_active = Arc::new(AtomicU64::new(now_secs()));
        let in_progress = Arc::new(AtomicBool::new(false));
        let socket_dir = socket.parent().map(Path::to_path_buf);

        // Watchdog: terminate when the parent app exits or after idle so
        // a root process never lingers.
        {
            let la = last_active.clone();
            let ip = in_progress.clone();
            let dir = socket_dir.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(3));
                if parent_pid > 0 {
                    // Running as root, kill(pid, 0) == 0 iff the process
                    // exists; anything else means the parent is gone.
                    let alive = unsafe { libc::kill(parent_pid, 0) } == 0;
                    if !alive {
                        if let Some(d) = &dir {
                            let _ = std::fs::remove_dir_all(d);
                        }
                        std::process::exit(0);
                    }
                }
                if !ip.load(Ordering::Relaxed) {
                    let idle = now_secs().saturating_sub(la.load(Ordering::Relaxed));
                    if idle > MAX_IDLE_SECS {
                        if let Some(d) = &dir {
                            let _ = std::fs::remove_dir_all(d);
                        }
                        std::process::exit(0);
                    }
                }
            });
        }

        for conn in listener.incoming() {
            match conn {
                Ok(stream) => handle_conn(
                    stream,
                    &token,
                    &last_active,
                    &in_progress,
                    socket_dir.as_deref(),
                ),
                Err(_) => continue,
            }
        }
        0
    }

    fn handle_conn(
        stream: UnixStream,
        token: &str,
        last_active: &Arc<AtomicU64>,
        in_progress: &Arc<AtomicBool>,
        socket_dir: Option<&Path>,
    ) {
        let mut writer = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let req: AgentRequest = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(_) => {
                let _ = write_response(&mut writer, &AgentResponse::err("malformed request"));
                return;
            }
        };
        if !constant_eq(req.token.as_bytes(), token.as_bytes()) {
            let _ = write_response(&mut writer, &AgentResponse::err("unauthorised"));
            return;
        }
        last_active.store(now_secs(), Ordering::Relaxed);

        let resp = match req.op.as_str() {
            "ping" => AgentResponse::ok_empty(),
            "shutdown" => {
                let _ = write_response(&mut writer, &AgentResponse::ok_empty());
                if let Some(d) = socket_dir {
                    let _ = std::fs::remove_dir_all(d);
                }
                std::process::exit(0);
            }
            "probe" => {
                if !ALLOWED_KINDS.contains(&req.kind.as_str()) {
                    AgentResponse::err(format!("probe kind not permitted: {}", req.kind))
                } else if !iface_ok(&req.iface) {
                    AgentResponse::err(format!("invalid interface name: {}", req.iface))
                } else {
                    in_progress.store(true, Ordering::Relaxed);
                    let result =
                        crate::probes::deep::run_probe_to_json(&req.kind, &req.iface, req.secs);
                    in_progress.store(false, Ordering::Relaxed);
                    last_active.store(now_secs(), Ordering::Relaxed);
                    match result {
                        Ok(json) => AgentResponse::ok_json(json),
                        Err(e) => AgentResponse::err(e),
                    }
                }
            }
            other => AgentResponse::err(format!("unknown op: {other}")),
        };
        let _ = write_response(&mut writer, &resp);
    }

    fn write_response(w: &mut UnixStream, resp: &AgentResponse) -> std::io::Result<()> {
        let mut line = serde_json::to_string(resp)
            .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialise\"}".to_string());
        line.push('\n');
        w.write_all(line.as_bytes())?;
        w.flush()
    }
}
