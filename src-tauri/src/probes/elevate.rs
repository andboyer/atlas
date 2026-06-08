//! Cross-platform helper that re-execs the current binary as an elevated
//! child so a privileged probe (currently: IGMP listen) can open the raw
//! sockets it needs.
//!
//! - **macOS**: `osascript ... with administrator privileges` — native
//!   auth prompt, cached ~5 min.
//! - **Windows**: `powershell.exe Start-Process -Verb RunAs` — UAC prompt.
//!   stdout cannot cross an elevation boundary cleanly, so the helper
//!   writes JSON to a `--probe-out <path>` temp file which the parent
//!   reads after `-Wait`.
//! - **Linux**: `pkexec` (GNOME / KDE / most modern distros ship
//!   `polkit-agent` for the desktop session, which makes pkexec produce a
//!   graphical auth prompt). If `pkexec` is unavailable, falls back to
//!   `sudo -A` which requires `SUDO_ASKPASS` to be wired to a graphical
//!   askpass helper (`ssh-askpass`, `lxqt-openssh-askpass`, etc.). Both
//!   take the temp-file route for the same reason as Windows — pkexec
//!   inherits a sanitised environment and the agent's stdin/stdout
//!   handling is unreliable in headless test environments.
//!
//! On any platform, returns the JSON string the helper emitted, or a
//! human-readable `Err(String)` (cancellations, sandbox refusals,
//! missing-binary, etc.) suitable for surfacing in the UI.

use std::time::Duration;

/// How long to allow the elevated child to run before giving up. The
/// caller's `secs` is the listen window; the helper itself takes a
/// fraction of a second to start, so a 30 s safety margin is plenty for
/// every probe we currently ship.
fn watchdog_for(listen_secs: u32) -> Duration {
    Duration::from_secs(listen_secs as u64 + 30)
}

/// Reject anything that isn't a kernel-style iface name. Defensive
/// against arg injection through the elevated shell wrapper on macOS /
/// pkexec's environment scrubbing on Linux.
fn validate_iface(iface: &str) -> Result<(), String> {
    if iface.is_empty() {
        return Err("interface name is empty".into());
    }
    if !iface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ' ')
    {
        return Err(format!("invalid interface name: {iface}"));
    }
    Ok(())
}

fn validate_probe_kind(kind: &str) -> Result<(), String> {
    if !kind
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("invalid probe kind: {kind}"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn elevate_and_run_probe(
    exe: &str,
    probe_kind: &str,
    iface: &str,
    secs: u32,
) -> Result<String, String> {
    validate_iface(iface)?;
    validate_probe_kind(probe_kind)?;
    // Quote the binary path for osascript's nested shell; backslash-escape
    // any embedded quotes.
    let escaped = exe.replace('\\', "\\\\").replace('"', "\\\"");
    let shell_cmd = format!("\"{escaped}\" --probe {probe_kind} --iface {iface} --secs {secs}");
    let apple_script = format!(
        "do shell script \"{}\" with administrator privileges",
        shell_cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let fut = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&apple_script)
        .output();
    let output = match tokio::time::timeout(watchdog_for(secs), fut).await {
        Ok(r) => r.map_err(|e| format!("spawn osascript: {e}"))?,
        Err(_) => return Err("Privileged helper did not return in time.".into()),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("canceled.") {
            return Err("Administrator authorisation was cancelled.".into());
        }
        return Err(format!(
            "Privileged helper failed (status {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Escape a single argument for the Win32 `CommandLineToArgvW` parser:
/// wrap in `"..."` if the value contains whitespace or a double quote,
/// and double any backslashes that immediately precede a quote (or the
/// closing quote). Without this, NIC FriendlyNames like
/// `Dante Nic - 192.168.7.245` reach the child as four separate args.
#[cfg(target_os = "windows")]
fn quote_for_createprocess(arg: &str) -> String {
    let needs_quote = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"'));
    if !needs_quote {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut pending_backslashes = 0usize;
    for c in arg.chars() {
        if c == '\\' {
            pending_backslashes += 1;
            continue;
        }
        if c == '"' {
            for _ in 0..(pending_backslashes * 2 + 1) {
                out.push('\\');
            }
            pending_backslashes = 0;
            out.push('"');
            continue;
        }
        for _ in 0..pending_backslashes {
            out.push('\\');
        }
        pending_backslashes = 0;
        out.push(c);
    }
    for _ in 0..(pending_backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(target_os = "windows")]
pub async fn elevate_and_run_probe(
    exe: &str,
    probe_kind: &str,
    iface: &str,
    secs: u32,
) -> Result<String, String> {
    validate_iface(iface)?;
    validate_probe_kind(probe_kind)?;
    let out_path = std::env::temp_dir().join(format!("atlas-probe-{}.json", uuid::Uuid::new_v4()));
    let out_path_str = out_path.to_string_lossy().into_owned();
    let ps_quote = |s: &str| s.replace('\'', "''");
    let secs_str = secs.to_string();
    let arg_list = [
        "--probe",
        probe_kind,
        "--iface",
        iface,
        "--secs",
        &secs_str,
        "--probe-out",
        &out_path_str,
    ]
    .iter()
    .map(|a| format!("'{}'", ps_quote(&quote_for_createprocess(a))))
    .collect::<Vec<_>>()
    .join(",");
    let ps_cmd = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ \
           Start-Process -FilePath '{exe}' -ArgumentList {args} -Verb RunAs -Wait -WindowStyle Hidden \
         }} catch {{ \
           if ($_.Exception.Message -match 'cancelled|canceled') {{ \
             Write-Error 'USER_CANCELLED'; exit 2 \
           }} else {{ \
             Write-Error $_.Exception.Message; exit 3 \
           }} \
         }}",
        exe = ps_quote(exe),
        args = arg_list,
    );
    let output = {
        use crate::process_util::NoConsoleExt;
        let fut = tokio::process::Command::new("powershell.exe")
            .no_console()
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output();
        match tokio::time::timeout(watchdog_for(secs), fut).await {
            Ok(r) => r.map_err(|e| format!("spawn powershell: {e}"))?,
            Err(_) => {
                let _ = tokio::fs::remove_file(&out_path).await;
                return Err("Privileged helper did not return in time.".into());
            }
        }
    };
    if !output.status.success() {
        let _ = tokio::fs::remove_file(&out_path).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("USER_CANCELLED") || stderr.contains("cancelled") {
            return Err("Administrator authorisation was cancelled.".into());
        }
        return Err(format!(
            "Privileged helper failed (status {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }
    let json = tokio::fs::read_to_string(&out_path)
        .await
        .map_err(|e| format!("read probe output {out_path_str}: {e}"))?;
    let _ = tokio::fs::remove_file(&out_path).await;
    Ok(json)
}

#[cfg(target_os = "linux")]
pub async fn elevate_and_run_probe(
    exe: &str,
    probe_kind: &str,
    iface: &str,
    secs: u32,
) -> Result<String, String> {
    validate_iface(iface)?;
    validate_probe_kind(probe_kind)?;
    // Same temp-file trick as Windows: pkexec's policy-agent dialog
    // sometimes inherits a confused stdio, and on the `sudo -A`
    // fallback the askpass helper drains stdin. A file is always safe.
    let out_path = std::env::temp_dir().join(format!("atlas-probe-{}.json", uuid::Uuid::new_v4()));
    let out_path_str = out_path.to_string_lossy().into_owned();
    let secs_str = secs.to_string();
    let helper_args = [
        exe,
        "--probe",
        probe_kind,
        "--iface",
        iface,
        "--secs",
        &secs_str,
        "--probe-out",
        &out_path_str,
    ];

    // Prefer pkexec — present on every desktop distro with polkit-agent
    // running (GNOME / KDE / XFCE / LXQt out of the box). It produces a
    // graphical auth dialog when the calling process has a DISPLAY /
    // WAYLAND_DISPLAY environment, and falls back to a TTY prompt
    // otherwise (useful for SSH sessions during testing).
    let pkexec_available = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("command -v pkexec >/dev/null 2>&1")
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    let (mut cmd, used) = if pkexec_available {
        let mut c = tokio::process::Command::new("pkexec");
        // Default polkit-agent selection — whichever agent registered
        // first with the session bus handles the prompt. Matches user
        // expectation across GNOME/KDE/XFCE distros.
        c.args(helper_args);
        (c, "pkexec")
    } else {
        // sudo -A: requires SUDO_ASKPASS to point at a graphical
        // askpass binary (`ssh-askpass`, `ksshaskpass`,
        // `lxqt-openssh-askpass`, etc.). If neither pkexec nor a wired
        // askpass exists the call will fail loudly and the UI surfaces
        // the error.
        let mut c = tokio::process::Command::new("sudo");
        c.arg("-A");
        c.args(helper_args);
        (c, "sudo -A")
    };

    let fut = cmd.output();
    let output = match tokio::time::timeout(watchdog_for(secs), fut).await {
        Ok(r) => r.map_err(|e| format!("spawn {used}: {e}"))?,
        Err(_) => {
            let _ = tokio::fs::remove_file(&out_path).await;
            return Err("Privileged helper did not return in time.".into());
        }
    };
    if !output.status.success() {
        let _ = tokio::fs::remove_file(&out_path).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code();
        // pkexec exit codes: 126 = not authorised, 127 = auth failed /
        // cancelled. sudo: 1 typically = auth failed.
        if matches!(code, Some(126) | Some(127))
            || stderr.contains("cancelled")
            || stderr.contains("canceled")
            || stderr.contains("Sorry, try again")
            || stderr.contains("Authentication failed")
        {
            return Err("Administrator authorisation was cancelled or denied.".into());
        }
        return Err(format!(
            "Privileged helper failed via {used} (status {:?}): {}",
            code,
            stderr.trim()
        ));
    }
    let json = tokio::fs::read_to_string(&out_path)
        .await
        .map_err(|e| format!("read probe output {out_path_str}: {e}"))?;
    let _ = tokio::fs::remove_file(&out_path).await;
    Ok(json)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub async fn elevate_and_run_probe(
    _exe: &str,
    _probe_kind: &str,
    _iface: &str,
    _secs: u32,
) -> Result<String, String> {
    Err("Privileged probes are not supported on this platform.".into())
}
