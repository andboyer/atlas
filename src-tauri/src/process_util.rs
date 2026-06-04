//! Cross-platform helpers for spawning child processes without flashing a
//! console window on Windows.
//!
//! Tauri GUI binaries run under the Windows subsystem and have no console
//! attached, so each spawned console child (cmd.exe, powershell.exe, netsh,
//! arp, ping, ...) allocates its own. The `CREATE_NO_WINDOW` (0x08000000)
//! creation flag suppresses that allocation. On non-Windows targets the
//! method is a no-op so call sites stay portable.

#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Adds `.no_console()` to both `tokio::process::Command` and
/// `std::process::Command`. On non-Windows targets the method does nothing.
pub trait NoConsoleExt {
    fn no_console(&mut self) -> &mut Self;
}

impl NoConsoleExt for tokio::process::Command {
    fn no_console(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            #[allow(unused_imports)]
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

impl NoConsoleExt for std::process::Command {
    fn no_console(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            #[allow(unused_imports)]
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}
