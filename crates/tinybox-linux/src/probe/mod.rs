//! Discoverability for the namespace backend's prerequisites.
//!
//! [`NamespaceSandbox`](crate::NamespaceSandbox) needs `bwrap` on `PATH` and
//! permission for an unprivileged process to create a user namespace. Either
//! can be missing without any hint at the point of use: Ubuntu 24.04 ships
//! `kernel.apparmor_restrict_unprivileged_userns=1`, which makes `bwrap` fail
//! with a bare "Operation not permitted". [`NamespaceProbe`] looks before the
//! first command runs and turns that into an actionable message, so a caller
//! can choose another backend or fail closed instead of guessing.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const BWRAP_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const BWRAP_PROBE_STDERR_LIMIT: usize = 4096;

/// Whether an unprivileged process may create a user namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernsStatus {
    /// No sysctl known to block user namespaces is set.
    Available,
    /// `user.max_user_namespaces` is zero, or Debian's
    /// `kernel.unprivileged_userns_clone` is zero.
    DisabledBySysctl,
    /// `kernel.apparmor_restrict_unprivileged_userns` is `1` (Ubuntu 24.04),
    /// so only binaries with an `AppArmor` profile granting `userns` may create
    /// one.
    RestrictedByAppArmor,
}

impl UsernsStatus {
    /// Derive the status from raw sysctl file contents (`None` when the file
    /// does not exist). Disabling wins over `AppArmor` restriction because it is
    /// the harder block.
    #[must_use]
    pub fn from_sysctls(
        max_user_namespaces: Option<&str>,
        unprivileged_userns_clone: Option<&str>,
        apparmor_restrict: Option<&str>,
    ) -> Self {
        if max_user_namespaces.is_some_and(|value| value.trim() == "0")
            || unprivileged_userns_clone.is_some_and(|value| value.trim() == "0")
        {
            Self::DisabledBySysctl
        } else if apparmor_restrict.is_some_and(|value| value.trim() == "1") {
            Self::RestrictedByAppArmor
        } else {
            Self::Available
        }
    }
}

/// What the namespace backend found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceProbe {
    /// Where `bwrap` was found, if anywhere.
    pub bwrap: Option<PathBuf>,
    /// Whether user namespaces can be created without privilege.
    pub userns: UsernsStatus,
    probe_error: Option<String>,
}

impl NamespaceProbe {
    /// Probe this machine: `PATH` for `bwrap`, and the user-namespace sysctls.
    #[must_use]
    pub fn detect() -> Self {
        static DETECTED: OnceLock<NamespaceProbe> = OnceLock::new();
        DETECTED.get_or_init(Self::detect_uncached).clone()
    }

    fn detect_uncached() -> Self {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let read = |name: &str| std::fs::read_to_string(Path::new("/proc/sys").join(name)).ok();
        let bwrap = find_on_path("bwrap", &path);
        let userns = UsernsStatus::from_sysctls(
            read("user/max_user_namespaces").as_deref(),
            read("kernel/unprivileged_userns_clone").as_deref(),
            read("kernel/apparmor_restrict_unprivileged_userns").as_deref(),
        );
        let probe_error = match (bwrap.as_deref(), userns) {
            (Some(program), UsernsStatus::Available | UsernsStatus::RestrictedByAppArmor) => {
                probe_bwrap_with_timeout(program, BWRAP_PROBE_TIMEOUT).err()
            }
            _ => None,
        };
        Self {
            bwrap,
            userns,
            probe_error,
        }
    }

    /// Whether the backend can be expected to start a box.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.problem().is_none()
    }

    /// The first thing wrong, phrased as what to do about it.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        if self.bwrap.is_none() {
            return Some(
                "bwrap is not on PATH; install bubblewrap (for example `apt install bubblewrap`)"
                    .to_owned(),
            );
        }
        if self.userns == UsernsStatus::DisabledBySysctl {
            return Some(
                "unprivileged user namespaces are disabled; set user.max_user_namespaces above 0 \
                 (and kernel.unprivileged_userns_clone=1 on Debian), or use another backend"
                    .to_owned(),
            );
        }
        self.probe_error.as_ref().map(|error| {
            let hint = if self.userns == UsernsStatus::RestrictedByAppArmor {
                "AppArmor may block unprivileged namespaces; install a bwrap profile that grants `userns` or use another backend"
            } else {
                "check user-namespace permissions or use another backend"
            };
            format!("bwrap user-namespace probe failed: {error}; {hint}")
        })
    }

    /// Convert the probe result into the runtime readiness reported by a sandbox.
    #[must_use]
    pub fn availability(&self) -> tinybox_core::SandboxAvailability {
        match self.problem() {
            Some(reason) => tinybox_core::SandboxAvailability::Unavailable { reason },
            None => tinybox_core::SandboxAvailability::Available,
        }
    }
}

/// Run the fixed, read-only user-namespace check and bound its lifetime.
fn probe_bwrap_with_timeout(program: &Path, timeout: Duration) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(["--unshare-user", "--ro-bind", "/", "/", "--", "/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start {}: {error}", program.display()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "could not capture bwrap probe diagnostics".to_owned())?;
    let reader = std::thread::spawn(move || read_bounded_diagnostic(stderr));
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let diagnostic = join_diagnostic(reader);
                if status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "exited with {status}{}",
                    diagnostic_suffix(&diagnostic)
                ));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let diagnostic = join_diagnostic(reader);
                return Err(format!(
                    "timed out after {timeout:?}{}",
                    diagnostic_suffix(&diagnostic)
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let diagnostic = join_diagnostic(reader);
                return Err(format!(
                    "could not wait for bwrap: {error}{}",
                    diagnostic_suffix(&diagnostic)
                ));
            }
        }
    }
}

fn read_bounded_diagnostic(mut stderr: impl Read) -> String {
    let mut diagnostic = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let remaining = BWRAP_PROBE_STDERR_LIMIT.saturating_sub(diagnostic.len());
                diagnostic.extend_from_slice(&buffer[..read.min(remaining)]);
            }
        }
    }
    String::from_utf8_lossy(&diagnostic).trim().to_owned()
}

fn join_diagnostic(reader: std::thread::JoinHandle<String>) -> String {
    reader
        .join()
        .unwrap_or_else(|_| "probe diagnostic reader failed".to_owned())
}

fn diagnostic_suffix(diagnostic: &str) -> String {
    if diagnostic.is_empty() {
        String::new()
    } else {
        format!(": {diagnostic}")
    }
}

/// The first executable regular file named `program` in the `PATH`-style list.
fn find_on_path(program: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
