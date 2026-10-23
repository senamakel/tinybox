//! Directory jail (`cwd_jail)`: jail an agent/tool into a single workspace.
//!
//! ## Why this exists
//!
//! `tinybox-linux` isolates a whole box with namespaces; this crate is a
//! different, lighter mechanism: it confines a single spawned `Command` to one
//! directory tree using whatever the host OS offers, with no daemon and no
//! container runtime.
//!
//! This crate is the user-facing facade. Callers describe *what* the
//! jail looks like ([`Jail`]) and the module picks the right OS backend:
//!
//! | OS      | Backend       | Mechanism                                  |
//! |---------|---------------|--------------------------------------------|
//! | Linux   | bubblewrap    | `bwrap` namespaces; process isolation      |
//! | Linux   | landlock      | Fallback: kernel 5.13+ LSM, spawn thread   |
//! | macOS   | seatbelt      | `sandbox-exec -p '<profile>' …`            |
//! | Windows | `AppContainer` | `AppContainer` ACLs + a kill-on-close Job |
//! | other   | unsupported   | Spawning is rejected                       |
//!
//! The Windows `AppContainer` backend is available to `TinyBox`'s captured,
//! owned-process API. The legacy API returning `std::process::Child` remains
//! unsupported on Windows; use [`default_owned_backend`] for owned launches.
//!
//! ## Quick start
//!
//! ```ignore
//! use tinybox_jail::{spawn, Jail};
//! use std::process::Command;
//!
//! let mut jail = Jail::new("/Users/x/work/proj", "agent.delegate")
//!     .add_read_only("/usr/lib")
//!     .deny_subprocess();
//! jail.canonicalize_or_log();
//!
//! let mut cmd = Command::new("node");
//! cmd.arg("script.js");
//! let child = spawn(&jail, cmd)?;
//! ```
//!
//! ## What this does *not* do
//!
//! - It does not jail the current process. Backends spawn a child. The core
//!   itself is trusted; only the things it shells out to are caged.
//! - It does not decide *whether* a command may run. The host applies its own
//!   policy first; this crate decides *what filesystem* the command sees once
//!   approved.
//! - It does not encrypt files. ACLs / Landlock rules / Seatbelt profiles
//!   are the wall — anything inside `root` is fully visible to the child.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod detect;
pub mod grants;
pub mod invocation;
pub mod jail;
pub mod noop;
pub mod registry;

// Platform backends. Linux (Landlock) is compiled on Linux only. The Seatbelt
// module is plain `std` (it shells out to `sandbox-exec`), so it compiles
// everywhere and its profile renderer is unit-tested on every host; it is only
// *selected* on macOS. Windows launches use the safe `win-custody` API and
// TinyBox's owned process boundary because stable Rust cannot construct a
// `std::process::Child` from the native handle.
#[cfg(target_os = "linux")]
pub mod bwrap;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use bwrap::{BWRAP_BACKEND_NAME, BubblewrapBackend};
pub use invocation::{JailInvocation, ResourceLimitPlan};
pub use jail::nested_denial;
pub use jail::{ChildStatus, Jail, JailBackend, OwnedChild, OwnedProcess, reject_symlinked_grants};
#[cfg(target_os = "linux")]
pub use linux::LandlockBackend;
pub use macos::SeatbeltBackend;
pub use noop::{NOOP_BACKEND_NAME, NoopBackend};
pub use registry::{IndexStore, JailRecord, JailRegistry};
#[cfg(target_os = "windows")]
pub use windows::AppContainerBackend;

use std::process::{Child, Command};
use std::sync::{Arc, OnceLock};

/// Cached default backend for the current platform.
static DEFAULT_BACKEND: OnceLock<Arc<dyn JailBackend>> = OnceLock::new();
static DEFAULT_OWNED_BACKEND: OnceLock<Arc<dyn JailBackend>> = OnceLock::new();

/// Returns the process-wide default backend, lazily auto-detected.
pub fn default_backend() -> Arc<dyn JailBackend> {
    DEFAULT_BACKEND.get_or_init(detect::pick_backend).clone()
}

/// Returns the process-wide backend for captured launches with an owned
/// process handle.
///
/// On Unix this is the same backend as [`default_backend`]. On Windows it
/// selects `AppContainer`, whose native process handle is retained through
/// [`OwnedChild`] instead of being converted into an unavailable
/// `std::process::Child`.
pub fn default_owned_backend() -> Arc<dyn JailBackend> {
    DEFAULT_OWNED_BACKEND
        .get_or_init(detect::pick_owned_backend)
        .clone()
}

/// Spawn `cmd` inside the jail described by `jail`, using the default backend.
///
/// `jail.canonicalize()` is called once here so the backends never see
/// `..` or symlinks. If the root does not exist, the spawn fails with
/// `NotFound` (canonicalize bubbles it up) — callers should create the
/// workspace before encapsulating.
///
/// This legacy entry point does not require fully enforced constraints. Use
/// [`spawn_required`] for a hard preflight before spawning.
///
/// # Errors
///
/// Returns an error if the jail root cannot be canonicalized or the backend
/// rejects the command.
pub fn spawn(jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    let backend = default_backend();
    require_resources(backend.as_ref(), &jail)?;
    jail.validate_denials(backend.carves_denials(), &backend.implicit_grants())?;
    backend.spawn(&jail, cmd)
}

/// Same as [`spawn`] but with a caller-supplied backend. Useful in
/// tests and for callers that want to opt into a weaker backend
/// explicitly (e.g. forcing [`NoopBackend`] during local dev).
///
/// This legacy entry point does not run [`JailBackend::require`]. Use
/// [`spawn_required_with`] when partial or absent enforcement must be refused.
///
/// # Errors
///
/// Returns an error if the jail root cannot be canonicalized or the backend
/// rejects the command.
pub fn spawn_with(backend: &dyn JailBackend, jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    require_resources(backend, &jail)?;
    jail.validate_denials(backend.carves_denials(), &backend.implicit_grants())?;
    backend.spawn(&jail, cmd)
}

/// Spawn captured native work using an explicitly chosen provider.
/// The caller retains the returned child and owns its pipes and cleanup.
/// # Errors
/// Returns a canonicalization, confinement, or native startup error.
pub fn spawn_captured_with(
    backend: &dyn JailBackend,
    jail: &Jail,
    cmd: Command,
) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    require_resources(backend, &jail)?;
    jail.validate_denials(backend.carves_denials(), &backend.implicit_grants())?;
    backend.spawn_captured(&jail, cmd)
}

/// Spawn captured work through a backend-owned process abstraction.
///
/// The backend is responsible for retaining the process handle while callers
/// consume the returned standard pipes. This is the extensible path for
/// process owners that cannot be represented by `std::process::Child`.
/// # Errors
/// Returns canonicalization, confinement, or native startup errors.
pub fn spawn_owned_captured_with(
    backend: &dyn JailBackend,
    jail: &Jail,
    cmd: Command,
) -> std::io::Result<OwnedChild> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    require_resources(backend, &jail)?;
    jail.validate_denials(backend.carves_denials(), &backend.implicit_grants())?;
    backend.spawn_owned_captured(&jail, cmd)
}

/// Spawn a typed invocation through the selected jail backend.
///
/// The backend receives the original argv, cwd, approved environment, stdio,
/// and optional per-dimension resource plan alongside the flattened command.
/// This lets a platform owner configure a suspended child before it resumes;
/// the default adapter preserves existing backend behavior.
/// # Errors
/// Returns validation, capability, confinement, or native startup errors.
pub fn spawn_owned_invocation_captured_with(
    backend: &dyn JailBackend,
    jail: &Jail,
    invocation: &JailInvocation,
) -> std::io::Result<OwnedChild> {
    let command = invocation.command()?;
    spawn_owned_invocation_with_command(backend, jail, invocation, command)
}

/// Spawn a typed invocation with a command that has trusted host-side
/// adjustments applied after flattening.
///
/// The command must preserve the invocation's program, argv, cwd, environment,
/// and stdio. This entry point exists for supervisors that add private
/// telemetry or wrapper arguments after the typed request is captured.
/// # Errors
/// Returns validation, capability, confinement, or native startup errors.
pub fn spawn_owned_invocation_with_command(
    backend: &dyn JailBackend,
    jail: &Jail,
    invocation: &JailInvocation,
    command: Command,
) -> std::io::Result<OwnedChild> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    require_resources(backend, &jail)?;
    require_resource_plan(backend, invocation.resources)?;
    jail.validate_denials(backend.carves_denials(), &backend.implicit_grants())?;
    backend.spawn_owned_invocation_captured(&jail, invocation, command)
}

fn require_resource_plan(
    backend: &dyn JailBackend,
    plan: Option<ResourceLimitPlan>,
) -> std::io::Result<()> {
    let Some(plan) = plan else {
        return Ok(());
    };
    if plan.is_empty() || plan.has_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid resource limit plan",
        ));
    }
    let mut requested = Vec::new();
    if plan.cpu_millis.is_some() {
        requested.push(tinybox_core::Constraint::Cpu);
    }
    if plan.memory_bytes.is_some() {
        requested.push(tinybox_core::Constraint::Memory);
    }
    if plan.pids_max.is_some() {
        requested.push(tinybox_core::Constraint::Pids);
    }
    if plan.disk_bytes.is_some() {
        requested.push(tinybox_core::Constraint::Disk);
    }
    backend
        .constraint_support()
        .require(backend.name(), &requested)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Unsupported, error))
}
fn require_resources(backend: &dyn JailBackend, jail: &Jail) -> std::io::Result<()> {
    backend.require_resources(jail).map_err(|error| {
        let kind = match error {
            tinybox_core::Error::ZeroResourceLimit { .. } => std::io::ErrorKind::InvalidInput,
            _ => std::io::ErrorKind::Unsupported,
        };
        std::io::Error::new(kind, error)
    })
}

/// Spawn only after all jail constraints pass a hard preflight.
///
/// This strict entry point rejects the explicitly trusted no-op backend and
/// any backend that cannot enforce a requested constraint (Seatbelt's partial
/// filesystem policy, Landlock's missing network and subprocess denial).
/// Whether a backend isolates *processes* well enough for untrusted code is a
/// separate question: ask [`JailBackend::is_suitable_for_untrusted_jail`].
/// Availability and actual policy application are also checked by the backend
/// when spawning.
///
/// # Errors
/// Returns `Unsupported` before spawning for partial or unsupported constraints,
/// or a filesystem/backend error while canonicalizing or applying the policy.
pub fn spawn_required_with(
    backend: &dyn JailBackend,
    jail: &Jail,
    cmd: Command,
) -> std::io::Result<Child> {
    backend
        .require(jail)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Unsupported, error))?;
    spawn_with(backend, jail, cmd)
}

/// Spawn using the detected backend after a hard preflight.
///
/// # Errors
/// Returns the same preflight and setup errors as [`spawn_required_with`].
pub fn spawn_required(jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    spawn_required_with(default_backend().as_ref(), jail, cmd)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
