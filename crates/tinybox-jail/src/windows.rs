//! Windows directory jail using the safe `win-custody` `AppContainer` launcher.
//!
//! This backend returns `TinyBox`'s owned-process abstraction because stable
//! `std::process::Child` cannot be constructed from a Win32 process handle.
//! Every child is assigned to a kill-on-close Job Object while suspended,
//! before its first instruction runs. CPU quota enforcement is deliberately
//! unsupported; Windows Job Objects do not provide the CPU quota contract used
//! by `TinyBox`'s resource plan.

#![cfg(target_os = "windows")]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tinybox_core::{Constraint, ConstraintSupport, Enforcement, IsolationLevel};
use win_custody::{
    AppContainerAccess, AppContainerProfile, Job, JobLimits, Launch, Process, anonymous_pipe,
};

use super::invocation::{JailInvocation, ResourceLimitPlan};
use super::jail::{ChildStatus, Jail, JailBackend, OwnedChild, OwnedProcess};

static PROFILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Windows `AppContainer` backend.
#[derive(Debug, Default)]
pub struct AppContainerBackend;

impl AppContainerBackend {
    /// Construct the `AppContainer` backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl JailBackend for AppContainerBackend {
    fn name(&self) -> &'static str {
        "appcontainer"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn constraint_support(&self) -> ConstraintSupport {
        ConstraintSupport::NONE
            .with(Constraint::Filesystem, Enforcement::Enforced)
            .with(Constraint::Network, Enforcement::Enforced)
            .with(Constraint::Subprocess, Enforcement::Enforced)
            .with(Constraint::Memory, Enforcement::Enforced)
            .with(Constraint::Pids, Enforcement::Enforced)
            .with(Constraint::Cpu, Enforcement::Unsupported)
            .with(Constraint::Disk, Enforcement::Unsupported)
    }

    fn isolation(&self) -> IsolationLevel {
        IsolationLevel::Kernel
    }

    fn carves_denials(&self) -> bool {
        false
    }

    fn spawn(&self, _jail: &Jail, _cmd: Command) -> io::Result<Child> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AppContainer returns an owned process; use the captured owned-process API",
        ))
    }

    fn spawn_owned_captured(&self, jail: &Jail, command: Command) -> io::Result<OwnedChild> {
        self.require_resources(jail).map_err(unsupported)?;
        spawn_command(jail, &command)
    }

    fn spawn_owned_invocation_captured(
        &self,
        jail: &Jail,
        invocation: &JailInvocation,
        command: Command,
    ) -> io::Result<OwnedChild> {
        self.require_resources(jail).map_err(unsupported)?;
        require_plan(self, invocation.resources)?;
        spawn_invocation(jail, invocation, &command)
    }
}

fn unsupported(error: tinybox_core::Error) -> io::Error {
    let kind = if matches!(error, tinybox_core::Error::ZeroResourceLimit { .. }) {
        io::ErrorKind::InvalidInput
    } else {
        io::ErrorKind::Unsupported
    };
    io::Error::new(kind, error)
}

fn require_plan(backend: &AppContainerBackend, plan: Option<ResourceLimitPlan>) -> io::Result<()> {
    let Some(plan) = plan else {
        return Ok(());
    };
    if plan.is_empty() || plan.has_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid resource limit plan",
        ));
    }
    let mut requested = Vec::new();
    if plan.cpu_millis.is_some() {
        requested.push(Constraint::Cpu);
    }
    if plan.memory_bytes.is_some() {
        requested.push(Constraint::Memory);
    }
    if plan.pids_max.is_some() {
        requested.push(Constraint::Pids);
    }
    if plan.disk_bytes.is_some() {
        requested.push(Constraint::Disk);
    }
    backend
        .constraint_support()
        .require(backend.name(), &requested)
        .map_err(unsupported)
}

fn spawn_invocation(
    jail: &Jail,
    invocation: &JailInvocation,
    command: &Command,
) -> io::Result<OwnedChild> {
    spawn_command_with_environment(
        jail,
        command,
        invocation.clear_env,
        invocation.resources,
        invocation.request.cwd.as_deref(),
    )
}

fn spawn_command(jail: &Jail, command: &Command) -> io::Result<OwnedChild> {
    // `Command` does not expose whether env_clear() was called, so the safe
    // untyped API always starts from an empty environment and forwards only
    // explicit env edits (plus the required SystemRoot platform variable).
    // Callers that need inherited values must pass them deliberately or use
    // the typed invocation API.
    spawn_command_with_environment(jail, command, true, None, None)
}

fn spawn_command_with_environment(
    jail: &Jail,
    command: &Command,
    clear_env: bool,
    resources: Option<ResourceLimitPlan>,
    requested_cwd: Option<&Path>,
) -> io::Result<OwnedChild> {
    let program = command.get_program();
    let args = command
        .get_args()
        .map(OsStr::to_os_string)
        .collect::<Vec<_>>();
    let environment = command
        .get_envs()
        .map(|(name, value)| (name.to_os_string(), value.map(OsStr::to_os_string)))
        .collect::<Vec<_>>();
    let cwd = command
        .get_current_dir()
        .or(requested_cwd)
        .unwrap_or(&jail.root);
    spawn_captured(
        jail,
        Path::new(program),
        args.iter().map(OsString::as_os_str),
        environment
            .iter()
            .map(|(name, value)| (name.as_os_str(), value.as_deref())),
        clear_env,
        cwd,
        resources,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_captured<'a>(
    jail: &Jail,
    program: &Path,
    args: impl IntoIterator<Item = &'a OsStr>,
    env: impl IntoIterator<Item = (&'a OsStr, Option<&'a OsStr>)>,
    clear_env: bool,
    cwd: &Path,
    resources: Option<ResourceLimitPlan>,
) -> io::Result<OwnedChild> {
    let profile_name = unique_profile_name();
    let profile = AppContainerProfile::create_or_open_with_capabilities(
        &profile_name,
        &format!("TinyBox {profile_name}"),
        "TinyBox confined process",
        if jail.allow_net {
            &["internetClient"]
        } else {
            &[]
        },
    )
    .map_err(|error| contextual_error("create AppContainer profile", &error))?;
    let writable = std::iter::once(&jail.root)
        .chain(jail.read_write.iter())
        .collect::<Vec<_>>();
    for path in &writable {
        profile
            .grant_path(path, AppContainerAccess::ReadWrite)
            .map_err(|error| contextual_error("grant AppContainer read/write path", &error))?;
    }
    for path in jail.read_only.iter().filter(|path| {
        !writable
            .iter()
            .any(|writable| writable.as_path() == path.as_path())
    }) {
        profile
            .grant_path(path, AppContainerAccess::Read)
            .map_err(|error| contextual_error("grant AppContainer read-only path", &error))?;
    }

    let job = Job::create(&job_limits(jail, resources)?)
        .map_err(|error| contextual_error("create AppContainer Job Object", &error))?;
    let (stdin_read, stdin_write) = anonymous_pipe()
        .map_err(|error| contextual_error("create AppContainer stdin pipe", &error))?;
    let (stdout_read, stdout_write) = anonymous_pipe()
        .map_err(|error| contextual_error("create AppContainer stdout pipe", &error))?;
    let (stderr_read, stderr_write) = anonymous_pipe()
        .map_err(|error| contextual_error("create AppContainer stderr pipe", &error))?;
    let mut launch = Launch::new(resolve_program(program, cwd)?);
    launch
        .args(args)
        .current_dir(cwd)
        .app_container(&profile)
        .stdin(&stdin_read)
        .stdout(&stdout_write)
        .stderr(&stderr_write);
    let (drive, environment_cwd) = drive_current_directory(cwd)?;
    launch
        .env_drive_current_dir(drive, environment_cwd)
        .map_err(|error| contextual_error("set AppContainer drive current directory", &error))?;
    if clear_env {
        launch.env_clear();
        // CreateProcess requires SystemRoot even when the caller clears the
        // inherited environment. Keep that OS location as the minimal
        // platform baseline; every other variable remains explicit-only.
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            launch.env("SystemRoot", system_root);
        }
    }
    for (name, value) in env {
        if let Some(value) = value {
            launch.env(name, value);
        } else {
            launch.env_remove(name);
        }
    }
    let suspended = launch
        .spawn_suspended()
        .map_err(|error| contextual_error("create suspended AppContainer child", &error))?;
    job.assign(suspended.process())
        .map_err(|error| contextual_error("assign AppContainer child to Job Object", &error))?;
    let process = suspended
        .resume()
        .map_err(|error| contextual_error("resume AppContainer child", &error))?;
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);

    Ok(OwnedChild::new(
        AppContainerProcess { process, job },
        Some(File::from(stdin_write)),
        Some(File::from(stdout_read)),
        Some(File::from(stderr_read)),
    ))
}

fn contextual_error(context: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

fn drive_current_directory(path: &Path) -> io::Result<(char, OsString)> {
    let (drive, environment_path) = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) => (drive, path.as_os_str().to_os_string()),
            Prefix::VerbatimDisk(drive) => {
                // Per-drive current-directory environment entries use normal
                // DOS paths. Passing Rust's canonical `\\?\C:\...` form as
                // the `=C:` value makes CreateProcess reject the environment
                // block with ERROR_ENVVAR_NOT_FOUND, even though it accepts
                // that same path as lpCurrentDirectory.
                let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
                let verbatim_prefix = [
                    u16::from(b'\\'),
                    u16::from(b'\\'),
                    u16::from(b'?'),
                    u16::from(b'\\'),
                ];
                if !wide.starts_with(&verbatim_prefix) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "AppContainer verbatim working directory has an invalid prefix",
                    ));
                }
                (drive, OsString::from_wide(&wide[verbatim_prefix.len()..]))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "AppContainer working directory must be on a drive-letter volume",
                ));
            }
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AppContainer working directory must be on a drive-letter volume",
            ));
        }
    };
    Ok((char::from(drive), environment_path))
}

fn job_limits(jail: &Jail, plan: Option<ResourceLimitPlan>) -> io::Result<JobLimits> {
    let mut limits = JobLimits::new().kill_on_close(true);
    let (memory, pids) = if let Some(resources) = plan {
        (
            resources.memory_bytes,
            resources
                .pids_max
                .map(u32::try_from)
                .transpose()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "process limit exceeds Windows range",
                    )
                })?,
        )
    } else if let Some(resources) = jail.resources {
        (Some(resources.memory_bytes), Some(resources.pids_max))
    } else {
        (None, None)
    };
    if let Some(memory) = memory {
        limits = limits.job_memory(usize::try_from(memory).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory limit exceeds Windows range",
            )
        })?);
    }
    let active_processes = pids.map(|limit| {
        if jail.allow_subprocess {
            limit
        } else {
            limit.min(1)
        }
    });
    let active_processes = if jail.allow_subprocess {
        active_processes
    } else {
        Some(active_processes.unwrap_or(1))
    };
    if let Some(active_processes) = active_processes {
        limits = limits.active_processes(active_processes);
    }
    Ok(limits)
}

fn resolve_program(program: &Path, cwd: &Path) -> io::Result<PathBuf> {
    if program.is_absolute() || program.components().count() > 1 {
        return Ok(program.to_path_buf());
    }
    let extensions = std::env::var_os("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .to_string_lossy()
        .split(';')
        .map(OsString::from)
        .collect::<Vec<_>>();
    let has_extension = program.extension().is_some();
    let candidates = if has_extension {
        vec![program.to_path_buf()]
    } else {
        extensions
            .iter()
            .map(|extension| program.with_extension(extension))
            .collect()
    };
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::iter::once(cwd.to_path_buf()).chain(std::env::split_paths(&search_path)) {
        for candidate in &candidates {
            let full = directory.join(candidate);
            if full.is_file() {
                return full.canonicalize();
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("could not resolve Windows executable {}", program.display()),
    ))
}

fn unique_profile_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("tinybox.{}.{timestamp:x}.{sequence:x}", std::process::id())
}

struct AppContainerProcess {
    process: Process,
    job: Job,
}

impl OwnedProcess for AppContainerProcess {
    fn id(&self) -> Option<u32> {
        self.process.pid().ok()
    }

    fn try_wait(&mut self) -> io::Result<Option<ChildStatus>> {
        self.process
            .exit_code()
            .map(|code| code.map(|code| ChildStatus::from_code(Some(code.cast_signed()))))
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.process.exit_code()?.is_some() {
            return Ok(());
        }
        self.job.terminate(1).or_else(|error| {
            if self.process.exit_code()?.is_some() {
                Ok(())
            } else {
                Err(error)
            }
        })
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
