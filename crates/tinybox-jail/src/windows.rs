//! Windows directory jail using the safe `win-custody` AppContainer launcher.
//!
//! This backend returns TinyBox's owned-process abstraction because stable
//! `std::process::Child` cannot be constructed from a Win32 process handle.
//! Every child is assigned to a kill-on-close Job Object while suspended,
//! before its first instruction runs. CPU quota enforcement is deliberately
//! unsupported; Windows Job Objects do not provide the CPU quota contract used
//! by TinyBox's resource plan.

#![cfg(target_os = "windows")]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use tinybox_core::{Constraint, ConstraintSupport, Enforcement, IsolationLevel};
use win_custody::{
    AppContainerAccess, AppContainerProfile, Job, JobLimits, Launch, Process, anonymous_pipe,
};

use super::invocation::{JailInvocation, ResourceLimitPlan};
use super::jail::{ChildStatus, Jail, JailBackend, OwnedChild, OwnedProcess};

/// Windows AppContainer backend.
#[derive(Debug, Default)]
pub struct AppContainerBackend;

impl AppContainerBackend {
    /// Construct the AppContainer backend.
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

    fn spawn_owned_captured(&self, _jail: &Jail, _cmd: Command) -> io::Result<OwnedChild> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows AppContainer requires a typed invocation to preserve its environment",
        ))
    }

    fn spawn_owned_invocation_captured(
        &self,
        jail: &Jail,
        invocation: &JailInvocation,
        _command: Command,
    ) -> io::Result<OwnedChild> {
        self.require_resources(jail).map_err(unsupported)?;
        require_plan(self, invocation.resources)?;
        spawn_invocation(jail, invocation)
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

fn spawn_invocation(jail: &Jail, invocation: &JailInvocation) -> io::Result<OwnedChild> {
    let request = &invocation.request;
    let program = request
        .program()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invocation has no program"))?;
    let args = request.argv.iter().skip(1).map(OsStr::new);
    let cwd = request.cwd.as_deref().unwrap_or(&jail.root);
    spawn_captured(
        jail,
        Path::new(program),
        args,
        request
            .env
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        invocation.clear_env,
        cwd,
        invocation.resources,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_captured<'a>(
    jail: &Jail,
    program: &Path,
    args: impl IntoIterator<Item = &'a OsStr>,
    env: impl IntoIterator<Item = (&'a str, &'a str)>,
    clear_env: bool,
    cwd: &Path,
    resources: Option<ResourceLimitPlan>,
) -> io::Result<OwnedChild> {
    let profile_name = sanitize_profile_name(&jail.label);
    let profile = AppContainerProfile::create_or_open_with_capabilities(
        &profile_name,
        &format!("TinyBox {profile_name}"),
        "TinyBox confined process",
        if jail.allow_net {
            &["internetClient"]
        } else {
            &[]
        },
    )?;
    for path in std::iter::once((&jail.root, AppContainerAccess::ReadWrite))
        .chain(
            jail.read_write
                .iter()
                .map(|path| (path, AppContainerAccess::ReadWrite)),
        )
        .chain(
            jail.read_only
                .iter()
                .map(|path| (path, AppContainerAccess::Read)),
        )
    {
        profile.grant_path(path.0, path.1)?;
    }

    let job = Job::create(&job_limits(jail, resources)?)?;
    let (stdin_read, stdin_write) = anonymous_pipe()?;
    let (stdout_read, stdout_write) = anonymous_pipe()?;
    let (stderr_read, stderr_write) = anonymous_pipe()?;
    let mut launch = Launch::new(resolve_program(program, cwd)?);
    launch
        .args(args)
        .current_dir(cwd)
        .app_container(&profile)
        .stdin(&stdin_read)
        .stdout(&stdout_write)
        .stderr(&stderr_write);
    if clear_env {
        launch.env_clear();
    }
    for (name, value) in env {
        launch.env(name, value);
    }
    let process = launch.spawn_in_job(&job)?;
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);

    Ok(OwnedChild::new(
        AppContainerProcess { process, _job: job },
        Some(File::from(stdin_write)),
        Some(File::from(stdout_read)),
        Some(File::from(stderr_read)),
    ))
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

fn sanitize_profile_name(label: &str) -> String {
    let clean: String = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '.' {
                character
            } else {
                '_'
            }
        })
        .take(50)
        .collect();
    format!("tinybox.{clean}")
}

struct AppContainerProcess {
    process: Process,
    _job: Job,
}

impl OwnedProcess for AppContainerProcess {
    fn id(&self) -> Option<u32> {
        self.process.pid().ok()
    }

    fn try_wait(&mut self) -> io::Result<Option<ChildStatus>> {
        self.process
            .exit_code()
            .map(|code| code.map(|code| ChildStatus::from_code(Some(code as i32))))
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.process.exit_code()?.is_some() {
            return Ok(());
        }
        self._job.terminate(1).or_else(|error| {
            if self.process.exit_code()?.is_some() {
                Ok(())
            } else {
                Err(error)
            }
        })
    }
}

#[allow(dead_code)]
fn _owned_handle_to_file(handle: OwnedHandle) -> File {
    File::from(handle)
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
