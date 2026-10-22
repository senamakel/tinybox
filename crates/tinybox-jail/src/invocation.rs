//! Typed process invocation passed to native jail backends before command flattening.

use std::{io, process::Command};
use tinybox_core::ExecRequest;

/// Independently optional resource dimensions for a native process launch.
///
/// This is a transport shape only. A backend must report or reject each
/// requested dimension according to its actual enforcement capability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimitPlan {
    /// Requested CPU allowance in thousandths of a core.
    pub cpu_millis: Option<u64>,
    /// Requested maximum resident memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Requested maximum number of processes and threads.
    pub pids_max: Option<u64>,
    /// Requested maximum writable filesystem size in bytes.
    pub disk_bytes: Option<u64>,
}

impl ResourceLimitPlan {
    /// Whether at least one resource dimension is requested.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.cpu_millis.is_none()
            && self.memory_bytes.is_none()
            && self.pids_max.is_none()
            && self.disk_bytes.is_none()
    }

    /// Whether any requested resource limit is zero.
    #[must_use]
    pub const fn has_zero(self) -> bool {
        matches!(self.cpu_millis, Some(0))
            || matches!(self.memory_bytes, Some(0))
            || matches!(self.pids_max, Some(0))
            || matches!(self.disk_bytes, Some(0))
    }
}

/// An approved command and its launch-time environment and resource request.
///
/// Keeping this typed value available to the backend allows platform process
/// owners to create a suspended child and apply limits before it can run. The
/// default adapter still turns it into a standard command and uses the
/// existing owned-child path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JailInvocation {
    /// The approved argv, working directory, environment values, and stdin.
    pub request: ExecRequest,
    /// Whether the parent environment must be cleared before approved values
    /// in `request.env` are installed.
    pub clear_env: bool,
    /// Independently optional resource dimensions for this launch.
    pub resources: Option<ResourceLimitPlan>,
}

impl JailInvocation {
    /// Build a typed invocation from the approved command and launch settings.
    #[must_use]
    pub const fn new(
        request: ExecRequest,
        clear_env: bool,
        resources: Option<ResourceLimitPlan>,
    ) -> Self {
        Self {
            request,
            clear_env,
            resources,
        }
    }

    /// Flatten the typed invocation into a captured standard command.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an empty argv or an invalid zero/empty
    /// resource plan.
    pub fn command(&self) -> io::Result<Command> {
        let Some(program) = self.request.program() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invocation has no program",
            ));
        };
        if self
            .resources
            .is_some_and(|plan| plan.has_zero() || plan.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invocation has an invalid resource plan",
            ));
        }

        let mut command = Command::new(program);
        command.args(&self.request.argv[1..]);
        if self.clear_env {
            command.env_clear();
        }
        command.envs(&self.request.env);
        if let Some(cwd) = &self.request.cwd {
            command.current_dir(cwd);
        }
        command
            .stdin(if self.request.stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        Ok(command)
    }
}

#[cfg(test)]
#[path = "invocation_tests.rs"]
mod tests;
