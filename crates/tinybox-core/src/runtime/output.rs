//! Output streams and provider-proven resource termination causes.

pub use tinybox_bus::OutputStream;

/// A resource-limit termination proven by provider-owned runtime evidence.
///
/// Backends must not infer these causes from a signal or exit code alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminationCause {
    /// The Linux cgroup v2 CPU controller throttled work under its quota.
    CpuQuota,
}

