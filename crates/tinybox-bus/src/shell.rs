//! Legacy command-analysis vocabulary retained for contract 1.x compatibility.
//!
//! Since contract 1.22, hosts must not use these values to make execution-policy,
//! authorization, allowlist, approval, or protected-path decisions. `TinySecurity`
//! owns command policy. Contract 2.0 removes this vocabulary; generic shell
//! transport and structural scanning remain separate capabilities.

use serde::{Deserialize, Serialize};

/// Legacy command categories retained for contract 1.x wire compatibility.
///
/// Deprecated since contract 1.22: this category is not an authorization or
/// permission result and must not drive host policy. `TinySecurity` owns command
/// policy. Contract 2.0 removes this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    /// Legacy scanner label; not proof that a command is safe to run.
    Read,
    /// Legacy scanner label; not a policy decision.
    Write,
    /// Legacy scanner label; not a policy decision.
    Network,
    /// Legacy scanner label; not a policy decision.
    Install,
    /// Legacy scanner label; not a policy decision.
    Destructive,
}

/// Legacy analysis fields for one live shell segment, retained for contract 1.x.
///
/// Deprecated since contract 1.22. These fields are scanner output, not inputs
/// for host authorization or execution policy; `TinySecurity` owns command policy.
/// Contract 2.0 removes this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSegment {
    /// Segment with quoted heredoc data removed.
    pub source: String,
    /// Segment after leading environment assignments are removed.
    pub command: String,
    /// Base command preserving the scanner's original case handling.
    pub basename: String,
    /// Legacy normalized command name; do not use it to decide host policy.
    pub normalized_name: String,
    /// Arguments in the legacy classifier's lower-case vocabulary.
    pub arguments: Vec<String>,
    /// Legacy scanner category; not an authorization or permission result.
    pub class: CommandClass,
    /// Legacy syntax fact; not a host policy decision.
    pub leading_env_assignment: bool,
    /// Legacy environment-guard fact; not an authorization decision.
    pub dangerous_env_prefix: bool,
    /// Legacy executor fact; not an authorization decision.
    pub executor: bool,
}

/// Legacy command-analysis output retained for contract 1.x compatibility.
///
/// Deprecated since contract 1.22. Hosts must not use this output for
/// allowlists, approvals, protected-path checks, authorization, or other
/// execution policy. `TinySecurity` owns command policy. Contract 2.0 removes
/// this type; generic shell scanning remains available independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// These independent syntax facts may coexist; they are not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct CommandAnalysis {
    /// Parsed live segments in their original order.
    pub segments: Vec<CommandSegment>,
    /// Legacy hidden-execution policy signal; not an authorization decision.
    pub hidden_execution: bool,
    /// Legacy scanner syntax fact; not a host policy decision.
    pub redirection: bool,
    /// Legacy scanner syntax fact; not a host policy decision.
    pub expansion: bool,
    /// Legacy scanner syntax fact; not a host policy decision.
    pub tee: bool,
    /// Legacy scanner syntax fact; not a host policy decision.
    pub background: bool,
    /// Legacy literal tokens outside quoted heredoc data; do not authorize paths from these.
    pub literal_words: Vec<String>,
}
