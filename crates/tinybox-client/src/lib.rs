//! Typed host calls to the `TinyBox` `TinyBus` module.
//!
//! Hosts construct and configure a [`tinybus::module::ModuleClient`], then
//! create a [`TinyBoxClient`] from it. This crate owns `TinyBox` member names,
//! request/reply types, confidential-call selection, and the compatibility
//! probe. Hosts retain module loading, configuration, legacy migration,
//! reporting, and their default call deadline.
//!
//! # Example
//!
//! ```no_run
//! use tinybox_client::TinyBoxClient;
//! use tinybus::module::ModuleClient;
//!
//! # async fn example(module_client: ModuleClient) -> Result<(), tinybus::module::ModuleCallError> {
//! let tinybox = TinyBoxClient::new(module_client).await?;
//! let capabilities = tinybox.capabilities();
//! assert_eq!(capabilities.contract_version.0, 1);
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};
use tinybus::module::{ModuleCallError, ModuleClient};

pub use tinybox_bus as contract;

/// Stable `TinyBus` module identifier used by the `TinyBox` release registry.
pub const MODULE_ID: &str = "tinybox";

/// Additional transport time allowed after a bounded Docker operation.
pub const DOCKER_CALL_GRACE: Duration = Duration::from_secs(5);

/// Result returned by every typed `TinyBox` operation.
pub type Result<T> = std::result::Result<T, ModuleCallError>;

/// Typed operations on one configured `TinyBox` module client.
///
/// Construction reads the module's capabilities once and refuses an
/// incompatible wire contract before exposing the operations. The wrapped
/// `TinyBus` client is supplied by the host, so its configured default timeout
/// remains in force for every operation without an operation-specific bound.
#[derive(Clone)]
pub struct TinyBoxClient {
    client: ModuleClient,
    capabilities: contract::ModuleCapabilities,
}

impl fmt::Debug for TinyBoxClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TinyBoxClient")
            .field("module_id", &MODULE_ID)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl TinyBoxClient {
    /// Create a typed client and verify the module's wire contract once.
    ///
    /// The module must advertise the same contract major and a minor version
    /// at least as new as this client. The returned client caches those
    /// capabilities; later operations do not repeat the probe.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module is unavailable,
    /// its capabilities cannot be read, or its contract is incompatible.
    pub async fn new(client: ModuleClient) -> Result<Self> {
        let capabilities: contract::ModuleCapabilities = client
            .call(MODULE_ID, contract::names::CAPABILITIES, ())
            .await?;
        if !contract::is_compatible(capabilities.contract_version) {
            return Err(ModuleCallError::IncompatibleContract);
        }
        Ok(Self {
            client,
            capabilities,
        })
    }

    /// Return the capabilities captured during construction.
    #[must_use]
    pub fn capabilities(&self) -> &contract::ModuleCapabilities {
        &self.capabilities
    }

    /// Describe the loaded `TinyBox` module.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn describe(&self) -> Result<String> {
        self.call(contract::names::DESCRIBE, (), false).await
    }

    /// Read native jail facts; the host applies its own policy to them.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn jail_status(&self) -> Result<contract::JailStatus> {
        self.call(contract::names::JAIL_STATUS, (), false).await
    }

    /// Reserve an opaque identifier before native startup.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn reserve(&self, request: contract::ReserveRequest) -> Result<contract::ResourceId> {
        self.call(contract::names::RESERVE, (request,), false).await
    }

    /// Create a sandbox using its caller-known reservation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn create(&self, request: contract::CreateRequest) -> Result<contract::ResourceInfo> {
        self.call(contract::names::CREATE, (request,), true).await
    }

    /// Execute a collected command in a resource.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn exec(&self, request: contract::ExecRequest) -> Result<contract::ExecOutput> {
        self.call(contract::names::EXEC, (request,), true).await
    }

    /// Inspect a module-owned resource.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn inspect(&self, resource: contract::ResourceId) -> Result<contract::ResourceInfo> {
        self.call(contract::names::INSPECT, (resource,), false)
            .await
    }

    /// Close a resource and wait for the module's native cleanup acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn close(&self, resource: contract::ResourceId) -> Result<()> {
        self.call(contract::names::CLOSE, (resource,), false).await
    }

    /// Shut down module-owned resources.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn shutdown(&self) -> Result<()> {
        self.call(contract::names::SHUTDOWN, (), false).await
    }

    /// Start a detached process using a pre-reserved process identifier.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn spawn(&self, request: contract::SpawnRequest) -> Result<contract::ProcessRef> {
        self.call(contract::names::SPAWN, (request,), true).await
    }

    /// Start a supervised process with live output collection.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn start_exec(
        &self,
        request: contract::SpawnRequest,
    ) -> Result<contract::ProcessRef> {
        self.call(contract::names::START_EXEC, (request,), true)
            .await
    }

    /// Start a process in the explicitly requested native directory jail.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn start_jailed_exec(
        &self,
        request: contract::SpawnRequest,
        jail: contract::NativeJailConfig,
    ) -> Result<contract::ProcessRef> {
        self.call(contract::names::START_JAILED_EXEC, (request, jail), true)
            .await
    }

    /// Ask `TinyBox` which shell it would use for a command on its machine.
    ///
    /// The reply is discovery only; the host executes through
    /// [`Self::start_native_shell_exec`].
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn select_shell(
        &self,
        request: contract::SelectShellRequest,
    ) -> Result<contract::ShellInvocation> {
        self.call(contract::names::SELECT_SHELL, (request,), false)
            .await
    }

    /// Start a local shell under module-owned supervision and output replay.
    ///
    /// The caller must authorize the command before sending this confidential
    /// request.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn start_native_shell_exec(
        &self,
        request: contract::ShellExecRequest,
    ) -> Result<contract::ProcessRef> {
        self.call(contract::names::START_NATIVE_SHELL_EXEC, (request,), true)
            .await
    }

    /// Ask whether a Docker run weakens isolation without starting it.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn validate_docker_policy(
        &self,
        request: contract::DockerPolicyRequest,
    ) -> Result<contract::DockerPolicyReport> {
        self.call(contract::names::VALIDATE_DOCKER_POLICY, (request,), false)
            .await
    }

    /// Ask `TinyBox` to resolve the toolchain and configured local grants.
    ///
    /// The host's protected-path floor remains authoritative and must be
    /// applied to the returned candidate grants.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn resolve_local_grants(
        &self,
        request: contract::ResolveLocalGrantsRequest,
    ) -> Result<contract::LocalGrants> {
        self.call(contract::names::RESOLVE_LOCAL_GRANTS, (request,), false)
            .await
    }

    /// Run one bounded Docker-isolated command through `TinyBox`.
    ///
    /// The transport deadline is the requested operation timeout plus the
    /// Docker reply grace. The confidential request is never retried through
    /// ordinary delivery.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn run_docker(
        &self,
        request: contract::DockerRunRequest,
    ) -> Result<contract::DockerRunOutput> {
        let timeout = Duration::from_millis(request.timeout_ms).saturating_add(DOCKER_CALL_GRACE);
        self.call_with_timeout(timeout, contract::names::RUN_DOCKER, (request,), true)
            .await
    }

    /// Run a bounded Docker command without mounting a host workspace.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn run_docker_without_workspace(
        &self,
        request: contract::DockerRunRequest,
    ) -> Result<contract::DockerRunOutput> {
        let timeout = Duration::from_millis(request.timeout_ms).saturating_add(DOCKER_CALL_GRACE);
        self.call_with_timeout(
            timeout,
            contract::names::RUN_DOCKER_WITHOUT_WORKSPACE,
            (request,),
            true,
        )
        .await
    }

    /// Probe the Docker daemon owned by the `TinyBox` module host.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn docker_status(
        &self,
        request: contract::DockerStatusRequest,
    ) -> Result<contract::DockerStatus> {
        let timeout = docker_control_deadline(request.timeout_ms, DOCKER_CALL_GRACE);
        self.call_with_timeout(timeout, contract::names::DOCKER_STATUS, (request,), false)
            .await
    }

    /// Stop `TinyBox`-owned containers matching the supplied label.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn cleanup_docker(
        &self,
        request: contract::CleanupDockerRequest,
    ) -> Result<contract::CleanupDockerOutput> {
        let timeout = docker_control_deadline(request.timeout_ms, DOCKER_CALL_GRACE);
        self.call_with_timeout(timeout, contract::names::CLEANUP_DOCKER, (request,), false)
            .await
    }

    /// Read a bounded output batch from a live or completed process.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn read_output(
        &self,
        process: contract::ProcessRef,
        cursor: u64,
    ) -> Result<contract::OutputBatch> {
        self.call(contract::names::READ_OUTPUT, (process, cursor), false)
            .await
    }

    /// Release retained output and process ownership after terminal observation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn release_output(&self, process: contract::ProcessRef) -> Result<()> {
        self.call(contract::names::RELEASE_OUTPUT, (process,), false)
            .await
    }

    /// Check whether a detached process remains active.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn is_running(&self, process: contract::ProcessRef) -> Result<bool> {
        self.call(contract::names::IS_RUNNING, (process,), false)
            .await
    }

    /// Cancel a detached process and wait for acknowledged cleanup.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn cancel(&self, process: contract::ProcessRef) -> Result<()> {
        self.call(contract::names::CANCEL, (process,), false).await
    }

    /// Open a module-owned port forward.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn forward(
        &self,
        request: contract::ForwardRequest,
    ) -> Result<contract::ForwardInfo> {
        self.call(contract::names::FORWARD, (request,), false).await
    }

    /// Close a module-owned port forward.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn close_forward(&self, request: contract::CloseForwardRequest) -> Result<()> {
        self.call(contract::names::CLOSE_FORWARD, (request,), false)
            .await
    }

    /// Ask `TinyBox` for structural shell facts; this is not an authorization check.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn analyze_shell(&self, command: String) -> Result<contract::ShellAnalysis> {
        self.call(contract::names::ANALYZE_SHELL, (command,), false)
            .await
    }

    /// Ask `TinyBox` for generic command facts; the caller still decides policy.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn analyze_command(&self, command: String) -> Result<contract::CommandAnalysis> {
        self.call(contract::names::ANALYZE_COMMAND, (command,), false)
            .await
    }

    /// Open a bounded workspace file reader.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn begin_file_read(
        &self,
        request: contract::BeginFileReadRequest,
    ) -> Result<contract::FileReadInfo> {
        self.call(contract::names::BEGIN_FILE_READ, (request,), false)
            .await
    }

    /// Read one bounded range from an open file reader.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn read_file_chunk(
        &self,
        request: contract::ReadFileChunkRequest,
    ) -> Result<contract::FileChunk> {
        self.call(contract::names::READ_FILE_CHUNK, (request,), false)
            .await
    }

    /// Close a workspace file reader.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn finish_file_read(&self, request: contract::FinishFileReadRequest) -> Result<()> {
        self.call(contract::names::FINISH_FILE_READ, (request,), false)
            .await
    }

    /// Open an atomic staged workspace file writer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn begin_file_write(
        &self,
        request: contract::BeginFileWriteRequest,
    ) -> Result<contract::FileWriteInfo> {
        self.call(contract::names::BEGIN_FILE_WRITE, (request,), false)
            .await
    }

    /// Write one bounded sequential file chunk.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn write_file_chunk(
        &self,
        request: contract::WriteFileChunkRequest,
    ) -> Result<contract::FileWriteProgress> {
        self.call(contract::names::WRITE_FILE_CHUNK, (request,), true)
            .await
    }

    /// Atomically publish the staged workspace file.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn finish_file_write(
        &self,
        request: contract::FinishFileWriteRequest,
    ) -> Result<contract::FileWriteProgress> {
        self.call(contract::names::FINISH_FILE_WRITE, (request,), false)
            .await
    }

    /// Abort a staged workspace write without publishing it.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `TinyBus` call error when the module call fails.
    pub async fn abort_file_write(&self, request: contract::AbortFileWriteRequest) -> Result<()> {
        self.call(contract::names::ABORT_FILE_WRITE, (request,), false)
            .await
    }

    async fn call<Request, Reply>(
        &self,
        member: &'static str,
        request: Request,
        confidential: bool,
    ) -> Result<Reply>
    where
        Request: Serialize + Send,
        Reply: DeserializeOwned,
    {
        self.call_with(&self.client, member, request, confidential)
            .await
    }

    async fn call_with_timeout<Request, Reply>(
        &self,
        timeout: Duration,
        member: &'static str,
        request: Request,
        confidential: bool,
    ) -> Result<Reply>
    where
        Request: Serialize + Send,
        Reply: DeserializeOwned,
    {
        let client = self.client.clone().with_timeout(timeout);
        self.call_with(&client, member, request, confidential).await
    }

    async fn call_with<Request, Reply>(
        &self,
        client: &ModuleClient,
        member: &'static str,
        request: Request,
        confidential: bool,
    ) -> Result<Reply>
    where
        Request: Serialize + Send,
        Reply: DeserializeOwned,
    {
        if confidential {
            client.call_confidential(MODULE_ID, member, request).await
        } else {
            client.call(MODULE_ID, member, request).await
        }
    }
}

fn docker_control_deadline(timeout_ms: u64, grace: Duration) -> Duration {
    Duration::from_millis(timeout_ms.min(contract::MAX_DOCKER_CONTROL_TIMEOUT_MS))
        .saturating_add(grace)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
