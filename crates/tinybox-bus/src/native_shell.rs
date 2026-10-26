//! Runtime-neutral orchestration for one supervised native shell execution.

use std::{
    future::Future,
    time::{Duration, Instant},
};

use futures_util::{FutureExt, pin_mut, select};

use crate::{
    CreateRequest, ExecutionState, OutputBatch, OutputChunk, ProcessRef, ReserveRequest,
    ResourceId, ShellExecRequest,
};

/// Transport operations required to supervise a native shell.
///
/// Adapters implement these methods with their own bus connection and runtime.
pub trait NativeShellClient {
    /// Transport error returned by one bus operation.
    type Error;

    /// Reserve a resource or process identifier.
    async fn reserve(&self, request: ReserveRequest) -> Result<ResourceId, Self::Error>;
    /// Create the resource with the module-issued reservation.
    async fn create(&self, request: CreateRequest) -> Result<(), Self::Error>;
    /// Start the requested native shell and return its owned process reference.
    async fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> Result<ProcessRef, Self::Error>;
    /// Read output starting at the supplied sequence cursor.
    async fn read_output(
        &self,
        process: ProcessRef,
        cursor: u64,
    ) -> Result<OutputBatch, Self::Error>;
    /// Cancel and reap a running native process.
    async fn cancel(&self, process: ProcessRef) -> Result<(), Self::Error>;
    /// Release retained output after the process reaches a terminal state.
    async fn release_output(&self, process: ProcessRef) -> Result<(), Self::Error>;
    /// Close the resource after process cleanup.
    async fn close(&self, resource: ResourceId) -> Result<(), Self::Error>;
}

/// Inputs for resource creation and native shell execution.
///
/// The `resource` and process reservation fields in `create` and `shell` are
/// replaced by identifiers reserved during the run.
#[derive(Debug, Clone)]
pub struct NativeShellRunRequest {
    /// Resource configuration; its reservation identifier is ignored.
    pub create: CreateRequest,
    /// Shell settings; its resource and process identifiers are ignored.
    pub shell: ShellExecRequest,
}

/// Collected native shell output after the module acknowledges process cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeShellOutput {
    /// Process exit code, including nonzero exits.
    pub exit_code: i32,
    /// Complete stdout bytes.
    pub stdout: Vec<u8>,
    /// Complete stderr bytes.
    pub stderr: Vec<u8>,
    /// Whether the shell exceeded its request timeout.
    pub timed_out: bool,
}

/// Failure during one phase of native shell orchestration.
#[derive(Debug)]
pub enum NativeShellError<E> {
    /// A bus operation failed.
    Transport { operation: &'static str, source: E },
    /// The module reported a terminal failed state.
    Execution(crate::ExecutionFailure),
    /// Cancellation failed, so native cleanup is not acknowledged.
    Cancellation(E),
    /// Output release failed after the process had stopped.
    OutputRelease(E),
    /// Resource close failed after process cleanup.
    ResourceClose(E),
}

/// Run one native shell and stream every output chunk to `on_chunk`.
///
/// The caller must keep this future supervised while signaling `cancelled`;
/// dropping it cannot await native process cleanup. The helper reserves and
/// creates the resource, starts the process, polls replayable output, cancels
/// on timeout or caller cancellation, releases output, and closes the resource.
///
/// # Errors
/// Returns the transport failure, module execution failure, or cleanup failure.
pub async fn run_native_shell<C, F, Fut>(
    client: &C,
    request: NativeShellRunRequest,
    cancelled: Fut,
    mut on_chunk: F,
) -> Result<NativeShellOutput, NativeShellError<C::Error>>
where
    C: NativeShellClient,
    F: FnMut(&OutputChunk),
    Fut: Future<Output = ()>,
{
    let mut create = request.create;
    let mut shell = request.shell;
    let resource = client
        .reserve(ReserveRequest::Resource)
        .await
        .map_err(|source| NativeShellError::Transport {
            operation: "reserve resource",
            source,
        })?;
    create.resource = resource.clone();
    let result = async {
        client.create(create).await.map_err(|source| NativeShellError::Transport { operation: "create resource", source })?;
        let process_id = client.reserve(ReserveRequest::Process(resource.clone())).await.map_err(|source| NativeShellError::Transport { operation: "reserve process", source })?;
        shell.resource = resource.clone();
        shell.process = process_id;
        let process = client.start_native_shell_exec(shell).await.map_err(|source| NativeShellError::Transport { operation: "start native shell", source })?;
        let deadline = Instant::now() + Duration::from_millis(request.shell.timeout_ms.max(1));
        let mut cursor = 0;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let cancelled = cancelled.fuse();
        pin_mut!(cancelled);
        let mut cancellation_requested = false;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let poll = client.read_output(process.clone(), cursor).fuse();
            let delay = futures_timer::Delay::new(if cancellation_requested { Duration::from_millis(20) } else { remaining.min(Duration::from_millis(20)) }).fuse();
            pin_mut!(poll, delay);
            let batch = if cancellation_requested {
                select! { result = poll => result.map_err(|source| NativeShellError::Transport { operation: "read output", source })? }
            } else {
                select! {
                    result = poll => result.map_err(|source| NativeShellError::Transport { operation: "read output", source })?,
                    _ = cancelled => {
                        client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                        cancellation_requested = true;
                        continue;
                    },
                    _ = delay => {
                        client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                        cancellation_requested = true;
                        continue;
                    }
                }
            };
            for chunk in &batch.chunks {
                on_chunk(chunk);
                match chunk.stream {
                    crate::OutputStream::Stdout => stdout.extend_from_slice(&chunk.bytes),
                    crate::OutputStream::Stderr => stderr.extend_from_slice(&chunk.bytes),
                }
            }
            cursor = batch.next_sequence;
            match batch.state {
                ExecutionState::Running => continue,
                ExecutionState::Exited { exit_code } => {
                    client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                    return Ok(NativeShellOutput { exit_code, stdout, stderr, timed_out: cancellation_requested });
                }
                ExecutionState::Cancelled => {
                    client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                    return Ok(NativeShellOutput { exit_code: -1, stdout, stderr, timed_out: cancellation_requested });
                }
                ExecutionState::Failed { code } => return Err(NativeShellError::Execution(code)),
            }
        }
    }.await;
    let close_result = client.close(resource).await;
    match (result, close_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(source)) => Err(NativeShellError::ResourceClose(source)),
        (Err(error), Err(_)) => Err(error),
    }
}
