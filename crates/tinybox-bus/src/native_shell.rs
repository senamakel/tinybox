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
pub trait NativeShellClient: Sync {
    /// Transport error returned by one bus operation.
    type Error;

    /// Reserve a resource or process identifier.
    fn reserve(
        &self,
        request: ReserveRequest,
    ) -> impl Future<Output = Result<ResourceId, Self::Error>> + Send;
    /// Create the resource with the module-issued reservation.
    fn create(
        &self,
        request: CreateRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Start the requested native shell and return its owned process reference.
    fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> impl Future<Output = Result<ProcessRef, Self::Error>> + Send;
    /// Read output starting at the supplied sequence cursor.
    fn read_output(
        &self,
        process: ProcessRef,
        cursor: u64,
    ) -> impl Future<Output = Result<OutputBatch, Self::Error>> + Send;
    /// Cancel and reap a running native process.
    fn cancel(&self, process: ProcessRef) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Release retained output after the process reaches a terminal state.
    fn release_output(
        &self,
        process: ProcessRef,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Close the resource after process cleanup.
    fn close(&self, resource: ResourceId) -> impl Future<Output = Result<(), Self::Error>> + Send;
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
    /// Return a running process after this duration, preserving cursor and output.
    pub yield_after: Option<Duration>,
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

/// Outcome of running a shell through TinyBox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeShellRunOutcome {
    /// The process exited or timed out and its output was released.
    Finished(NativeShellOutput),
    /// The process is still running; the caller now owns its cleanup lifecycle.
    Running(NativeShellRunning),
}

/// A running process handed back at the configured yield point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeShellRunning {
    /// Resource that must be closed after the process is finished.
    pub resource: ResourceId,
    /// Owned process reference for polling, cancellation, or release.
    pub process: ProcessRef,
    /// Cursor for the next output read.
    pub cursor: u64,
    /// Stdout collected before yielding.
    pub stdout: Vec<u8>,
    /// Stderr collected before yielding.
    pub stderr: Vec<u8>,
}

/// Failure during one phase of native shell orchestration.
#[derive(Debug)]
pub enum NativeShellError<E> {
    /// A bus operation failed.
    Transport {
        /// Human-readable operation that failed.
        operation: &'static str,
        /// Underlying adapter error.
        source: E,
    },
    /// The module reported a terminal failed state.
    Execution(crate::ExecutionFailure),
    /// An output batch did not advance its cursor despite containing chunks.
    InvalidOutputCursor,
    /// Cancellation failed, so native cleanup is not acknowledged.
    Cancellation(E),
    /// Output release failed after the process had stopped.
    OutputRelease(E),
    /// Resource close failed after process cleanup.
    ResourceClose(E),
    /// Cleanup failed while another operation was already failing.
    Cleanup {
        /// Cleanup operation that failed.
        operation: &'static str,
        /// Cleanup adapter error.
        source: E,
        /// Earlier failure that led to cleanup.
        during: Box<Self>,
    },
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
#[allow(clippy::too_many_lines)] // This function keeps the owned process lifecycle in one auditable scope.
pub async fn run_native_shell<C, F, Fut>(
    client: &C,
    request: NativeShellRunRequest,
    cancelled: Fut,
    mut on_chunk: F,
) -> Result<NativeShellRunOutcome, NativeShellError<C::Error>>
where
    C: NativeShellClient,
    F: FnMut(&OutputChunk),
    Fut: Future<Output = ()> + Send,
    F: Send,
    C::Error: Send,
{
    let mut create = request.create;
    let timeout_ms = request.shell.timeout_ms.max(1);
    let yield_after = request.yield_after;
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
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut cursor = 0;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let started = Instant::now();
        let cancelled = cancelled.fuse();
        pin_mut!(cancelled);
        let mut cancellation_requested = false;
        let mut timed_out = false;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let poll = client.read_output(process.clone(), cursor).fuse();
            let delay = futures_timer::Delay::new(if cancellation_requested { Duration::from_millis(20) } else { remaining.min(Duration::from_millis(20)) }).fuse();
            pin_mut!(poll, delay);
            let batch = if cancellation_requested {
                select! { result = poll => result.map_err(|source| NativeShellError::Transport { operation: "read output", source })? }
            } else {
                select! {
                    result = poll => match result {
                        Ok(batch) => batch,
                        Err(source) => {
                            client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                            client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                            return Err(NativeShellError::Transport { operation: "read output", source });
                        }
                    },
                    () = cancelled => {
                        client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                        cancellation_requested = true;
                        continue;
                    },
                    () = delay => {
                        client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                        cancellation_requested = true;
                        timed_out = true;
                        continue;
                    }
                }
            };
            if !batch.chunks.is_empty() && batch.next_sequence <= cursor {
                let primary = NativeShellError::InvalidOutputCursor;
                if let Err(source) = client.cancel(process.clone()).await {
                    return Err(NativeShellError::Cleanup {
                        operation: "cancel after invalid output cursor",
                        source,
                        during: Box::new(primary),
                    });
                }
                if let Err(source) = client.release_output(process.clone()).await {
                    return Err(NativeShellError::Cleanup {
                        operation: "release output after invalid cursor",
                        source,
                        during: Box::new(primary),
                    });
                }
                return Err(primary);
            }
            for chunk in &batch.chunks {
                on_chunk(chunk);
                match chunk.stream {
                    crate::OutputStream::Stdout => stdout.extend_from_slice(&chunk.bytes),
                    crate::OutputStream::Stderr => stderr.extend_from_slice(&chunk.bytes),
                }
            }
            cursor = batch.next_sequence;
            match batch.state {
                ExecutionState::Running => {
                    if yield_after.is_some_and(|after| started.elapsed() >= after) {
                        return Ok(NativeShellRunOutcome::Running(NativeShellRunning {
                            resource: resource.clone(),
                            process,
                            cursor,
                            stdout,
                            stderr,
                        }));
                    }
                }
                ExecutionState::Exited { exit_code } => {
                    client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                    return Ok(NativeShellRunOutcome::Finished(NativeShellOutput { exit_code, stdout, stderr, timed_out }));
                }
                ExecutionState::Cancelled => {
                    client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                    return Ok(NativeShellRunOutcome::Finished(NativeShellOutput { exit_code: -1, stdout, stderr, timed_out }));
                }
                ExecutionState::Failed {
                    code: crate::ExecutionFailure::TimedOut,
                } => {
                    client
                        .release_output(process.clone())
                        .await
                        .map_err(NativeShellError::OutputRelease)?;
                    return Ok(NativeShellRunOutcome::Finished(NativeShellOutput {
                        exit_code: -1,
                        stdout,
                        stderr,
                        timed_out: true,
                    }));
                }
                ExecutionState::Failed { code } => {
                    client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                    return Err(NativeShellError::Execution(code));
                }
            }
        }
    }.await;
    let result = match result {
        Ok(NativeShellRunOutcome::Running(running)) => {
            return Ok(NativeShellRunOutcome::Running(running));
        }
        result => result,
    };
    let close_result = client.close(resource).await;
    match (result, close_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(source)) => Err(NativeShellError::ResourceClose(source)),
        (Err(error), Err(source)) => Err(NativeShellError::Cleanup {
            operation: "close resource",
            source,
            during: Box::new(error),
        }),
    }
}

#[cfg(test)]
#[path = "native_shell_tests.rs"]
mod tests;
