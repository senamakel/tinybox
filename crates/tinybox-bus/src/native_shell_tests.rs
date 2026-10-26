//! Tests for runtime-neutral native shell orchestration.
use super::*;
use crate::{
    HostConfig, NetworkPolicy, OutputStream, ResourceLimits, SelectShellRequest, Workspace,
};
use std::{collections::BTreeMap, sync::Mutex};

struct MockClient {
    calls: Mutex<Vec<&'static str>>,
    fail_create: bool,
    cancel_changes_state: bool,
}

impl NativeShellClient for MockClient {
    type Error = &'static str;

    async fn reserve(&self, request: ReserveRequest) -> Result<ResourceId, Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("reserve");
        Ok(match request {
            ReserveRequest::Resource => ResourceId("resource-1".into()),
            ReserveRequest::Process(_) => ResourceId("process-1".into()),
            _ => return Err("unexpected reservation"),
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("create");
        assert_eq!(request.resource, ResourceId("resource-1".into()));
        if self.fail_create {
            return Err("create failed");
        }
        Ok(())
    }

    async fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> Result<ProcessRef, Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("start");
        assert_eq!(request.process, ResourceId("process-1".into()));
        Ok(ProcessRef {
            resource: request.resource,
            process: request.process,
        })
    }

    async fn read_output(&self, _: ProcessRef, _: u64) -> Result<OutputBatch, Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("read");
        let state = if self.cancel_changes_state
            && self.calls.lock().map_err(|_| "poisoned")?.contains(&"cancel")
        {
            ExecutionState::Cancelled
        } else {
            ExecutionState::Exited { exit_code: 7 }
        };
        Ok(OutputBatch {
            chunks: vec![OutputChunk {
                sequence: 0,
                stream: OutputStream::Stdout,
                bytes: b"done".to_vec(),
            }],
            next_sequence: 1,
            state,
        })
    }

    async fn cancel(&self, _: ProcessRef) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("cancel");
        Ok(())
    }

    async fn release_output(&self, _: ProcessRef) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("release");
        Ok(())
    }

    async fn close(&self, _: ResourceId) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("close");
        Ok(())
    }
}

#[test]
fn runs_and_cleans_up_a_shell_while_streaming_chunks() -> Result<(), &'static str> {
    futures_executor::block_on(runs_and_cleans_up_a_shell())
}

async fn runs_and_cleans_up_a_shell() -> Result<(), &'static str> {
    let client = MockClient {
        calls: Mutex::new(Vec::new()),
        fail_create: false,
        cancel_changes_state: false,
    };
    let mut chunks = Vec::new();
    let output = run_native_shell(&client, request(), std::future::pending(), |chunk| {
        chunks.push(chunk.clone());
    })
    .await
    .map_err(|_| "run failed")?;
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, b"done");
    assert!(!output.timed_out);
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        *client.calls.lock().map_err(|_| "poisoned")?,
        [
            "reserve", "create", "reserve", "start", "read", "release", "close"
        ]
    );
    Ok(())
}

#[test]
fn cancellation_reaps_the_process_before_releasing_and_closing() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = MockClient {
            calls: Mutex::new(Vec::new()),
            fail_create: false,
            cancel_changes_state: true,
        };
        let output = run_native_shell(&client, request(), std::future::ready(()), |_| {})
            .await
            .map_err(|_| "run failed")?;
        assert_eq!(output.exit_code, -1);
        assert!(!output.timed_out);
        assert_eq!(
            *client.calls.lock().map_err(|_| "poisoned")?,
            [
                "reserve", "create", "reserve", "start", "cancel", "read", "release", "close"
            ]
        );
        Ok(())
    })
}

#[test]
fn create_failure_still_releases_the_resource_reservation() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = MockClient {
            calls: Mutex::new(Vec::new()),
            fail_create: true,
            cancel_changes_state: false,
        };
        let error = run_native_shell(&client, request(), std::future::pending(), |_| {})
            .await
            .err()
            .ok_or("expected failure")?;
        assert!(matches!(error, NativeShellError::Transport { operation: "create resource", .. }));
        assert_eq!(
            *client.calls.lock().map_err(|_| "poisoned")?,
            ["reserve", "create", "close"]
        );
        Ok(())
    })
}

fn request() -> NativeShellRunRequest {
    NativeShellRunRequest {
        create: CreateRequest {
            resource: ResourceId("placeholder-resource".into()),
            backend: "passthrough".into(),
            host: HostConfig::Local,
            workspace: Workspace::Directory("/workspace".into()),
            network: NetworkPolicy::Open,
            resources: ResourceLimits::default(),
            ports: Vec::new(),
            env: BTreeMap::new(),
        },
        shell: ShellExecRequest {
            process: ResourceId("placeholder-process".into()),
            resource: ResourceId("placeholder-resource".into()),
            shell: SelectShellRequest {
                command: "echo done".into(),
                preserve_pipeline_status: false,
                runtime_path: None,
                python_utf8: false,
            },
            cwd: None,
            extra_env: BTreeMap::new(),
            state_dir: "/state".into(),
            timeout_ms: 1_000,
            stdin: None,
            jail: None,
            hide_window: false,
        },
    }
}
