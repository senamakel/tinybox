//! Tests for runtime-neutral native shell orchestration.
use super::*;
use crate::{
    HostConfig, NetworkPolicy, OutputStream, ResourceLimits, SelectShellRequest, Workspace,
};
use std::{collections::BTreeMap, sync::Mutex};

struct MockClient {
    calls: Mutex<Vec<&'static str>>,
}

impl NativeShellClient for MockClient {
    type Error = &'static str;

    async fn reserve(&self, request: ReserveRequest) -> Result<ResourceId, Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("reserve");
        Ok(match request {
            ReserveRequest::Resource => ResourceId("resource-1".into()),
            ReserveRequest::Process(_) => ResourceId("process-1".into()),
            _ => return Err("unexpected reservation"),
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<(), Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("create");
        assert_eq!(request.resource, ResourceId("resource-1".into()));
        Ok(())
    }

    async fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> Result<ProcessRef, Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("start");
        assert_eq!(request.process, ResourceId("process-1".into()));
        Ok(ProcessRef {
            resource: request.resource,
            process: request.process,
        })
    }

    async fn read_output(&self, _: ProcessRef, _: u64) -> Result<OutputBatch, Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("read");
        Ok(OutputBatch {
            chunks: vec![OutputChunk {
                sequence: 0,
                stream: OutputStream::Stdout,
                bytes: b"done".to_vec(),
            }],
            next_sequence: 1,
            state: ExecutionState::Exited { exit_code: 7 },
        })
    }

    async fn cancel(&self, _: ProcessRef) -> Result<(), Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("cancel");
        Ok(())
    }

    async fn release_output(&self, _: ProcessRef) -> Result<(), Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("release");
        Ok(())
    }

    async fn close(&self, _: ResourceId) -> Result<(), Self::Error> {
        self.calls.lock().map_err(|_| "poisoned")?.push("close");
        Ok(())
    }
}

#[tokio::test]
async fn runs_and_cleans_up_a_shell_while_streaming_chunks() -> Result<(), &'static str> {
    let client = MockClient {
        calls: Mutex::new(Vec::new()),
    };
    let mut chunks = Vec::new();
    let output = run_native_shell(&client, request(), std::future::pending(), |chunk| {
        chunks.push(chunk.clone())
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
