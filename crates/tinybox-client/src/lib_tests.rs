//! In-memory TinyBus tests for the typed TinyBox host client.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use tinybus::broker::Broker;
use tinybus::module::{
    AccessFuture, FailureReport, FailureReporter, FailureSink, ModuleAccess, ModuleClient,
    ProxyFailure, Reason, ReleaseRecord,
};
use tinybus::service::Interface;
use tinybus::transport::memory::MemoryBus;
use tinybus::{Connection, InterfaceName, MemberName, ObjectPath, Proxy};

use super::*;

const MODULE_ID: &str = "tinybox";
static RELEASE: ReleaseRecord = ReleaseRecord {
    id: MODULE_ID,
    bus_name: tinybox_bus::INTERFACE,
    object_path: tinybox_bus::OBJECT_PATH,
    version: "0.1.37",
    release_url: "https://example.invalid/tinybox",
    assets: &[],
};

#[derive(Default)]
struct IgnoreFailures;

impl FailureSink for IgnoreFailures {
    fn capture(&self, _report: &FailureReport<'_>) {}
}

struct FixtureAccess {
    reporter: FailureReporter,
}

impl ModuleAccess for FixtureAccess {
    fn find(&self, id: &str) -> Option<&'static ReleaseRecord> {
        (id == MODULE_ID).then_some(&RELEASE)
    }

    fn enabled(&self) -> bool {
        true
    }

    fn reporter(&self) -> &FailureReporter {
        &self.reporter
    }

    fn ensure_loaded<'a>(&'a self, _id: &'a str) -> AccessFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }

    fn proxy<'a>(
        &'a self,
        _bus_name: &'a str,
        _object_path: &'a str,
    ) -> AccessFuture<'a, Result<Proxy, ProxyFailure>> {
        Box::pin(async { Err(ProxyFailure::Transport) })
    }
}

struct MockTinyBox {
    contract_version: (u32, u32),
    calls: Arc<Mutex<Vec<(String, Value)>>>,
}

#[async_trait::async_trait]
impl Interface for MockTinyBox {
    fn name(&self) -> InterfaceName {
        InterfaceName::new(tinybox_bus::INTERFACE).expect("valid TinyBox interface")
    }

    fn members(&self) -> Vec<MemberName> {
        tinybox_bus::METHODS
            .iter()
            .map(|name| MemberName::new(*name).expect("valid TinyBox member"))
            .collect()
    }

    async fn call(&self, member: &MemberName, args: Value) -> tinybus::Result<Value> {
        let name = member.as_str();
        self.calls
            .lock()
            .expect("fixture call log lock")
            .push((name.to_owned(), args));
        let value = match name {
            tinybox_bus::names::DESCRIBE => json!("tinybox fixture"),
            tinybox_bus::names::CAPABILITIES => json!({
                "contract_version": self.contract_version,
                "create_backends": ["docker"],
                "exec_backends": ["docker"],
                "spawn_backends": ["docker"]
            }),
            tinybox_bus::names::JAIL_STATUS => json!({
                "backend": "fixture", "available": true, "isolation": "process",
                "suitable_for_untrusted_code": true, "filesystem": "enforced",
                "network": "enforced", "subprocess": "enforced"
            }),
            tinybox_bus::names::RESERVE => json!("reservation-1"),
            tinybox_bus::names::INSPECT | tinybox_bus::names::CREATE => json!({
                "resource": "resource-1", "backend": "docker", "state": "running",
                "published_ports": []
            }),
            tinybox_bus::names::EXEC => json!({
                "exit_code": 0, "stdout": [], "stderr": []
            }),
            tinybox_bus::names::SPAWN
            | tinybox_bus::names::START_EXEC
            | tinybox_bus::names::START_JAILED_EXEC
            | tinybox_bus::names::START_NATIVE_SHELL_EXEC => json!({
                "resource": "resource-1", "process": "process-1"
            }),
            tinybox_bus::names::IS_RUNNING => json!(true),
            tinybox_bus::names::ANALYZE_SHELL => json!({
                "segments": ["printf hello"], "hidden_execution": false, "redirection": false
            }),
            tinybox_bus::names::ANALYZE_COMMAND => json!({
                "segments": [], "hidden_execution": false, "redirection": false,
                "expansion": false, "tee": false, "background": false,
                "literal_words": ["printf", "hello"]
            }),
            tinybox_bus::names::SELECT_SHELL => json!({
                "flavor": "posix", "program": "/bin/sh", "arguments": ["-c"],
                "raw_arguments": null, "bootstrap_environment": [], "remove_environment": []
            }),
            tinybox_bus::names::RESOLVE_LOCAL_GRANTS => json!({
                "read_only": [], "read_write": []
            }),
            tinybox_bus::names::VALIDATE_DOCKER_POLICY => json!({}),
            tinybox_bus::names::RUN_DOCKER | tinybox_bus::names::RUN_DOCKER_WITHOUT_WORKSPACE => {
                json!({
                    "exit_code": 0, "stdout": "ok", "stderr": "", "timed_out": false
                })
            }
            tinybox_bus::names::DOCKER_STATUS => json!({ "available": true }),
            tinybox_bus::names::CLEANUP_DOCKER => json!({ "containers_stopped": 2 }),
            tinybox_bus::names::FORWARD => json!({
                "resource": "resource-1", "forward": "forward-1", "local_address": "127.0.0.1:1234"
            }),
            tinybox_bus::names::READ_OUTPUT => json!({
                "chunks": [], "next_sequence": 0, "state": {"Exited": {"exit_code": 0}}
            }),
            tinybox_bus::names::BEGIN_FILE_READ => json!({
                "resource": "resource-1", "transfer": "read-1", "size": 0
            }),
            tinybox_bus::names::READ_FILE_CHUNK => json!({
                "offset": 0, "bytes": [], "total_bytes": 0
            }),
            tinybox_bus::names::BEGIN_FILE_WRITE => json!({
                "resource": "resource-1", "transfer": "write-1", "next_offset": 0
            }),
            tinybox_bus::names::WRITE_FILE_CHUNK | tinybox_bus::names::FINISH_FILE_WRITE => {
                json!({ "next_offset": 0 })
            }
            _ => Value::Null,
        };
        Ok(value)
    }
}

async fn fixture(
    contract_version: (u32, u32),
) -> (Connection, TinyBoxClient, Arc<Mutex<Vec<(String, Value)>>>) {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await.expect("service transport"))
        .await
        .expect("service connection");
    let calls = Arc::new(Mutex::new(Vec::new()));
    service
        .serve_at(
            ObjectPath::new(tinybox_bus::OBJECT_PATH).expect("valid TinyBox path"),
            MockTinyBox {
                contract_version,
                calls: Arc::clone(&calls),
            },
        )
        .await
        .expect("serve mock TinyBox");
    service
        .request_name(tinybox_bus::INTERFACE)
        .await
        .expect("request TinyBox name");
    let caller = Connection::connect(bus.connect().await.expect("client transport"))
        .await
        .expect("client connection");
    let proxy = caller
        .proxy(
            tinybox_bus::INTERFACE,
            tinybox_bus::OBJECT_PATH,
            tinybox_bus::INTERFACE,
        )
        .expect("TinyBox proxy");
    let access = FixtureAccess {
        reporter: FailureReporter::new(Arc::new(IgnoreFailures)),
    };
    let module = ModuleClient::new(access).with_fixture(proxy);
    let client = TinyBoxClient::new(MODULE_ID, module)
        .await
        .expect("compatible TinyBox contract");
    (service, client, calls)
}

fn expected<Request: Serialize>(member: &str, request: Request) -> (String, Value) {
    (
        member.to_owned(),
        serde_json::to_value((request,)).expect("serialize expected wire arguments"),
    )
}

#[tokio::test]
async fn construction_checks_compatibility_once_across_typed_calls()
-> Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await;
    assert_eq!(client.describe().await?, "tinybox fixture");
    assert_eq!(
        client
            .analyze_command("printf hello".to_owned())
            .await?
            .literal_words,
        ["printf", "hello"]
    );
    assert_eq!(
        client.capabilities().await?.contract_version,
        tinybox_bus::CONTRACT_VERSION
    );

    let calls = calls.lock().expect("fixture call log lock");
    assert_eq!(
        calls
            .iter()
            .filter(|(member, _)| member == tinybox_bus::names::CAPABILITIES)
            .count(),
        1,
        "compatibility is probed only during construction"
    );
    Ok(())
}

#[tokio::test]
async fn incompatible_contracts_are_rejected_before_any_typed_operation() {
    for version in [
        (
            tinybox_bus::CONTRACT_VERSION.0,
            tinybox_bus::CONTRACT_VERSION.1 - 1,
        ),
        (
            tinybox_bus::CONTRACT_VERSION.0 + 1,
            tinybox_bus::CONTRACT_VERSION.1,
        ),
    ] {
        let (_service, calls) = incompatible_fixture(version).await;
        assert_eq!(calls.lock().expect("fixture call log lock").len(), 1);
    }
}

async fn incompatible_fixture(
    version: (u32, u32),
) -> (Connection, Arc<Mutex<Vec<(String, Value)>>>) {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await.expect("service transport"))
        .await
        .expect("service connection");
    let calls = Arc::new(Mutex::new(Vec::new()));
    service
        .serve_at(
            ObjectPath::new(tinybox_bus::OBJECT_PATH).expect("valid TinyBox path"),
            MockTinyBox {
                contract_version: version,
                calls: Arc::clone(&calls),
            },
        )
        .await
        .expect("serve mock TinyBox");
    service
        .request_name(tinybox_bus::INTERFACE)
        .await
        .expect("request TinyBox name");
    let caller = Connection::connect(bus.connect().await.expect("client transport"))
        .await
        .expect("client connection");
    let proxy = caller
        .proxy(
            tinybox_bus::INTERFACE,
            tinybox_bus::OBJECT_PATH,
            tinybox_bus::INTERFACE,
        )
        .expect("TinyBox proxy");
    let module = ModuleClient::new(FixtureAccess {
        reporter: FailureReporter::new(Arc::new(IgnoreFailures)),
    })
    .with_fixture(proxy);
    assert!(TinyBoxClient::new(MODULE_ID, module).await.is_err());
    (service, calls)
}

#[tokio::test]
async fn ordinary_wrappers_preserve_canonical_members_typed_replies_and_wire_arguments()
-> Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await;
    let resource = tinybox_bus::ResourceId("resource-1".into());
    let process = tinybox_bus::ProcessRef {
        resource: resource.clone(),
        process: tinybox_bus::ResourceId("process-1".into()),
    };
    let mut expected_calls = vec![
        (tinybox_bus::names::CAPABILITIES.to_owned(), json!([])),
        (tinybox_bus::names::DESCRIBE.to_owned(), json!([])),
        (tinybox_bus::names::JAIL_STATUS.to_owned(), json!([])),
    ];
    assert_eq!(client.describe().await?, "tinybox fixture");
    assert!(client.jail_status().await?.available);
    let reserve = tinybox_bus::ReserveRequest::Resource;
    assert_eq!(
        client.reserve(reserve.clone()).await?,
        tinybox_bus::ResourceId("reservation-1".into())
    );
    expected_calls.push(expected(tinybox_bus::names::RESERVE, reserve));
    assert_eq!(client.inspect(resource.clone()).await?.backend, "docker");
    expected_calls.push(expected(tinybox_bus::names::INSPECT, resource.clone()));
    client.close(resource.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::CLOSE, resource.clone()));
    client.shutdown().await?;
    expected_calls.push((tinybox_bus::names::SHUTDOWN.to_owned(), json!([])));
    assert!(client.is_running(process.clone()).await?);
    expected_calls.push(expected(tinybox_bus::names::IS_RUNNING, process.clone()));
    client.cancel(process.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::CANCEL, process.clone()));

    let shell_command = "printf hello".to_owned();
    assert_eq!(
        client.analyze_shell(shell_command.clone()).await?.segments,
        [shell_command.clone()]
    );
    expected_calls.push(expected(tinybox_bus::names::ANALYZE_SHELL, shell_command));
    let command = "printf hello".to_owned();
    assert_eq!(
        client.analyze_command(command.clone()).await?.literal_words,
        ["printf", "hello"]
    );
    expected_calls.push(expected(tinybox_bus::names::ANALYZE_COMMAND, command));
    let select = tinybox_bus::SelectShellRequest {
        command: "printf hello".into(),
        preserve_pipeline_status: true,
        runtime_path: Some("/opt/bin".into()),
        python_utf8: true,
    };
    assert_eq!(
        client.select_shell(select.clone()).await?.program,
        "/bin/sh"
    );
    expected_calls.push(expected(tinybox_bus::names::SELECT_SHELL, select));
    let grants = tinybox_bus::ResolveLocalGrantsRequest {
        home: Some("/home/test".into()),
        config: tinybox_bus::LocalGrantConfig::default(),
        protected: tinybox_bus::ProtectedPaths::default(),
    };
    assert!(
        client
            .resolve_local_grants(grants.clone())
            .await?
            .read_only
            .is_empty()
    );
    expected_calls.push(expected(tinybox_bus::names::RESOLVE_LOCAL_GRANTS, grants));
    let policy = tinybox_bus::DockerPolicyRequest::default();
    let _ = client.validate_docker_policy(policy.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::VALIDATE_DOCKER_POLICY, policy));

    let status = tinybox_bus::DockerStatusRequest { timeout_ms: 2_000 };
    assert!(client.docker_status(status).await?.available);
    expected_calls.push(expected(tinybox_bus::names::DOCKER_STATUS, status));
    let cleanup = tinybox_bus::CleanupDockerRequest {
        label: "openhuman.sandbox=true".into(),
        timeout_ms: 2_000,
    };
    assert_eq!(
        client
            .cleanup_docker(cleanup.clone())
            .await?
            .containers_stopped,
        2
    );
    expected_calls.push(expected(tinybox_bus::names::CLEANUP_DOCKER, cleanup));

    let forward = tinybox_bus::ForwardRequest {
        resource: resource.clone(),
        forward: tinybox_bus::ResourceId("forward-1".into()),
        guest_port: 8080,
    };
    assert_eq!(
        client.forward(forward.clone()).await?.local_address,
        "127.0.0.1:1234"
    );
    expected_calls.push(expected(tinybox_bus::names::FORWARD, forward));
    let close_forward = tinybox_bus::CloseForwardRequest {
        resource: resource.clone(),
        forward: tinybox_bus::ResourceId("forward-1".into()),
    };
    client.close_forward(close_forward.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::CLOSE_FORWARD, close_forward));
    assert_eq!(
        client.read_output(process.clone(), 0).await?.next_sequence,
        0
    );
    expected_calls.push((
        tinybox_bus::names::READ_OUTPUT.to_owned(),
        json!([process.clone(), 0]),
    ));
    client.release_output(process.clone()).await?;
    expected_calls.push(expected(
        tinybox_bus::names::RELEASE_OUTPUT,
        process.clone(),
    ));

    let read = tinybox_bus::BeginFileReadRequest {
        resource: resource.clone(),
        transfer: tinybox_bus::ResourceId("read-1".into()),
        path: "input.txt".into(),
    };
    assert_eq!(client.begin_file_read(read.clone()).await?.size, 0);
    expected_calls.push(expected(tinybox_bus::names::BEGIN_FILE_READ, read));
    let read_chunk = tinybox_bus::ReadFileChunkRequest {
        resource: resource.clone(),
        transfer: tinybox_bus::ResourceId("read-1".into()),
        offset: 0,
        max_bytes: 10,
    };
    assert!(
        client
            .read_file_chunk(read_chunk.clone())
            .await?
            .bytes
            .is_empty()
    );
    expected_calls.push(expected(tinybox_bus::names::READ_FILE_CHUNK, read_chunk));
    let finish_read = tinybox_bus::FinishFileReadRequest {
        resource: resource.clone(),
        transfer: tinybox_bus::ResourceId("read-1".into()),
    };
    client.finish_file_read(finish_read.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::FINISH_FILE_READ, finish_read));
    let write = tinybox_bus::BeginFileWriteRequest {
        resource: resource.clone(),
        transfer: tinybox_bus::ResourceId("write-1".into()),
        path: "output.txt".into(),
    };
    assert_eq!(client.begin_file_write(write.clone()).await?.next_offset, 0);
    expected_calls.push(expected(tinybox_bus::names::BEGIN_FILE_WRITE, write));
    let finish_write = tinybox_bus::FinishFileWriteRequest {
        resource: resource.clone(),
        transfer: tinybox_bus::ResourceId("write-1".into()),
    };
    assert_eq!(
        client
            .finish_file_write(finish_write.clone())
            .await?
            .next_offset,
        0
    );
    expected_calls.push(expected(
        tinybox_bus::names::FINISH_FILE_WRITE,
        finish_write,
    ));
    let abort_write = tinybox_bus::AbortFileWriteRequest {
        resource,
        transfer: tinybox_bus::ResourceId("write-1".into()),
    };
    client.abort_file_write(abort_write.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::ABORT_FILE_WRITE, abort_write));

    let actual = calls.lock().expect("fixture call log lock").clone();
    assert_eq!(actual, expected_calls);
    assert!(
        actual
            .iter()
            .all(|(member, _)| tinybox_bus::METHODS.contains(&member.as_str()))
    );
    Ok(())
}

#[tokio::test]
async fn confidential_operations_fail_closed_without_ordinary_retry() {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await;
    let secret = "/private/marker";
    let create = tinybox_bus::CreateRequest::default();
    assert!(client.create(create).await.is_err());
    let exec = tinybox_bus::ExecRequest {
        resource: tinybox_bus::ResourceId("resource-1".into()),
        argv: vec!["cat".into(), secret.into()],
        cwd: None,
        env: Default::default(),
        stdin: None,
    };
    let error = client
        .exec(exec)
        .await
        .expect_err("confidential execution requires attestation");
    assert!(!error.to_string().contains(secret));
    let spawn = tinybox_bus::SpawnRequest {
        process: tinybox_bus::ResourceId("process-1".into()),
        command: tinybox_bus::ExecRequest {
            resource: tinybox_bus::ResourceId("resource-1".into()),
            argv: vec!["echo".into(), secret.into()],
            cwd: None,
            env: Default::default(),
            stdin: None,
        },
    };
    assert!(client.spawn(spawn.clone()).await.is_err());
    assert!(client.start_exec(spawn.clone()).await.is_err());
    let jail = tinybox_bus::NativeJailConfig {
        read_only: Vec::new(),
        read_write: Vec::new(),
        allow_net: false,
        allow_subprocess: false,
        enforcement: tinybox_bus::JailEnforcement::Enforced,
        require_process_isolation: true,
        deny_read: Vec::new(),
    };
    assert!(client.start_jailed_exec(spawn, jail).await.is_err());
    let shell_exec = tinybox_bus::ShellExecRequest {
        process: tinybox_bus::ResourceId("process-1".into()),
        resource: tinybox_bus::ResourceId("resource-1".into()),
        shell: tinybox_bus::SelectShellRequest {
            command: format!("echo {secret}"),
            preserve_pipeline_status: false,
            runtime_path: None,
            python_utf8: false,
        },
        cwd: None,
        extra_env: Default::default(),
        state_dir: "/private/state".into(),
        timeout_ms: 1000,
        stdin: None,
        jail: None,
        hide_window: false,
    };
    assert!(client.start_native_shell_exec(shell_exec).await.is_err());
    let write = tinybox_bus::WriteFileChunkRequest {
        resource: tinybox_bus::ResourceId("resource-1".into()),
        transfer: tinybox_bus::ResourceId("write-1".into()),
        offset: 0,
        bytes: secret.as_bytes().to_vec(),
    };
    assert!(client.write_file_chunk(write).await.is_err());
    let docker = tinybox_bus::DockerRunRequest {
        workspace: "/workspace".into(),
        image: None,
        command: format!("echo {secret}"),
        login_shell: false,
        network: None,
        memory_limit_mb: None,
        cpus: None,
        read_only_rootfs: None,
        read_only_mounts: vec![],
        extra_cap_drops: vec![],
        env: Default::default(),
        label: None,
        timeout_ms: 1_000,
    };
    assert!(client.run_docker(docker.clone()).await.is_err());
    assert!(
        client
            .run_docker_without_workspace(tinybox_bus::DockerRunRequest {
                workspace: String::new(),
                ..docker
            })
            .await
            .is_err()
    );
    let calls = calls.lock().expect("fixture call log lock");
    assert_eq!(
        calls.len(),
        1,
        "only the construction capability probe reaches the un-attested fixture"
    );
    assert_eq!(calls[0].0, tinybox_bus::names::CAPABILITIES);
}

#[test]
fn docker_control_deadline_clamps_the_request_before_adding_grace() {
    let grace = Duration::from_secs(5);
    assert_eq!(
        docker_control_deadline(10_000, grace),
        Duration::from_secs(15)
    );
    assert_eq!(
        docker_control_deadline(1, grace),
        Duration::from_millis(5_001)
    );
    assert_eq!(
        docker_control_deadline(u64::MAX, grace),
        Duration::from_secs(tinybox_bus::MAX_DOCKER_CONTROL_TIMEOUT_MS / 1_000 + 5)
    );
}
