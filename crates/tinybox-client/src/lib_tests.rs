//! In-memory `TinyBus` tests for the typed `TinyBox` host client.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use serde_json::{Value, json};
use tinybus::broker::Broker;
use tinybus::module::{
    AccessFuture, FailureReport, FailureReporter, FailureSink, ModuleAccess, ModuleClient,
    ProxyFailure, ReleaseRecord,
};
use tinybus::service::Interface;
use tinybus::transport::memory::MemoryBus;
use tinybus::{Connection, InterfaceName, MemberName, ObjectPath, Proxy};

use super::*;

const MODULE_ID: &str = "tinybox";
type Calls = Arc<Mutex<Vec<(String, Value)>>>;

const ATTESTED_METHODS: &[&str] = &[
    tinybox_bus::names::CAPABILITIES,
    tinybox_bus::names::CREATE,
    tinybox_bus::names::EXEC,
    tinybox_bus::names::SPAWN,
    tinybox_bus::names::START_EXEC,
    tinybox_bus::names::START_JAILED_EXEC,
    tinybox_bus::names::START_NATIVE_SHELL_EXEC,
    tinybox_bus::names::WRITE_FILE_CHUNK,
    tinybox_bus::names::RUN_DOCKER,
    tinybox_bus::names::RUN_DOCKER_WITHOUT_WORKSPACE,
];

static LINKED_CAPTURES: OnceLock<Mutex<HashMap<String, Calls>>> = OnceLock::new();

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

    fn ensure_loaded<'a>(
        &'a self,
        _id: &'a str,
    ) -> AccessFuture<'a, std::result::Result<(), String>> {
        Box::pin(async { Ok(()) })
    }

    fn proxy<'a>(
        &'a self,
        _bus_name: &'a str,
        _object_path: &'a str,
    ) -> AccessFuture<'a, std::result::Result<Proxy, ProxyFailure>> {
        Box::pin(async { Err(ProxyFailure::Transport) })
    }
}

struct MockTinyBox {
    contract_version: (u32, u32),
    calls: Calls,
    members: &'static [&'static str],
}

#[derive(Deserialize)]
struct LinkedFixtureConfig {
    capture_id: String,
    contract_version: (u32, u32),
}

async fn linked_fixture_setup(
    connection: Connection,
    config: LinkedFixtureConfig,
) -> tinybus::Result<()> {
    let calls = LINKED_CAPTURES
        .get()
        .and_then(|captures| captures.lock().ok())
        .and_then(|captures| captures.get(&config.capture_id).cloned())
        .ok_or_else(|| tinybus::Error::failed("linked fixture capture is missing"))?;
    connection
        .serve_at(
            ObjectPath::new(tinybox_bus::OBJECT_PATH)?,
            MockTinyBox {
                contract_version: config.contract_version,
                calls,
                members: ATTESTED_METHODS,
            },
        )
        .await?;
    connection.request_name(tinybox_bus::INTERFACE).await
}

tinybus_module::module_export_static! {
    setup = linked_fixture_setup,
    config = LinkedFixtureConfig,
    worker_threads = 1,
    provides = ["ai.tinyhumans.tinybox.Box"],
    methods = [
        "Capabilities", "Create", "Exec", "Spawn", "StartExec",
        "StartJailedExec", "StartNativeShellExec", "WriteFileChunk",
        "RunDocker", "RunDockerWithoutWorkspace"
    ],
    signals = [],
    requires = [],
    optional = [],
    lazy = false,
}

#[async_trait::async_trait]
impl Interface for MockTinyBox {
    fn name(&self) -> InterfaceName {
        InterfaceName::new(tinybox_bus::INTERFACE).unwrap_or_else(|_| std::process::abort())
    }

    fn members(&self) -> Vec<MemberName> {
        self.members
            .iter()
            .filter_map(|name| MemberName::new(*name).ok())
            .collect()
    }

    async fn call(&self, member: &MemberName, args: Value) -> tinybus::Result<Value> {
        let name = member.as_str();
        self.calls
            .lock()
            .map_err(|_| tinybus::Error::failed("fixture call log is poisoned"))?
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
            tinybox_bus::names::VALIDATE_DOCKER_POLICY => json!({ "issues": [] }),
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
) -> std::result::Result<(Connection, TinyBoxClient, Calls), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    service
        .serve_at(
            ObjectPath::new(tinybox_bus::OBJECT_PATH)?,
            MockTinyBox {
                contract_version,
                calls: Arc::clone(&calls),
                members: tinybox_bus::METHODS,
            },
        )
        .await?;
    service.request_name(tinybox_bus::INTERFACE).await?;
    let caller = Connection::connect(bus.connect().await?).await?;
    let proxy = caller
        .proxy(
            tinybox_bus::INTERFACE,
            tinybox_bus::OBJECT_PATH,
            tinybox_bus::INTERFACE,
        )?;
    let access = FixtureAccess {
        reporter: FailureReporter::new(Arc::new(IgnoreFailures)),
    };
    let module = ModuleClient::new(access).with_fixture(proxy);
    let client = TinyBoxClient::new(module).await?;
    Ok((service, client, calls))
}

async fn attested_fixture() -> std::result::Result<(
    tinybus::module::ModuleHost,
    Connection,
    TinyBoxClient,
    Calls,
), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_CAPTURE: AtomicUsize = AtomicUsize::new(1);
    let capture_id = format!(
        "tinybox-client-{}",
        NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    LINKED_CAPTURES
        .get_or_init(Default::default)
        .lock()
        .map_err(std::io::Error::other)?
        .insert(capture_id.clone(), Arc::clone(&calls));

    let bus = MemoryBus::new();
    let broker = Broker::new();
    broker.clone().spawn(bus.clone());
    let host = tinybus::module::ModuleHost::new(broker);
    host.attach_linked_with_config(
        linked_module()?,
        json!({
            "capture_id": capture_id,
            "contract_version": tinybox_bus::CONTRACT_VERSION,
        }),
    )?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if host
                .list()
                .iter()
                .any(|module| matches!(module.state, tinybus::module::ModuleState::Ready))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let caller = Connection::connect(bus.connect().await?).await?;
    let proxy = caller
        .proxy(
            tinybox_bus::INTERFACE,
            tinybox_bus::OBJECT_PATH,
            tinybox_bus::INTERFACE,
        )?;
    let module = ModuleClient::new(FixtureAccess {
        reporter: FailureReporter::new(Arc::new(IgnoreFailures)),
    })
    .with_fixture(proxy);
    let client = TinyBoxClient::new(module).await?;
    Ok((host, caller, client, calls))
}

fn expected<Request: Serialize>(member: &str, request: Request) -> (String, Value) {
    expected_args(member, (request,))
}

fn expected_args<Args: Serialize>(member: &str, args: Args) -> (String, Value) {
    (
        member.to_owned(),
        serde_json::to_value(args).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn construction_checks_compatibility_once_across_typed_calls()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await?;
    assert_eq!(client.describe().await?, "tinybox fixture");
    assert_eq!(
        client
            .analyze_command("printf hello".to_owned())
            .await?
            .literal_words,
        ["printf", "hello"]
    );
    assert_eq!(
        client.capabilities().contract_version,
        tinybox_bus::CONTRACT_VERSION
    );

    let calls = calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
async fn a_newer_minor_contract_is_accepted() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let version = (
        tinybox_bus::CONTRACT_VERSION.0,
        tinybox_bus::CONTRACT_VERSION.1 + 1,
    );
    let (_service, client, calls) = fixture(version).await?;
    assert_eq!(client.capabilities().contract_version, version);
    assert_eq!(
        calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(),
        1,
        "construction performs the compatibility probe exactly once"
    );
    Ok(())
}

#[tokio::test]
async fn incompatible_contracts_are_rejected_before_any_typed_operation() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        let (_service, calls) = incompatible_fixture(version).await?;
        assert_eq!(calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    }
    Ok(())
}

async fn incompatible_fixture(
    version: (u32, u32),
) -> std::result::Result<(Connection, Calls), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    service
        .serve_at(
            ObjectPath::new(tinybox_bus::OBJECT_PATH)?,
            MockTinyBox {
                contract_version: version,
                calls: Arc::clone(&calls),
                members: tinybox_bus::METHODS,
            },
        )
        .await?;
    service.request_name(tinybox_bus::INTERFACE).await?;
    let caller = Connection::connect(bus.connect().await?).await?;
    let proxy = caller
        .proxy(
            tinybox_bus::INTERFACE,
            tinybox_bus::OBJECT_PATH,
            tinybox_bus::INTERFACE,
        )?;
    let module = ModuleClient::new(FixtureAccess {
        reporter: FailureReporter::new(Arc::new(IgnoreFailures)),
    })
    .with_fixture(proxy);
    assert!(TinyBoxClient::new(module).await.is_err());
    Ok((service, calls))
}

fn assert_recorded(calls: &Calls, expected: &[(String, Value)]) {
    let actual = calls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(actual, expected);
    assert!(
        actual
            .iter()
            .all(|(member, _)| tinybox_bus::METHODS.contains(&member.as_str()))
    );
}

#[tokio::test]
async fn discovery_and_resource_wrappers_preserve_typed_wire_calls()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await?;
    let resource = tinybox_bus::ResourceId("resource-1".into());
    let process = tinybox_bus::ProcessRef {
        resource: resource.clone(),
        process: tinybox_bus::ResourceId("process-1".into()),
    };
    let mut expected_calls = vec![(tinybox_bus::names::CAPABILITIES.to_owned(), json!([]))];
    assert_eq!(client.describe().await?, "tinybox fixture");
    expected_calls.push((tinybox_bus::names::DESCRIBE.to_owned(), json!([])));
    assert!(client.jail_status().await?.available);
    expected_calls.push((tinybox_bus::names::JAIL_STATUS.to_owned(), json!([])));

    let reserve = tinybox_bus::ReserveRequest::Resource;
    assert_eq!(client.reserve(reserve.clone()).await?, tinybox_bus::ResourceId("reservation-1".into()));
    expected_calls.push(expected(tinybox_bus::names::RESERVE, reserve));
    assert_eq!(client.inspect(resource.clone()).await?.backend, "docker");
    expected_calls.push(expected(tinybox_bus::names::INSPECT, resource.clone()));
    client.close(resource.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::CLOSE, resource.clone()));
    client.shutdown().await?;
    expected_calls.push((tinybox_bus::names::SHUTDOWN.to_owned(), json!([])));
    assert!(client.is_running(process.clone()).await?);
    expected_calls.push(expected(tinybox_bus::names::IS_RUNNING, process.clone()));
    client.cancel(process).await?;
    expected_calls.push(expected(tinybox_bus::names::CANCEL, tinybox_bus::ProcessRef {
        resource: resource.clone(),
        process: tinybox_bus::ResourceId("process-1".into()),
    }));

    let shell_command = "printf hello".to_owned();
    assert_eq!(
        client.analyze_shell(shell_command.clone()).await?.segments,
        std::slice::from_ref(&shell_command)
    );
    expected_calls.push(expected(tinybox_bus::names::ANALYZE_SHELL, shell_command));
    let command = "printf hello".to_owned();
    assert_eq!(client.analyze_command(command.clone()).await?.literal_words, ["printf", "hello"]);
    expected_calls.push(expected(tinybox_bus::names::ANALYZE_COMMAND, command));
    let select = tinybox_bus::SelectShellRequest {
        command: "printf hello".into(),
        preserve_pipeline_status: true,
        runtime_path: Some("/opt/bin".into()),
        python_utf8: true,
    };
    assert_eq!(client.select_shell(select.clone()).await?.program, "/bin/sh");
    expected_calls.push(expected(tinybox_bus::names::SELECT_SHELL, select));
    let grants = tinybox_bus::ResolveLocalGrantsRequest {
        home: Some("/home/test".into()),
        config: tinybox_bus::LocalGrantConfig::default(),
        protected: tinybox_bus::ProtectedPaths::default(),
    };
    assert!(client.resolve_local_grants(grants.clone()).await?.read_only.is_empty());
    expected_calls.push(expected(tinybox_bus::names::RESOLVE_LOCAL_GRANTS, grants));
    let policy = tinybox_bus::DockerPolicyRequest::default();
    assert!(client.validate_docker_policy(policy.clone()).await?.issues.is_empty());
    expected_calls.push(expected(tinybox_bus::names::VALIDATE_DOCKER_POLICY, policy));
    assert_recorded(&calls, &expected_calls);
    Ok(())
}

#[tokio::test]
async fn docker_and_process_observation_wrappers_preserve_wire_calls()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await?;
    let resource = tinybox_bus::ResourceId("resource-1".into());
    let process = tinybox_bus::ProcessRef {
        resource: resource.clone(),
        process: tinybox_bus::ResourceId("process-1".into()),
    };
    let mut expected_calls = vec![(tinybox_bus::names::CAPABILITIES.to_owned(), json!([]))];
    let status = tinybox_bus::DockerStatusRequest { timeout_ms: 2_000 };
    assert!(client.docker_status(status).await?.available);
    expected_calls.push(expected(tinybox_bus::names::DOCKER_STATUS, status));
    let cleanup = tinybox_bus::CleanupDockerRequest {
        label: "openhuman.sandbox=true".into(),
        timeout_ms: 2_000,
    };
    assert_eq!(client.cleanup_docker(cleanup.clone()).await?.containers_stopped, 2);
    expected_calls.push(expected(tinybox_bus::names::CLEANUP_DOCKER, cleanup));
    let forward = tinybox_bus::ForwardRequest {
        resource: resource.clone(),
        forward: tinybox_bus::ResourceId("forward-1".into()),
        guest_port: 8080,
    };
    assert_eq!(client.forward(forward.clone()).await?.local_address, "127.0.0.1:1234");
    expected_calls.push(expected(tinybox_bus::names::FORWARD, forward));
    let close_forward = tinybox_bus::CloseForwardRequest {
        resource,
        forward: tinybox_bus::ResourceId("forward-1".into()),
    };
    client.close_forward(close_forward.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::CLOSE_FORWARD, close_forward));
    assert_eq!(client.read_output(process.clone(), 0).await?.next_sequence, 0);
    expected_calls.push((tinybox_bus::names::READ_OUTPUT.to_owned(), json!([process.clone(), 0])));
    client.release_output(process.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::RELEASE_OUTPUT, process));
    assert_recorded(&calls, &expected_calls);
    Ok(())
}

#[tokio::test]
async fn workspace_file_wrappers_preserve_typed_wire_calls()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await?;
    let resource = tinybox_bus::ResourceId("resource-1".into());
    let mut expected_calls = vec![(tinybox_bus::names::CAPABILITIES.to_owned(), json!([]))];
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
    assert!(client.read_file_chunk(read_chunk.clone()).await?.bytes.is_empty());
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
    assert_eq!(client.finish_file_write(finish_write.clone()).await?.next_offset, 0);
    expected_calls.push(expected(tinybox_bus::names::FINISH_FILE_WRITE, finish_write));
    let abort_write = tinybox_bus::AbortFileWriteRequest {
        resource,
        transfer: tinybox_bus::ResourceId("write-1".into()),
    };
    client.abort_file_write(abort_write.clone()).await?;
    expected_calls.push(expected(tinybox_bus::names::ABORT_FILE_WRITE, abort_write));
    assert_recorded(&calls, &expected_calls);
    Ok(())
}

#[tokio::test]
async fn confidential_operations_fail_closed_without_ordinary_retry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_service, client, calls) = fixture(tinybox_bus::CONTRACT_VERSION).await?;
    let secret = "/private/marker";
    assert!(client.create(tinybox_bus::CreateRequest::default()).await.is_err());
    let exec = tinybox_bus::ExecRequest {
        resource: tinybox_bus::ResourceId("resource-1".into()),
        argv: vec!["cat".into(), secret.into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    let error = client.exec(exec).await.err();
    assert!(error.as_ref().is_some_and(|error| !error.to_string().contains(secret)));
    let spawn = spawn_request(secret);
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
    let shell = shell_exec_request(secret);
    assert!(client.start_native_shell_exec(shell).await.is_err());
    let write = tinybox_bus::WriteFileChunkRequest {
        resource: tinybox_bus::ResourceId("resource-1".into()),
        transfer: tinybox_bus::ResourceId("write-1".into()),
        offset: 0,
        bytes: secret.as_bytes().to_vec(),
    };
    assert!(client.write_file_chunk(write).await.is_err());
    let docker = docker_request(format!("echo {secret}"));
    assert!(client.run_docker(docker.clone()).await.is_err());
    assert!(client.run_docker_without_workspace(tinybox_bus::DockerRunRequest {
        workspace: String::new(),
        ..docker
    }).await.is_err());
    let calls = calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(calls.len(), 1, "only the construction probe reaches an un-attested fixture");
    assert_eq!(calls[0].0, tinybox_bus::names::CAPABILITIES);
    Ok(())
}

fn spawn_request(command: &str) -> tinybox_bus::SpawnRequest {
    tinybox_bus::SpawnRequest {
        process: tinybox_bus::ResourceId("process-1".into()),
        command: tinybox_bus::ExecRequest {
            resource: tinybox_bus::ResourceId("resource-1".into()),
            argv: vec!["echo".into(), command.into()],
            cwd: None,
            env: std::collections::BTreeMap::new(),
            stdin: None,
        },
    }
}

fn shell_exec_request(command: &str) -> tinybox_bus::ShellExecRequest {
    tinybox_bus::ShellExecRequest {
        process: tinybox_bus::ResourceId("process-1".into()),
        resource: tinybox_bus::ResourceId("resource-1".into()),
        shell: tinybox_bus::SelectShellRequest {
            command: format!("echo {command}"),
            preserve_pipeline_status: false,
            runtime_path: None,
            python_utf8: false,
        },
        cwd: None,
        extra_env: std::collections::BTreeMap::new(),
        state_dir: "/private/state".into(),
        timeout_ms: 1_000,
        stdin: None,
        jail: None,
        hide_window: false,
    }
}

fn docker_request(command: String) -> tinybox_bus::DockerRunRequest {
    tinybox_bus::DockerRunRequest {
        workspace: "/workspace".into(),
        image: None,
        command,
        login_shell: false,
        network: None,
        memory_limit_mb: None,
        cpus: None,
        read_only_rootfs: None,
        read_only_mounts: vec![],
        extra_cap_drops: vec![],
        env: std::collections::BTreeMap::new(),
        label: None,
        timeout_ms: 1_000,
    }
}

async fn exercise_confidential_resource_wrappers(
    client: &TinyBoxClient,
    expected_calls: &mut Vec<(String, Value)>,
) -> tinybus::module::ModuleCallResult<()> {
    let resource = tinybox_bus::ResourceId("resource-1".into());
    let process = tinybox_bus::ResourceId("process-1".into());
    let create = tinybox_bus::CreateRequest::default();
    assert_eq!(client.create(create.clone()).await?.backend, "docker");
    expected_calls.push(expected(tinybox_bus::names::CREATE, create));
    let exec = tinybox_bus::ExecRequest {
        resource: resource.clone(),
        argv: vec!["printf".into(), "hello".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    assert_eq!(client.exec(exec.clone()).await?.exit_code, 0);
    expected_calls.push(expected(tinybox_bus::names::EXEC, exec));
    let spawn = spawn_request("printf hello");
    assert_eq!(client.spawn(spawn.clone()).await?.process, process);
    expected_calls.push(expected(tinybox_bus::names::SPAWN, spawn.clone()));
    assert_eq!(client.start_exec(spawn.clone()).await?.resource, resource);
    expected_calls.push(expected(tinybox_bus::names::START_EXEC, spawn.clone()));
    let jail = tinybox_bus::NativeJailConfig {
        read_only: vec!["/usr".into()],
        read_write: vec!["/workspace".into()],
        allow_net: false,
        allow_subprocess: false,
        enforcement: tinybox_bus::JailEnforcement::Enforced,
        require_process_isolation: true,
        deny_read: vec!["/home/user/.ssh".into()],
    };
    assert_eq!(client.start_jailed_exec(spawn.clone(), jail.clone()).await?.process, process);
    expected_calls.push(expected_args(tinybox_bus::names::START_JAILED_EXEC, (spawn, jail)));
    Ok(())
}

async fn exercise_confidential_shell_and_write_wrappers(
    client: &TinyBoxClient,
    expected_calls: &mut Vec<(String, Value)>,
) -> tinybus::module::ModuleCallResult<()> {
    let shell = shell_exec_request("printf hello");
    assert_eq!(client.start_native_shell_exec(shell.clone()).await?.process.0, "process-1");
    expected_calls.push(expected(tinybox_bus::names::START_NATIVE_SHELL_EXEC, shell));
    let write = tinybox_bus::WriteFileChunkRequest {
        resource: tinybox_bus::ResourceId("resource-1".into()),
        transfer: tinybox_bus::ResourceId("write-1".into()),
        offset: 0,
        bytes: b"payload".to_vec(),
    };
    assert_eq!(client.write_file_chunk(write.clone()).await?.next_offset, 0);
    expected_calls.push(expected(tinybox_bus::names::WRITE_FILE_CHUNK, write));
    Ok(())
}

async fn exercise_confidential_docker_wrappers(
    client: &TinyBoxClient,
    expected_calls: &mut Vec<(String, Value)>,
) -> tinybus::module::ModuleCallResult<()> {
    let docker = docker_request("printf hello".into());
    assert_eq!(client.run_docker(docker.clone()).await?.stdout, "ok");
    expected_calls.push(expected(tinybox_bus::names::RUN_DOCKER, docker.clone()));
    let without_workspace = tinybox_bus::DockerRunRequest {
        workspace: String::new(),
        ..docker
    };
    assert_eq!(client.run_docker_without_workspace(without_workspace.clone()).await?.exit_code, 0);
    expected_calls.push(expected(tinybox_bus::names::RUN_DOCKER_WITHOUT_WORKSPACE, without_workspace));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attested_linked_module_accepts_every_confidential_wrapper()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_host, _caller, client, calls) = attested_fixture().await?;
    let mut expected_calls = vec![(tinybox_bus::names::CAPABILITIES.to_owned(), json!([]))];
    exercise_confidential_resource_wrappers(&client, &mut expected_calls).await?;
    exercise_confidential_shell_and_write_wrappers(&client, &mut expected_calls).await?;
    exercise_confidential_docker_wrappers(&client, &mut expected_calls).await?;
    assert_eq!(
        calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        expected_calls
    );
    Ok(())
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
