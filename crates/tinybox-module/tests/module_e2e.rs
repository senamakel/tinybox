//! End-to-end proof for the compiled `TinyBox` module's workspace file contract.

use std::{sync::Arc, time::Duration};

use tinybox_bus::{
    BeginFileReadRequest, BeginFileWriteRequest, CreateRequest, FileChunk, FinishFileReadRequest,
    FinishFileWriteRequest, ReadFileChunkRequest, ReserveRequest, ResourceId, ResourceInfo,
    Workspace, WriteFileChunkRequest,
};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, ModuleState};
use tinybus::transport::memory::MemoryBus;
use tinystoragedrivers_busproxy::{
    AuditEvent, AuditSink, Environment, GovernedEndpointLimits, GovernedStorage, GrantPolicy,
    HostContext, HostFailure, HostStorageContext, ResolvedStorage, StorageGrant,
};
use tinystoragedrivers_client::StorageServer;
use tinystoragedrivers_core::StorageBackend;

const BUS_NAME: &str = "ai.tinyhumans.tinybox.Box";
const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE to point at the built cdylib"]
#[expect(
    clippy::too_many_lines,
    reason = "the compiled artifact proof keeps manifest, broker, transfer, and cleanup assertions in one fixture"
)]
async fn compiled_module_transfers_workspace_files_over_a_broker()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    let workspace = tempfile::tempdir()?;
    let input = workspace.path().join("source.bin");
    let output = workspace.path().join("nested/output.bin");
    let payload = (0_u8..=255).cycle().take(150_000).collect::<Vec<u8>>();
    std::fs::write(&input, &payload)?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(artifact)?;
    assert_eq!(loaded.name, "tinybox-module");
    assert_eq!(loaded.manifest.bus_name.as_str(), BUS_NAME);
    assert_eq!(loaded.manifest.object_path.as_str(), OBJECT_PATH);
    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);

    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let capabilities: tinybox_bus::ModuleCapabilities = proxy.call("Capabilities", ()).await?;
    assert_eq!(capabilities.contract_version, tinybox_bus::CONTRACT_VERSION);
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    let created: ResourceInfo = proxy
        .call(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;

    let reader: ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileRead(resource.clone()),))
        .await?;
    let read_info: tinybox_bus::FileReadInfo = proxy
        .call(
            "BeginFileRead",
            (BeginFileReadRequest {
                resource: resource.clone(),
                transfer: reader.clone(),
                path: "source.bin".into(),
            },),
        )
        .await?;
    assert_eq!(read_info.size, payload.len() as u64);
    let mut offset = 0_u64;
    let writer: ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileWrite(resource.clone()),))
        .await?;
    proxy
        .call::<tinybox_bus::FileWriteInfo>(
            "BeginFileWrite",
            (BeginFileWriteRequest {
                resource: resource.clone(),
                transfer: writer.clone(),
                path: "nested/output.bin".into(),
            },),
        )
        .await?;
    while offset < read_info.size {
        let chunk: FileChunk = proxy
            .call(
                "ReadFileChunk",
                (ReadFileChunkRequest {
                    resource: resource.clone(),
                    transfer: reader.clone(),
                    offset,
                    max_bytes: tinybox_bus::MAX_FILE_CHUNK_BYTES,
                },),
            )
            .await?;
        assert_eq!(chunk.offset, offset);
        assert_ne!(chunk.bytes, Vec::<u8>::new());
        let progress: tinybox_bus::FileWriteProgress = proxy
            .call(
                "WriteFileChunk",
                (WriteFileChunkRequest {
                    resource: resource.clone(),
                    transfer: writer.clone(),
                    offset,
                    bytes: chunk.bytes.clone(),
                },),
            )
            .await?;
        offset = offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or("transfer offset overflow")?;
        assert_eq!(progress.next_offset, offset);
    }
    proxy
        .call::<tinybox_bus::FileWriteProgress>(
            "FinishFileWrite",
            (FinishFileWriteRequest {
                resource: resource.clone(),
                transfer: writer,
            },),
        )
        .await?;
    proxy
        .call::<()>(
            "FinishFileRead",
            (FinishFileReadRequest {
                resource: resource.clone(),
                transfer: reader,
            },),
        )
        .await?;
    assert_eq!(std::fs::read(&output)?, payload);
    #[cfg(unix)]
    verify_live_output(&proxy, &resource).await?;
    #[cfg(unix)]
    verify_native_jail(&proxy, &resource).await?;
    proxy.call::<()>("Close", (created.resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE to point at the built cdylib"]
#[expect(
    clippy::too_many_lines,
    reason = "the compiled artifact proof verifies both existing and no-workspace Docker calls through one broker"
)]
async fn compiled_module_runs_one_shot_docker_through_a_broker()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/docker")
        .canonicalize()?;
    let path = std::env::var_os("PATH").ok_or("PATH is required")?;
    let selected = std::env::split_paths(&path)
        .find_map(|directory| {
            let candidate = directory.join("docker");
            candidate.is_file().then_some(candidate)
        })
        .ok_or("local Docker transport fixture is required")?;
    assert_eq!(
        selected.canonicalize()?,
        fixture,
        "refuse real Docker transport"
    );
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    let workspace = tempfile::tempdir()?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(artifact)?;
    assert_eq!(loaded.name, "tinybox-module");
    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);

    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let status: tinybox_bus::DockerStatus = proxy
        .call(
            "DockerStatus",
            (tinybox_bus::DockerStatusRequest { timeout_ms: 5_000 },),
        )
        .await?;
    assert!(status.available, "the local fixture answers Docker info");
    let cleanup: tinybox_bus::CleanupDockerOutput = proxy
        .call(
            "CleanupDocker",
            (tinybox_bus::CleanupDockerRequest {
                label: "openhuman.sandbox=true".into(),
                timeout_ms: 5_000,
            },),
        )
        .await?;
    assert_eq!(cleanup.containers_stopped, 1);
    let result: tinybox_bus::DockerRunOutput = proxy
        .call(
            "RunDocker",
            (tinybox_bus::DockerRunRequest {
                workspace: workspace.path().display().to_string(),
                image: None,
                command: "ignored by fixture".into(),
                login_shell: false,
                network: None,
                memory_limit_mb: None,
                cpus: None,
                read_only_rootfs: None,
                read_only_mounts: Vec::new(),
                extra_cap_drops: Vec::new(),
                env: std::collections::BTreeMap::new(),
                label: None,
                timeout_ms: 120_000,
            },),
        )
        .await?;
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, "fixture-container\n");
    assert_eq!(result.stderr, "");
    assert!(!result.timed_out);
    let unmounted: tinybox_bus::DockerRunOutput = proxy
        .call(
            "RunDockerWithoutWorkspace",
            (tinybox_bus::DockerRunRequest {
                workspace: String::new(),
                image: None,
                command: "ignored by fixture".into(),
                login_shell: true,
                network: None,
                memory_limit_mb: None,
                cpus: None,
                read_only_rootfs: None,
                read_only_mounts: Vec::new(),
                extra_cap_drops: Vec::new(),
                env: std::collections::BTreeMap::new(),
                label: None,
                timeout_ms: 120_000,
            },),
        )
        .await?;
    assert_eq!(unmounted.exit_code, 0);
    assert_eq!(unmounted.stdout, "fixture-container\n");
    assert_eq!(unmounted.stderr, "");
    assert!(!unmounted.timed_out);
    modules.shutdown(Duration::from_secs(5)).await;
    broker_task.abort();
    Ok(())
}

/// The caller prepends the checked-in local SSH fixture to PATH before starting
/// this process; no runtime environment mutation or real SSH server is needed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE and the local SSH fixture first on PATH"]
async fn compiled_module_streams_ssh_output_and_acknowledges_remote_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ssh")
        .canonicalize()?;
    let path = std::env::var_os("PATH").ok_or("PATH is required")?;
    let selected = std::env::split_paths(&path)
        .find_map(|directory| {
            let candidate = directory.join("ssh");
            candidate.is_file().then_some(candidate)
        })
        .ok_or("local SSH transport fixture is required")?;
    assert_eq!(
        selected.canonicalize()?,
        fixture,
        "refuse real SSH transport"
    );
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    // Give this independently loaded module its own native-library identity;
    // another artifact fixture may load the original path concurrently.
    let artifact_directory = tempfile::tempdir()?;
    // The module host checks every ancestor with symlink_metadata, so preserve
    // the real path rather than tempfile's possibly symlinked TMPDIR spelling.
    let artifact_directory_path = artifact_directory.path().canonicalize()?;
    let isolated_artifact = artifact_directory_path.join(
        std::path::Path::new(&artifact)
            .file_name()
            .ok_or("module filename is required")?,
    );
    std::fs::copy(artifact, &isolated_artifact)?;
    let workspace = tempfile::tempdir()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    modules.load_file(isolated_artifact)?;
    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    proxy
        .call::<ResourceInfo>(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                host: tinybox_bus::HostConfig::Ssh(tinybox_bus::SshHostConfig {
                    destination: "fixture.invalid".into(),
                    port: None,
                    identity: None,
                    known_hosts: None,
                    accept_new_host_key: false,
                }),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;
    verify_live_output(&proxy, &resource).await?;
    verify_binary_stdin(&proxy, &resource).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

/// The caller prepends the checked-in local Docker fixture to PATH before starting
/// this process; no runtime environment mutation or real Docker server is needed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE and the local Docker fixture first on PATH"]
async fn compiled_module_streams_docker_output_and_acknowledges_container_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/docker")
        .canonicalize()?;
    let path = std::env::var_os("PATH").ok_or("PATH is required")?;
    let selected = std::env::split_paths(&path)
        .find_map(|directory| {
            let candidate = directory.join("docker");
            candidate.is_file().then_some(candidate)
        })
        .ok_or("local Docker transport fixture is required")?;
    assert_eq!(
        selected.canonicalize()?,
        fixture,
        "refuse real Docker transport"
    );
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    // Give this independently loaded module its own native-library identity;
    // another artifact fixture may load the original path concurrently.
    let artifact_directory = tempfile::tempdir()?;
    // The module host checks every ancestor with symlink_metadata, so preserve
    // the real path rather than tempfile's possibly symlinked TMPDIR spelling.
    let artifact_directory_path = artifact_directory.path().canonicalize()?;
    let isolated_artifact = artifact_directory_path.join(
        std::path::Path::new(&artifact)
            .file_name()
            .ok_or("module filename is required")?,
    );
    std::fs::copy(artifact, &isolated_artifact)?;
    let workspace = tempfile::tempdir()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    modules.load_file(isolated_artifact)?;
    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    proxy
        .call::<ResourceInfo>(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "docker".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;
    verify_docker_rejects_local_jail(&proxy, &resource).await?;
    verify_live_output(&proxy, &resource).await?;
    verify_binary_stdin(&proxy, &resource).await?;
    verify_cancellation_is_scoped(&proxy, &resource).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

async fn wait_until_serving(
    client: &Connection,
    modules: &ModuleHost,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await?
                .iter()
                .any(|name| name.as_str() == BUS_NAME)
            {
                return Ok::<(), tinybus::Error>(());
            }
            if modules
                .list()
                .first()
                .is_some_and(|module| matches!(module.state, ModuleState::Faulted { .. }))
            {
                return Err(tinybus::Error::failed(
                    "TinyBox module faulted during startup",
                ));
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("module service did not start before deadline: {error}"),
        )
    })??;
    Ok(())
}

async fn wait_until_idle(modules: &ModuleHost) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = modules
                .list()
                .first()
                .map(|module| module.state.clone())
                .ok_or_else(|| tinybus::Error::failed("loaded TinyBox module disappeared"))?;
            match state {
                ModuleState::Ready => return Ok::<(), tinybus::Error>(()),
                ModuleState::Serving => tokio::task::yield_now().await,
                _ => return Err(tinybus::Error::failed("TinyBox module left service")),
            }
        }
    })
    .await
    .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("module service did not become idle before deadline: {error}"),
        )
    })??;
    Ok(())
}

#[cfg(unix)]
#[expect(
    clippy::too_many_lines,
    reason = "single compiled-artifact lifecycle fixture verifies output, replay and acknowledged cancellation"
)]
async fn verify_live_output(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{
        ExecRequest, ExecutionState, OutputBatch, OutputStream, ProcessRef, SpawnRequest,
    };
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let request = SpawnRequest {
        process,
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf '\\377\\000'; printf error >&2; exit 7".into(),
            ],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let process: ProcessRef = proxy.call("StartExec", (request.clone(),)).await?;
    assert_eq!(
        process,
        proxy.call::<ProcessRef>("StartExec", (request,)).await?
    );
    let batch: OutputBatch = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if batch.state != ExecutionState::Running {
                return Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("output process did not exit before deadline: {error}"),
        )
    })??;
    assert_eq!(batch.state, ExecutionState::Exited { exit_code: 7 });
    let stdout: Vec<u8> = batch
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == OutputStream::Stdout)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    let stderr: Vec<u8> = batch
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == OutputStream::Stderr)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    assert_eq!(stdout, [255, 0]);
    assert_eq!(stderr, b"error");
    assert_eq!(
        batch,
        proxy
            .call::<OutputBatch>("ReadOutput", (process.clone(), 0_u64))
            .await?
    );
    proxy
        .call::<()>("ReleaseOutput", (process.clone(),))
        .await?;
    assert!(
        proxy
            .call::<OutputBatch>("ReadOutput", (process, 0_u64))
            .await
            .is_err()
    );

    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let process: ProcessRef = proxy
        .call(
            "StartExec",
            (SpawnRequest {
                process,
                command: ExecRequest {
                    resource: resource.clone(),
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf ready; exec sleep 600".into(),
                    ],
                    cwd: None,
                    env: std::collections::BTreeMap::default(),
                    stdin: None,
                },
            },),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if !batch.chunks.is_empty() {
                assert_eq!(batch.state, ExecutionState::Running);
                return Ok::<_, tinybus::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("cancellation process did not publish output before deadline: {error}"),
        )
    })??;
    assert!(
        proxy
            .call::<()>("ReleaseOutput", (process.clone(),))
            .await
            .is_err()
    );
    proxy.call::<()>("Cancel", (process.clone(),)).await?;
    let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
    assert_eq!(batch.state, ExecutionState::Cancelled);
    assert_eq!(
        batch
            .chunks
            .iter()
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect::<Vec<_>>(),
        b"ready"
    );
    assert!(!proxy.call::<bool>("IsRunning", (process.clone(),)).await?);
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_binary_stdin(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, ExecutionState, OutputBatch, ProcessRef, SpawnRequest};
    let input = vec![0, 1, 255, 0, 42];
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let process: ProcessRef = proxy
        .call(
            "StartExec",
            (SpawnRequest {
                process,
                command: ExecRequest {
                    resource: resource.clone(),
                    argv: vec!["/bin/cat".into()],
                    cwd: None,
                    env: std::collections::BTreeMap::default(),
                    stdin: Some(input.clone()),
                },
            },),
        )
        .await?;
    let batch: OutputBatch = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if batch.state != ExecutionState::Running {
                return Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("stdin process did not exit before deadline: {error}"),
        )
    })??;
    assert_eq!(batch.state, ExecutionState::Exited { exit_code: 0 });
    assert_eq!(
        batch
            .chunks
            .iter()
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect::<Vec<_>>(),
        input
    );
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_native_jail(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{
        ExecRequest, ExecutionState, JailEnforcement, NativeJailConfig, OutputBatch, ProcessRef,
        SpawnRequest,
    };
    let id: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let outside = tempfile::tempdir()?;
    let forbidden = outside.path().join("forbidden");
    let request = SpawnRequest {
        process: id,
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "if printf escaped > \"$1\" 2>/dev/null; then exit 9; fi; printf confined".into(),
                "fixture".into(),
                forbidden.to_string_lossy().into_owned(),
            ],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let config = NativeJailConfig {
        read_only: ["/usr", "/bin", "/lib", "/lib64", "/dev"]
            .into_iter()
            .filter(|path| std::path::Path::new(path).exists())
            .map(str::to_owned)
            .collect(),
        read_write: vec![],
        allow_net: true,
        allow_subprocess: true,
        enforcement: JailEnforcement::Enforced,
        require_process_isolation: false,
        deny_read: Vec::new(),
        resources: None,
    };
    let status: tinybox_bus::JailStatus = proxy.call("JailStatus", ()).await?;
    eprintln!(
        "native jail fixture: backend={} available={} filesystem={}",
        status.backend, status.available, status.filesystem
    );
    let started = proxy
        .call::<ProcessRef>("StartJailedExec", (request.clone(), config.clone()))
        .await;
    if status.available && status.filesystem == "enforced" {
        let process = started?;
        assert_eq!(
            proxy
                .call::<ProcessRef>("StartJailedExec", (request.clone(), config.clone()))
                .await?,
            process
        );
        let mut changed = config.clone();
        changed.require_process_isolation = true;
        assert!(
            proxy
                .call::<ProcessRef>("StartJailedExec", (request, changed))
                .await
                .is_err()
        );
        let batch: OutputBatch = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
                if batch.state != ExecutionState::Running {
                    return Ok::<_, tinybus::Error>(batch);
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        assert_eq!(batch.state, ExecutionState::Exited { exit_code: 0 });
        assert_eq!(
            batch
                .chunks
                .iter()
                .filter(|chunk| chunk.stream == tinybox_bus::OutputStream::Stdout)
                .flat_map(|chunk| chunk.bytes.iter().copied())
                .collect::<Vec<_>>(),
            b"confined"
        );
        proxy.call::<()>("ReleaseOutput", (process,)).await?;
        verify_jailed_cancel(proxy, resource, config).await?;
    } else {
        assert!(started.is_err());
    }
    assert!(!forbidden.exists());
    Ok(())
}

#[cfg(unix)]
async fn verify_jailed_cancel(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
    config: tinybox_bus::NativeJailConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, ExecutionState, OutputBatch, ProcessRef, SpawnRequest};
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let process: ProcessRef = proxy
        .call(
            "StartJailedExec",
            (
                SpawnRequest {
                    process,
                    command: ExecRequest {
                        resource: resource.clone(),
                        argv: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "printf ready; sleep 600".into(),
                        ],
                        cwd: None,
                        env: std::collections::BTreeMap::default(),
                        stdin: None,
                    },
                },
                config,
            ),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if !batch.chunks.is_empty() {
                break;
            }
            assert_eq!(batch.state, ExecutionState::Running);
            tokio::task::yield_now().await;
        }
        proxy.call::<()>("Cancel", (process.clone(),)).await
    })
    .await??;
    let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
    assert_eq!(batch.state, ExecutionState::Cancelled);
    assert!(!proxy.call::<bool>("IsRunning", (process.clone(),)).await?);
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_docker_rejects_local_jail(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, JailEnforcement, NativeJailConfig, ProcessRef, SpawnRequest};
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let request = SpawnRequest {
        process,
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec!["/bin/true".into()],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let result = proxy
        .call::<ProcessRef>(
            "StartJailedExec",
            (
                request.clone(),
                NativeJailConfig {
                    read_only: Vec::new(),
                    read_write: Vec::new(),
                    allow_net: true,
                    allow_subprocess: true,
                    enforcement: JailEnforcement::Declared,
                    require_process_isolation: false,
                    deny_read: Vec::new(),
                    resources: None,
                },
            ),
        )
        .await;
    assert_eq!(
        result
            .err()
            .ok_or("Docker admitted local jail execution")?
            .wire_name(),
        tinybox_bus::UNSUPPORTED_OPERATION
    );
    let process: ProcessRef = proxy.call("StartExec", (request,)).await?;
    proxy.call::<()>("Cancel", (process.clone(),)).await?;
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_cancellation_is_scoped(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, ExecutionState, OutputBatch, ProcessRef, SpawnRequest};
    let mut processes = Vec::new();
    for _ in 0..2 {
        let process: ResourceId = proxy
            .call("Reserve", (ReserveRequest::Process(resource.clone()),))
            .await?;
        let process: ProcessRef = proxy
            .call(
                "StartExec",
                (SpawnRequest {
                    process,
                    command: ExecRequest {
                        resource: resource.clone(),
                        argv: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "printf ready; exec sleep 600".into(),
                        ],
                        cwd: None,
                        env: std::collections::BTreeMap::default(),
                        stdin: None,
                    },
                },),
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
                if !batch.chunks.is_empty() {
                    assert_eq!(batch.state, ExecutionState::Running);
                    return Ok::<_, tinybus::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        processes.push(process);
    }
    proxy.call::<()>("Cancel", (processes[0].clone(),)).await?;
    let other: OutputBatch = proxy
        .call("ReadOutput", (processes[1].clone(), 0_u64))
        .await?;
    assert_eq!(other.state, ExecutionState::Running);
    assert!(
        proxy
            .call::<bool>("IsRunning", (processes[1].clone(),))
            .await?
    );
    for process in processes {
        proxy.call::<()>("Cancel", (process.clone(),)).await?;
        let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
        assert_eq!(batch.state, ExecutionState::Cancelled);
        proxy.call::<()>("ReleaseOutput", (process,)).await?;
    }
    Ok(())
}

fn stage_allowlisted_module(
    source: &std::path::Path,
) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let parent = source
        .parent()
        .ok_or_else(|| std::io::Error::other("module artifact has no parent directory"))?;
    let name = source
        .file_name()
        .ok_or_else(|| std::io::Error::other("module artifact has no filename"))?;
    let staging = tempfile::tempdir_in(parent)?;
    let staged = staging.path().join(name);
    std::fs::copy(source, &staged)?;
    let digest = tinybus::module::sha256_file(&staged)?;
    std::fs::write(
        staging.path().join("modules.toml"),
        format!("{:?} = {:?}\n", name.to_string_lossy(), digest),
    )?;
    Ok((staging, staged))
}

async fn connect_migration_peer(broker: &Broker, controller: bool) -> tinybus::Result<Connection> {
    let (broker_transport, client_transport) = tinybus::transport::memory::MemoryTransport::pair();
    if controller {
        broker.attach_module_controller(std::sync::Arc::new(broker_transport))?;
    } else {
        broker.attach(std::sync::Arc::new(broker_transport));
    }
    Connection::connect(Box::new(client_transport)).await
}

fn legacy_v1_box() -> serde_json::Value {
    serde_json::json!({
        "id": "build-1",
        "state": "Ready",
        "spec": {
            "runner": {"host": "local", "sandbox": "passthrough"},
            "workspace": {"host": "local", "sandbox": "passthrough"},
            "source": {"LocalDir": "/srv/work"},
            "resources": {
                "cpu_millis": 2000,
                "memory_bytes": 2_147_483_648_u64,
                "pids_max": 512,
                "disk_bytes": 8_589_934_592_u64,
            },
            "lifecycle": {"Ephemeral": {"ttl": {"secs": 3600, "nanos": 0}}},
            "network": {"Allowlist": {"hosts": ["example.test"], "ports": [443]}},
            "ports": [{"guest": 80, "host": null}],
            "env": {"KEY": "value"},
        },
        "created_at": {"secs_since_epoch": 1_700_000_000_u64, "nanos_since_epoch": 5_000_000_u32},
    })
}

fn legacy_v1_jail_index() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "records": {
            "j1": {
                "id": "j1",
                "label": "build",
                "dir": "/srv/j1",
                "backend_at_create": "landlock",
                "created_at_unix": 1_700_000_000_u64,
                "updated_at_unix": 1_700_000_060_u64,
                "notes": "keep",
            },
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE to point at the built cdylib"]
async fn compiled_module_migrates_owner_data_before_storage_is_served()
-> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{CreateRequest, ReserveRequest, ResourceInfo};
    use tinystoragedrivers_tinybus::migration::{
        EXCHANGE_MEMBER, GET_SCHEMA_MEMBER, MIGRATION_INTERFACE, MIGRATION_OBJECT_PATH,
    };

    let source = std::env::var_os("TINYBOX_TEST_MODULE")
        .map(std::path::PathBuf::from)
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    let fixture = load_compiled_migration_fixture(&source).await?;
    let (backend, _storage) = migrate_legacy_box(fixture.module).await?;

    let outsider_migration = fixture.outsider.proxy(
        fixture.module_peer.as_str(),
        MIGRATION_OBJECT_PATH,
        MIGRATION_INTERFACE,
    )?;
    let denied = outsider_migration
        .call_confidential::<serde_json::Value>(EXCHANGE_MEMBER, serde_json::json!(17))
        .await
        .err()
        .ok_or("outsider's malformed migration exchange unexpectedly succeeded")?;
    assert!(
        denied
            .to_string()
            .contains("migration authority unavailable")
    );

    let registration = attach_box_storage(
        &fixture.modules,
        &fixture.controller,
        Arc::clone(&backend),
    )
    .await?;
    let (lease_a, descriptor_a) =
        register_box_lease(&registration, &fixture.module_peer, "local").await?;
    reinitialize_box(&fixture.modules, descriptor_a.clone()).await?;
    let proxy = fixture.controller.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let workspace_a = tempfile::tempdir()?;
    let resource_a = create_passthrough_resource(&proxy, workspace_a.path()).await?;
    assert_eq!(
        box_record_count(&backend, "local").await?,
        2,
        "TinyBox opens its ordinary storage path only after host migration completes"
    );

    let profile_b = "box-other-profile";
    let migration_b = tinystoragedrivers_tinybus::migration::MigrationModuleClient::discover(
        &fixture.controller,
        &fixture.module_peer,
    )
    .await?;
    migrate_empty_box_profile(&backend, profile_b, migration_b).await?;
    let (_lease_b, descriptor_b) =
        register_box_lease(&registration, &fixture.module_peer, profile_b).await?;
    reinitialize_box(&fixture.modules, descriptor_b.clone()).await?;
    assert_eq!(
        proxy
            .call::<ResourceInfo>("Inspect", (resource_a.resource.clone(),))
            .await?
            .resource,
        resource_a.resource,
        "resource A remains in the shared module registry after binding B"
    );
    let workspace_b = tempfile::tempdir()?;
    let resource_b = create_passthrough_resource(&proxy, workspace_b.path()).await?;
    assert_eq!(box_record_count(&backend, "local").await?, 2);
    assert_eq!(box_record_count(&backend, profile_b).await?, 1);

    let (_invalid_lease, descriptor_invalid) =
        register_box_lease(&registration, &fixture.module_peer, "box-invalid-profile").await?;
    let mut forged_descriptor = serde_json::to_value(&descriptor_invalid)?;
    forged_descriptor["registration_id"] = serde_json::json!(u64::MAX);
    assert!(
        fixture
            .modules
            .reinitialize(
                "tinybox-module",
                serde_json::json!({"storage_descriptor": forged_descriptor}),
            )
            .await
            .is_err(),
        "a malformed descriptor must fail before service replacement"
    );
    assert_eq!(
        proxy
            .call::<ResourceInfo>("Inspect", (resource_b.resource.clone(),))
            .await?
            .resource,
        resource_b.resource,
        "failed reinitialization leaves B's active service and resource live"
    );

    reinitialize_box(&fixture.modules, descriptor_a).await?;
    assert_eq!(
        proxy
            .call::<ResourceInfo>("Inspect", (resource_b.resource.clone(),))
            .await?
            .resource,
        resource_b.resource,
        "resource B keeps its original store after reinitializing A"
    );
    let workspace_a2 = tempfile::tempdir()?;
    let resource_a2 = create_passthrough_resource(&proxy, workspace_a2.path()).await?;
    assert_eq!(box_record_count(&backend, "local").await?, 3);
    assert_eq!(box_record_count(&backend, profile_b).await?, 1);

    proxy
        .call::<()>("Close", (resource_a.resource.clone(),))
        .await?;
    proxy
        .call::<()>("Close", (resource_a2.resource.clone(),))
        .await?;
    proxy
        .call::<()>("Close", (resource_b.resource.clone(),))
        .await?;
    assert_eq!(box_record_count(&backend, "local").await?, 1);
    assert_eq!(box_record_count(&backend, profile_b).await?, 0);

    assert!(registration.revoke(&lease_a).await);
    let workspace_revoked = tempfile::tempdir()?;
    let failed_resource = proxy
        .call::<ResourceInfo>(
            "Create",
            (CreateRequest {
                resource: proxy.call("Reserve", (ReserveRequest::Resource,)).await?,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(
                    workspace_revoked.path().to_string_lossy().into_owned(),
                ),
                ..Default::default()
            },),
        )
        .await
        .err()
        .ok_or("a revoked current-only lease unexpectedly created a resource")?;
    assert_eq!(failed_resource.wire_name(), tinybox_bus::BACKEND_ERROR);
    assert_eq!(box_record_count(&backend, "local").await?, 1);

    reinitialize_box(&fixture.modules, descriptor_b).await?;
    let workspace_b2 = tempfile::tempdir()?;
    let _resource_b2 = create_passthrough_resource(&proxy, workspace_b2.path()).await?;
    assert_eq!(box_record_count(&backend, "local").await?, 1);
    assert_eq!(box_record_count(&backend, profile_b).await?, 1);

    let (lease_revoked, descriptor_revoked) =
        register_box_lease(&registration, &fixture.module_peer, "box-revoked-profile").await?;
    assert!(registration.revoke(&lease_revoked).await);
    assert!(
        fixture
            .modules
            .reinitialize(
                "tinybox-module",
                serde_json::json!({"storage_descriptor": descriptor_revoked}),
            )
            .await
            .is_err(),
        "a revoked descriptor must fail before service replacement"
    );
    let workspace_b3 = tempfile::tempdir()?;
    let _resource_b3 = create_passthrough_resource(&proxy, workspace_b3.path()).await?;
    assert_eq!(box_record_count(&backend, profile_b).await?, 2);

    proxy.call::<()>("Shutdown", ()).await?;
    assert_eq!(box_record_count(&backend, "local").await?, 1);
    assert_eq!(box_record_count(&backend, profile_b).await?, 0);
    assert_eq!(
        fixture
            .controller
            .proxy(
                fixture.module_peer.as_str(),
                MIGRATION_OBJECT_PATH,
                MIGRATION_INTERFACE,
            )?
            .call_confidential::<serde_json::Value>(GET_SCHEMA_MEMBER, ())
            .await?["declaration"]["owner"],
        "box",
        "the selected host and module remain live after storage operations"
    );
    registration.shutdown().await?;
    fixture.modules.shutdown(Duration::from_secs(5)).await;
    Ok(())
}

#[derive(Clone)]
struct BoxStorageContext(String);

impl HostContext for BoxStorageContext {}

struct BoxStorageEnvironment {
    backend: Arc<tinystoragedrivers_core::MemoryStorage>,
}

#[async_trait::async_trait]
impl Environment<BoxStorageContext> for BoxStorageEnvironment {
    async fn resolve(
        &self,
        context: &BoxStorageContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<ResolvedStorage, HostFailure> {
        let scope = tinystoragedrivers_core::Scope::new(&context.0)
            .map_err(|_| HostFailure::Denied("invalid-box-test-scope"))?;
        let storage = self
            .backend
            .for_scope(&scope)
            .map_err(|_| HostFailure::Denied("box-test-storage-unavailable"))?;
        let collections = [
            tinystoragedrivers_bus::CollectionSpec {
                name: tinybox_bus::BOX_COLLECTION.to_owned(),
                indexes: Vec::new(),
                ttl_field: None,
                search: None,
            },
            tinystoragedrivers_bus::CollectionSpec {
                name: tinybox_bus::JAIL_INDEX_COLLECTION.to_owned(),
                indexes: Vec::new(),
                ttl_field: None,
                search: None,
            },
        ];
        let grant = StorageGrant::from_needs(
            tinystoragedrivers_bus::StorageNeeds {
                collections: &collections,
                ..tinystoragedrivers_bus::StorageNeeds::default()
            },
            &GrantPolicy {
                writable: true,
                ..GrantPolicy::default()
            },
        )
        .map_err(|_| HostFailure::Denied("invalid-box-test-grant"))?;
        Ok(ResolvedStorage {
            backend_identity: format!("tinybox-memory-{}", context.0),
            binding_epoch: 1,
            canonical_scope: context.0.clone(),
            grant,
            server: Arc::new(StorageServer::new(storage)),
        })
    }

    async fn admit_write(
        &self,
        _context: &BoxStorageContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<(), HostFailure> {
        Ok(())
    }
}

struct BoxTestAudit;

impl AuditSink for BoxTestAudit {
    fn record(&self, _event: AuditEvent) {}
}

type BoxStorageRegistration = tinystoragedrivers_tinybus::StorageRegistration<
    BoxStorageEnvironment,
    BoxTestAudit,
    BoxStorageContext,
>;

async fn attach_box_storage(
    host: &ModuleHost,
    observer: &Connection,
    backend: Arc<tinystoragedrivers_core::MemoryStorage>,
) -> Result<BoxStorageRegistration, Box<dyn std::error::Error>> {
    tinystoragedrivers_tinybus::attach_storage(
        host,
        observer,
        GovernedStorage::new(
            Arc::new(BoxStorageEnvironment { backend }),
            Arc::new(BoxTestAudit),
            GovernedEndpointLimits::default(),
        ),
        tokio::runtime::Handle::current(),
    )
    .await
    .map_err(|_| std::io::Error::other("governed Box storage registration failed").into())
}

async fn register_box_lease(
    registration: &BoxStorageRegistration,
    peer: &tinybus::BusName,
    profile: &str,
) -> Result<
    (
        tinystoragedrivers_busproxy::StorageLease,
        tinystoragedrivers_busproxy::StorageDescriptor,
    ),
    Box<dyn std::error::Error>,
> {
    registration
        .register_lease(
            HostStorageContext::new(BoxStorageContext(profile.to_owned())),
            peer.clone(),
        )
        .await
        .map_err(|_| std::io::Error::other("governed Box lease registration failed").into())
}

async fn reinitialize_box(
    modules: &ModuleHost,
    descriptor: tinystoragedrivers_busproxy::StorageDescriptor,
) -> tinybus::Result<()> {
    modules
        .reinitialize(
            "tinybox-module",
            serde_json::json!({"storage_descriptor": descriptor}),
        )
        .await
        .map(|_| ())
}

async fn create_passthrough_resource(
    proxy: &tinybus::Proxy,
    workspace: &std::path::Path,
) -> tinybus::Result<ResourceInfo> {
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    proxy
        .call(
            "Create",
            (CreateRequest {
                resource,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(workspace.to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await
}

async fn box_record_count(
    backend: &Arc<tinystoragedrivers_core::MemoryStorage>,
    profile: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    use tinystoragedrivers_core::{DocumentStoreExt, Query, Scope, StorageBackend};

    let scope = Scope::new(profile)?;
    let storage = backend.as_ref().for_scope(&scope)?;
    Ok(storage
        .documents()
        .query_all(tinybox_drivers::BOX_COLLECTION, &Query::all())
        .await?
        .len())
}

async fn migrate_empty_box_profile(
    backend: &Arc<tinystoragedrivers_core::MemoryStorage>,
    profile: &str,
    migration: tinystoragedrivers_tinybus::migration::MigrationModuleClient,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinystoragedrivers_core::{
        MigrateOptions, Registry, Scope, StorageBackend, schema::delivery::MigrationDeliveryClient,
    };

    let scope = Scope::new(profile)?;
    let registry = Registry::compose_with_declarations(
        std::iter::empty::<tinystoragedrivers_core::Schema>(),
        [migration.declaration().clone()],
    )?;
    registry.prepare(backend.as_ref()).await?;
    let storage = backend.as_ref().for_scope(&scope)?;
    let executor = MigrationDeliveryClient::new(Arc::new(migration));
    registry
        .migrate_with_executor(&storage, &MigrateOptions::new(), &executor)
        .await?;
    registry.check_ready_in(&scope, tinybox_drivers::BOX_COLLECTION)?;
    registry.check_ready_in(&scope, tinybox_drivers::JAIL_INDEX_COLLECTION)?;
    Ok(())
}

struct CompiledMigrationFixture {
    _staging: tempfile::TempDir,
    outsider: Connection,
    controller: Connection,
    modules: ModuleHost,
    module_peer: tinybus::BusName,
    module: tinystoragedrivers_tinybus::migration::MigrationModuleClient,
}

async fn load_compiled_migration_fixture(
    source: &std::path::Path,
) -> Result<CompiledMigrationFixture, Box<dyn std::error::Error>> {
    use tinystoragedrivers_tinybus::migration::MigrationModuleClient;

    let (staging, artifact) = stage_allowlisted_module(source)?;
    let broker = Broker::new_restricted_module_control();
    let controller = connect_migration_peer(&broker, true).await?;
    let outsider = connect_migration_peer(&broker, false).await?;
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(&artifact)?;
    modules
        .ensure_ready(loaded.manifest.bus_name.as_str())
        .await?;
    let module_peer = controller
        .name_owner(loaded.manifest.bus_name.as_str())
        .await?
        .ok_or("compiled TinyBox module did not acquire its bus name")?;
    let module = MigrationModuleClient::discover(&controller, &module_peer).await?;
    Ok(CompiledMigrationFixture {
        _staging: staging,
        outsider,
        controller,
        modules,
        module_peer,
        module,
    })
}

async fn migrate_legacy_box(
    module: tinystoragedrivers_tinybus::migration::MigrationModuleClient,
) -> Result<
    (
        Arc<tinystoragedrivers_core::MemoryStorage>,
        tinystoragedrivers_core::ScopedStorage,
    ),
    Box<dyn std::error::Error>,
> {
    use tinystoragedrivers_core::{
        MemoryStorage, Precondition, Scope, StorageBackend,
        schema::{MigrateOptions, Registry, delivery::MigrationDeliveryClient},
    };

    assert_eq!(module.declaration().owner.as_str(), "box");
    assert!(
        module
            .declaration()
            .items
            .iter()
            .any(|item| item.name() == tinybox_bus::BOX_COLLECTION)
    );
    assert!(
        module
            .declaration()
            .items
            .iter()
            .any(|item| item.name() == tinybox_bus::JAIL_INDEX_COLLECTION)
    );
    let backend = Arc::new(MemoryStorage::new());
    let migration_scope = Scope::local();
    let registry =
        Registry::compose_with_declarations(std::iter::empty(), [module.declaration().clone()])?;
    registry.prepare(backend.as_ref()).await?;
    let storage = backend.for_scope(&migration_scope)?;
    storage
        .documents()
        .ensure_collection(&tinystoragedrivers_core::CollectionSpec::new(
            "tinybox_boxes",
        ))
        .await?;
    storage
        .documents()
        .ensure_collection(&tinystoragedrivers_core::CollectionSpec::new(
            "tinybox_jail_index",
        ))
        .await?;
    storage
        .documents()
        .put(
            "tinybox_boxes",
            "build-1",
            legacy_v1_box(),
            Precondition::Absent,
        )
        .await?;
    storage
        .documents()
        .put(
            "tinybox_jail_index",
            "main",
            legacy_v1_jail_index(),
            Precondition::Absent,
        )
        .await?;
    let executor = MigrationDeliveryClient::new(std::sync::Arc::new(module));
    registry
        .migrate_with_executor(&storage, &MigrateOptions::new(), &executor)
        .await?;
    registry.check_ready_in(&migration_scope, "box.boxes")?;
    registry.check_ready_in(&migration_scope, "box.jail_index")?;
    assert_migrated_owner_rows(&storage).await?;
    Ok((backend, storage))
}

async fn assert_migrated_owner_rows(
    storage: &tinystoragedrivers_core::ScopedStorage,
) -> Result<(), Box<dyn std::error::Error>> {
    let migrated = storage
        .documents()
        .get("box.boxes", "build-1")
        .await?
        .ok_or("migration did not write the TinyBox v2 target")?;
    assert_eq!(migrated.doc["state"], "ready");
    assert_eq!(migrated.doc["created_ms"], 1_700_000_000_005_i64);
    assert_eq!(migrated.doc["spec"]["source"]["kind"], "local_dir");
    assert!(
        storage
            .documents()
            .get("tinybox_boxes", "build-1")
            .await?
            .is_none(),
        "legacy Box rows are removed after the owner conversion succeeds"
    );
    let migrated_index = storage
        .documents()
        .get("box.jail_index", "main")
        .await?
        .ok_or("migration did not write the TinyBox jail-index target")?;
    assert_eq!(
        migrated_index.doc["records"]["j1"]["created_ms"],
        1_700_000_000_000_i64
    );
    assert_eq!(
        migrated_index.doc["records"]["j1"]["updated_ms"],
        1_700_000_060_000_i64
    );
    assert!(
        storage
            .documents()
            .get("tinybox_jail_index", "main")
            .await?
            .is_none(),
        "legacy jail-index rows are removed after the owner conversion succeeds"
    );
    Ok(())
}
