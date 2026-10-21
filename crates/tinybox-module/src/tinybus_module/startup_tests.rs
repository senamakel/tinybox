//! Initial setup tests for the module's host-bound storage route.

use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tinybox_bus::{CreateRequest, ReserveRequest, ResourceId, ResourceInfo, Workspace};
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, PreReadyConfidentialRoute};
use tinybus::transport::memory::{MemoryBus, MemoryTransport};
use tinystoragedrivers_bus::StorageNeeds;
use tinystoragedrivers_busproxy::{
    AuditEvent, AuditSink, Environment, GovernedEndpointLimits, GovernedStorage, GrantPolicy,
    HostContext, HostFailure, HostStorageContext, ResolvedStorage, StorageGrant,
};
use tinystoragedrivers_client::StorageServer;
use tinystoragedrivers_core::{DocumentStoreExt, MemoryStorage, Query, Scope, StorageBackend};
use tinystoragedrivers_tinybus::migration::MigrationModuleClient;

struct SetupStorageContext {
    controller: Connection,
    module_peer: tinybus::BusName,
    require_migration: std::sync::Arc<AtomicBool>,
    migration_attempted: std::sync::Arc<AtomicBool>,
    migration_discovered: std::sync::Arc<AtomicBool>,
}

impl HostContext for SetupStorageContext {}

struct SetupStorageEnvironment {
    backend: std::sync::Arc<MemoryStorage>,
}

#[async_trait]
impl Environment<SetupStorageContext> for SetupStorageEnvironment {
    async fn resolve(
        &self,
        context: &SetupStorageContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<ResolvedStorage, HostFailure> {
        if context.require_migration.load(Ordering::Acquire) {
            context.migration_attempted.store(true, Ordering::Release);
            MigrationModuleClient::discover(&context.controller, &context.module_peer)
                .await
                .map_err(|_| HostFailure::Denied("tinybox-migration-unavailable"))?;
            context.migration_discovered.store(true, Ordering::Release);
        }

        let storage = self
            .backend
            .for_scope(&Scope::local())
            .map_err(|_| HostFailure::Denied("tinybox-test-storage-unavailable"))?;
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
            StorageNeeds {
                collections: &collections,
                ..StorageNeeds::default()
            },
            &GrantPolicy {
                writable: true,
                ..GrantPolicy::default()
            },
        )
        .map_err(|_| HostFailure::Denied("tinybox-test-storage-grant-invalid"))?;
        Ok(ResolvedStorage {
            backend_identity: "tinybox-initial-setup-test".to_owned(),
            binding_epoch: 1,
            canonical_scope: "local".to_owned(),
            grant,
            server: std::sync::Arc::new(StorageServer::new(storage)),
        })
    }

    async fn admit_write(
        &self,
        _context: &SetupStorageContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<(), HostFailure> {
        Ok(())
    }
}

struct SetupStorageAudit;

impl AuditSink for SetupStorageAudit {
    fn record(&self, _event: AuditEvent) {}
}

type SetupStorageRegistration = tinystoragedrivers_tinybus::StorageRegistration<
    SetupStorageEnvironment,
    SetupStorageAudit,
    SetupStorageContext,
>;

struct InitialSetupFixture {
    registration: std::sync::Arc<SetupStorageRegistration>,
    controller: Connection,
    require_migration: std::sync::Arc<AtomicBool>,
    migration_attempted: std::sync::Arc<AtomicBool>,
    migration_discovered: std::sync::Arc<AtomicBool>,
}

static INITIAL_SETUP_FIXTURE: std::sync::OnceLock<std::sync::Mutex<Option<InitialSetupFixture>>> =
    std::sync::OnceLock::new();
static INITIAL_SETUP_LEASE: std::sync::OnceLock<
    std::sync::Mutex<Option<tinystoragedrivers_busproxy::StorageLease>>,
> = std::sync::OnceLock::new();

fn initial_setup_fixture() -> &'static std::sync::Mutex<Option<InitialSetupFixture>> {
    INITIAL_SETUP_FIXTURE.get_or_init(|| std::sync::Mutex::new(None))
}

mod initial_setup_export {
    use super::*;

    async fn setup(context: ModuleSetupContext, _config: BoxModuleConfig) -> TinyBusResult<()> {
        let fixture = initial_setup_fixture()
            .lock()
            .map_err(|_| tinybus::Error::failed("initial TinyBox setup fixture lock poisoned"))?
            .take()
            .ok_or_else(|| tinybus::Error::failed("initial TinyBox setup fixture missing"))?;
        let connection = context.connection().clone();
        let peer = connection
            .unique_name()
            .ok_or_else(|| tinybus::Error::failed("TinyBox setup connection has no unique peer"))?;
        let (lease, descriptor) = fixture
            .registration
            .register_lease(
                HostStorageContext::new(SetupStorageContext {
                    controller: fixture.controller,
                    module_peer: peer.clone(),
                    require_migration: std::sync::Arc::clone(&fixture.require_migration),
                    migration_attempted: std::sync::Arc::clone(&fixture.migration_attempted),
                    migration_discovered: std::sync::Arc::clone(&fixture.migration_discovered),
                }),
                peer,
            )
            .await
            .map_err(|_| tinybus::Error::failed("TinyBox storage lease was refused"))?;

        // Lease creation resolves once before the schema discovery check is
        // enabled. Configured validation must resolve again and discover the
        // actual module-owned migration endpoint before storage is usable.
        fixture.require_migration.store(true, Ordering::Release);
        INITIAL_SETUP_LEASE
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .map_err(|_| tinybus::Error::failed("initial TinyBox setup lease lock poisoned"))?
            .replace(lease);

        super::super::setup_with_context(
            context,
            BoxModuleConfig {
                storage_descriptor: Some(descriptor),
            },
            std::sync::Arc::new(resources::Resources::default()),
        )
        .await
    }

    tinybus_module::module_export_static! {
        setup_with_context = setup,
        config = BoxModuleConfig,
        worker_threads = 2,
        provides = ["ai.tinyhumans.tinybox.Box", "org.tinystoragedrivers.Migration"],
        methods = ["Describe", "Create", "Exec", "Inspect", "Close", "Spawn", "IsRunning", "Cancel", "AnalyzeShell", "Reserve", "Capabilities", "Shutdown", "Forward", "CloseForward", "JailStatus", "AnalyzeCommand", "BeginFileRead", "ReadFileChunk", "FinishFileRead", "BeginFileWrite", "WriteFileChunk", "FinishFileWrite", "AbortFileWrite", "StartExec", "ReadOutput", "ReleaseOutput", "StartJailedExec", "RunDocker", "DockerStatus", "CleanupDocker", "RunDockerWithoutWorkspace", "ResolveLocalGrants", "SelectShell", "StartShellExec", "StartNativeShellExec", "ValidateDockerPolicy", "StartStdio", "WriteStdio", "ReadStdio", "CloseStdin", "KillStdio", "StdioStatus"],
        signals = [],
        requires = [],
        optional = [],
        lazy = false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_bound_storage_validation_discovers_tinybox_migrations()
-> Result<(), Box<dyn std::error::Error>> {
    use tinystoragedrivers_tinybus::migration::{
        EXCHANGE_MEMBER, GET_SCHEMA_MEMBER, MIGRATION_INTERFACE, MIGRATION_OBJECT_PATH,
    };

    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker.attach_module_controller(std::sync::Arc::new(broker_transport))?;
    let controller = Connection::connect(Box::new(controller_transport)).await?;
    let broker_task = broker.spawn(bus);
    let host = ModuleHost::new(broker);
    host.set_pre_ready_confidential_routes(vec![
        PreReadyConfidentialRoute {
            path: MIGRATION_OBJECT_PATH.parse()?,
            interface: MIGRATION_INTERFACE.parse()?,
            member: GET_SCHEMA_MEMBER.parse()?,
        },
        PreReadyConfidentialRoute {
            path: MIGRATION_OBJECT_PATH.parse()?,
            interface: MIGRATION_INTERFACE.parse()?,
            member: EXCHANGE_MEMBER.parse()?,
        },
    ])?;

    let backend = std::sync::Arc::new(MemoryStorage::new());
    tinystoragedrivers_core::schema::Registry::compose([tinybox_drivers::storage_schema()])?
        .prepare(backend.as_ref())
        .await?;
    let require_migration = std::sync::Arc::new(AtomicBool::new(false));
    let migration_attempted = std::sync::Arc::new(AtomicBool::new(false));
    let migration_discovered = std::sync::Arc::new(AtomicBool::new(false));
    let registration: std::sync::Arc<SetupStorageRegistration> = std::sync::Arc::new(
        tinystoragedrivers_tinybus::attach_storage(
            &host,
            &controller,
            GovernedStorage::new(
                std::sync::Arc::new(SetupStorageEnvironment {
                    backend: std::sync::Arc::clone(&backend),
                }),
                std::sync::Arc::new(SetupStorageAudit),
                GovernedEndpointLimits::default(),
            ),
            tokio::runtime::Handle::current(),
        )
        .await
        .map_err(|_| std::io::Error::other("governed TinyBox storage attachment failed"))?,
    );
    *initial_setup_fixture()
        .lock()
        .map_err(|_| std::io::Error::other("initial TinyBox setup fixture lock poisoned"))? =
        Some(InitialSetupFixture {
            registration: std::sync::Arc::clone(&registration),
            controller: controller.clone(),
            require_migration: std::sync::Arc::clone(&require_migration),
            migration_attempted: std::sync::Arc::clone(&migration_attempted),
            migration_discovered: std::sync::Arc::clone(&migration_discovered),
        });

    let info = host.attach_linked_with_config(
        initial_setup_export::linked_module()?,
        serde_json::json!({}),
    )?;
    if let Err(error) = host.ensure_ready(info.manifest.bus_name.as_str()).await {
        return Err(std::io::Error::other(format!(
            "initial TinyBox setup failed (migration required: {}, discover attempted: {}, discover succeeded: {}): {error}",
            require_migration.load(Ordering::Acquire),
            migration_attempted.load(Ordering::Acquire),
            migration_discovered.load(Ordering::Acquire),
        ))
        .into());
    }
    assert!(
        migration_attempted.load(Ordering::Acquire),
        "initial bound storage validation must attempt real migration discovery"
    );
    assert!(
        migration_discovered.load(Ordering::Acquire),
        "initial bound storage validation must discover TinyBox's migration schema before storage is usable"
    );

    let module_peer = controller
        .name_owner(INTERFACE)
        .await?
        .ok_or_else(|| std::io::Error::other("TinyBox module did not request its bus name"))?;
    let migration = MigrationModuleClient::discover(&controller, &module_peer).await?;
    assert_eq!(migration.declaration().owner.as_str(), "box");

    let proxy = controller.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    let workspace = tempfile::tempdir()?;
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
    assert_eq!(created.resource, resource);
    let scoped = backend.for_scope(&Scope::local())?;
    let records = scoped
        .documents()
        .query_all(tinybox_drivers::BOX_COLLECTION, &Query::all())
        .await?;
    assert_eq!(records.len(), 1, "configured storage is usable after setup");
    proxy.call::<()>("Close", (resource,)).await?;

    let lease = INITIAL_SETUP_LEASE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .map_err(|_| std::io::Error::other("initial TinyBox setup lease lock poisoned"))?
        .take()
        .ok_or_else(|| std::io::Error::other("initial TinyBox setup did not retain its lease"))?;
    assert!(registration.revoke(&lease).await);
    let registration = std::sync::Arc::try_unwrap(registration)
        .map_err(|_| std::io::Error::other("TinyBox storage registration remained in use"))?;
    registration.shutdown().await?;
    host.shutdown(Duration::from_secs(2)).await;
    broker_task.abort();
    Ok(())
}
