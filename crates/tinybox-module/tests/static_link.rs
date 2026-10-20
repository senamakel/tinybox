//! The statically linked build is admitted by a `ModuleHost` and reaches `Ready`.

#![cfg(feature = "static-link")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use tinybus::{
    Connection,
    broker::Broker,
    module::{ModuleHost, ModuleState},
    transport::memory::{MemoryBus, MemoryTransport},
};
use tinystoragedrivers_busproxy::{
    AuditEvent, AuditSink, Environment, GovernedEndpointLimits, GovernedStorage, GrantPolicy,
    HostContext, HostFailure, HostStorageContext, ResolvedStorage, StorageGrant,
};
use tinystoragedrivers_client::StorageServer;
use tinystoragedrivers_core::{DocumentStoreExt, MemoryStorage, Scope, StorageBackend};

const BUS_NAME: &str = "ai.tinyhumans.tinybox.Box";

#[derive(Clone)]
struct TestStorageContext(String);

impl HostContext for TestStorageContext {}

struct TestStorageEnvironment {
    backend: std::sync::Arc<MemoryStorage>,
}

#[async_trait::async_trait]
impl Environment<TestStorageContext> for TestStorageEnvironment {
    async fn resolve(
        &self,
        context: &TestStorageContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<ResolvedStorage, HostFailure> {
        let scope =
            Scope::new(&context.0).map_err(|_| HostFailure::Denied("invalid-test-scope"))?;
        let storage = self
            .backend
            .for_scope(&scope)
            .map_err(|_| HostFailure::Denied("storage-unavailable"))?;
        let collections = [
            tinybox_bus::CollectionSpec {
                name: tinybox_bus::BOX_COLLECTION.to_owned(),
                indexes: Vec::new(),
                ttl_field: None,
                search: None,
            },
            tinybox_bus::CollectionSpec {
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
        .map_err(|_| HostFailure::Denied("invalid-test-grant"))?;
        Ok(ResolvedStorage {
            backend_identity: format!("tinybox-static-test-{}", context.0),
            binding_epoch: 1,
            canonical_scope: context.0.clone(),
            grant,
            server: std::sync::Arc::new(StorageServer::new(storage)),
        })
    }

    async fn admit_write(
        &self,
        _context: &TestStorageContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<(), HostFailure> {
        Ok(())
    }
}

struct TestAudit;

impl AuditSink for TestAudit {
    fn record(&self, _event: AuditEvent) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_module_is_admitted_and_becomes_ready() {
    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker
        .attach_module_controller(std::sync::Arc::new(broker_transport))
        .expect("module controller is selected");
    let _controller = Connection::connect(Box::new(controller_transport))
        .await
        .expect("controller connects");
    broker.clone().spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let info = host
        .attach_linked_with_config(tinybox::linked_module().unwrap(), serde_json::json!({}))
        .expect("linked module is admitted");
    assert_eq!(info.name, "tinybox-module");
    host.ensure_ready(info.manifest.bus_name.as_str())
        .await
        .expect("linked module initializes with its selected host");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if host
                .list()
                .iter()
                .any(|module| matches!(module.state, ModuleState::Ready))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("linked module reaches Ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_module_uses_its_host_issued_storage_descriptor()
-> Result<(), Box<dyn std::error::Error>> {
    use tinystoragedrivers_busproxy::HostStorageContext;

    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker.attach_module_controller(std::sync::Arc::new(broker_transport))?;
    let controller = Connection::connect(Box::new(controller_transport)).await?;
    let broker_task = broker.spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let info = host.attach_linked_with_config(tinybox::linked_module()?, serde_json::json!({}))?;
    host.ensure_ready(info.manifest.bus_name.as_str()).await?;

    let backend = std::sync::Arc::new(MemoryStorage::new());
    tinystoragedrivers_core::schema::Registry::compose([tinybox_drivers::storage_schema()])?
        .prepare(backend.as_ref())
        .await?;
    let registration = tinystoragedrivers_tinybus::attach_storage(
        &host,
        &controller,
        GovernedStorage::new(
            std::sync::Arc::new(TestStorageEnvironment {
                backend: backend.clone(),
            }),
            std::sync::Arc::new(TestAudit),
            GovernedEndpointLimits::default(),
        ),
        tokio::runtime::Handle::current(),
    )
    .await
    .map_err(|_| std::io::Error::other("governed storage attachment failed"))?;
    let module_peer = controller
        .name_owner(BUS_NAME)
        .await?
        .ok_or("linked TinyBox module has no unique peer")?;
    let (lease, descriptor) = registration
        .register_lease(
            HostStorageContext::new(TestStorageContext("box-profile".into())),
            module_peer,
        )
        .await
        .map_err(|_| std::io::Error::other("governed storage lease failed"))?;
    host.reinitialize(
        "tinybox-module",
        serde_json::json!({"storage_descriptor": descriptor}),
    )
    .await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(
        tinybox_bus::INTERFACE,
        tinybox_bus::OBJECT_PATH,
        tinybox_bus::INTERFACE,
    )?;
    let workspace = tempfile::tempdir()?;
    let resource: tinybox_bus::ResourceId = proxy
        .call("Reserve", (tinybox_bus::ReserveRequest::Resource,))
        .await?;
    let _: tinybox_bus::ResourceInfo = proxy
        .call(
            "Create",
            (tinybox_bus::CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: tinybox_bus::Workspace::Directory(
                    workspace.path().to_string_lossy().into_owned(),
                ),
                ..Default::default()
            },),
        )
        .await?;
    let scope = Scope::new("box-profile")?;
    let records = backend
        .for_scope(&scope)?
        .documents()
        .query_all(
            tinybox_bus::BOX_COLLECTION,
            &tinystoragedrivers_core::Query::all(),
        )
        .await?;
    assert_eq!(
        records.len(),
        1,
        "Create must persist through its bound grant"
    );

    proxy.call::<()>("Close", (resource,)).await?;
    proxy.call::<()>("Shutdown", ()).await?;
    assert!(registration.revoke(&lease).await);
    registration.shutdown().await?;
    host.shutdown(std::time::Duration::from_secs(5)).await;
    broker_task.abort();
    Ok(())
}
