//! Tests for [`ModuleStorage`]: host-backed box records, jail index documents,
//! the in-memory fallback, and connect retry.

use super::*;

use super::super::{INTERFACE, OBJECT_PATH, setup};
use serde_json::Value;
use tinybox_core::WorkspaceSource;
use tinybox_core::{BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef};
use tinybus::broker::Broker;
use tinybus::transport::memory::MemoryBus;
use tinystoragedrivers_busproxy::{PerCallerEndpoint, ServedStorage, serve};
use tinystoragedrivers_client::StorageServer;
use tinystoragedrivers_core::{
    Capabilities, CollectionSpec, DocumentStore, DocumentStoreExt, Filter, MemoryStorage, Page,
    Precondition, Query, Scope, ScopedStorage, Sort, StorageBackend, StorageError, Version,
    Versioned, WriteOptions,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct DescriptorContext(String);

impl tinystoragedrivers_busproxy::HostContext for DescriptorContext {}

struct DescriptorEnvironment {
    backend: MemoryStorage,
}

#[async_trait::async_trait]
impl tinystoragedrivers_busproxy::Environment<DescriptorContext> for DescriptorEnvironment {
    async fn resolve(
        &self,
        context: &DescriptorContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<
        tinystoragedrivers_busproxy::ResolvedStorage,
        tinystoragedrivers_busproxy::HostFailure,
    > {
        let scope = Scope::new(&context.0)
            .map_err(|_| tinystoragedrivers_busproxy::HostFailure::Denied("invalid-test-scope"))?;
        let storage = self
            .backend
            .for_scope(&scope)
            .map_err(|_| tinystoragedrivers_busproxy::HostFailure::Denied("storage-unavailable"))?;
        let collections = [
            CollectionSpec {
                name: tinybox_drivers::BOX_COLLECTION.to_owned(),
                indexes: Vec::new(),
                ttl_field: None,
                search: None,
            },
            CollectionSpec {
                name: tinybox_drivers::JAIL_INDEX_COLLECTION.to_owned(),
                indexes: Vec::new(),
                ttl_field: None,
                search: None,
            },
        ];
        let grant = tinystoragedrivers_busproxy::StorageGrant::from_needs(
            tinystoragedrivers_bus::StorageNeeds {
                collections: &collections,
                ..tinystoragedrivers_bus::StorageNeeds::default()
            },
            &tinystoragedrivers_busproxy::GrantPolicy {
                writable: true,
                ..tinystoragedrivers_busproxy::GrantPolicy::default()
            },
        )
        .map_err(|_| tinystoragedrivers_busproxy::HostFailure::Denied("invalid-test-grant"))?;
        Ok(tinystoragedrivers_busproxy::ResolvedStorage {
            backend_identity: format!("tinybox-storage-test-{}", context.0),
            binding_epoch: 1,
            canonical_scope: context.0.clone(),
            grant,
            server: Arc::new(StorageServer::new(storage)),
        })
    }

    async fn admit_write(
        &self,
        _context: &DescriptorContext,
        _module: &tinybus::module::ModuleId,
    ) -> Result<(), tinystoragedrivers_busproxy::HostFailure> {
        Ok(())
    }
}

struct DescriptorAudit;

impl tinystoragedrivers_busproxy::AuditSink for DescriptorAudit {
    fn record(&self, _event: tinystoragedrivers_busproxy::AuditEvent) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_descriptor_initializes_box_storage_on_the_authenticated_route() -> TestResult {
    use tinybus::transport::memory::{MemoryBus, MemoryTransport};
    use tinystoragedrivers_busproxy::{
        GovernedEndpointLimits, GovernedStorage, HostStorageContext,
    };

    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker.attach_module_controller(Arc::new(broker_transport))?;
    let controller = Connection::connect(Box::new(controller_transport)).await?;
    let broker_task = broker.spawn(bus.clone());
    let host = tinybus::module::ModuleHost::new(broker);
    let backend = MemoryStorage::new();
    tinystoragedrivers_core::schema::Registry::compose([tinybox_drivers::storage_schema()])?
        .prepare(&backend)
        .await?;
    let registration = tinystoragedrivers_tinybus::attach_storage(
        &host,
        &controller,
        GovernedStorage::new(
            Arc::new(DescriptorEnvironment {
                backend: backend.clone(),
            }),
            Arc::new(DescriptorAudit),
            GovernedEndpointLimits::default(),
        ),
        tokio::runtime::Handle::current(),
    )
    .await
    .map_err(|_| std::io::Error::other("governed storage attachment failed"))?;
    let module = Connection::connect(bus.connect().await?).await?;
    let peer = module
        .unique_name()
        .ok_or("module connection has no authenticated peer")?;
    let (_lease, descriptor) = registration
        .register_lease(
            HostStorageContext::new(DescriptorContext("box-profile".into())),
            peer,
        )
        .await
        .map_err(|_| std::io::Error::other("storage lease registration failed"))?;

    let storage = ModuleStorage::with_descriptor(module, Some(descriptor));
    storage.validate_configured().await?;
    let boxes = storage.box_store().await?;
    let records = tokio::task::spawn_blocking(move || boxes.list()).await??;
    assert!(records.is_empty());

    registration.shutdown().await?;
    host.shutdown(std::time::Duration::from_secs(5)).await;
    broker_task.abort();
    Ok(())
}

/// A broker with a module-side connection and, optionally, a storage host.
struct Rig {
    module: Connection,
    backend: MemoryStorage,
    _served: Option<ServedStorage>,
}

async fn rig(serve_storage: bool) -> Result<Rig, Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let backend = MemoryStorage::new();
    // The host declares what the module may store from the module's own schema.
    tinystoragedrivers_core::schema::Registry::compose([tinybox_drivers::storage_schema()])?
        .prepare(&backend)
        .await?;
    let host = Connection::connect(bus.connect().await?).await?;
    let served = if serve_storage {
        let bound = backend.clone();
        let endpoint = PerCallerEndpoint::new(move |_sender| {
            let scoped: ScopedStorage = bound.for_scope(&Scope::local()).ok()?;
            Some(StorageServer::new(scoped))
        });
        Some(serve(&host, Arc::new(endpoint)).await?)
    } else {
        None
    };
    let module = Connection::connect(bus.connect().await?).await?;
    // Keep the host connection alive for the life of the broker.
    std::mem::forget(host);
    Ok(Rig {
        module,
        backend,
        _served: served,
    })
}

/// Document port that exposes exactly the named collection grant and records
/// every refused collection access.
#[derive(Debug)]
struct CurrentOnlyDocuments {
    inner: Arc<dyn DocumentStore>,
    allowed: std::collections::HashSet<String>,
    refused: Arc<std::sync::Mutex<Vec<String>>>,
}

impl CurrentOnlyDocuments {
    fn check(&self, collection: &str) -> Result<(), StorageError> {
        if self.allowed.contains(collection) {
            return Ok(());
        }
        self.refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(collection.to_owned());
        Err(StorageError::invalid_input(format!(
            "collection `{collection}` is outside this module's storage grant"
        )))
    }
}

#[async_trait::async_trait]
impl DocumentStore for CurrentOnlyDocuments {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StorageError> {
        self.check(&spec.name)?;
        self.inner.ensure_collection(spec).await
    }

    async fn validate_collection_spec(
        &self,
        required: &CollectionSpec,
    ) -> Result<(), StorageError> {
        self.check(&required.name)?;
        self.inner.validate_collection_spec(required).await
    }

    async fn get(
        &self,
        collection: &str,
        id: &str,
    ) -> Result<Option<Versioned<Value>>, StorageError> {
        self.check(collection)?;
        self.inner.get(collection, id).await
    }

    async fn put(
        &self,
        collection: &str,
        id: &str,
        doc: Value,
        precondition: Precondition,
    ) -> Result<Version, StorageError> {
        self.check(collection)?;
        self.inner.put(collection, id, doc, precondition).await
    }

    async fn put_with(
        &self,
        collection: &str,
        id: &str,
        doc: Value,
        precondition: Precondition,
        options: WriteOptions,
    ) -> Result<Version, StorageError> {
        self.check(collection)?;
        self.inner
            .put_with(collection, id, doc, precondition, options)
            .await
    }

    async fn delete(
        &self,
        collection: &str,
        id: &str,
        precondition: Precondition,
    ) -> Result<bool, StorageError> {
        self.check(collection)?;
        self.inner.delete(collection, id, precondition).await
    }

    async fn query(
        &self,
        collection: &str,
        query: &Query,
    ) -> Result<Page<Versioned<Value>>, StorageError> {
        self.check(collection)?;
        self.inner.query(collection, query).await
    }

    async fn count(&self, collection: &str, filter: &Filter) -> Result<u64, StorageError> {
        self.check(collection)?;
        self.inner.count(collection, filter).await
    }

    async fn delete_where(&self, collection: &str, filter: &Filter) -> Result<u64, StorageError> {
        self.check(collection)?;
        self.inner.delete_where(collection, filter).await
    }

    async fn claim(
        &self,
        collection: &str,
        filter: &Filter,
        sort: &[Sort],
        patch: &Value,
    ) -> Result<Option<Versioned<Value>>, StorageError> {
        self.check(collection)?;
        self.inner.claim(collection, filter, sort, patch).await
    }

    async fn drop_collection(&self, collection: &str) -> Result<(), StorageError> {
        self.check(collection)?;
        self.inner.drop_collection(collection).await
    }
}

struct CurrentOnlyRig {
    _host: Connection,
    module: Connection,
    client: Connection,
    backend: MemoryStorage,
    refused: Arc<std::sync::Mutex<Vec<String>>>,
    _served: ServedStorage,
}

async fn current_only_rig(allowed: &[&str]) -> Result<CurrentOnlyRig, Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let backend = MemoryStorage::new();
    tinystoragedrivers_core::schema::Registry::compose([tinybox_drivers::storage_schema()])?
        .prepare(&backend)
        .await?;
    let scope = backend.for_scope(&Scope::local())?;
    let refused = Arc::new(std::sync::Mutex::new(Vec::new()));
    let documents: Arc<dyn DocumentStore> = Arc::new(CurrentOnlyDocuments {
        inner: Arc::clone(scope.documents()),
        allowed: allowed.iter().map(|name| (*name).to_owned()).collect(),
        refused: Arc::clone(&refused),
    });
    let restricted = ScopedStorage::new(
        scope.scope().clone(),
        scope.driver(),
        documents,
        Arc::clone(scope.streams()),
        Arc::clone(scope.blobs()),
    );
    let host = Connection::connect(bus.connect().await?).await?;
    let endpoint =
        PerCallerEndpoint::new(move |_sender| Some(StorageServer::new(restricted.clone())));
    let served = serve(&host, Arc::new(endpoint)).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    Ok(CurrentOnlyRig {
        _host: host,
        module,
        client,
        backend,
        refused,
        _served: served,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_operations_succeed_with_only_current_storage_grants() -> TestResult {
    use tinybox_bus::{CreateRequest, ReserveRequest, ResourceId, ResourceInfo, Workspace};

    let rig = current_only_rig(&[
        tinybox_drivers::BOX_COLLECTION,
        tinybox_drivers::JAIL_INDEX_COLLECTION,
    ])
    .await?;
    setup(rig.module.clone()).await?;
    let proxy = rig.client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    let workspace = tempfile::tempdir()?;
    let _: ResourceInfo = proxy
        .call(
            "Create",
            (CreateRequest {
                resource,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;

    let storage = ModuleStorage::connected(rig.module.clone());
    let boxes = storage.box_store().await?;
    let records = tokio::task::spawn_blocking({
        let boxes = Arc::clone(&boxes);
        move || boxes.list()
    })
    .await??;
    assert_eq!(records.len(), 1, "Create wrote a module box record");
    let record = records[0].clone();
    let writer = Arc::clone(&boxes);
    let id = record.id.clone();
    tokio::task::spawn_blocking(move || writer.set_state(&id, BoxState::Stopped)).await??;
    let reader = Arc::clone(&boxes);
    let id = record.id.clone();
    let updated = tokio::task::spawn_blocking(move || reader.get(&id)).await??;
    assert_eq!(updated.state, BoxState::Stopped);
    let remover = Arc::clone(&boxes);
    let id = record.id.clone();
    tokio::task::spawn_blocking(move || remover.remove(&id)).await??;
    let reader = Arc::clone(&boxes);
    let records = tokio::task::spawn_blocking(move || reader.list()).await??;
    assert!(records.is_empty(), "box removal must persist on the host");

    let base = tempfile::tempdir()?;
    let registry = storage
        .jail_registry(base.path().to_path_buf(), "current-only".into())
        .await
        .ok_or("host serves storage")??;
    let created = tokio::task::spawn_blocking(move || registry.create("scratch")).await??;
    let reopened = storage
        .jail_registry(base.path().to_path_buf(), "current-only".into())
        .await
        .ok_or("host serves storage")??;
    let records = tokio::task::spawn_blocking(move || reopened.list()).await?;
    assert_eq!(
        records.len(),
        1,
        "jail index was read from the current grant"
    );
    assert_eq!(records[0].id, created.id);
    let refused = rig
        .refused
        .lock()
        .map_err(|_| "grant refusal list was poisoned")?;
    assert!(refused.is_empty(), "module only used its current grants");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_denied_current_collection_fails_module_creation_without_memory_fallback() -> TestResult {
    use tinybox_bus::{CreateRequest, ReserveRequest, ResourceId, ResourceInfo, Workspace};

    let rig = current_only_rig(&[tinybox_drivers::JAIL_INDEX_COLLECTION]).await?;
    setup(rig.module.clone()).await?;
    let proxy = rig.client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    let workspace = tempfile::tempdir()?;
    let result = proxy
        .call::<ResourceInfo>(
            "Create",
            (CreateRequest {
                resource,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await;
    assert!(result.is_err(), "a missing current grant must fail closed");
    {
        let refused = rig
            .refused
            .lock()
            .map_err(|_| "grant refusal list was poisoned")?;
        assert!(
            refused
                .iter()
                .any(|name| name == tinybox_drivers::BOX_COLLECTION),
            "the module must reach the denied current collection"
        );
    }
    assert!(
        backend_docs(&rig.backend, tinybox_drivers::BOX_COLLECTION)
            .await?
            .is_empty(),
        "denied current writes must not fall back to module memory"
    );
    Ok(())
}

fn info(id: &str) -> Result<BoxInfo, Box<dyn std::error::Error>> {
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    );
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec))
}

async fn host_docs(
    rig: &Rig,
    collection: &'static str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    backend_docs(&rig.backend, collection).await
}

async fn backend_docs(
    backend: &MemoryStorage,
    collection: &'static str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let docs = Arc::clone(backend.for_scope(&Scope::local())?.documents());
    let all = docs.query_all(collection, &Query::all()).await?;
    Ok(all.into_iter().map(|entry| entry.doc).collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_records_land_on_the_host_document_port() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await?;
    let record = info("module-box-1")?;
    let writer = Arc::clone(&store);
    let written = record.clone();
    tokio::task::spawn_blocking(move || writer.insert(&written)).await??;

    let stored = host_docs(&rig, tinybox_drivers::BOX_COLLECTION).await?;
    assert_eq!(stored.len(), 1, "the record is a document on the host");
    let read = Arc::clone(&store);
    let listed = tokio::task::spawn_blocking(move || read.list()).await??;
    assert_eq!(listed, vec![record]);
    Ok(())
}

/// The module runs on one worker; a store call made directly from async code
/// must not wait on a bus reply that only that worker could deliver.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn store_calls_on_the_only_worker_do_not_deadlock() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await?;
    let record = info("single-worker-box")?;
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        store.insert(&record)?;
        let listed = store.list()?;
        assert_eq!(listed, vec![record.clone()]);
        store.remove(&record.id)?;
        Ok::<(), tinybox_core::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_storage_host_box_records_stay_in_memory() -> TestResult {
    let rig = rig(false).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    assert!(storage.documents().await?.is_none());
    let store = storage.box_store().await?;
    let record = info("memory-box")?;
    let writer = Arc::clone(&store);
    let written = record.clone();
    tokio::task::spawn_blocking(move || writer.insert(&written)).await??;
    let docs = host_docs(&rig, tinybox_drivers::BOX_COLLECTION).await?;
    assert_eq!(docs.len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_unconnected_module_has_no_documents() -> TestResult {
    let storage = ModuleStorage::default();
    assert!(storage.documents().await?.is_none());
    assert!(
        storage
            .jail_registry(std::env::temp_dir(), "none".into())
            .await
            .is_none()
    );
    assert!(format!("{storage:?}").contains("connected: false"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_jail_index_is_a_document_on_the_host_not_a_file() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let base = tempfile::tempdir()?;
    let registry = storage
        .jail_registry(base.path().to_path_buf(), "jails".into())
        .await
        .ok_or("host serves storage")??;
    let created = tokio::task::spawn_blocking(move || registry.create("scratch")).await??;

    assert!(
        !base.path().join("index.json").exists(),
        "no index file is written"
    );
    let stored = host_docs(&rig, tinybox_drivers::JAIL_INDEX_COLLECTION).await?;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].to_string().contains(&created.id));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_connect_is_retried_when_the_host_starts_serving() -> TestResult {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let storage = ModuleStorage::connected(module);
    assert!(storage.documents().await?.is_none());

    let backend = MemoryStorage::new();
    let endpoint = PerCallerEndpoint::new(move |_sender| {
        Some(StorageServer::new(backend.for_scope(&Scope::local()).ok()?))
    });
    let _served = serve(&host, Arc::new(endpoint)).await?;
    assert!(storage.documents().await?.is_some());
    Ok(())
}

/// Every `Store` method forwards through the worker-safe wrapper.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_wrapper_forwards_get_and_set_state() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await?;
    let record = info("forwarded-box")?;
    store.insert(&record)?;
    assert_eq!(store.get(&record.id)?, record);
    store.set_state(&record.id, BoxState::Stopped)?;
    assert_eq!(store.get(&record.id)?.state, BoxState::Stopped);
    Ok(())
}

/// Off a multi-thread runtime there is no worker to hand off, so the call runs
/// in place.
#[test]
fn the_wrapper_runs_in_place_without_a_multi_thread_runtime() -> TestResult {
    let store = OffWorkerStore(MemoryStore::new());
    let record = info("plain-box")?;
    store.insert(&record)?;
    assert_eq!(store.list()?, vec![record.clone()]);
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        store.remove(&record.id)?;
        Ok::<(), tinybox_core::Error>(())
    })?;
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scoped_handle_is_connected_once_and_shared() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    assert!(storage.documents().await?.is_some());
    assert!(storage.documents().await?.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_scope_leaves_the_module_on_memory() -> TestResult {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let endpoint = PerCallerEndpoint::new(move |_sender| None::<StorageServer>);
    let _served = serve(&host, Arc::new(endpoint)).await?;
    let storage = ModuleStorage::connected(module);
    assert!(storage.documents().await?.is_none());
    let _memory = storage.box_store().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_host_backed_box_store_is_shared_by_every_resource() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let first = storage.box_store().await?;
    let second = storage.box_store().await?;
    assert!(Arc::ptr_eq(&first, &second));
    Ok(())
}

/// Two resources share one collection; each finds only the record it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_view_finds_only_its_own_record() -> TestResult {
    let shared: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let first = RecordingStore::new(Arc::clone(&shared));
    let second = RecordingStore::new(Arc::clone(&shared));
    assert!(first.first_inserted().is_none());
    first.insert(&info("box-0")?)?;
    second.insert(&info("box-1")?)?;
    assert_eq!(first.first_inserted(), Some(BoxId::new("box-0")?));
    assert_eq!(second.first_inserted(), Some(BoxId::new("box-1")?));
    assert_eq!(second.list()?.len(), 2);
    second.set_state(&BoxId::new("box-1")?, BoxState::Stopped)?;
    assert_eq!(second.get(&BoxId::new("box-1")?)?.state, BoxState::Stopped);
    second.remove(&BoxId::new("box-1")?)?;
    assert!(second.first_inserted().is_none());
    assert!(first.insert(&info("box-0")?).is_err());
    // After a delete the id may be reissued to another resource; the view
    // that removed it must not claim the new holder's record.
    first.remove(&BoxId::new("box-0")?)?;
    second.insert(&info("box-0")?)?;
    assert!(first.first_inserted().is_none());
    Ok(())
}
