//! The document drivers persist exactly the schemas declared by tinybox-bus.

use super::*;
use std::sync::Arc;
use tinybox_bus::{CollectionSpec, IndexSpec, STORAGE_NEEDS, SearchSpec};
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, Store, WorkspaceSource,
};
use tinybox_jail::IndexStore;
use tinystoragedrivers_core::{
    Blocking, DocumentStore, IndexSpec as DriverIndexSpec, MemoryStorage, Scope, StorageBackend,
};

#[test]
fn stores_create_every_collection_the_bus_declares()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryStorage::new().for_scope(&Scope::local())?;
    let documents: Arc<dyn DocumentStore> = storage.documents().clone();
    let boxes = DocumentBoxStore::new(Arc::clone(&documents))?;
    let index = DocumentIndexStore::new(Arc::clone(&documents), "main")?;

    let bridge = Blocking::new()?;
    let record = BoxInfo::new(
        BoxId::new("storage-needs")?,
        BoxState::Ready,
        BoxSpec::new(
            Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
            WorkspaceSource::LocalDir("/workspace".into()),
        ),
    );
    boxes.insert(&record)?;
    assert_eq!(boxes.get(&record.id)?, record);

    index.save(br#"{"records":{},"schema_version":1}"#)?;
    assert_eq!(
        index.load()?.as_deref(),
        Some(br#"{"records":{},"schema_version":1}"#.as_slice())
    );

    for declaration in STORAGE_NEEDS.collections {
        let required = to_driver_collection_spec(declaration);
        let documents = Arc::clone(&documents);
        bridge.run(async move { documents.validate_collection_spec(&required).await })??;
    }
    Ok(())
}

#[test]
fn conversion_preserves_indexes_expiry_and_search_fields() {
    let declaration = CollectionSpec {
        name: "tinybox_example".into(),
        indexes: vec![IndexSpec {
            name: "by_owner".into(),
            fields: vec!["owner.id".into(), "state".into()],
            unique: true,
        }],
        ttl_field: Some("expires_ms".into()),
        search: Some(SearchSpec {
            fields: vec!["title".into(), "description".into()],
        }),
    };

    assert_eq!(
        to_driver_collection_spec(&declaration),
        tinystoragedrivers_core::CollectionSpec {
            name: "tinybox_example".into(),
            indexes: vec![DriverIndexSpec::new("by_owner", ["owner.id", "state"]).unique()],
            ttl_field: Some("expires_ms".into()),
            search: Some(tinystoragedrivers_core::SearchSpec {
                fields: vec!["title".into(), "description".into()],
            }),
        }
    );
}
