//! The document drivers persist exactly the schemas declared by tinybox-bus.

use super::*;
use tinybox_bus::{CollectionSpec, IndexSpec, STORAGE_NEEDS, SearchSpec};
use tinystoragedrivers_core::{
    Blocking, DocumentStore, IndexSpec as DriverIndexSpec, MemoryStorage, Scope, StorageBackend,
};

#[test]
fn stores_create_every_collection_the_bus_declares()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryStorage::new().for_scope(&Scope::local())?;
    let documents: Arc<dyn DocumentStore> = storage.documents().clone();
    DocumentBoxStore::new(Arc::clone(&documents))?;
    DocumentIndexStore::new(Arc::clone(&documents), "main")?;

    let bridge = Blocking::new()?;
    let collections = bridge.run(async move { documents.collections("").await })??;
    let declared: Vec<_> = STORAGE_NEEDS
        .collections
        .iter()
        .map(|collection| collection.name.as_str())
        .collect();
    assert_eq!(
        collections.iter().map(String::as_str).collect::<Vec<_>>(),
        declared
    );
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
