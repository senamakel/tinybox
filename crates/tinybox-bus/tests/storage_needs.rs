//! Public storage declarations exposed by the `TinyBox` bus contract.

use tinybox_bus::{BOX_COLLECTION, JAIL_INDEX_COLLECTION, STORAGE_NEEDS};

#[test]
fn storage_needs_declare_every_persisted_collection_and_no_other_resources() {
    assert_eq!(BOX_COLLECTION, "box.boxes");
    assert_eq!(JAIL_INDEX_COLLECTION, "box.jail_index");
    assert_eq!(
        STORAGE_NEEDS
            .collections
            .iter()
            .map(|collection| collection.name.as_str())
            .collect::<Vec<_>>(),
        [BOX_COLLECTION, JAIL_INDEX_COLLECTION]
    );
    assert_eq!(STORAGE_NEEDS.blob_prefixes, &[] as &[&str]);
    assert_eq!(STORAGE_NEEDS.stream_prefixes, &[] as &[&str]);
    assert_eq!(STORAGE_NEEDS.secret_prefixes, &[] as &[&str]);
    assert!(
        STORAGE_NEEDS
            .collections
            .iter()
            .all(|collection| collection.indexes.is_empty()
                && collection.ttl_field.is_none()
                && collection.search.is_none())
    );
}
