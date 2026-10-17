use std::collections::BTreeSet;

use tinystoragedrivers_bus::StorageNeeds as CanonicalStorageNeeds;
use tinybox_bus::{BOX_COLLECTION, JAIL_INDEX_COLLECTION, STORAGE_NEEDS};

fn main() {
    // This assignment fails if TinyBox and the isolated consumer resolve
    // different copies of the canonical storage-bus type.
    let needs: &CanonicalStorageNeeds<'static> = &STORAGE_NEEDS;
    assert_eq!(needs.collections.len(), 2);
    let declared: BTreeSet<&str> = needs
        .collections
        .iter()
        .map(|collection| collection.name.as_str())
        .collect();
    let expected = BTreeSet::from([BOX_COLLECTION, JAIL_INDEX_COLLECTION]);
    assert_eq!(declared, expected);
    assert!(needs.blob_prefixes.is_empty());
    assert!(needs.stream_prefixes.is_empty());
    assert!(needs.secret_prefixes.is_empty());
    for collection in needs.collections {
        assert!(collection.indexes.is_empty());
        assert!(collection.ttl_field.is_none());
        assert!(collection.search.is_none());
    }
}
