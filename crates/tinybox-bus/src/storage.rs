//! Storage resources requested by the TinyBox module.

use std::sync::LazyLock;

pub use tinystoragedrivers_bus::{CollectionSpec, IndexSpec, SearchSpec, StorageNeeds};

/// Collection holding one document per box record, keyed by box id.
pub const BOX_COLLECTION: &str = "tinybox_boxes";
/// Collection holding one index document per jail registry.
pub const JAIL_INDEX_COLLECTION: &str = "tinybox_jail_index";

static COLLECTIONS: LazyLock<[CollectionSpec; 2]> = LazyLock::new(|| {
    [
        CollectionSpec {
            name: BOX_COLLECTION.into(),
            indexes: Vec::new(),
            ttl_field: None,
            search: None,
        },
        CollectionSpec {
            name: JAIL_INDEX_COLLECTION.into(),
            indexes: Vec::new(),
            ttl_field: None,
            search: None,
        },
    ]
});

/// Storage declarations the TinyBox module requests from its host.
///
/// These metadata describe the two persisted resources used by the drivers;
/// the host still decides whether to grant them to a module instance.
pub static STORAGE_NEEDS: LazyLock<StorageNeeds<'static>> = LazyLock::new(|| StorageNeeds {
    collections: &COLLECTIONS[..],
    ..StorageNeeds::default()
});
