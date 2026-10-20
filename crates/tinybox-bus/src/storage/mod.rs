//! Storage names and needs requested by the `TinyBox` module.
//!
//! The needs declaration is available in the default, data-only bus build.
//! Schema declarations and v1-to-v2 migrations belong to `tinybox-drivers`.

use std::sync::LazyLock;

pub use tinystoragedrivers_bus::{CollectionSpec, IndexSpec, SearchSpec, StorageNeeds};

/// The collection that holds one document per box, keyed by box id.
pub const BOX_COLLECTION: &str = "box.boxes";
/// The collection that holds one index document per jail registry.
pub const JAIL_INDEX_COLLECTION: &str = "box.jail_index";

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

/// Storage declarations the `TinyBox` module requests from its host.
///
/// The host decides whether to grant these resources to a module instance.
pub static STORAGE_NEEDS: LazyLock<StorageNeeds<'static>> = LazyLock::new(|| StorageNeeds {
    collections: &COLLECTIONS[..],
    ..StorageNeeds::default()
});
