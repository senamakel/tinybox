//! tinybox on the host's `tinystoragedrivers` ports.
//!
//! The backend (`SQLite`, `MongoDB`, files, memory) and the tenant scope are the
//! host's choice, made when it builds the [`DocumentStore`] handle. Nothing here
//! names a database.
//!
//! - [`DocumentBoxStore`]: box records as documents, behind
//!   [`tinybox_core::Store`].
//! - [`DocumentIndexStore`]: the jail registry's index as one document, behind
//!   [`tinybox_jail::IndexStore`].
//! - [`storage_schema`]: the box-owned schema and v1-to-v2 migration used by
//!   this storage implementation. Stores here never declare collections.
//!
//! The bus separately declares the module's requested storage through
//! `tinybox_bus::STORAGE_NEEDS`; that declaration gives the module no authority.
//! Both store traits are synchronous, so each store owns a [`Blocking`] bridge
//! that runs the port's futures on a dedicated runtime thread. That works from
//! inside or outside a tokio runtime.
//!
//! [`DocumentStore`]: tinystoragedrivers_core::DocumentStore
//! [`Blocking`]: tinystoragedrivers_core::Blocking

mod box_store;
mod index_store;
mod record;
mod storage_schema;

pub use box_store::DocumentBoxStore;
pub use index_store::DocumentIndexStore;
pub use storage_schema::storage_schema;
pub use tinybox_bus::storage::{BOX_COLLECTION, JAIL_INDEX_COLLECTION};

#[cfg(test)]
#[path = "faulty_tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod faulty;

#[cfg(test)]
#[path = "storage_needs_tests.rs"]
mod storage_needs_tests;

#[cfg(test)]
fn to_driver_collection_spec(
    declaration: &tinybox_bus::CollectionSpec,
) -> tinystoragedrivers_core::CollectionSpec {
    tinystoragedrivers_core::CollectionSpec {
        name: declaration.name.clone(),
        indexes: declaration
            .indexes
            .iter()
            .map(|index| {
                let spec = tinystoragedrivers_core::IndexSpec::new(
                    index.name.clone(),
                    index.fields.clone(),
                );
                if index.unique { spec.unique() } else { spec }
            })
            .collect(),
        ttl_field: declaration.ttl_field.clone(),
        search: declaration
            .search
            .as_ref()
            .map(|search| tinystoragedrivers_core::SearchSpec {
                fields: search.fields.clone(),
            }),
    }
}
