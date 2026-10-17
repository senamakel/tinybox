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
//!
//! Both traits are synchronous, so each store owns a [`Blocking`] bridge that
//! runs the port's futures on a dedicated runtime thread. That works from inside
//! or outside a tokio runtime.
//!
//! [`DocumentStore`]: tinystoragedrivers_core::DocumentStore
//! [`Blocking`]: tinystoragedrivers_core::Blocking

mod box_store;
mod index_store;

pub use box_store::DocumentBoxStore;
pub use index_store::DocumentIndexStore;
pub use tinybox_bus::{BOX_COLLECTION, JAIL_INDEX_COLLECTION};

fn collection_spec(name: &str) -> tinybox_core::Result<tinystoragedrivers_core::CollectionSpec> {
    let declaration = tinybox_bus::STORAGE_NEEDS
        .collections
        .iter()
        .find(|declaration| declaration.name == name)
        .ok_or_else(|| tinybox_core::Error::Store {
            operation: "open",
            message: format!("storage needs do not declare collection `{name}`"),
        })?;

    Ok(to_driver_collection_spec(declaration))
}

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

#[cfg(test)]
#[path = "faulty_tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod faulty;

#[cfg(test)]
#[path = "storage_needs_tests.rs"]
mod storage_needs_tests;
