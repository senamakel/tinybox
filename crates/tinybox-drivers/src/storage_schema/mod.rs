//! What `TinyBox` stores, as the schema used by its storage implementation.
//!
//! Owner `box`, both collections at body version 2 in the module scope:
//!
//! | v1 | v2 |
//! |---|---|
//! | `tinybox_boxes` | [`BOX_COLLECTION`] (`box.boxes`) |
//! | `tinybox_jail_index` | [`JAIL_INDEX_COLLECTION`] (`box.jail_index`) |
//!
//! The two collections are module-scoped. The migration steps bring v1 rows
//! forward when `Registry::migrate` runs; they are pure transformations and
//! touch no storage themselves.
//!
//! This implementation crate stores and loads v2 bodies, so it owns the v1
//! decoders as well as the migrations that invoke them.

use super::{BOX_COLLECTION, JAIL_INDEX_COLLECTION};
use tinystoragedrivers_core::schema::declaration_from_schema;
use tinystoragedrivers_core::schema::delivery::MigrationPayloadHandler;
use tinystoragedrivers_core::schema::{
    MigrationPayload, MigrationPayloadReply, Owner, Schema, SchemaDeclaration, ScopeClass,
    SourceRecord, Step, TargetRecord, TransformError, TransformErrorKind,
};
use tinystoragedrivers_core::{Key, Result, StorageError};

#[path = "box_v1.rs"]
pub(crate) mod box_v1;
#[path = "jail_index.rs"]
pub(crate) mod jail_index;

/// The v1 name of [`BOX_COLLECTION`].
pub(crate) const V1_BOX_COLLECTION: &str = "tinybox_boxes";

/// The v1 name of [`JAIL_INDEX_COLLECTION`].
pub(crate) const V1_JAIL_INDEX_COLLECTION: &str = "tinybox_jail_index";

/// The body version both collections are declared at.
pub(crate) const BODY_VERSION: u32 = 2;

const MIGRATION_TRANSFORM_VERSION: u32 = 1;
const BOX_MIGRATION_OPERATION: &str = "box.rename_boxes";
const JAIL_INDEX_MIGRATION_OPERATION: &str = "box.rename_jail_index";

/// Everything tinybox stores, with the v1 to v2 migration steps.
///
/// # Panics
///
/// Never in practice: the owner name is a constant that satisfies the owner
/// grammar.
#[must_use]
pub fn storage_schema() -> Schema {
    #[allow(clippy::expect_used, reason = "a constant that satisfies the grammar")]
    let owner = Owner::new("box").expect("`box` is a valid owner");
    Schema::new(owner)
        .collection(BOX_COLLECTION, BODY_VERSION, ScopeClass::Module)
        .collection(JAIL_INDEX_COLLECTION, BODY_VERSION, ScopeClass::Module)
        .step(
            Step::new("rename_boxes", BOX_COLLECTION, 1, BODY_VERSION, |batch| {
                batch.into_iter().map(box_to_v2).collect()
            })
            .source(V1_BOX_COLLECTION),
        )
        .step(
            Step::new(
                "rename_jail_index",
                JAIL_INDEX_COLLECTION,
                1,
                BODY_VERSION,
                |batch| batch.into_iter().map(jail_index_to_v2).collect(),
            )
            .source(V1_JAIL_INDEX_COLLECTION),
        )
}

/// Export this owner's existing schema and explicit operation selectors for
/// confidential module migration delivery.
///
/// # Errors
/// Returns an error if a schema step has no operation mapping.
pub fn storage_schema_declaration() -> Result<SchemaDeclaration> {
    let schema = storage_schema();
    declaration_from_schema(&schema, |step| {
        let operation = match step.id {
            "rename_boxes" => BOX_MIGRATION_OPERATION,
            "rename_jail_index" => JAIL_INDEX_MIGRATION_OPERATION,
            _ => return None,
        };
        Some((operation.to_owned(), MIGRATION_TRANSFORM_VERSION))
    })
}

/// Stateless TinyBox owner transforms for the TSD migration exchange.
#[derive(Debug, Default)]
pub struct TinyBoxMigrationHandler;

impl MigrationPayloadHandler for TinyBoxMigrationHandler {
    fn transform(&self, payload: MigrationPayload) -> MigrationPayloadReply {
        match payload {
            MigrationPayload::Documents(request) => {
                MigrationPayloadReply::Documents(transform_documents(request))
            }
            MigrationPayload::BlobTarget(_) => {
                MigrationPayloadReply::BlobTarget(Err(unsupported_transform()))
            }
            MigrationPayload::StreamPlan(_) => {
                MigrationPayloadReply::StreamPlan(Err(unsupported_transform()))
            }
            MigrationPayload::StreamEntries(_) => {
                MigrationPayloadReply::StreamEntries(Err(unsupported_transform()))
            }
        }
    }
}

fn transform_documents(
    _request: tinystoragedrivers_core::schema::DocumentsTransformRequest,
) -> std::result::Result<Vec<TargetRecord>, TransformError> {
    Err(unsupported_transform())
}

fn unsupported_transform() -> TransformError {
    TransformError {
        kind: TransformErrorKind::UnsupportedOperation,
        message: "unsupported TinyBox migration operation".to_owned(),
    }
}

/// A v1 box row (a serialized `BoxInfo`) as a v2 record under the same id.
fn box_to_v2(source: SourceRecord) -> Result<TargetRecord> {
    let id = Key::of([source.id.as_str()])?;
    let body = box_v1::to_body(source.body).map_err(|error| {
        StorageError::serialization(format!("v1 box `{}` does not decode: {error}", source.id))
    })?;
    Ok(TargetRecord::new(BOX_COLLECTION, id.as_str(), body))
}

/// A v1 jail index row as a v2 record under the same id.
fn jail_index_to_v2(source: SourceRecord) -> Result<TargetRecord> {
    let id = Key::of([source.id.as_str()])?;
    let body = jail_index::to_body(source.body).map_err(|error| {
        StorageError::serialization(format!("v1 jail index `{}`: {error}", source.id))
    })?;
    Ok(TargetRecord::new(JAIL_INDEX_COLLECTION, id.as_str(), body))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
