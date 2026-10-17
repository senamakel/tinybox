//! A jail [`IndexStore`] on the document port.

use std::io;
use std::sync::Arc;

use serde_json::Value;
use tinybox_jail::IndexStore;
use tinystoragedrivers_core::{Blocking, DocumentStore, ErrorKind, Precondition, StorageError};

use crate::JAIL_INDEX_COLLECTION;

/// A jail registry's index as one document, `tinybox_jail_index/<registry>`.
///
/// The registry serializes the index; this keeps the JSON value, so the
/// document has the same shape as the legacy `index.json`. A document that is
/// not valid JSON reads as [`io::ErrorKind::InvalidData`].
#[derive(Clone)]
pub struct DocumentIndexStore {
    documents: Arc<dyn DocumentStore>,
    bridge: Blocking,
    registry: String,
}

impl std::fmt::Debug for DocumentIndexStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentIndexStore")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl DocumentIndexStore {
    /// An index store for the registry named `registry`; the collection is
    /// declared here.
    ///
    /// # Errors
    ///
    /// Returns an error when the bridge cannot start or the backend refuses
    /// the collection.
    pub fn new(documents: Arc<dyn DocumentStore>, registry: impl Into<String>) -> io::Result<Self> {
        let collection = crate::collection_spec(JAIL_INDEX_COLLECTION)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let bridge = Blocking::new().map_err(|e| to_io(&e))?;
        let docs = Arc::clone(&documents);
        bridge
            .run(async move { docs.ensure_collection(&collection).await })
            .and_then(|inner| inner)
            .map_err(|e| to_io(&e))?;
        Ok(Self {
            documents,
            bridge,
            registry: registry.into(),
        })
    }
}

fn to_io(error: &StorageError) -> io::Error {
    let kind = match error.kind() {
        ErrorKind::Serialization => io::ErrorKind::InvalidData,
        ErrorKind::NotFound => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error.to_string())
}

impl IndexStore for DocumentIndexStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let docs = Arc::clone(&self.documents);
        let key = self.registry.clone();
        let found = self
            .bridge
            .run(async move { docs.get(JAIL_INDEX_COLLECTION, &key).await })
            .and_then(|inner| inner)
            .map_err(|e| to_io(&e))?;
        found
            .map(|entry| {
                serde_json::to_vec(&entry.doc)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .transpose()
    }

    fn save(&self, bytes: &[u8]) -> io::Result<()> {
        let doc: Value = serde_json::from_slice(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let docs = Arc::clone(&self.documents);
        let key = self.registry.clone();
        self.bridge
            .run(async move {
                docs.put(JAIL_INDEX_COLLECTION, &key, doc, Precondition::None)
                    .await
            })
            .and_then(|inner| inner)
            .map(|_| ())
            .map_err(|e| to_io(&e))
    }
}

#[cfg(test)]
#[path = "index_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
