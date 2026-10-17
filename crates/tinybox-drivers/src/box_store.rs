//! A [`Store`] on the document port.

use std::sync::Arc;

use serde_json::Value;
use tinybox_core::{BoxId, BoxInfo, BoxState, Error, Result, Store};
use tinystoragedrivers_core::{
    Blocking, DocumentStore, DocumentStoreExt, ErrorKind, Precondition, Query, StorageError,
    Versioned,
};

use crate::BOX_COLLECTION;

/// How many times a read-modify-write retries when another writer wins.
const CAS_ATTEMPTS: usize = 8;

/// Box records as documents, `tinybox_boxes/<box id>`.
///
/// Inserts use an absent-only precondition, so two processes racing for one
/// name resolve to a [`Error::DuplicateBox`] for the loser (which
/// [`insert_new`](tinybox_core::store::insert_new) retries). State changes are
/// compare-and-swap on the document version, so they never overwrite a
/// concurrent change.
#[derive(Clone)]
pub struct DocumentBoxStore {
    documents: Arc<dyn DocumentStore>,
    bridge: Blocking,
}

impl std::fmt::Debug for DocumentBoxStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentBoxStore").finish_non_exhaustive()
    }
}

impl DocumentBoxStore {
    /// A store on `documents`; the collection is declared here.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the bridge cannot start or the backend
    /// refuses the collection.
    pub fn new(documents: Arc<dyn DocumentStore>) -> Result<Self> {
        let collection = crate::collection_spec(BOX_COLLECTION)?;
        let bridge = Blocking::new().map_err(|error| store_error("open", &error))?;
        let store = Self { documents, bridge };
        let docs = Arc::clone(&store.documents);
        store.run("open", async move {
            docs.ensure_collection(&collection).await
        })?;
        log::debug!("[tinybox_drivers] box store ready collection={BOX_COLLECTION}");
        Ok(store)
    }

    fn run<T, F>(&self, operation: &'static str, future: F) -> Result<T>
    where
        F: std::future::Future<Output = std::result::Result<T, StorageError>> + Send + 'static,
        T: Send + 'static,
    {
        self.bridge
            .run(future)
            .and_then(|inner| inner)
            .map_err(|error| store_error(operation, &error))
    }

    fn fetch(&self, id: &BoxId) -> Result<Versioned<Value>> {
        let docs = Arc::clone(&self.documents);
        let key = id.as_str().to_owned();
        self.run("read", async move { docs.get(BOX_COLLECTION, &key).await })?
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
    }
}

fn store_error(operation: &'static str, error: &StorageError) -> Error {
    Error::Store {
        operation,
        message: error.to_string(),
    }
}

fn decode(found: Value) -> Result<BoxInfo> {
    serde_json::from_value(found).map_err(|error| Error::Store {
        operation: "decode",
        message: error.to_string(),
    })
}

impl Store for DocumentBoxStore {
    fn insert(&self, info: &BoxInfo) -> Result<()> {
        let doc = serde_json::to_value(info).map_err(|error| Error::Store {
            operation: "encode",
            message: error.to_string(),
        })?;
        let docs = Arc::clone(&self.documents);
        let key = info.id.as_str().to_owned();
        let outcome = self.bridge.run(async move {
            docs.put(BOX_COLLECTION, &key, doc, Precondition::Absent)
                .await
        });
        match outcome.and_then(|inner| inner) {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(error.kind(), ErrorKind::AlreadyExists | ErrorKind::Conflict) =>
            {
                Err(Error::DuplicateBox {
                    id: info.id.as_str().to_owned(),
                })
            }
            Err(error) => Err(store_error("insert", &error)),
        }
    }

    fn get(&self, id: &BoxId) -> Result<BoxInfo> {
        decode(self.fetch(id)?.doc)
    }

    fn list(&self) -> Result<Vec<BoxInfo>> {
        let docs = Arc::clone(&self.documents);
        let found = self.run("list", async move {
            docs.query_all(BOX_COLLECTION, &Query::default()).await
        })?;
        // Documents come back ordered by id; keep that so output is stable.
        found.into_iter().map(|entry| decode(entry.doc)).collect()
    }

    fn set_state(&self, id: &BoxId, state: BoxState) -> Result<()> {
        for _ in 0..CAS_ATTEMPTS {
            let found = self.fetch(id)?;
            let mut info = decode(found.doc)?;
            info.state = state;
            let doc = serde_json::to_value(&info).map_err(|error| Error::Store {
                operation: "encode",
                message: error.to_string(),
            })?;
            let docs = Arc::clone(&self.documents);
            let key = id.as_str().to_owned();
            let version = found.version;
            let outcome = self.bridge.run(async move {
                docs.put(BOX_COLLECTION, &key, doc, Precondition::Version(version))
                    .await
            });
            match outcome.and_then(|inner| inner) {
                Ok(_) => return Ok(()),
                // Another writer changed the record first: read it again.
                Err(error) if matches!(error.kind(), ErrorKind::Conflict) => {
                    log::trace!("[tinybox_drivers] set_state conflict, retrying");
                }
                Err(error) => return Err(store_error("write", &error)),
            }
        }
        Err(Error::Store {
            operation: "write",
            message: format!("the record kept changing after {CAS_ATTEMPTS} attempts"),
        })
    }

    fn remove(&self, id: &BoxId) -> Result<()> {
        let docs = Arc::clone(&self.documents);
        let key = id.as_str().to_owned();
        let removed = self.run("remove", async move {
            docs.delete(BOX_COLLECTION, &key, Precondition::None).await
        })?;
        if removed {
            Ok(())
        } else {
            Err(Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
        }
    }
}

#[cfg(test)]
#[path = "box_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
