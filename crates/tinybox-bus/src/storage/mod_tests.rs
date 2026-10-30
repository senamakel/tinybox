//! Tests for `TinyBox`'s pure storage collection contract.

use super::*;

#[test]
fn the_owner_collections_are_stable_and_include_migration_receipts() {
    let names: Vec<_> = collections().into_iter().map(|spec| spec.name).collect();
    assert_eq!(
        names,
        [
            BOX_COLLECTION,
            JAIL_INDEX_COLLECTION,
            TEMPLATE_COLLECTION,
            MIGRATIONS_COLLECTION,
            CLI_IMPORTS_COLLECTION,
        ]
    );
}

#[test]
fn current_and_legacy_collection_names_are_distinct() {
    assert_ne!(BOX_COLLECTION, V1_BOX_COLLECTION);
    assert_ne!(JAIL_INDEX_COLLECTION, V1_JAIL_INDEX_COLLECTION);
}

#[test]
fn storage_declarations_are_serializable_names_without_backend_policy() {
    let declaration = CollectionDeclaration::new(BOX_COLLECTION);

    assert_eq!(
        serde_json::to_value(&declaration).expect("serialize declaration"),
        serde_json::json!({ "name": BOX_COLLECTION })
    );
    assert_eq!(
        serde_json::from_value::<CollectionDeclaration>(
            serde_json::json!({ "name": BOX_COLLECTION })
        )
        .expect("deserialize declaration"),
        declaration
    );
}

#[test]
fn every_declared_collection_has_a_nonempty_name() {
    for declaration in collections() {
        assert!(!declaration.name.is_empty());
    }
    assert_eq!(BODY_VERSION, 2);
}
