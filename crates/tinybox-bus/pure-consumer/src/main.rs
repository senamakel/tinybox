use tinybox_bus::{BOX_COLLECTION, STORAGE_NEEDS};

fn main() {
    assert_eq!(STORAGE_NEEDS.collections[0].name, BOX_COLLECTION);
}
