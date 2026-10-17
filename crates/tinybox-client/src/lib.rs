//! Typed host calls to the TinyBox TinyBus module.
//!
//! This crate is the bus adapter only. Host applications provide a configured
//! [`tinybus::module::ModuleClient`] and retain responsibility for loading,
//! deadlines, migrations, and host-specific error reporting.

pub use tinybox_bus as contract;

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
