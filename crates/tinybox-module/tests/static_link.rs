//! The statically linked build is admitted by a `ModuleHost` and reaches `Ready`.

#![cfg(feature = "static-link")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use tinybus::{
    Connection,
    broker::Broker,
    module::{ModuleHost, ModuleState},
    transport::memory::{MemoryBus, MemoryTransport},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_module_is_admitted_and_becomes_ready() {
    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker
        .attach_module_controller(std::sync::Arc::new(broker_transport))
        .expect("module controller is selected");
    let _controller = Connection::connect(Box::new(controller_transport))
        .await
        .expect("controller connects");
    broker.clone().spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let info = host
        .attach_linked_with_config(tinybox::linked_module().unwrap(), serde_json::json!({}))
        .expect("linked module is admitted");
    assert_eq!(info.name, "tinybox-module");
    host.ensure_ready(info.manifest.bus_name.as_str())
        .await
        .expect("linked module initializes with its selected host");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if host
                .list()
                .iter()
                .any(|module| matches!(module.state, ModuleState::Ready))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("linked module reaches Ready");
}
