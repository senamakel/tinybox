//! Downloads a tagged release asset and calls the loaded `TinyBus` module.
//!
//! Run it with the release tag URL, platform archive, and archive SHA-256:
//!
//! ```text
//! cargo run --example verify_github_release -- \
//!   https://github.com/tinyhumansai/tinybox/releases/tag/v0.1.5 \
//!   tinybox-0.1.5-ubuntu-24.04-x86_64.tar.gz \
//!   <sha256>
//! ```

use std::io;
use std::time::Duration;

use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::ModuleHost;
use tinybus::transport::memory::MemoryBus;

const INTERFACE: &str = "ai.tinyhumans.tinybox.Box";
const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (release_url, archive, sha256) = arguments()?;
    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let (broker_transport, controller_transport) =
        tinybus::transport::memory::MemoryTransport::pair();
    broker.attach_module_controller(std::sync::Arc::new(broker_transport))?;
    let controller = Connection::connect(Box::new(controller_transport)).await?;
    let broker_task = broker.spawn(bus.clone());
    let module_host = ModuleHost::new(broker);
    let info = module_host.load_github_release(
        &release_url,
        &archive,
        Some(&sha256),
        serde_json::Value::default(),
    )?;
    module_host
        .ensure_ready(info.manifest.bus_name.as_str())
        .await?;

    if info.name != env!("CARGO_PKG_NAME") {
        return Err(io::Error::other(format!(
            "loaded module `{}` instead of `{}`",
            info.name,
            env!("CARGO_PKG_NAME")
        ))
        .into());
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let names = controller.list_names().await?;
            if names.iter().any(|name| name.as_str() == INTERFACE) {
                return tinybus::Result::Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;

    let proxy = controller.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    // `Describe` is the module's only method, and it must at least name the
    // crate. Asserting the whole string would couple this verifier to the
    // registered-sandbox list, which changes as backends land.
    let description: String = proxy.call("Describe", ()).await?;
    if !description.starts_with("tinybox ") {
        return Err(io::Error::other(format!(
            "module returned an unexpected description: {description}"
        ))
        .into());
    }

    println!(
        "verified {archive} from {release_url} as TinyBus module `{}`",
        info.name
    );
    broker_task.abort();
    Ok(())
}

fn arguments() -> Result<(String, String, String), io::Error> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: cargo run --example verify_github_release -- \
                 <release-tag-url> <archive-name> <sha256>";
    let release_url = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?;
    let archive = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?;
    let sha256 = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?;
    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage));
    }
    Ok((release_url, archive, sha256))
}
