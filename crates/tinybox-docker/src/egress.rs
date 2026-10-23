//! Planning helpers for future network allowlist enforcement.
//!
//! These types pin resolver answers for a later proxy or firewall to consume.
//! They do not enforce traffic and do not make `NetworkPolicy::Allowlist`
//! available in [`DockerSandbox`](crate::DockerSandbox).

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

use tinybox_core::{EgressAllowlist, Error, Result};

/// Resolves one hostname to all of its addresses in the environment where an
/// enforcing backend will use the result.
pub trait EgressResolver: std::fmt::Debug + Send + Sync {
    /// Resolve `hostname` once and return every address in the answer.
    ///
    /// # Errors
    ///
    /// Returns an error when the hostname cannot be resolved.
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// A resolved allowlist plan whose destinations no longer depend on DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEgressPlan {
    targets: Vec<PinnedEgressTarget>,
}

impl PinnedEgressPlan {
    /// The host, port, and pinned IP combinations that an enforcer must apply.
    #[must_use]
    pub fn targets(&self) -> &[PinnedEgressTarget] {
        &self.targets
    }
}

/// One permitted hostname and port paired with one pinned destination address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedEgressTarget {
    host: String,
    port: u16,
    address: IpAddr,
}

impl PinnedEgressTarget {
    /// The normalized allowlist hostname.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The permitted destination port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The address returned by the resolver, retained without another lookup.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// The pinned socket address an enforcing backend can connect to directly.
    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Resolve and pin all destinations in an allowlist.
///
/// Every distinct hostname is passed to `resolver` exactly once. If any answer
/// is a cloud metadata or loopback address, the whole plan is rejected. Safe
/// private addresses are retained because this policy does not forbid them.
///
/// This function only prepares data for an enforcing proxy or firewall. It does
/// not apply network rules and does not enable allowlists in `DockerSandbox`.
/// The resolver must answer in the environment where the eventual enforcer will
/// use the plan, which may be remote from the caller for an SSH-backed host.
///
/// # Errors
///
/// Returns [`Error::InvalidNetworkPolicy`] for a malformed allowlist, an empty
/// DNS answer, or any resolved metadata or loopback address. Resolver errors
/// are returned as [`Error::Backend`].
pub fn plan_egress_allowlist(
    allowlist: &EgressAllowlist,
    resolver: &dyn EgressResolver,
) -> Result<PinnedEgressPlan> {
    allowlist.validate()?;

    let mut addresses_by_host = BTreeMap::<String, BTreeSet<IpAddr>>::new();
    for configured_host in &allowlist.hosts {
        let host = normalize_host(configured_host);
        if addresses_by_host.contains_key(&host) {
            continue;
        }

        let addresses = match host.parse::<IpAddr>() {
            Ok(address) => vec![address],
            Err(_) => resolver.resolve(&host).map_err(|error| Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "resolve an egress allowlist host",
                message: format!("{host}: {error}"),
            })?,
        };
        if addresses.is_empty() {
            return Err(Error::InvalidNetworkPolicy {
                reason: "allowlist host resolved to no addresses",
            });
        }
        if addresses.iter().any(is_forbidden_address) {
            return Err(Error::InvalidNetworkPolicy {
                reason: "allowlist host resolves to a metadata or loopback address",
            });
        }
        addresses_by_host.insert(host, addresses.into_iter().collect());
    }

    let ports: BTreeSet<_> = allowlist.ports.iter().copied().collect();
    let mut targets = Vec::new();
    for (host, addresses) in addresses_by_host {
        for port in &ports {
            for address in &addresses {
                targets.push(PinnedEgressTarget {
                    host: host.clone(),
                    port: *port,
                    address: *address,
                });
            }
        }
    }

    Ok(PinnedEgressPlan { targets })
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn is_forbidden_address(address: &IpAddr) -> bool {
    if EgressAllowlist::is_metadata_host(&address.to_string()) {
        return true;
    }

    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_loopback() || EgressAllowlist::is_metadata_host(&mapped.to_string())
                })
        }
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;
