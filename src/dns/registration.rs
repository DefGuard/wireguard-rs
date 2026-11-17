//! DNS dynamic update (RFC 2136) of the host's name on Windows.
//!
//! Windows registers a host only with the DNS servers configured on its adapter. Split DNS keeps
//! the tunnel's servers off the adapter (NRPT is used instead), so the update is sent from here.

use std::net::IpAddr;

/// Registry path of the "Dynamic update" group policy.
pub(crate) const POLICY_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

/// Policy value disabling registration when set to 0.
pub(crate) const POLICY_REGISTRATION_ENABLED: &str = "RegistrationEnabled";

/// Registry path of the TCP/IP stack parameters.
pub(crate) const TCPIP_PARAMETERS_PATH: &str =
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

/// Global value disabling registration when set to 1.
pub(crate) const DISABLE_DYNAMIC_UPDATE: &str = "DisableDynamicUpdate";

/// TTL of the registered records, the Windows DNS client default.
pub(crate) const RECORD_TTL: u32 = 1200;

/// Tells whether the registry allows registration; `None` is a missing value. The tunnel
/// adapter's own setting is ignored, as `set_dns` manages it.
pub(crate) fn registration_enabled(
    policy_enabled: Option<u32>,
    global_disabled: Option<u32>,
) -> bool {
    // A configured policy overrides the local settings.
    if let Some(enabled) = policy_enabled {
        return enabled != 0;
    }
    global_disabled.unwrap_or(0) == 0
}

/// Returns the name to register, or `None` if the host has no primary DNS suffix.
pub(crate) fn registration_name(fqdn: &str) -> Option<&str> {
    let name = fqdn.trim().trim_end_matches('.');
    let (host, suffix) = name.split_once('.')?;
    (!host.is_empty() && !suffix.is_empty()).then_some(name)
}

/// Tells whether `name` is under one of the NRPT `namespaces`, i.e. the tunnel's servers answer
/// for the host's zone.
pub(crate) fn name_in_namespaces(name: &str, namespaces: &[String]) -> bool {
    let name = format!(".{}", name.to_lowercase());
    namespaces
        .iter()
        .any(|namespace| namespace == "." || name.ends_with(namespace.as_str()))
}

/// Tells whether an address is worth registering: not link-local, loopback etc.
fn registrable(address: &IpAddr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || match address {
            IpAddr::V4(address) => address.is_link_local() || address.is_broadcast(),
            IpAddr::V6(address) => address.is_unicast_link_local(),
        })
}

/// Appends the `new` addresses which `addresses` doesn't have yet.
pub(crate) fn extend_unique(addresses: &mut Vec<IpAddr>, new: impl IntoIterator<Item = IpAddr>) {
    for address in new {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
}

/// Returns the registrable addresses, without duplicates.
pub(crate) fn registrable_addresses(addresses: &[IpAddr]) -> Vec<IpAddr> {
    let mut registrable_addresses = Vec::new();
    extend_unique(
        &mut registrable_addresses,
        addresses.iter().copied().filter(registrable),
    );
    registrable_addresses
}

/// Encodes the IPv4 servers as an `IP4_ARRAY`: count, then addresses in network byte order.
/// Returns `None` if there is no IPv4 server.
pub(crate) fn ip4_array(servers: &[IpAddr]) -> Option<Vec<u32>> {
    let mut array = vec![0];
    array.extend(servers.iter().filter_map(|server| match server {
        IpAddr::V4(address) => Some(u32::from_ne_bytes(address.octets())),
        IpAddr::V6(_) => None,
    }));
    array[0] = (array.len() - 1) as u32;
    (array[0] > 0).then_some(array)
}
