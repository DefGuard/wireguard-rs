#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(any(
    feature = "check_dependencies",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "netbsd"
))]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::{collections::HashSet, fs::OpenOptions, io::Write};

#[cfg(not(target_os = "windows"))]
use crate::Peer;
use crate::WireguardInterfaceError;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use crate::{
    IpVersion,
    bsd::{add_gateway, add_linked_route, get_gateway},
    net::IpAddrMask,
};
#[cfg(target_os = "linux")]
use crate::{IpVersion, netlink};

#[cfg(target_os = "linux")]
fn setup_default_route(
    ifname: &str,
    addr: &super::IpAddrMask,
) -> Result<(), WireguardInterfaceError> {
    const DEFAULT_FWMARK_TABLE: u32 = 51820; // specific to wg-quick

    debug!("Found default route in AllowedIPs: {addr:?}");

    debug!("Getting current host configuration for interface {ifname}");
    let mut host = netlink::get_host(ifname)?;
    debug!("Host configuration read for interface {ifname}");
    trace!("Current host: {host:?}");

    debug!("Choosing fwmark for marking WireGuard traffic");
    let fwmark = match host.fwmark {
        Some(fwmark) if fwmark != 0 => fwmark,
        Some(_) | None => {
            let mut table = DEFAULT_FWMARK_TABLE;
            loop {
                let count = netlink::count_routes(addr.ip_version(), table)?;
                if count == 0 {
                    host.fwmark = Some(table);
                    netlink::set_host(ifname, &host)?;
                    debug!("Assigned fwmark: {table}");
                    break;
                }
                table += 1;
            }
            table
        }
    };
    debug!("Using the following fwmark for marking WireGuard traffic: {fwmark}");

    // Add routes and table rules
    debug!("Adding default route: {addr}");
    netlink::add_route(ifname, addr, Some(fwmark))?;
    debug!("Default route added successfully");
    debug!("Adding fwmark rule for the WireGuard interface to prevent routing loops");
    netlink::add_fwmark_rule(addr, fwmark)?;
    debug!("Fwmark rule added successfully");

    debug!("Adding rule for main table to suppress current default gateway");
    netlink::add_main_table_rule(addr, 0)?;
    debug!("Main table rule added successfully");

    if !addr.address.is_ipv6() {
        debug!("Setting net.ipv4.conf.all.src_valid_mark=1");
        OpenOptions::new()
            .write(true)
            .open("/proc/sys/net/ipv4/conf/all/src_valid_mark")?
            .write_all(b"1")?;
        debug!("net.ipv4.conf.all.src_valid_mark=1 set successfully");
    }
    Ok(())
}

/// Adds routing entries for allowed IPs of WireGuard peers on a Linux system.
///
/// Iterates over the provided list of peers and installs routing rules based on their
/// allowed IP addresses. It distinguishes between IPv4 and IPv6 addresses, and handles
/// default routes (0.0.0.0/0 or ::/0) separately. If a default route is present, it
/// takes precedence and all specific routes of that IP version are skipped.
///
/// # Arguments
/// * `peers` - A slice of `Peer` objects containing allowed IP configurations.
/// * `ifname` - The name of the WireGuard interface to which routes should be applied.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(WireguardInterfaceError)` if any route setup fails.
///
#[cfg(target_os = "linux")]
pub(crate) fn add_peer_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peer routing for interface: {ifname}");

    // (ipv4, ipv6)
    let mut allowed_ips = (HashSet::new(), HashSet::new());
    let mut default_routes = (None, None);

    // Gather allowed IPs and default routes
    for peer in peers {
        for addr in &peer.allowed_ips {
            if addr.address.is_unspecified() {
                // Default route - store for later
                if addr.address.is_ipv4() {
                    default_routes.0 = Some(addr);
                } else {
                    default_routes.1 = Some(addr);
                }
                continue;
            }
            // Regular route - add to set
            if addr.address.is_ipv4() {
                allowed_ips.0.insert(addr);
            } else {
                allowed_ips.1.insert(addr);
            }
        }
    }
    debug!("Allowed IPs that will be used during the peer routing setup: {allowed_ips:?}");

    // Add default route if present, otherwise setup individual allowed IP routes
    if let Some(default_route) = default_routes.0 {
        setup_default_route(ifname, default_route)?;
    } else {
        for allowed_ip in allowed_ips.0 {
            debug!("Adding a route for allowed IPv4: {allowed_ip}");
            netlink::add_route(ifname, allowed_ip, None)?;
            debug!("Route added for allowed IPv4: {allowed_ip}");
        }
    }
    if let Some(default_route) = default_routes.1 {
        if let Err(err) = setup_default_route(ifname, default_route) {
            warn!("Failed to setup IPv6 default route for interface {ifname}: {err}.");
        }
    } else {
        for allowed_ip in allowed_ips.1 {
            debug!("Adding a route for allowed IPv6: {allowed_ip}");
            if let Err(err) = netlink::add_route(ifname, allowed_ip, None) {
                warn!(
                    "Failed to add route for allowed IPv6 {allowed_ip} \
                    on interface {ifname}: {err}."
                );
            } else {
                debug!("Route added for allowed IPv6: {allowed_ip}");
            }
        }
    }
    debug!("Peers routing added successfully");
    Ok(())
}

/// Helper function to add routing.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
pub(crate) fn add_peer_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    use crate::bsd::{IoError, delete_gateway};

    let gateway_v4 = get_gateway(IpVersion::IPv4);
    if let Ok(Some(gateway)) = gateway_v4 {
        debug!("Default gateway for IPv4: {gateway}");
    }
    let gateway_v6 = get_gateway(IpVersion::IPv6);
    if let Ok(Some(gateway)) = gateway_v6 {
        debug!("Default gateway for IPv6: {gateway}");
    }

    debug!("Adding peer routing for interface: {ifname}");
    for peer in peers {
        debug!("Processing peer: {}", peer.public_key);
        for addr in &peer.allowed_ips {
            debug!("Processing route for allowed IP: {addr}, interface: {ifname}");
            // FIXME: currently it is impossible to add another default route, so use the hack from
            // wg-quick for Darwin.
            if addr.address.is_unspecified() && addr.cidr == 0 {
                debug!(
                    "Found following default route in the allowed IPs: {addr}, interface: \
                    {ifname}, proceeding with default route initial setup."
                );

                let (default1, default2) = if addr.address.is_ipv4() {
                    // 0.0.0.0/1
                    (
                        IpAddrMask::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
                        IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
                    )
                } else {
                    // ::/1
                    (
                        IpAddrMask::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
                        IpAddrMask::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
                    )
                };
                match add_linked_route(&default1, ifname) {
                    Ok(()) => debug!("Route to {default1} has been added for interface {ifname}"),
                    Err(IoError::Io(err)) => {
                        if let Some(raw_os_err) = err.raw_os_error()
                            && raw_os_err == libc::ENETUNREACH
                        {
                            warn!(
                                "Failed to add default route {default1} for interface {ifname}: \
                                Network is unreachable. This may happen if interface's IP address \
                                is not the same IP version as the default gateway ({default1}) \
                                that was tried to be set, in this case this warning can be \
                                ignored. Otherwise, there may be some other issues with network \
                                configuration."
                            );
                        } else {
                            error!(
                                "Failed to add route to {default1} for interface {ifname}: {err}"
                            );
                        }
                    }
                    Err(err) => {
                        error!("Failed to add route to {default1} for interface {ifname}: {err}");
                    }
                }
                match add_linked_route(&default2, ifname) {
                    Ok(()) => debug!("Route to {default2} has been added for interface {ifname}"),
                    Err(IoError::Io(err)) => {
                        if let Some(raw_os_err) = err.raw_os_error()
                            && raw_os_err == libc::ENETUNREACH
                        {
                            warn!(
                                "Failed to add default route {default2} for interface {ifname}: \
                                Network is unreachable. This may happen if interface's IP address \
                                is not the same IP version as the default gateway ({default2}) \
                                that was tried to be set, in this case this warning can be \
                                ignored. Otherwise, there may be some other issues with network \
                                configuration."
                            );
                        } else {
                            error!(
                                "Failed to add route to {default2} for interface {ifname}: {err}"
                            );
                        }
                    }
                    Err(err) => {
                        error!("Failed to add route to {default2} for interface {ifname}: {err}");
                    }
                }
            } else {
                // Equivalent to `route -n add -inet[6] <allowed_ip> -interface <ifname>`.
                match add_linked_route(addr, ifname) {
                    Ok(()) => debug!("Route to {addr} has been added for interface {ifname}"),
                    Err(err) => {
                        error!("Failed to add route to {addr} for interface {ifname}: {err}");
                    }
                }
            }
        }

        // Logic below is valid only in case an endpoint has been configured for the peer.
        let Some(endpoint) = peer.endpoint else {
            continue;
        };

        let endpoint_ip = IpAddrMask::host(endpoint.ip());
        let localhost = if endpoint.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };

        match delete_gateway(&endpoint_ip) {
            Ok(()) => {
                debug!("Former route to {endpoint_ip} has been removed, if it existed.");
            }
            Err(err) => {
                debug!("Former route to {endpoint_ip} has not been removed: {err}");
            }
        }

        debug!("Default routes have been set, proceeding with further configuration.");
        if endpoint.is_ipv6() {
            debug!(
                "Endpoint is an IPv6 address and a default IPv6 route is present in the allowed \
                IPs; proceeding with further configuration."
            );
            match gateway_v6 {
                Ok(Some(gateway)) => {
                    debug!(
                        "Default gateway for IPv6 has been found before: {gateway}, routing the \
                        traffic destined to {endpoint_ip} through it."
                    );
                    match add_gateway(&endpoint_ip, gateway, false) {
                        Ok(()) => {
                            debug!("Route to {endpoint_ip} has been added for gateway {gateway}");
                        }
                        Err(err) => {
                            error!(
                                "Failed to add route to {endpoint_ip} for gateway {gateway}: {err}"
                            );
                        }
                    }
                }
                Ok(None) => {
                    debug!(
                        "Default gateway for IPv6 has not been found, routing the traffic destined \
                        to {endpoint_ip} through localhost as a blackhole route."
                    );
                    match add_gateway(&endpoint_ip, localhost, true) {
                        Ok(()) => debug!("Blackhole route to {endpoint_ip} has been added"),
                        Err(err) => {
                            error!("Failed to add blackhole route to {endpoint_ip}: {err}");
                        }
                    }
                }
                Err(ref err) => {
                    error!("Failed to get gateway for {endpoint_ip}: {err}");
                }
            }
        } else {
            debug!(
                "Endpoint is an IPv4 address and a default IPv4 route is present in the allowed \
                IPs; proceeding with further configuration."
            );
            match gateway_v4 {
                Ok(Some(gateway)) => {
                    debug!(
                        "Default gateway for IPv4 has been found before: {gateway}, routing the \
                        traffic destined to {endpoint_ip} through it."
                    );
                    match add_gateway(&endpoint_ip, gateway, false) {
                        Ok(()) => {
                            debug!("Added route to {endpoint_ip} for gateway {gateway}");
                        }
                        Err(err) => {
                            error!(
                                "Failed to add route to {endpoint_ip} for gateway {gateway}: {err}"
                            );
                        }
                    }
                }
                Ok(None) => {
                    debug!(
                        "Default gateway for IPv4 has not been found, routing the traffic destined \
                        to {endpoint_ip} through localhost as a blackhole route."
                    );
                    match add_gateway(&endpoint_ip, localhost, true) {
                        Ok(()) => debug!("Blackhole route to {endpoint_ip} has been added"),
                        Err(err) => {
                            error!("Failed to add blackhole route to {endpoint_ip}: {err}");
                        }
                    }
                }
                Err(ref err) => {
                    error!("Failed to get gateway for {endpoint_ip}: {err}");
                }
            }
        }
    }

    debug!("Peers routing added successfully");
    Ok(())
}

/// Clean fwmark rules while removing interface (based on wg-quick).
#[cfg(target_os = "linux")]
pub(crate) fn clean_fwmark_rules(fwmark: u32) -> Result<(), WireguardInterfaceError> {
    debug!("Removing firewall rules.");
    netlink::delete_rule(IpVersion::IPv4, fwmark)?;
    netlink::delete_main_table_rule(IpVersion::IPv4, 0)?;
    netlink::delete_rule(IpVersion::IPv6, fwmark)?;
    netlink::delete_main_table_rule(IpVersion::IPv6, 0)?;
    Ok(())
}

/// Resolves domain name to [`SocketAddr`].
pub(crate) fn resolve(addr: &str) -> Result<SocketAddr, WireguardInterfaceError> {
    let error = || {
        WireguardInterfaceError::PeerConfigurationError(format!(
            "Failed to resolve address: {addr}"
        ))
    };
    addr.to_socket_addrs()
        .map_err(|_| error())?
        .next()
        .ok_or_else(error)
}

#[cfg(any(
    feature = "check_dependencies",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "netbsd"
))]
pub(crate) fn get_command_path(command: &str) -> Result<Option<PathBuf>, WireguardInterfaceError> {
    use std::env;

    debug!("Searching for command {command} in PATH");
    let paths = env::var_os("PATH").ok_or_else(|| {
        WireguardInterfaceError::MissingDependency("Environment variable `PATH` not found".into())
    })?;
    debug!("PATH variable: {}", paths.display());

    Ok(env::split_paths(&paths).find_map(|dir| {
        let full_path = dir.join(command);
        match full_path.try_exists() {
            Ok(true) => {
                debug!("Command {command} found in {}", dir.display());
                Some(full_path)
            }
            Ok(false) => {
                debug!("Command {command} not found in {}", dir.display());
                None
            }
            Err(err) => {
                warn!(
                    "Error while checking for {command} in {}: {err}",
                    dir.display()
                );
                None
            }
        }
    }))
}
