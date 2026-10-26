#[cfg(not(target_os = "windows"))]
use std::collections::HashSet;
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
use std::{fs::OpenOptions, io::Write};

use crate::WireguardInterfaceError;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use crate::bsd::{IoError, add_gateway, add_linked_route, delete_gateway, get_gateway};
#[cfg(target_os = "linux")]
use crate::netlink;
#[cfg(not(target_os = "windows"))]
use crate::{IpVersion, Peer, net::IpAddrMask};

#[cfg(target_os = "linux")]
fn setup_default_route(ifname: &str, addr: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
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

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
fn setup_default_route(ifname: &str, addr: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
    debug!(
        "Found default route in the allowed IPs: {addr}, interface: {ifname}, \
        proceeding with default route initial setup."
    );
    // FIXME: currently it is impossible to add another default route, so use the hack from
    // wg-quick for Darwin.
    let default_routes = if addr.address.is_ipv4() {
        // 0.0.0.0/1
        [
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
        ]
    } else {
        // ::/1
        [
            IpAddrMask::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
            IpAddrMask::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
        ]
    };
    for addr in default_routes {
        match add_linked_route(&addr, ifname) {
            Ok(()) => debug!("Route to {addr} has been added for interface {ifname}"),
            Err(IoError::Io(err)) => {
                if let Some(raw_os_err) = err.raw_os_error()
                    && raw_os_err == libc::ENETUNREACH
                {
                    warn!(
                        "Failed to add default route {addr} for interface {ifname}: \
                        Network is unreachable. This may happen if interface's IP address \
                        is not the same IP version as the default gateway ({addr}) \
                        that was tried to be set, in this case this warning can be \
                        ignored. Otherwise, there may be some other issues with network \
                        configuration."
                    );
                } else {
                    error!("Failed to add route to {addr} for interface {ifname}: {err}");
                }
            }
            Err(err) => {
                error!("Failed to add route to {addr} for interface {ifname}: {err}");
            }
        }
    }

    Ok(())
}

/// Adds routing entries for allowed IPs of WireGuard peers.
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
#[cfg(not(target_os = "windows"))]
pub(crate) fn add_peer_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peer routing for interface: {ifname}");

    let mut allowed_ips_v4 = HashSet::new();
    let mut allowed_ips_v6 = HashSet::new();
    let mut default_route_v4 = None;
    let mut default_route_v6 = None;

    // Gather allowed IPs and default routes
    for peer in peers {
        for addr in &peer.allowed_ips {
            if addr.is_default_route() {
                // Default route - store for later
                if addr.address.is_ipv4() {
                    default_route_v4 = Some(addr);
                } else {
                    default_route_v6 = Some(addr);
                }
                continue;
            }
            // Regular route - add to set
            if addr.address.is_ipv4() {
                allowed_ips_v4.insert(addr);
            } else {
                allowed_ips_v6.insert(addr);
            }
        }
    }

    // Add default route if present, otherwise setup individual allowed IP routes
    if let Some(default_route) = default_route_v4 {
        setup_default_route(ifname, default_route)?;
    } else {
        for addr in allowed_ips_v4 {
            debug!("Adding a route for allowed IPv4: {addr}");

            #[cfg(not(target_os = "linux"))]
            let result = add_linked_route(addr, ifname);
            #[cfg(target_os = "linux")]
            let result = netlink::add_route(ifname, addr, None);

            if let Err(err) = result {
                warn!(
                    "Failed to add route for allowed IPv4 {addr} \
                    on interface {ifname}: {err}."
                );
            } else {
                debug!("Route added for allowed IPv4: {addr}");
            }
        }
    }
    if let Some(default_route) = default_route_v6 {
        if let Err(err) = setup_default_route(ifname, default_route) {
            warn!("Failed to setup IPv6 default route for interface {ifname}: {err}.");
        }
    } else {
        for addr in allowed_ips_v6 {
            debug!("Adding a route for allowed IPv6: {addr}");

            #[cfg(not(target_os = "linux"))]
            let result = add_linked_route(addr, ifname);
            #[cfg(target_os = "linux")]
            let result = netlink::add_route(ifname, addr, None);

            if let Err(err) = result {
                warn!(
                    "Failed to add route for allowed IPv6 {addr} \
                    on interface {ifname}: {err}."
                );
            } else {
                debug!("Route added for allowed IPv6: {addr}");
            }
        }
    }

    debug!("Peers routing added successfully");
    Ok(())
}

/// Route peer endpoints through the default gateway when allowed IPs contain a default route.
///
/// `peers` should be all peers of the interface. Routes added are tracked in `routes`;
/// existing routes are kept and not tracked.
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
pub(crate) fn configure_endpoints(peers: &[Peer], routes: &mut HashSet<IpAddr>) {
    remove_endpoint_routes(routes);

    // Default gateway for each IP version with a default route in allowed IPs.
    let has_default_route = |is_ipv4: bool| {
        peers
            .iter()
            .flat_map(|peer| &peer.allowed_ips)
            .any(|addr| addr.is_default_route() && addr.address.is_ipv4() == is_ipv4)
    };
    let gateway_v4 = has_default_route(true).then(|| get_gateway(IpVersion::IPv4));
    let gateway_v6 = has_default_route(false).then(|| get_gateway(IpVersion::IPv6));

    for peer in peers {
        let Some(endpoint) = peer.endpoint else {
            continue;
        };
        let endpoint_ip = endpoint.ip();
        let (Some(gateway), localhost) = (match endpoint_ip {
            IpAddr::V4(_) => (&gateway_v4, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            IpAddr::V6(_) => (&gateway_v6, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        }) else {
            continue;
        };
        if routes.contains(&endpoint_ip) {
            continue;
        }

        let dest = IpAddrMask::host(endpoint_ip);
        let result = match gateway {
            Ok(Some(gateway)) => {
                debug!("Routing the traffic destined to {dest} through gateway {gateway}.");
                add_gateway(&dest, *gateway, false)
            }
            Ok(None) => {
                debug!(
                    "Default gateway has not been found, routing the traffic destined to {dest} \
                    through localhost as a blackhole route."
                );
                add_gateway(&dest, localhost, true)
            }
            Err(err) => {
                error!("Failed to get default gateway for {dest}: {err}");
                continue;
            }
        };
        match result {
            Ok(()) => {
                debug!("Route to {dest} has been added.");
                routes.insert(endpoint_ip);
            }
            Err(IoError::Io(err)) if err.raw_os_error() == Some(libc::EEXIST) => {
                debug!("Route to {dest} already exists, leaving it intact.");
            }
            Err(err) => error!("Failed to add route to {dest}: {err}"),
        }
    }
}

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
fn delete_endpoint_route(endpoint_ip: IpAddr) {
    let dest = IpAddrMask::host(endpoint_ip);
    match delete_gateway(&dest) {
        Ok(()) => debug!("Route to {dest} has been removed."),
        Err(err) => warn!("Failed to remove route to {dest}: {err}"),
    }
}

/// Remove a route to `endpoint_ip` added by [`configure_endpoints`].
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
pub(crate) fn remove_endpoint_route(endpoint_ip: IpAddr, routes: &mut HashSet<IpAddr>) {
    if routes.remove(&endpoint_ip) {
        delete_endpoint_route(endpoint_ip);
    } else {
        debug!("Route to {endpoint_ip} has not been added by us, leaving it intact.");
    }
}

/// Remove all routes added by [`configure_endpoints`].
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
pub(crate) fn remove_endpoint_routes(routes: &mut HashSet<IpAddr>) {
    for endpoint_ip in routes.drain() {
        delete_endpoint_route(endpoint_ip);
    }
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
