#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::io::{BufRead, BufReader, Cursor, Error as IoError};
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    fs::OpenOptions,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    process::Command,
};
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use std::{io::Write, process::Stdio};

#[cfg(target_os = "freebsd")]
use crate::check_command_output_status;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use crate::{
    bsd::{add_gateway, add_linked_route, get_gateway},
    net::IpAddrMask,
    IpVersion,
};
#[cfg(target_os = "linux")]
use crate::{check_command_output_status, netlink, IpVersion};
use crate::{Peer, WireguardInterfaceError};

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
pub(crate) fn configure_dns(
    ifname: &str,
    dns: &[IpAddr],
    search_domains: &[&str],
) -> Result<(), WireguardInterfaceError> {
    // Build the resolvconf command
    debug!("Starting DNS servers configuration for interface {ifname}, DNS: {dns:?}, search domains: {search_domains:?}");
    let mut cmd = Command::new("resolvconf");
    let mut args = vec!["-a", ifname, "-m", "0"];
    // Set the exclusive flag if no search domains are provided,
    // making the DNS servers a preferred route for any domain
    if search_domains.is_empty() {
        args.push("-x");
    }
    debug!("Executing command resolvconf with args: {args:?}");
    cmd.args(args);

    match cmd.stdin(Stdio::piped()).spawn() {
        Ok(mut child) => {
            debug!("Command resolvconf spawned successfully, proceeding with writing nameservers and search domains to its stdin");
            if let Some(mut stdin) = child.stdin.take() {
                for entry in dns {
                    debug!("Adding nameserver entry: {entry}");
                    writeln!(stdin, "nameserver {entry}")?;
                }
                for domain in search_domains {
                    debug!("Adding search domain entry: {domain}");
                    writeln!(stdin, "search {domain}")?;
                }
            }
            debug!("Waiting for resolvconf command to finish");

            let status = child.wait().expect("Failed to wait for command");
            if status.success() {
                info!("DNS servers and search domains set successfully for interface {ifname}");
                Ok(())
            } else {
                Err(WireguardInterfaceError::DnsError(format!("Failed to execute resolvconf command while setting DNS servers and search domains: {status}")))
            }
        }
        Err(e) => {
            Err(WireguardInterfaceError::DnsError(format!("Failed to execute resolvconf command while setting DNS servers and search domains: {e}")))
        }
    }
}

#[cfg(target_os = "macos")]
/// Obtain list of network services
fn network_services() -> Result<Vec<String>, IoError> {
    debug!("Getting list of network services");
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()?;

    if output.status.success() {
        let buf = BufReader::new(Cursor::new(output.stdout));
        // Get all lines from stdout without asterisk (*).
        // An asterisk (*) denotes that a network service is disabled.
        let lines = buf
            .lines()
            .filter_map(|line| line.ok().filter(|line| !line.contains('*')))
            .collect();
        debug!("Network services: {lines:?}");
        Ok(lines)
    } else {
        Err(IoError::other(format!(
            "network setup command failed: {}",
            output.status
        )))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn configure_dns(
    dns: &[IpAddr],
    search_domains: &[&str],
) -> Result<(), WireguardInterfaceError> {
    debug!("Configuring DNS servers and search domains, DNS: {dns:?}, search domains: {search_domains:?}");

    for service in network_services()? {
        debug!("Setting DNS entries for {service}");
        let mut cmd = Command::new("networksetup");
        cmd.arg("-setdnsservers").arg(&service);
        if dns.is_empty() {
            // This clears all DNS entries.
            cmd.arg("Empty");
        } else {
            cmd.args(dns.iter().map(ToString::to_string));
        }

        let status = cmd.status()?;
        if !status.success() {
            return Err(WireguardInterfaceError::DnsError(format!(
                "Command `networksetup` failed while setting DNS servers for {service}: {status}"
            )));
        }
        info!("DNS servers set successfully for {service}");

        // Set search domains, if empty, clear all search domains.
        debug!("Setting search domains for {service}");
        let mut cmd = Command::new("networksetup");
        cmd.arg("-setsearchdomains").arg(&service);
        if search_domains.is_empty() {
            // This clears all search domains.
            cmd.arg("Empty");
        } else {
            cmd.args(search_domains.iter());
        }

        let status = cmd.status()?;
        if !status.success() {
            return Err(WireguardInterfaceError::DnsError(format!("Command `networksetup` failed while setting search domains for {service}: {status}")));
        }

        info!("Search domains set successfully for {service}");
    }

    info!("DNS servers and search domains set successfully");
    Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
pub(crate) fn clear_dns(ifname: &str) -> Result<(), WireguardInterfaceError> {
    debug!("Removing DNS configuration for interface {ifname}");
    let args = ["-d", ifname, "-f"];
    debug!("Executing resolvconf with args: {args:?}");
    let mut cmd = Command::new("resolvconf");
    let output = cmd.args(args).output()?;
    check_command_output_status(output)?;
    info!("DNS configuration removed successfully for interface {ifname}");
    Ok(())
}

#[cfg(target_os = "linux")]
const DEFAULT_FWMARK_TABLE: u32 = 51820;

/// Helper function to add routing.
#[cfg(target_os = "linux")]
pub(crate) fn add_peer_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peer routing for interface: {ifname}");

    let mut unique_allowed_ips = HashSet::new();
    let mut default_route = None;
    for peer in peers {
        for addr in &peer.allowed_ips {
            if addr.ip.is_unspecified() {
                // Handle default route
                default_route = Some(addr);
                break;
            }
            unique_allowed_ips.insert(addr);
        }
    }
    debug!("Allowed IPs that will be used during the peer routing setup: {unique_allowed_ips:?}");

    // If there is default route skip adding other routes.
    if let Some(default_route) = default_route {
        debug!("Found default route in AllowedIPs: {default_route:?}");
        let is_ipv6 = default_route.ip.is_ipv6();
        let proto = if is_ipv6 { "-6" } else { "-4" };
        debug!("Using the following IP version: {proto}");

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
                    let output = Command::new("ip")
                        .args([proto, "route", "show", "table", &table.to_string()])
                        .output()?;
                    if output.stdout.is_empty() {
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
        debug!("Adding default route: {default_route}");
        netlink::add_route(ifname, default_route, Some(fwmark))?;
        debug!("Default route added successfully");
        debug!("Adding fwmark rule for the WireGuard interface to prevent routing loops");
        netlink::add_fwmark_rule(default_route, fwmark)?;
        debug!("Fwmark rule added successfully");

        debug!("Adding rule for main table to suppress current default gateway");
        netlink::add_main_table_rule(default_route, 0)?;
        debug!("Main table rule added successfully");

        if !is_ipv6 {
            debug!("Setting net.ipv4.conf.all.src_valid_mark=1");
            OpenOptions::new()
                .write(true)
                .open("/proc/sys/net/ipv4/conf/all/src_valid_mark")?
                .write_all(b"1")?;
            debug!("net.ipv4.conf.all.src_valid_mark=1 set successfully");
        }
    } else {
        for allowed_ip in unique_allowed_ips {
            debug!("Adding a route for allowed IP: {allowed_ip}");
            netlink::add_route(ifname, allowed_ip, None)?;
            debug!("Route added for allowed IP: {allowed_ip}");
        }
    }
    info!("Peers routing added successfully");
    Ok(())
}

/// Helper function to add routing.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
pub(crate) fn add_peer_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    use nix::errno::Errno;

    use crate::bsd::{delete_gateway, IoError};

    debug!("Adding peer routing for interface: {ifname}");
    for peer in peers {
        debug!("Processing peer: {}", peer.public_key);
        let mut default_route_v4 = false;
        let mut default_route_v6 = false;
        let mut gateway_v4 = Ok(None);
        let mut gateway_v6 = Ok(None);
        for addr in &peer.allowed_ips {
            debug!("Processing route for allowed IP: {addr}, interface: {ifname}");
            // FIXME: currently it is impossible to add another default route, so use the hack from wg-quick for Darwin.
            if addr.ip.is_unspecified() && addr.cidr == 0 {
                debug!("Found following default route in the allowed IPs: {addr}, interface: {ifname}, proceeding with default route initial setup...");
                let default1;
                let default2;
                if addr.ip.is_ipv4() {
                    // 0.0.0.0/1
                    default1 = IpAddrMask::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1);
                    // 128.0.0.0/1
                    default2 = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);
                    gateway_v4 = get_gateway(IpVersion::IPv4);
                    debug!("Default gateway for IPv4 value: {gateway_v4:?}");
                    default_route_v4 = true;
                } else {
                    // ::/1
                    default1 = IpAddrMask::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1);
                    // 8000::/1
                    default2 =
                        IpAddrMask::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1);
                    gateway_v6 = get_gateway(IpVersion::IPv6);
                    debug!("Default gateway for IPv6 value: {gateway_v6:?}");
                    default_route_v6 = true;
                }
                match add_linked_route(&default1, ifname) {
                    Ok(()) => debug!("Route to {default1} has been added for interface {ifname}"),
                    Err(err) => {
                        match err {
                            IoError::WriteIo(errno) if errno == Errno::ENETUNREACH => {
                                warn!("Failed add default route {default1} for interface {ifname}: Network is unreachable. \
                                    This may happen if your interface's IP address is not the same IP version as the default gateway ({default1}) that was tried to be set, in this case this warning can be ignored. \
                                    Otherwise, there may be some other issues with your network configuration.");
                            }
                            _ => {
                                error!("Failed to add route to {default1} for interface {ifname}: {err}");
                            }
                        }
                    }
                }
                match add_linked_route(&default2, ifname) {
                    Ok(()) => debug!("Route to {default2} has been added for interface {ifname}"),
                    Err(err) => {
                        match err {
                            IoError::WriteIo(errno) if errno == Errno::ENETUNREACH => {
                                warn!("Failed add default route {default2} for interface {ifname}: Network is unreachable. \
                                    This may happen if your interface's IP address is not the same IP version as the default gateway ({default2}) that was tried to be set, in this case this warning can be ignored. \
                                    Otherwise, there may be some other issues with your network configuration.");
                            }
                            _ => {
                                error!("Failed to add route to {default2} for interface {ifname}: {err}");
                            }
                        }
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

        if default_route_v4 || default_route_v6 {
            if let Some(endpoint) = peer.endpoint {
                debug!("Default routes have been set, proceeding with further configuration...");
                let host = IpAddrMask::host(endpoint.ip());
                let localhost = if endpoint.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                };
                debug!("Cleaning up old route to {host}, if it exists...");
                match delete_gateway(&host) {
                    Ok(()) => {
                        debug!(
                            "Previously existing route to {host} has been removed, if it existed"
                        );
                    }
                    Err(err) => {
                        debug!("Previously existing route to {host} has not been removed: {err}");
                    }
                }
                if endpoint.is_ipv6() && default_route_v6 {
                    debug!("Endpoint is an IPv6 address and a default route (IPv6) is present in the alloweds IPs, proceeding with further configuration...");
                    match gateway_v6 {
                        Ok(Some(gateway)) => {
                            debug!("Default gateway for IPv4 has been found before: {gateway}, routing the traffic destined to {host} through it...");
                            match add_gateway(&host, gateway, false) {
                                Ok(()) => {
                                    debug!("Route to {host} has been added for gateway {gateway}");
                                }
                                Err(err) => {
                                    error!("Failed to add route to {host} for gateway {gateway}: {err}");
                                }
                            };
                        }
                        Ok(None) => {
                            debug!("Default gateway for IPv6 has not been found, routing the traffic destined to {host} through localhost as a blackhole route...");
                            match add_gateway(&host, localhost, true) {
                                Ok(()) => debug!("Blackhole route to {host} has been added"),
                                Err(err) => {
                                    error!("Failed to add blackhole route to {host}: {err}");
                                }
                            };
                        }
                        Err(err) => {
                            error!("Failed to get gateway for {host}: {err}");
                        }
                    }
                } else if default_route_v4 {
                    debug!("Endpoint is an IPv4 address and a default route (IPv4) is present in the alloweds IPs, proceeding with further configuration...");
                    match gateway_v4 {
                        Ok(Some(gateway)) => {
                            debug!("Default gateway for IPv4 has been found before: {gateway}, routing the traffic destined to {host} through it...");
                            match add_gateway(&host, gateway, false) {
                                Ok(()) => {
                                    debug!("Added route to {host} for gateway {gateway}");
                                }
                                Err(err) => {
                                    error!("Failed to add route to {host} for gateway {gateway}: {err}");
                                }
                            };
                        }
                        Ok(None) => {
                            debug!("Default gateway for IPv4 has not been found, routing the traffic destined to {host} through localhost as a blackhole route...");
                            match add_gateway(&host, localhost, true) {
                                Ok(()) => debug!("Blackhole route to {host} has been added"),
                                Err(err) => {
                                    error!("Failed to add blackhole route to {host}: {err}");
                                }
                            };
                        }
                        Err(err) => {
                            error!("Failed to get gateway for {host}: {err}");
                        }
                    }
                }
            }
        }
    }

    info!("Peers routing added successfully");
    Ok(())
}

/// Clean fwmark rules while removing interface same as in wg-quick
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
