#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::io::{BufRead, BufReader, Cursor, Error as IoError};
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use std::{io::Write, process::Stdio};
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    fs::OpenOptions,
    process::Command,
};

#[cfg(target_os = "freebsd")]
use crate::check_command_output_status;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use crate::{
    bsd::{add_gateway_host, add_linked_route, get_gateway},
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
                .open("/proc/sys/net/ipv4/conf/all/src_valid_mark")?.write_all(b"1")?;
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
    use crate::bsd::delete_gateway_host;

    debug!("Adding peer routing for interface: {ifname}");
    for peer in peers {
        for addr in &peer.allowed_ips {
            // FIXME: currently it is impossible to add another default route, so use the hack from wg-quick for Darwin.
            if addr.ip.is_unspecified() && addr.cidr == 0 {
                let default1;
                let default2;
                let gateway;
                if addr.ip.is_ipv4() {
                    // 0.0.0.0/1
                    default1 = IpAddrMask::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1);
                    // 128.0.0.0/1
                    default2 = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);
                    gateway = get_gateway(IpVersion::IPv4).unwrap();
                } else {
                    // ::/1
                    default1 = IpAddrMask::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1);
                    // 8000::/1
                    default2 =
                        IpAddrMask::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1);
                    gateway = get_gateway(IpVersion::IPv6).unwrap();
                }
                match add_linked_route(&default1, ifname) {
                    Ok(()) => debug!("Route to {default1} has been added for interface {ifname}"),
                    Err(err) => {
                        error!("Failed to add route to {default1} for interface {ifname}: {err}");
                    }
                }
                match add_linked_route(&default2, ifname) {
                    Ok(()) => debug!("Route to {default2} has been added for interface {ifname}"),
                    Err(err) => {
                        error!("Failed to add route to {default2} for interface {ifname}: {err}");
                    }
                }
                if let Some(endpoint) = peer.endpoint {
                    let host = IpAddrMask::host(endpoint.ip());
                    if let Some(gateway) = gateway {
                        // Try to silently remove route to host as it may already exist.
                        let _ = delete_gateway_host(&host);
                        match add_gateway_host(&host, gateway, false) {
                            Ok(()) => {
                                debug!("Route to {host} has been added for gateway {gateway}");
                            }
                            Err(err) => {
                                error!(
                                    "Failed to add route to {host} for gateway {gateway}: {err}"
                                );
                            }
                        }
                    } else {
                        // Equivalent to `route -n add -inet[6] <endpoint> <localhost> -blackhole`
                        let localhost = if endpoint.is_ipv4() {
                            IpAddr::V4(Ipv4Addr::LOCALHOST)
                        } else {
                            IpAddr::V6(Ipv6Addr::LOCALHOST)
                        };
                        match add_gateway_host(&host, localhost, true) {
                            Ok(()) => debug!("Blackhole route to {host} has been added"),
                            Err(err) => {
                                error!("Failed to add blackhole route to {host}: {err}");
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
pub fn resolve(addr: &str) -> Result<SocketAddr, WireguardInterfaceError> {
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
