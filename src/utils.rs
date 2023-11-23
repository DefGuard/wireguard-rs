use crate::{check_command_output_status, Peer, WireguardInterfaceError};
#[cfg(target_os = "linux")]
use crate::{netlink, IpAddrMask};
use std::{collections::HashSet, process::Command};

#[cfg(target_os = "linux")]
const DEFAULT_FWMARK_TABLE: u32 = 51820;

/// Helper function to add routing.  
#[cfg(target_os = "linux")]
pub(crate) fn add_peers_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peers routing for interface: {ifname}");

    let mut unique_allowed_ips = HashSet::new();
    let mut default_route = None;
    for peer in peers {
        for addr in &peer.allowed_ips {
            if addr.ip.is_unspecified() {
                // Handle default route
                default_route = Some(addr.to_string());
                break;
            }
            unique_allowed_ips.insert(addr.to_string());
        }
    }

    // If there is default route skip adding other routings.
    if let Some(default_route) = default_route {
        let is_ipv6 = default_route.contains(':');
        let proto = if is_ipv6 { "-6" } else { "-4" };

        let mut host = netlink::get_host(ifname)?;
        debug!("Current host: {host:?}");

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
                    } else {
                        table += 1;
                    }
                }
                table
            }
        };
        debug!("Using fwmark: {fwmark}");
        // Add table rules
        debug!("Adding route for allowed IP: {default_route}");
        let address = default_route.parse::<IpAddrMask>()?;
        netlink::add_route(ifname, &address, Some(fwmark))?;
        netlink::add_rule(&address, fwmark)?;

        debug!("Adding rule for main table");
        netlink::add_main_table_rule(&address, 0)?;

        if is_ipv6 {
            debug!("Reloading ip6tables");
            debug!("Running ip6tables-restore -n");
            let output = Command::new("ip6tables-restore").arg("-n").output()?;
            check_command_output_status(output)?;
        } else {
            debug!("Setting systemctl net.ipv4.conf.all.src_valid_mark=1");
            let output = Command::new("sysctl")
                .args(["-q", "net.ipv4.conf.all.src_valid_mark=1"])
                .output()?;
            check_command_output_status(output)?;

            debug!("Reloading iptables");
            debug!("Running iptables-restore -n");
            let output = Command::new("iptables-restore").arg("-n").output()?;
            check_command_output_status(output)?;
        }
    } else {
        for allowed_ip in unique_allowed_ips {
            debug!("Processing allowed IP: {allowed_ip}");
            let address = allowed_ip.parse::<IpAddrMask>()?;
            netlink::add_route(ifname, &address, None)?;
        }
    }
    info!("Peers routing added successfully");
    Ok(())
}

/// Helper function to add routing.  
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn add_peers_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peers routing for interface: {}", ifname);
    let mut unique_allowed_ips = HashSet::new();
    let mut endpoints = HashSet::new();
    let mut default_route = None;
    for peer in peers {
        if let Some(endpoint) = peer.endpoint {
            endpoints.insert(endpoint);
        }
        for addr in &peer.allowed_ips {
            // Handle default route
            if addr.ip.is_unspecified() {
                default_route = Some(addr.to_string());
                break;
            }
            unique_allowed_ips.insert(addr.to_string());
        }
    }
    if let Some(default_route) = default_route {
        let is_ipv6 = default_route.contains(':');
        let (proto, route1, route2) = match is_ipv6 {
            true => ("-inet6", "::/1", "8000::/1"),
            false => ("-inet", "0.0.0.0/1", "128.0.0.0/1"),
        };
        // Add table rules
        let args = ["-q", "-n", "add", proto, route1, "-interface", ifname];
        debug!("Executing command route with args: {args:?}");
        let output = Command::new("route").args(args).output()?;
        check_command_output_status(output)?;
        let args = ["-q", "-n", "add", proto, route2, "-interface", ifname];
        debug!("Executing command route with args: {args:?}");
        let output = Command::new("route").args(args).output()?;
        check_command_output_status(output)?;
        // route endpoints
        for endpoint in &endpoints {
            let (ip_version, proto) = match endpoint.is_ipv4() {
                true => (IpVersion::IPv4, "-inet"),
                false => (IpVersion::IPv6, "-inet6"),
            };
            let gateway = collect_gateway(ip_version)?;
            // Precautionary route delete don't handle result because it may not exist
            let _ = Command::new("route")
                .args(["-q", "-n", "delete", proto, &endpoint.ip().to_string()])
                .output();
            if !gateway.is_empty() {
                debug!("Found default gateway: {gateway}");
                let args = [
                    "-q",
                    "-n",
                    "add",
                    proto,
                    &endpoint.ip().to_string(),
                    "-gateway",
                    &gateway,
                ];
                debug!("Executing command rotue with args: {args:?}");
                let output = Command::new("route").args(args).output()?;
                check_command_output_status(output)?;
            } else {
                // Prevent routing loop as in wg-quick
                debug!("Default gateway not found.");
                let address = match endpoint.is_ipv4() {
                    true => "127.0.0.1",
                    false => "::1",
                };
                let args = [
                    "-q",
                    "-n",
                    "add",
                    proto,
                    &endpoint.ip().to_string(),
                    address,
                    "-blackhole",
                ];
                debug!("Executing command route with args: {args:?}");
                let output = Command::new("route").args(args).output()?;
                check_command_output_status(output)?;
            }
        }
    } else {
        for allowed_ip in unique_allowed_ips {
            debug!("Processing allowed IP: {}", allowed_ip);
            let is_ipv6 = allowed_ip.contains(':');
            let proto = if is_ipv6 { "-inet6" } else { "-inet" };
            let args = ["-q", "-n", "add", proto, &allowed_ip, "-interface", ifname];
            debug!("Executing command route with args: {args:?}");
            let output = Command::new("route").args(args).output()?;
            check_command_output_status(output)?;
        }
    }
    Ok(())
}

//#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub enum IpVersion {
    IPv4,
    IPv6,
}

/// Helper function to find default ipv4 or ipv6 gateway on FreeBSD and MacOS systems.
/// Same as in wg-quick find default gateway info using `netstat -nr -f inet` or `inet6`
/// based on allowed ip version.
/// Needed to add proper routing for 0.0.0.0/0, ::/0.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn collect_gateway(ip_version: IpVersion) -> Result<String, WireguardInterfaceError> {
    let command_args = match ip_version {
        IpVersion::IPv4 => &["-nr", "-f", "inet"],
        IpVersion::IPv6 => &["-nr", "-f", "inet6"],
    };

    let output = Command::new("netstat").args(command_args).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > 1 && fields[0] == "default" && !fields[1].contains("link#") {
            return Ok(fields[1].to_string());
        }
    }

    Ok(String::new())
}

/// Clean fwmark rules while removing interface same as in wg-quick
#[cfg(target_os = "linux")]
pub(crate) fn clean_fwmark_rules(fwmark: u32) -> Result<(), WireguardInterfaceError> {
    netlink::delete_rule(IpVersion::IPv4, fwmark)?;
    netlink::delete_main_table_rule(IpVersion::IPv4, 0)?;
    netlink::delete_rule(IpVersion::IPv6, fwmark)?;
    netlink::delete_main_table_rule(IpVersion::IPv6, 0)?;
    Ok(())
}
