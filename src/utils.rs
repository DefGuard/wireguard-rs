#[cfg(target_os = "linux")]
use crate::netlink;
use crate::{check_command_output_status, Peer, WireguardInterfaceError};
use std::{collections::HashSet, process::Command};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::{io::Write, net::IpAddr, process::Stdio};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn configure_dns(ifname: &str, dns: Vec<IpAddr>) -> Result<(), WireguardInterfaceError> {
    // Build the resolvconf command
    debug!("Setting dns");
    let mut cmd = Command::new("resolvconf");
    let args = ["-a", ifname, "-m", "0", "-x"];
    debug!("Executing comamnd resolvconf with args: {:?}", args);
    cmd.args(args);

    // Execute resolvconf command and pipe filtered DNS entries
    if let Ok(mut child) = cmd.stdin(Stdio::piped()).spawn() {
        if let Some(mut stdin) = child.stdin.take() {
            for entry in &dns {
                debug!("Adding nameserver entry: {entry}");
                writeln!(stdin, "nameserver {entry}")?;
            }
        }

        let status = child.wait().expect("Failed to wait for command");
        if status.success() {
            return Ok(());
        }
    }

    Err(WireguardInterfaceError::DnsError)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn clean_dns(ifname: &str) {
    let args = ["-d", ifname, "-f"];
    debug!("Executing resolvconf with args: {args:?}");
    Command::new("resolvconf").args(args);
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

    // If there is default route skip adding other routings.
    if let Some(default_route) = default_route {
        debug!("Found default route: {default_route:?}");
        let is_ipv6 = default_route.ip.is_ipv6();
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
        netlink::add_route(ifname, default_route, Some(fwmark))?;
        netlink::add_rule(default_route, fwmark)?;

        debug!("Adding rule for main table");
        netlink::add_main_table_rule(default_route, 0)?;

        if is_ipv6 {
            debug!("Reloading ip6tables");
            let output = Command::new("ip6tables-restore").arg("-n").output()?;
            check_command_output_status(output)?;
        } else {
            debug!("Setting systemctl net.ipv4.conf.all.src_valid_mark=1");
            let output = Command::new("sysctl")
                .args(["-q", "net.ipv4.conf.all.src_valid_mark=1"])
                .output()?;
            check_command_output_status(output)?;

            debug!("Reloading iptables");
            let output = Command::new("iptables-restore").arg("-n").output()?;
            check_command_output_status(output)?;
        }
    } else {
        for allowed_ip in unique_allowed_ips {
            debug!("Processing allowed IP: {allowed_ip}");
            netlink::add_route(ifname, allowed_ip, None)?;
        }
    }
    info!("Peers routing added successfully");
    Ok(())
}

/// Helper function to add routing.  
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn add_peer_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peer routing for interface: {ifname}");
    let mut unique_allowed_ips = HashSet::new();
    let mut endpoints = HashSet::new();
    let mut default_route = None;

    // TODO: find a better way to handle default routes.
    for peer in peers {
        if let Some(endpoint) = peer.endpoint {
            endpoints.insert(endpoint);
        }
        for addr in &peer.allowed_ips {
            // Handle default route
            if addr.ip.is_unspecified() {
                default_route = Some(addr);
                break;
            }
            unique_allowed_ips.insert(addr);
        }
    }

    if let Some(default_route) = default_route {
        debug!("Found default route: {default_route:?}");
        let is_ipv6 = default_route.ip.is_ipv6();
        let (proto, route1, route2) = if is_ipv6 {
            ("-inet6", "::/1", "8000::/1")
        } else {
            ("-inet", "0.0.0.0/1", "128.0.0.0/1")
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
            let (ip_version, proto) = if endpoint.is_ipv4() {
                (IpVersion::IPv4, "-inet")
            } else {
                (IpVersion::IPv6, "-inet6")
            };
            let gateway = get_gateway(&ip_version)?;
            // Precautionary `route delete` don't handle result because it may not exist.
            let _ = Command::new("route")
                .args(["-q", "-n", "delete", proto, &endpoint.ip().to_string()])
                .output();

            let endpoint_ip = endpoint.ip().to_string();
            let args = if gateway.is_empty() {
                // Prevent routing loop as in wg-quick
                debug!("Default gateway not found.");
                let address = if endpoint.is_ipv4() {
                    "127.0.0.1"
                } else {
                    "::1"
                };
                [
                    "-q",
                    "-n",
                    "add",
                    proto,
                    &endpoint_ip,
                    address,
                    "-blackhole",
                ]
            } else {
                debug!("Found default gateway: {gateway}");
                ["-q", "-n", "add", proto, &endpoint_ip, "-gateway", &gateway]
            };
            debug!("Executing command route with args: {args:?}");
            let output = Command::new("route").args(args).output()?;
            check_command_output_status(output)?;
        }
    } else {
        for allowed_ip in unique_allowed_ips {
            debug!("Processing allowed IP: {}", allowed_ip);
            let is_ipv6 = allowed_ip.ip.is_ipv6();
            let proto = if is_ipv6 { "-inet6" } else { "-inet" };
            let args = [
                "-q",
                "-n",
                "add",
                proto,
                &allowed_ip.to_string(),
                "-interface",
                ifname,
            ];
            debug!("Executing command route with args: {args:?}");
            let output = Command::new("route").args(args).output()?;
            check_command_output_status(output)?;
        }
    }

    info!("Peers routing added successfully");
    Ok(())
}

pub enum IpVersion {
    IPv4,
    IPv6,
}

/// Get IP gateway.
///
/// Helper function to find default IP v4 or v6 gateway on FreeBSD and macOS systems.
/// Same as in wg-quick find default gateway info using `netstat -nr -f inet` or `inet6`
/// based on allowed IP version.
/// Needed to add proper routing for 0.0.0.0/0, ::/0.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn get_gateway(ip_version: &IpVersion) -> Result<String, WireguardInterfaceError> {
    let command_args = match ip_version {
        IpVersion::IPv4 => &["-nr", "-f", "inet"],
        IpVersion::IPv6 => &["-nr", "-f", "inet6"],
    };

    let output = Command::new("netstat").args(command_args).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > 1 && fields[0] == "default" && !fields[1].starts_with("link#") {
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
