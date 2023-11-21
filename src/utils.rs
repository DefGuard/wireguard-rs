#[cfg(target_os = "linux")]
use crate::netlink;
use crate::{check_command_output_status, Peer, WireguardInterfaceError};
use std::{collections::HashSet, process::Command};

/// Add peer routing
#[cfg(target_os = "linux")]
pub(crate) fn add_peers_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    let mut unique_allowed_ips = HashSet::new();
    for peer in peers {
        for addr in &peer.allowed_ips {
            unique_allowed_ips.insert(addr.to_string());
        }
    }
    for allowed_ip in unique_allowed_ips {
        let is_ipv6 = allowed_ip.contains(':');
        let proto = match is_ipv6 {
            false => "-4",
            true => "-6",
        };
        if ["0.0.0.0/0".to_string(), "::/0".to_string()].contains(&allowed_ip) {
            let mut host = netlink::get_host(ifname)?;
            // Get fwmark table as in wg-quick
            let fwmark = match host.fwmark {
                Some(fwmark) if fwmark != 0 => fwmark,
                Some(_) | None => {
                    let mut table = 51820;
                    loop {
                        let output = Command::new("ip")
                            .args([proto, "route", "show", "table", &table.to_string()])
                            .output()?;
                        if output.stdout.is_empty() {
                            host.fwmark = Some(table);
                            netlink::set_host(ifname, &host)?;
                            break;
                        } else {
                            table += 1;
                        }
                    }
                    table
                }
            };
            // Add table rules
            let output = Command::new("ip")
                .args([
                    proto,
                    "route",
                    "add",
                    &allowed_ip,
                    "dev",
                    ifname,
                    "table",
                    &fwmark.to_string(),
                ])
                .output()?;
            check_command_output_status(output)?;
            let output = Command::new("ip")
                .args([
                    proto,
                    "rule",
                    "add",
                    "not",
                    "fwmark",
                    &fwmark.to_string(),
                    "table",
                    &fwmark.to_string(),
                ])
                .output()?;
            check_command_output_status(output)?;
            let output = Command::new("ip")
                .args([
                    proto,
                    "rule",
                    "add",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ])
                .output()?;
            check_command_output_status(output)?;
            if is_ipv6 {
                let output = Command::new("ip6tables-restore").arg("-n").output()?;
                check_command_output_status(output)?;
            } else {
                let output = Command::new("sysctl")
                    .args(["-q", "net.ipv4.conf.all.src_valid_mark=1"])
                    .output()?;
                check_command_output_status(output)?;
                let output = Command::new("iptables-restore").arg("-n").output()?;
                check_command_output_status(output)?;
            }
        } else {
            // Normal routing
            let output = Command::new("ip")
                .args([proto, "route", "add", &allowed_ip, "dev", ifname])
                .output()?;
            check_command_output_status(output)?
        }
    }
    Ok(())
}
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn add_peers_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    let mut unique_allowed_ips = HashSet::new();
    let mut endpoints = HashSet::new();
    for peer in peers {
        if let Some(endpoint) = peer.endpoint {
            endpoints.insert(endpoint);
        }
        for addr in &peer.allowed_ips {
            unique_allowed_ips.insert(addr.to_string());
        }
    }
    for allowed_ip in unique_allowed_ips {
        let is_ipv6 = allowed_ip.contains(':');
        let (proto, route1, route2) = match is_ipv6 {
            true => ("-inet", "0.0.0.0/1", "128.0.0.0/1"),
            false => ("-inet6", "::/1", "8000::/1"),
        };
        if ["0.0.0.0/0".to_string(), "::/0".to_string()].contains(&allowed_ip) {
            // Add table rules
            Command::new("route")
                .args(["-q", "-n", "add", proto, route1, "-interface", ifname])
                .output()?;
            Command::new("route")
                .args(["-q", "-n", "add", proto, route2, "-interface", ifname])
                .output()?;
            // route endpoints
            for endpoint in &endpoints {
                let proto = match endpoint.is_ipv4() {
                    true => "-inet",
                    false => "-inet6",
                };
                let (ip_version, proto) = match endpoint.is_ipv4() {
                    true => (IpVersion::IPv4, "-inet"),
                    false => (IpVersion::IPv6, "-inet6"),
                };
                let gateway = collect_gateway(ip_version)?;
                let output = Command::new("route")
                    .args(["-q", "-n", "delete", proto, &endpoint.ip().to_string()])
                    .output()?;
                check_command_output_status(output)?;
                if !gateway.is_empty() {
                    let output = Command::new("route")
                        .args([
                            "-q",
                            "-n",
                            "add",
                            proto,
                            &endpoint.ip().to_string(),
                            "-gateway",
                            &gateway,
                        ])
                        .output()?;
                    check_command_output_status(output)?;
                } else {
                    // Prevent routing loop as in wg-quick
                    let address = match endpoint.is_ipv4() {
                        true => "127.0.0.1",
                        false => "::1",
                    };
                    let output = Command::new("route")
                        .args([
                            "-q",
                            "-n",
                            "add",
                            proto,
                            &endpoint.ip().to_string(),
                            address,
                            "-blackhole",
                        ])
                        .output()?;
                    check_command_output_status(output)?;
                }
            }
        } else {
            let output = Command::new("route")
                .args(["-q", "-n", "add", proto, &allowed_ip, "-interface", ifname])
                .output()?;
            check_command_output_status(output)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) enum IpVersion {
    IPv4,
    IPv6,
}

/// Helper function to extracts gateway on FreeBSD and MacOS systems
/// Needed to add proper routing for 0.0.0.0/0, ::/0
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

/// Clean fwmark rules while removing interface
#[cfg(target_os = "linux")]
pub(crate) fn clean_fwmark_rules(fwmark: &str) -> Result<(), WireguardInterfaceError> {
    for ip_type in ["-4", "-6"] {
        let ip_rules = Command::new("ip")
            .args([ip_type, "rule", "show"])
            .output()?
            .stdout;
        if String::from_utf8_lossy(&ip_rules).contains(&format!("lookup {}", fwmark)) {
            let output = Command::new("ip")
                .args([ip_type, "rule", "delete", "table", fwmark])
                .output()?;
            check_command_output_status(output)?;
        };
        if String::from_utf8_lossy(&ip_rules)
            .contains("from all lookup main suppress_prefixlength 0")
        {
            let output = Command::new("ip")
                .args([
                    ip_type,
                    "rule",
                    "delete",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ])
                .output()?;
            check_command_output_status(output)?;
        };
    }
    Ok(())
}
