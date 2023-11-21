#[cfg(target_os = "linux")]
use crate::netlink;
use crate::{check_command_output_status, Peer, WireguardInterfaceError};
use std::{collections::HashSet, process::Command};

/// Add peer routing basically copy of wg-quick
/// On linux system sysctl command is requried to work if using 0.0.0.0/0 or ::/0
/// For every allowed ip it runs ip `ip_version` route add `allowed_ip` dev `ifname`
/// For 0.0.0.0/0 allowed ip it runs in order:
/// ip -4 route add 0.0.0.0/0 dev `ifname` table `fwmark` fwmark is host.fwmark
/// or default 51820 if value is None
/// ip -4 rule add not fwmark `host.fwmark` table `host.fwmark`
/// ip -4 rule add table main supress_prefixlength 0
/// sysctl -q net.ipv4.conf.all.src_valid_mark=1
/// iptables-restore -n

#[cfg(target_os = "linux")]
pub(crate) fn add_peers_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peers routing for interface: {}", ifname);

    let mut unique_allowed_ips = HashSet::new();
    for peer in peers {
        for addr in &peer.allowed_ips {
            unique_allowed_ips.insert(addr.to_string());
        }
    }

    for allowed_ip in unique_allowed_ips {
        debug!("Processing allowed IP: {}", allowed_ip);

        let is_ipv6 = allowed_ip.contains(':');
        let proto = match is_ipv6 {
            false => "-4",
            true => "-6",
        };

        if ["0.0.0.0/0".to_string(), "::/0".to_string()].contains(&allowed_ip) {
            debug!("Processing default route: {}", allowed_ip);

            let mut host = netlink::get_host(ifname)?;
            debug!("Current host: {:?}", host);

            let fwmark = match host.fwmark {
                Some(fwmark) => fwmark,
                None => {
                    let mut table = 51820;
                    loop {
                        let output = Command::new("ip")
                            .args([proto, "route", "show", "table", &table.to_string()])
                            .output()?;
                        if output.stdout.is_empty() {
                            host.fwmark = Some(table);
                            netlink::set_host(ifname, &host)?;
                            debug!("Assigned fwmark: {}", table);
                            break;
                        } else {
                            table += 1;
                        }
                    }
                    table
                }
            };

            debug!("Using fwmark: {}", fwmark);

            // Add table rules
            debug!("Adding route for allowed IP: {}", allowed_ip);
            let args = [
                proto,
                "route",
                "add",
                &allowed_ip,
                "dev",
                ifname,
                "table",
                &fwmark.to_string(),
            ];
            debug!("Executing command `ip` with args: {:?}", args);
            let output = Command::new("ip").args(args).output()?;
            check_command_output_status(output)?;

            debug!("Adding rule for fwmark: {}", fwmark);
            let args = [
                proto,
                "rule",
                "add",
                "not",
                "fwmark",
                &fwmark.to_string(),
                "table",
                &fwmark.to_string(),
            ];
            debug!("Executing command `ip` with args: {:?}", args);
            let output = Command::new("ip").args(args).output()?;
            check_command_output_status(output)?;

            debug!("Adding rule for main table");
            let args = [
                proto,
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ];
            debug!("Executing command `ip` with args: {:?}", args);
            let output = Command::new("ip").args(args).output()?;
            check_command_output_status(output)?;

            if is_ipv6 {
                debug!("Reloading ip6tables");
                debug!("Executing ip6tables-restore -n");
                let output = Command::new("ip6tables-restore").arg("-n").output()?;
                check_command_output_status(output)?;
            } else {
                debug!("executing `sysctl -q systemctl net.ipv4.conf.all.src_valid_mark=1`");
                let output = Command::new("sysctl")
                    .args(["-q", "net.ipv4.conf.all.src_valid_mark=1"])
                    .output()?;
                check_command_output_status(output)?;

                debug!("Reloading iptables");
                debug!("Executing `iptables-restore -n`");
                let output = Command::new("iptables-restore").arg("-n").output()?;
                check_command_output_status(output)?;
            }
        } else {
            // Normal routing
            let args = [proto, "route", "add", &allowed_ip, "dev", ifname];
            debug!("Adding route for allowed IP: {}", allowed_ip);
            debug!("Executing command `ip` with args: {:?}", args);
            let output = Command::new("ip").args(args).output()?;
            check_command_output_status(output)?;
        }
    }

    info!("Peers routing added successfully");
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn add_peers_routing(
    peers: &[Peer],
    ifname: &str,
) -> Result<(), WireguardInterfaceError> {
    debug!("Adding peers routing for interface: {}", ifname);
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
        debug!("Processing allowed IP: {}", allowed_ip);
        let is_ipv6 = allowed_ip.contains(':');
        let (proto, route1, route2) = match is_ipv6 {
            true => ("-inet6", "::/1", "8000::/1"),
            false => ("-inet", "0.0.0.0/1", "128.0.0.0/1"),
        };
        if ["0.0.0.0/0".to_string(), "::/0".to_string()].contains(&allowed_ip) {
            debug!("Processing default route: {}", allowed_ip);
            // Add table rules
            let args = ["-q", "-n", "add", proto, route1, "-interface", ifname];
            debug!("Executing command `route` with args: {:?}", args);
            let output = Command::new("route").args(args).output()?;
            check_command_output_status(output)?;
            let args = ["-q", "-n", "add", proto, route2, "-interface", ifname];
            debug!("Executing command `route` with args: {:?}", args);
            let output = Command::new("route").args(args).output()?;
            check_command_output_status(output)?;
            // route endpoints
            for endpoint in &endpoints {
                debug!("Processing endpoint: {}", endpoint);
                let (ip_version, proto) = match endpoint.is_ipv4() {
                    true => (IpVersion::IPv4, "-inet"),
                    false => (IpVersion::IPv6, "-inet6"),
                };
                let gateway = collect_gateway(ip_version)?;
                // Precautionary route delete don't handle result because it may not exist
                let args = ["-q", "-n", "delete", proto, &endpoint.ip().to_string()];
                debug!("Executing command `route` with args {:?}", args);
                let _ = Command::new("route").args(args).output();
                if !gateway.is_empty() {
                    let args = [
                        "-q",
                        "-n",
                        "add",
                        proto,
                        &endpoint.ip().to_string(),
                        "-gateway",
                        &gateway,
                    ];
                    debug!("Executing command `route` with args {:?}", args);
                    let output = Command::new("route").args(args).output()?;
                    check_command_output_status(output)?;
                } else {
                    // Prevent routing loop as in wg-quick
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
                    debug!("Executing command `route` with args {:?}", args);
                    let output = Command::new("route").args(args).output()?;
                    check_command_output_status(output)?;
                }
            }
        } else {
            let args = ["-q", "-n", "add", proto, &allowed_ip, "-interface", ifname];
            debug!("Executing command `route` with args {:?}", args);
            let output = Command::new("route").args(args).output()?;
            check_command_output_status(output)?;
        }
    }
    info!("Peers routing added successfully");
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) enum IpVersion {
    IPv4,
    IPv6,
}

/// Helper function to extracts gateway on FreeBSD and MacOS systems
/// Same as in wg-quick extract gateway info using `netstat -nr -f inet` or `inet6`
/// based on allowed ip  version
/// Needed to add proper routing for 0.0.0.0/0, ::/0
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn collect_gateway(ip_version: IpVersion) -> Result<String, WireguardInterfaceError> {
    debug!("Collecting gateway.");
    let command_args = match ip_version {
        IpVersion::IPv4 => &["-nr", "-f", "inet"],
        IpVersion::IPv6 => &["-nr", "-f", "inet6"],
    };
    debug!("Executing command `netstat` with args: {:?}", command_args);

    let output = Command::new("netstat").args(command_args).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        debug!("Processing output line: {:?}", fields);
        if fields.len() > 1 && fields[0] == "default" && !fields[1].contains("link#") {
            return Ok(fields[1].to_string());
        }
    }
    error!("Gateway not found");

    Ok(String::new())
}

/// Clean fwmark rules while removing interface same as in wg-quick
/// Under the hood it runs:
/// based on ip -4 rule show output or ip -6 rule show output
/// ip -4 rule delete table (Interface host fwmark)
/// ip -4 rule delete table main suppress_prefixlength 0
/// or:
/// ip -6 rule delete table (Interface host fwmark)
/// ip -6 rule delete table main suppress_prefixlength 0
#[cfg(target_os = "linux")]
pub(crate) fn clean_fwmark_rules(fwmark: &str) -> Result<(), WireguardInterfaceError> {
    debug!("Removing fwmark rules.");
    for ip_type in ["-4", "-6"] {
        // Check if rule exists `ip <ip_type> rule show`
        let args = [ip_type, "rule", "show"];
        debug!("Executing command `ip` with args: {:?}", args);
        let ip_rules = Command::new("ip").args(args).output()?.stdout;
        // Check ip rules contains fwmark rules if yes run `ip <ip_type> rule delete table fwmark`
        if String::from_utf8_lossy(&ip_rules).contains(&format!("lookup {}", fwmark)) {
            let args = [ip_type, "rule", "delete", "table", fwmark];
            debug!("Executing command `ip` with args: {:?}", args);
            let output = Command::new("ip").args(args).output()?;
            check_command_output_status(output)?;
        };
        // Check ip rules contains suppress lookup if yes delete using:
        // `ip <ip_type> rule delete table main suppress_prefixlength 0`
        if String::from_utf8_lossy(&ip_rules)
            .contains("from all lookup main suppress_prefixlength 0")
        {
            let args = [
                ip_type,
                "rule",
                "delete",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ];
            debug!("Executing command `ip` with args: {:?}", args);
            let output = Command::new("ip").args(args).output()?;
            check_command_output_status(output)?;
        };
    }
    Ok(())
}
