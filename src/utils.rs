#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::WireguardInterfaceError;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn set_dns(ifname: &str, dns: Vec<String>) -> Result<(), WireguardInterfaceError> {
    // Build the resolvconf command
    let mut cmd = Command::new("resolvconf");
    let args = ["-a", ifname, "-m", "0", "-x"];
    debug!("Executing comamnd resolvconf with args: {:?}", args);
    cmd.args(args);

    let search_entries: Vec<String> = dns
        .iter()
        .filter_map(|s| {
            if s.parse::<std::net::IpAddr>().is_err() {
                Some(s.clone())
            } else {
                None
            }
        })
        .collect();
    let nameserver_entries: Vec<&String> = dns
        .iter()
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .collect();

    // Execute resolvconf command and pipe filtered DNS entries
    if let Ok(mut child) = cmd.stdin(Stdio::piped()).spawn() {
        if let Some(mut stdin) = child.stdin.take() {
            for entry in &nameserver_entries {
                debug!("Adding nameserver entry: {entry}");
                writeln!(stdin, "nameserver {}", entry)?;
            }
            let search_entries = search_entries.join(" ");
            debug!("Adding following search entries: {search_entries}",);
            writeln!(stdin, "search {}", search_entries)?;
        }

        let status = child.wait().expect("Failed to wait for command");
        if status.success() {
            Ok(())
        } else {
            Err(WireguardInterfaceError::DnsError)
        }
    } else {
        Err(WireguardInterfaceError::DnsError)
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn clean_dns(ifname: &str) {
    let args = ["-d", ifname, "-f"];
    debug!("Executing resolvconf with args: {args:?}");
    Command::new("resolvconf").args(args);
}
