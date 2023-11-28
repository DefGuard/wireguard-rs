#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::WireguardInterfaceError;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::{
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn set_dns(ifname: &str, dns: Vec<IpAddr>) -> Result<(), WireguardInterfaceError> {
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
                writeln!(stdin, "nameserver {}", entry)?;
            }
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
