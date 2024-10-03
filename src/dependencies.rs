use std::process::Command;

use crate::error::WireguardInterfaceError;

#[cfg(target_os = "linux")]
const COMMANDS: [(&str, &str); 5] = [
    ("resolvconf", "--version"),
    ("ip", "help"),
    ("iptables-restore", "--version"),
    ("ip6tables-restore", "--version"),
    ("sysctl", "--version"),
];

#[cfg(target_os = "windows")]
const COMMANDS: [(&str, &str); 1] = [("wireguard", "/")];

#[cfg(target_os = "macos")]
const COMMANDS: [(&str, &str); 2] = [("wireguard-go", "--version"), ("networksetup", "-version")];

#[cfg(target_os = "freebsd")]
const COMMANDS: [(&str, &str); 0] = [];

/// Check if the commands/executables required for interface management are available.
pub(crate) fn check_external_dependencies() -> Result<(), WireguardInterfaceError> {
    for (cmd, arg) in COMMANDS.iter() {
        debug!(
            "Checking if command `{}` is available by running: {} {}",
            cmd, cmd, arg
        );
        Command::new(cmd).arg(arg).output().map_err(|err| {
            WireguardInterfaceError::MissingDependency(format!(
                "Command `{}` required by wireguard-rs couldn't be found, details: {}",
                cmd, err
            ))
        })?;
        debug!("Command `{}` is available", cmd);
    }

    Ok(())
}
