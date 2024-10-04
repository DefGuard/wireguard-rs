use std::process::Command;

use crate::error::WireguardInterfaceError;

#[cfg(target_os = "linux")]
const COMMANDS: [(&str, &str); 2] = [
    ("resolvconf", "--version"),
    ("ip", "help"),
];

// There is no Windows command to check the version of WireGuard.
// The "/" argument (or any other non-existent argument) normally returns a help message popup. However when invoked
// by means of rust's std::process::Command, it only results in an `Ok` output (or an `Err` if the command is not found),
// allowing us to check if the command is available.
#[cfg(target_os = "windows")]
const COMMANDS: [(&str, &str); 1] = [("wireguard", "/")];

#[cfg(target_os = "macos")]
const COMMANDS: [(&str, &str); 2] = [("wireguard-go", "--version"), ("networksetup", "-version")];

#[cfg(any(target_os = "freebsd", target_os="netbsd"))]
const COMMANDS: [(&str, &str); 1] = [("resolvconf", "--version")];

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
