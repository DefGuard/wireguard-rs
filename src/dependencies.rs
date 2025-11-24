use std::env;

use crate::{error::WireguardInterfaceError, utils::get_command_path};

#[cfg(target_os = "linux")]
const COMMANDS: [&str; 2] = ["resolvconf", "ip"];

#[cfg(target_os = "windows")]
const COMMANDS: [&str; 1] = [("wireguard.exe")];

#[cfg(target_os = "macos")]
const COMMANDS: [&str; 2] = ["wireguard-go", "networksetup"];

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
const COMMANDS: [&str; 1] = ["resolvconf"];

pub(crate) fn check_external_dependencies() -> Result<(), WireguardInterfaceError> {
    debug!("Checking if all commands required by wireguard-rs are available");
    let paths = env::var_os("PATH").ok_or_else(|| {
        WireguardInterfaceError::MissingDependency("Environment variable `PATH` not found".into())
    });

    // Find the missing command to provide a more informative error message later.
    let missing_command = COMMANDS
        .iter()
        .find(|cmd| get_command_path(cmd).map_or(true, |path_opt| path_opt.is_none()));

    missing_command.map_or_else(|| {
            debug!("All commands required by wireguard-rs are available");
            Ok(())
    }, |cmd| Err(WireguardInterfaceError::MissingDependency(format!(
        "Command `{cmd}` required by wireguard-rs couldn't be found. The following directories were checked: {paths:?}"
    ))))
}
