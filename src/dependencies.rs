use std::env;

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use crate::dns::detect_dns_backend;
use crate::{error::WireguardInterfaceError, utils::get_command_path};

#[cfg(target_os = "linux")]
const COMMANDS: [&str; 1] = ["ip"];

#[cfg(target_os = "macos")]
const COMMANDS: [&str; 1] = ["networksetup"];

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "windows"))]
const COMMANDS: [&str; 0] = [];

pub(crate) fn check_external_dependencies() -> Result<(), WireguardInterfaceError> {
    debug!("Checking if all commands required by wireguard-rs are available");
    let paths = env::var_os("PATH").ok_or_else(|| {
        WireguardInterfaceError::MissingDependency("Environment variable `PATH` not found".into())
    });

    // Find the missing command to provide a more informative error message later.
    let missing_command = COMMANDS
        .iter()
        .find(|cmd| get_command_path(cmd).map_or(true, |path_opt| path_opt.is_none()));

    if let Some(cmd) = missing_command {
        return Err(WireguardInterfaceError::MissingDependency(format!(
            "Command `{cmd}` required by wireguard-rs couldn't be found. The following directories were checked: {paths:?}"
        )));
    }

    // DNS can be configured through more than one backend, so check that at least one of them
    // is available instead of requiring a specific command.
    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
    detect_dns_backend()?;

    debug!("All commands required by wireguard-rs are available");
    Ok(())
}
