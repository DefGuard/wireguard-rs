use std::env;

use crate::error::WireguardInterfaceError;

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
    let paths = env::var_os("PATH").ok_or(WireguardInterfaceError::MissingDependency(
        "Environment variable `PATH` not found".into(),
    ))?;

    // Find the missing command to provide a more informative error message later.
    let missing = COMMANDS.iter().find(|cmd| {
        !env::split_paths(&paths).any(|dir| {
            trace!("Trying to find {cmd} in {dir:?}");
            match dir.join(cmd).try_exists() {
                Ok(true) => {
                    debug!("{cmd} found in {dir:?}");
                    true
                }
                Ok(false) => {
                    trace!("{cmd} not found in {dir:?}");
                    false
                }
                Err(err) => {
                    warn!("Error while checking for {cmd} in {dir:?}: {err}");
                    false
                }
            }
        })
    });

    if let Some(cmd) = missing {
        Err(WireguardInterfaceError::MissingDependency(format!(
            "Command `{cmd}` required by wireguard-rs couldn't be found. The following directories were checked: {paths:?}"
        )))
    } else {
        debug!("All commands required by wireguard-rs are available");
        Ok(())
    }
}
