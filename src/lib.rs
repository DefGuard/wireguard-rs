#[cfg(target_os = "freebsd")]
pub mod bsd;
pub mod error;
pub mod host;
pub mod key;
pub mod net;
#[cfg(target_os = "linux")]
pub mod netlink;
pub mod wgapi;

#[cfg(target_os = "freebsd")]
mod wgapi_freebsd;
#[cfg(target_os = "linux")]
mod wgapi_linux;
#[cfg(target_family = "unix")]
mod wgapi_userspace;
mod wireguard_interface;

#[macro_use]
extern crate log;

use std::process::Output;

// public reexports
#[cfg(target_os = "freebsd")]
pub use wgapi_freebsd::WireguardApiFreebsd;
#[cfg(target_os = "linux")]
pub use wgapi_linux::WireguardApiLinux;
#[cfg(target_family = "unix")]
pub use wgapi_userspace::WireguardApiUserspace;
pub use {
    self::error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::{IpAddrMask, IpAddrParseError},
    wgapi::WGApi,
    wireguard_interface::WireguardInterfaceApi,
};

/// Wireguard Interface configuration
#[derive(Debug, Clone)]
pub struct InterfaceConfiguration {
    pub name: String,
    pub prvkey: String,
    pub address: String,
    pub port: u32,
    pub peers: Vec<Peer>,
}

impl TryFrom<&InterfaceConfiguration> for Host {
    type Error = WireguardInterfaceError;

    fn try_from(config: &InterfaceConfiguration) -> Result<Self, Self::Error> {
        let key = config.prvkey.as_str().try_into()?;
        let mut host = Host::new(config.port as u16, key);
        for peercfg in &config.peers {
            let key: Key = peercfg.public_key.clone();
            let mut peer = Peer::new(key.clone());
            peer.set_allowed_ips(peercfg.allowed_ips.clone());
            host.peers.insert(key, peer);
        }
        Ok(host)
    }
}

/// Util function which checks external command output status.
pub fn check_command_output_status(output: Output) -> Result<(), WireguardInterfaceError> {
    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF8 sequence in stdout");
        let stderr = String::from_utf8(output.stderr).expect("Invalid UTF8 sequence in stderr");
        return Err(WireguardInterfaceError::CommandExecutionError { stdout, stderr });
    }
    Ok(())
}
