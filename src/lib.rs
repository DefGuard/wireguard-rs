#[cfg(target_os = "freebsd")]
pub mod bsd;
pub mod error;
pub mod host;
pub mod key;
pub mod net;
#[cfg(target_os = "linux")]
pub mod netlink;
pub mod wgapi;
mod wgapi_freebsd;
mod wgapi_linux;
mod wgapi_userspace;
mod wireguard_interface;

#[macro_use]
extern crate log;

use std::{process::Command, str::FromStr};
use wgapi::WGApi;

// public reexports
pub use {
    self::error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::{IpAddrMask, IpAddrParseError},
    wgapi_userspace::WireguardApiUserspace,
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

/// Assigns address to interface.
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `addr` - Address to assign to interface
pub fn assign_addr(ifname: &str, addr: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
    if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        netlink::address_interface(ifname, addr)?;
    } else if cfg!(target_os = "macos") {
        // On macOS, interface is point-to-point and requires a pair of addresses
        let address_string = addr.ip.to_string();
        Command::new("ifconfig")
            .args([ifname, &address_string, &address_string])
            .output()?;
    } else {
        Command::new("ifconfig")
            .args([ifname, &addr.to_string()])
            .output()?;
    }

    Ok(())
}

/// Helper method performing interface configuration
pub fn setup_interface(
    ifname: &str,
    userspace: bool,
    config: &InterfaceConfiguration,
) -> Result<(), WireguardInterfaceError> {
    if userspace {
        #[cfg(feature = "boringtun")]
        create_interface_userspace(ifname)?;
    } else {
        #[cfg(target_os = "linux")]
        netlink::create_interface(ifname)?;
    }

    let address = IpAddrMask::from_str(&config.address)?;
    assign_addr(ifname, &address)?;
    let key = config.prvkey.as_str().try_into()?;
    let mut host = Host::new(config.port as u16, key);
    for peercfg in &config.peers {
        let key: Key = peercfg.public_key.clone();
        let mut peer = Peer::new(key.clone());
        peer.set_allowed_ips(peercfg.allowed_ips.clone());

        host.peers.insert(key, peer);
    }
    let api = WGApi::new(ifname.into(), userspace);
    api.write_host(&host)?;

    Ok(())
}
