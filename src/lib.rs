//! # `defguard_wireguard_rs`
//!
//! `defguard_wireguard_rs` is a multi-platform Rust library providing a unified high-level API
//! for managing WireGuard interfaces using native OS kernel and userspace WireGuard protocol implementations.
//!
//! It can be used to create your own [WireGuard:tm:](https://www.wireguard.com/) VPN servers or clients for secure and private networking.
//!
//! It was developed as part of [defguard](https://github.com/defguard/defguard) security platform and used in the [gateway/server](https://github.com/defguard/gateway) as well as [desktop client](https://github.com/defguard/client).
//!
//! ## Example
//!
//! ```no_run
//! use x25519_dalek::{EphemeralSecret, PublicKey};
//! use defguard_wireguard_rs::{InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi, host::Peer};
//! # use defguard_wireguard_rs::error::WireguardInterfaceError;
//!
//! // Create new API struct for interface
//! let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
//!     "wg0".into()
//! } else {
//!     "utun3".into()
//! };
//! let mut wgapi = WGApi::<Userspace>::new(ifname.clone())?;
//!
//! // Create host interfaces
//! wgapi.create_interface()?;
//!
//! // Configure host interface
//! let interface_config = InterfaceConfiguration {
//!     name: ifname.clone(),
//!     prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
//!     addresses: vec!["10.6.0.30".parse().unwrap()],
//!     port: 12345,
//!     peers: vec![],
//!     mtu: None,
//! };
//! wgapi.configure_interface(&interface_config)?;
//!
//! // Create, add & remove peers
//! for _ in 0..32 {
//!     let secret = EphemeralSecret::random();
//!     let key = PublicKey::from(&secret);
//!     let peer = Peer::new(key.as_ref().try_into().unwrap());
//!     wgapi.configure_peer(&peer)?;
//!     wgapi.remove_peer(&peer.public_key)?;
//! }
//!
//! // Remove host interface
//! wgapi.remove_interface()?;
//! # Ok::<(), WireguardInterfaceError>(())
//! ```

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
pub mod bsd;
pub mod error;
pub mod host;
pub mod key;
pub mod net;
#[cfg(target_os = "linux")]
pub(crate) mod netlink;
mod utils;
mod wgapi;

#[cfg(feature = "check_dependencies")]
mod dependencies;
#[cfg(target_os = "freebsd")]
mod wgapi_freebsd;
#[cfg(target_os = "linux")]
mod wgapi_linux;
#[cfg(unix)]
mod wgapi_userspace;
#[cfg(target_family = "windows")]
mod wgapi_windows;
mod wireguard_interface;

#[macro_use]
extern crate log;

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
// public re-exports
pub use wgapi::{Kernel, Userspace, WGApi};
pub use wireguard_interface::WireguardInterfaceApi;

use self::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
};

// Internet Protocol (IP) address variant.
#[derive(Clone, Copy)]
pub enum IpVersion {
    IPv4,
    IPv6,
}

/// Host WireGuard interface configuration.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct InterfaceConfiguration {
    pub name: String,
    pub prvkey: String,
    pub addresses: Vec<IpAddrMask>,
    pub port: u32,
    pub peers: Vec<Peer>,
    /// Maximum transfer unit. `None` means do not set MTU, but keep the system default.
    pub mtu: Option<u32>,
}

// Implement `Debug` manually to avoid exposing private keys.
impl fmt::Debug for InterfaceConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceConfiguration")
            .field("name", &self.name)
            .field("addresses", &self.addresses)
            .field("port", &self.port)
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl TryFrom<&InterfaceConfiguration> for Host {
    type Error = WireguardInterfaceError;

    fn try_from(config: &InterfaceConfiguration) -> Result<Self, Self::Error> {
        let key = config.prvkey.as_str().try_into()?;
        let mut host = Host::new(config.port as u16, key);
        for peercfg in &config.peers {
            let peer = peercfg.clone();
            let key: Key = peer.public_key.clone();
            host.peers.insert(key, peer);
        }
        Ok(host)
    }
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
/// Utility function which checks external command output status.
fn check_command_output_status(
    output: std::process::Output,
) -> Result<(), WireguardInterfaceError> {
    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF8 sequence in stdout");
        let stderr = String::from_utf8(output.stderr).expect("Invalid UTF8 sequence in stderr");
        return Err(WireguardInterfaceError::CommandExecutionError { stdout, stderr });
    }
    Ok(())
}
