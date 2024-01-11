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
//! use defguard_wireguard_rs::{InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer};
//! # use defguard_wireguard_rs::error::WireguardInterfaceError;
//!
//! // Create new API struct for interface
//! let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
//!     "wg0".into()
//! } else {
//!     "utun3".into()
//! };
//! let wgapi = WGApi::new(ifname.clone(), false)?;
//!
//! // Create host interfaces
//! wgapi.create_interface()?;
//!
//! // Configure host interface
//! let interface_config = InterfaceConfiguration {
//!     name: ifname.clone(),
//!     prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
//!     address: "10.6.0.30".to_string(),
//!     port: 12345,
//!     peers: vec![],
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

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub mod bsd;
pub mod error;
pub mod host;
pub mod key;
pub mod net;
#[cfg(target_os = "linux")]
pub mod netlink;
mod utils;
mod wgapi;

#[cfg(target_os = "freebsd")]
mod wgapi_freebsd;
#[cfg(target_os = "linux")]
mod wgapi_linux;
#[cfg(target_family = "unix")]
mod wgapi_userspace;
#[cfg(target_family = "windows")]
mod wgapi_windows;
mod wireguard_interface;

#[macro_use]
extern crate log;

use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Formatter},
    process::Output,
};

use self::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
};

// public re-exports
pub use wgapi::WGApi;
#[cfg(target_os = "freebsd")]
pub use wgapi_freebsd::WireguardApiFreebsd;
#[cfg(target_os = "linux")]
pub use wgapi_linux::WireguardApiLinux;
#[cfg(target_family = "unix")]
pub use wgapi_userspace::WireguardApiUserspace;
#[cfg(target_os = "windows")]
pub use wgapi_windows::WireguardApiWindows;
pub use wireguard_interface::WireguardInterfaceApi;

/// Host WireGuard interface configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct InterfaceConfiguration {
    pub name: String,
    pub prvkey: String,
    pub address: String,
    pub port: u32,
    pub peers: Vec<Peer>,
}

// implement manually to avoid exposing private keys
impl Debug for InterfaceConfiguration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceConfiguration")
            .field("name", &self.name)
            .field("address", &self.address)
            .field("port", &self.port)
            .field("peers", &self.peers)
            .finish()
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

/// Utility function which checks external command output status.
fn check_command_output_status(output: Output) -> Result<(), WireguardInterfaceError> {
    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF8 sequence in stdout");
        let stderr = String::from_utf8(output.stderr).expect("Invalid UTF8 sequence in stderr");
        return Err(WireguardInterfaceError::CommandExecutionError { stdout, stderr });
    }
    Ok(())
}
