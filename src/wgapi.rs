//! Shared multi-platform management API abstraction
use std::net::IpAddr;

#[cfg(target_os = "freebsd")]
use crate::WireguardApiFreebsd;
#[cfg(target_os = "linux")]
use crate::WireguardApiLinux;
#[cfg(target_family = "unix")]
use crate::WireguardApiUserspace;
#[cfg(target_os = "windows")]
use crate::WireguardApiWindows;
use crate::{
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};

/// Shared multi-platform WireGuard management API
///
/// This struct adds an additional level of abstraction and can be used
/// to detect the correct API implementation for most common platforms.
pub struct WGApi(Box<dyn WireguardInterfaceApi + Send + Sync>);

impl WGApi {
    /// Create new instance of `WGApi`.
    ///
    /// # Errors
    /// Will return `WireguardInterfaceError` is platform is not supported.
    pub fn new(ifname: String, userspace: bool) -> Result<Self, WireguardInterfaceError> {
        if userspace {
            #[cfg(target_family = "unix")]
            return Ok(Self(Box::new(WireguardApiUserspace::new(ifname)?)));

            #[cfg(not(target_family = "unix"))]
            return Err(WireguardInterfaceError::UserspaceNotSupported);
        } else {
            #[cfg(target_os = "windows")]
            return Ok(Self(Box::new(WireguardApiWindows::new(ifname))));

            #[cfg(target_os = "macos")]
            return Ok(Self(Box::new(WireguardApiUserspace::new(ifname)?)));

            #[cfg(target_os = "linux")]
            return Ok(Self(Box::new(WireguardApiLinux::new(ifname))));

            #[cfg(target_os = "freebsd")]
            return Ok(Self(Box::new(WireguardApiFreebsd::new(ifname))));

            #[cfg(not(any(
                target_os = "linux",
                target_os = "freebsd",
                target_os = "macos",
                target_os = "windows"
            )))]
            Err(WireguardInterfaceError::PlatformNotSupported)
        }
    }
}

impl WireguardInterfaceApi for WGApi {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        self.0.create_interface()
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        self.0.assign_address(address)
    }

    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        self.0.configure_peer_routing(peers)
    }

    #[cfg(not(target_os = "windows"))]
    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        self.0.configure_interface(config)
    }

    #[cfg(target_os = "windows")]
    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
        dns: &[IpAddr],
    ) -> Result<(), WireguardInterfaceError> {
        self.0.configure_interface(config, dns)
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        self.0.remove_interface()
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        self.0.configure_peer(peer)
    }

    fn configure_dns(&self, dns: &[IpAddr]) -> Result<(), WireguardInterfaceError> {
        self.0.configure_dns(dns)
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        self.0.remove_peer(peer_pubkey)
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        self.0.read_interface_data()
    }
}
