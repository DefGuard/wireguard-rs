use crate::{
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};

/// Manages interfaces created with FreeBSD kernel WireGuard module.
///
/// Requires FreeBSD version 14+.
pub struct WireguardApiFreebsd {
    ifname: String,
}

impl WireguardApiFreebsd {
    pub fn new(ifname: String) -> Self {
        WireguardApiFreebsd { ifname }
    }
}

impl WireguardInterfaceApi for WireguardApiFreebsd {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        todo!()
    }

    fn assign_address(&self, addr: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        todo!()
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        todo!()
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        todo!()
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        todo!()
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        todo!()
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        todo!()
    }
}
