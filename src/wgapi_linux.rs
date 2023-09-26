use crate::{
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};

/// Manages interfaces created with Linux kernel WireGuard module.
///
/// Communicates with kernel module using `Netlink` IPC protocol.
/// Requires Linux kernel version 5.6+.
pub struct WireguardApiLinux {
    ifname: String,
}

impl WireguardApiLinux {
    pub fn new(ifname: String) -> Self {
        WireguardApiLinux { ifname }
    }
}

impl WireguardInterfaceApi for WireguardApiLinux {
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
