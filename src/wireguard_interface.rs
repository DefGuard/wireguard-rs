use crate::error::WireguardInterfaceError;
use crate::{Host, InterfaceConfiguration, IpAddrMask, Peer};

/// API for managing a WireGuard interface.
///
/// Specific interface being managed is identified by name.
pub trait WireguardInterfaceApi {
    /// Creates a new WireGuard interface.
    fn create_interface(&self) -> Result<(), WireguardInterfaceError>;

    /// Assigns IP address to an existing interface.
    fn assign_address(&self, addr: &IpAddrMask) -> Result<(), WireguardInterfaceError>;

    /// Updates configuration of an existing WireGuard interface.
    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError>;

    /// Removes the WireGuard interface being managed.
    ///
    /// Meant to be used in `drop` method for a given API struct.
    fn remove_interface(&self) -> Result<(), WireguardInterfaceError>;

    /// Adds a peer or updates peer configuration.
    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError>;

    /// Removes a configured peer with a given pubkey.
    fn remove_peer(&self, peer_pubkey: &str) -> Result<(), WireguardInterfaceError>;

    /// Reads current WireGuard interface configuration and stats.
    ///
    /// Similar to 'wg show <if_name>` command.
    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError>;
}
