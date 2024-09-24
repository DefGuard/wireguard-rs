use std::net::IpAddr;

use crate::{error::WireguardInterfaceError, Host, InterfaceConfiguration, IpAddrMask, Key, Peer};

/// API for managing a WireGuard interface.
///
/// Specific interface being managed is identified by name.
pub trait WireguardInterfaceApi {
    /// Creates a new WireGuard interface.
    fn create_interface(&self) -> Result<(), WireguardInterfaceError>;

    /// Assigns IP address to an existing interface.
    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError>;

    /// Add peer routing, basically a copy of `wg-quick up <if_name>` routing.
    /// Extracts all uniques allowed ips from [Peer](crate::Peer) slice and add routing for every
    /// address.
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError>;

    /// Updates configuration of an existing WireGuard interface.
    #[cfg(not(target_os = "windows"))]
    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError>;

    #[cfg(target_os = "windows")]
    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
        dns: &[IpAddr],
        search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError>;

    /// Removes the WireGuard interface being managed.
    ///
    /// Meant to be used in `drop` method for a given API struct.
    fn remove_interface(&self) -> Result<(), WireguardInterfaceError>;

    /// Adds a peer or updates peer configuration.
    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError>;

    /// Removes a configured peer with a given pubkey.
    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError>;

    /// Reads current WireGuard interface configuration and stats.
    ///
    /// Similar to `wg show <if_name>` command.
    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError>;

    /// Sets the DNS configuration for the WireGuard interface.
    ///
    /// This function takes a slice of DNS server addresses (`dns`) and search domains (`search_domains`) and configures the
    /// WireGuard interface to use them. If the search domain vector is empty it sets the "exclusive" flag making the DNS servers a
    /// preferred route for any domain. This method is equivalent to specifying the
    /// DNS section in a WireGuard configuration file and using `wg-quick` to apply the
    /// configuration.
    ///
    /// # Arguments
    ///
    /// * `dns` - A slice of [`IpAddr`](std::net::IpAddr) representing the DNS server addresses to be set for
    ///   the WireGuard interface.
    ///
    /// * `search_domains` - A slice of [`&str`](std::str) representing the search domains to be set for
    ///   the WireGuard interface.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the DNS configuration is successfully set, or an
    /// `Err(WireguardInterfaceError)` if there is an error during the configuration process.
    fn configure_dns(
        &self,
        dns: &[IpAddr],
        search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError>;
}
