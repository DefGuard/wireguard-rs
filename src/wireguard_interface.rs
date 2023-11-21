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
    ///
    /// # Linux:
    /// On a Linux system, the `sysctl` command is required to work if using `0.0.0.0/0` or `::/0`.  
    /// For every allowed IP, it runs:  
    /// `ip <ip_version> route add <allowed_ip> dev <ifname>`   
    /// `<ifname>` - interface name while creating api  
    /// `<ip_version>` - `-4` or `-6` based on allowed ip type  
    /// `<allowed_ip>`- one of [Peer](crate::Peer) allowed ip
    ///
    /// For `0.0.0.0/0` or `::/0`  allowed IP, it runs belowed additional commands in order:
    /// - `ip <ip_version> route add 0.0.0.0/0 dev <ifname> table <fwmark>`  
    /// `<fwmark>` - fwmark attribute of [Host](crate::Host) or 51820 default if value is `None`.  
    /// `<ifname>` - Interface name.  
    /// - `ip <ip_version> rule add not fwmark <fwmark> table <fwmark>`.  
    /// - `ip <ip_version> rule add table main suppress_prefixlength 0`.   
    /// - `sysctl -q net.ipv4.conf.all.src_valid_mark=1` - runs only for `0.0.0.0/0`.  
    /// - `iptables-restore -n`. For `0.0.0.0/0` only.  
    /// - `iptables6-restore -n`. For `::/0` only.    
    /// Based on ip type `<ip_version>` will be equal to `-4` or `-6`.
    ///
    ///
    /// # MacOS, FreeBSD:  
    /// For every allowed IP, it runs:  
    /// - `route -q -n add <inet> allowed_ip -interface if_name`   
    /// `ifname` - interface name while creating api  
    /// `allowed_ip`- one of [Peer](crate::Peer) allowed ip
    /// For `0.0.0.0/0` or `::/0`  allowed IP, it runs additional commands in order:
    /// - `route -q -n add <inet> 0.0.0.0/1 -interface if_name`.   
    /// - `route -q -n add <inet> 128.0.0.0/1 -interface if_name`.   
    /// - `route -q -n add <inet> <endpoint> -gateway <gateway>`  
    /// `<endpoint>` - Add routing for every unique Peer endpoint.   
    /// `<gateway>`- Gateway extracted using `netstat -nr -f <inet>`.    
    /// ## Note:
    /// Based on ip type `<inet>` will be equal to `-inet` or `-inet6`
    fn route_peers(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError>;

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
    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError>;

    /// Reads current WireGuard interface configuration and stats.
    ///
    /// Similar to `wg show <if_name>` command.
    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError>;
}
