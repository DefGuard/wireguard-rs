use std::net::IpAddr;

use crate::{
    bsd,
    utils::{add_peer_routing, clear_dns, configure_dns},
    wgapi::{Kernel, WGApi},
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};

/// Manages interfaces created with FreeBSD kernel WireGuard module.
///
/// Requires FreeBSD version 13+.
impl WireguardInterfaceApi for WGApi<Kernel> {
    /// Creates a WireGuard network interface.
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        let _ = bsd::load_wireguard_kernel_module();
        debug!("Creating interface {}", &self.ifname);
        bsd::create_interface(&self.ifname)?;
        debug!("Interface {} created successfully", &self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        bsd::assign_address(&self.ifname, address)?;
        debug!(
            "Address {address} assigned to interface {} successfully",
            self.ifname
        );
        Ok(())
    }

    /// Add peer addresses to network routing table.
    ///
    /// For every allowed IP, it runs:
    /// - `route -q -n add <inet> allowed_ip -interface if_name`
    /// `ifname` - interface name while creating api
    /// `allowed_ip`- one of [Peer](crate::Peer) allowed ip
    /// For `0.0.0.0/0` or `::/0`  allowed IP, it adds default routing and skips other using:
    /// - `route -q -n add <inet> 0.0.0.0/1 -interface if_name`.
    /// - `route -q -n add <inet> 128.0.0.0/1 -interface if_name`.
    /// - `route -q -n add <inet> <endpoint> -gateway <gateway>`
    /// `<endpoint>` - Add routing for every unique Peer endpoint.
    /// `<gateway>`- Gateway extracted using `netstat -nr -f <inet>`.
    /// ## Note:
    /// Based on ip type `<inet>` will be equal to `-inet` or `-inet6`
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring peer routing for interface {}", self.ifname);
        add_peer_routing(peers, &self.ifname)?;
        info!(
            "Peer routing configured successfully for interface {}",
            self.ifname
        );
        Ok(())
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Configuring interface {} with config: {config:?}",
            self.ifname
        );

        // Assign IP address to the interface.
        for address in &config.addresses {
            self.assign_address(address)?;
        }

        // configure interface
        debug!(
            "Applying the WireGuard host configuration for interface {}",
            self.ifname
        );
        let host = config.try_into()?;
        bsd::set_host(&self.ifname, &host)?;
        debug!(
            "WireGuard host configuration set for interface {}.",
            self.ifname
        );
        trace!("WireGuard host configuration: {host:?}");

        // Set maximum transfer unit (MTU).
        if let Some(mtu) = config.mtu {
            debug!("Setting MTU of {mtu} for interface {}", self.ifname);
            bsd::set_mtu(&self.ifname, mtu)?;
            debug!(
                "MTU of {mtu} set for interface {}, value: {mtu}",
                self.ifname
            );
        }

        info!(
            "Interface {} has been successfully configured. \
            It has been assigned the following addresses: {:?}",
            self.ifname, config.addresses
        );
        debug!(
            "Interface {} configured with config: {config:?}",
            self.ifname
        );

        Ok(())
    }

    /// Remove WireGuard network interface.
    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        debug!("Removing interface {}", &self.ifname);
        bsd::delete_interface(&self.ifname)?;
        debug!("Interface {} removed successfully", &self.ifname);

        clear_dns(&self.ifname)?;

        info!("Interface {} removed successfully", &self.ifname);
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring peer {peer:?} on interface {}", self.ifname);
        bsd::set_peer(&self.ifname, peer)?;
        debug!(
            "Peer {peer:?} configured successfully on interface {}",
            self.ifname
        );
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        bsd::delete_peer(&self.ifname, peer_pubkey)?;
        debug!(
            "Peer with public key {peer_pubkey} removed successfully from interface {}",
            self.ifname
        );
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);
        let host = bsd::get_host(&self.ifname)?;
        debug!("Host info read for interface {}", self.ifname);
        trace!("Host configuration: {host:?}");
        Ok(host)
    }

    /// Sets DNS configuration for a Wireguard interface using the `resolvconf` command.
    ///
    /// It executes the `resolvconf` command with appropriate arguments to update DNS
    /// configurations for the specified Wireguard interface. The DNS entries are filtered
    /// for nameservers and search domains before being piped to the `resolvconf` command.
    fn configure_dns(
        &self,
        dns: &[IpAddr],
        search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError> {
        if dns.is_empty() {
            warn!("Received empty DNS server list. Skipping DNS configuration...");
            return Ok(());
        }
        configure_dns(&self.ifname, dns, search_domains)?;
        Ok(())
    }
}
