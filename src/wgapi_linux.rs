use std::net::IpAddr;

use crate::{
    netlink,
    utils::{add_peer_routing, clean_fwmark_rules, clear_dns, configure_dns},
    wgapi::{Kernel, WGApi},
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};

/// Manages interfaces created with Linux kernel WireGuard module.
///
/// Communicates with kernel module using `Netlink` IPC protocol.
/// Requires Linux kernel version 5.6+.
impl WireguardInterfaceApi for WGApi<Kernel> {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        debug!("Creating interface {}", self.ifname);
        netlink::create_interface(&self.ifname)?;
        debug!("Interface {} created successfully", self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        netlink::address_interface(&self.ifname, address)?;
        debug!(
            "Address {address} assigned to interface {} successfully",
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

        // Flush all IP addresses from WireGuard interface.
        debug!(
            "Flushing all existing IP addresses from interface {} before assigning a new one",
            self.ifname
        );
        netlink::flush_interface(&self.ifname)?;
        debug!(
            "All existing IP addresses flushed from interface {}",
            self.ifname
        );

        // Assign IP addresses to the interface.
        for address in &config.addresses {
            debug!("Assigning address {address} to interface {}", self.ifname);
            self.assign_address(address)?;
            debug!(
                "Address {address} assigned to interface {} successfully",
                self.ifname
            );
        }

        // configure interface
        debug!(
            "Applying the WireGuard host configuration for interface {}",
            self.ifname
        );
        let host = config.try_into()?;
        netlink::set_host(&self.ifname, &host)?;
        debug!(
            "WireGuard host configuration set for interface {}.",
            self.ifname
        );
        trace!("WireGuard host configuration: {host:?}");

        // set maximum transfer unit
        if let Some(mtu) = config.mtu {
            debug!("Setting MTU of {mtu} for interface {}", self.ifname);
            netlink::set_mtu(&self.ifname, mtu)?;
            debug!("MTU of {mtu} set for interface {}, value: {{", self.ifname);
        } else {
            debug!(
                "Skipping setting the MTU for interface {}, as it has not been provided",
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

    /// Configures peer routing. Internally uses netlink to set up routing rules for each peer.
    /// If allowed IPs contain a default route, instead of adding a route for every peer, the following changes are made:
    /// - A new default route is added
    /// - The current default route is suppressed by modifying the main routing table rule with `suppress_prefixlen 0`, this makes
    ///   it so that the whole main routing table rules are still applied except for the default route rules (so the new default route is used instead)
    /// - A rule pushing all traffic through the WireGuard interface is added with the exception of traffic marked with 51820 (default) fwmark which
    ///   is used for the WireGuard traffic itself (so it doesn't get stuck in a loop)
    ///
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        add_peer_routing(peers, &self.ifname)?;
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Removing interface {}. Getting its WireGuard host configuration first...",
            self.ifname
        );
        let host = netlink::get_host(&self.ifname)?;
        debug!(
            "WireGuard host configuration read for interface {}",
            self.ifname
        );
        trace!("WireGuard host configuration: {host:?}");
        if let Some(fwmark) = host.fwmark {
            if fwmark != 0 {
                debug!("Cleaning fwmark rules for interface {}", self.ifname);
                clean_fwmark_rules(fwmark)?;
                debug!("Fwmark rules cleaned for interface {}", self.ifname);
            }
        }
        debug!("Performing removal of interface {}", self.ifname);
        netlink::delete_interface(&self.ifname)?;
        debug!(
            "Interface {} removed successfully. Clearing the dns...",
            self.ifname
        );
        clear_dns(&self.ifname)?;
        debug!("DNS cleared for interface {}", self.ifname);

        info!("Interface {} removed successfully", self.ifname);
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring peer {peer:?} on interface {}", self.ifname);
        netlink::set_peer(&self.ifname, peer)?;
        debug!("Peer {peer:?} configured on interface {}", self.ifname);
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        netlink::delete_peer(&self.ifname, peer_pubkey)?;
        debug!(
            "Peer with public key {peer_pubkey} removed from interface {}",
            self.ifname
        );
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);
        let host = netlink::get_host(&self.ifname)?;
        debug!("Host info read for interface {}", self.ifname);
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
