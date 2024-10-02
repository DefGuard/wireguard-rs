use std::{marker::PhantomData, net::IpAddr, process::Command, str::FromStr};

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
        info!("Interface {} created successfully", self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        netlink::address_interface(&self.ifname, address)?;
        info!(
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

        // flush all IP addresses
        debug!("Flushing all IP addresses from interface {}", self.ifname);
        netlink::flush_interface(&self.ifname)?;
        debug!("All IP addresses flushed from interface {}", self.ifname);

        // assign IP address to interface
        debug!(
            "Assigning address {} to interface {}",
            config.address, self.ifname
        );
        let address = IpAddrMask::from_str(&config.address)?;
        self.assign_address(&address)?;
        debug!(
            "Address {} assigned to interface {} successfully",
            config.address, self.ifname
        );

        // configure interface
        debug!("Setting host configuration for interface {}", self.ifname);
        let host = config.try_into()?;
        netlink::set_host(&self.ifname, &host)?;
        debug!("Host configuration set for interface {}.", self.ifname);
        trace!("Host configuration: {host:?}");

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
            "Interface {} configured successfully with config: {config:?}",
            self.ifname
        );

        Ok(())
    }

    /// On a Linux system, the `sysctl` command is required to work if using `0.0.0.0/0` or `::/0`.
    /// For every allowed IP, it runs:
    /// `ip <ip_version> route add <allowed_ip> dev <ifname>`
    /// `<ifname>` - interface name while creating api
    /// `<ip_version>` - `-4` or `-6` based on allowed ip type
    /// `<allowed_ip>`- one of [Peer](crate::Peer) allowed ip
    ///
    /// For `0.0.0.0/0` or `::/0`  allowed IP, it adds default routing and skips other routings.:
    /// - `ip <ip_version> route add 0.0.0.0/0 dev <ifname> table <fwmark>`
    /// `<fwmark>` - fwmark attribute of [Host](crate::Host) or 51820 default if value is `None`.
    /// `<ifname>` - Interface name.
    /// - `ip <ip_version> rule add not fwmark <fwmark> table <fwmark>`.
    /// - `ip <ip_version> rule add table main suppress_prefixlength 0`.
    /// - `sysctl -q net.ipv4.conf.all.src_valid_mark=1` - runs only for `0.0.0.0/0`.
    /// - `iptables-restore -n`. For `0.0.0.0/0` only.
    /// - `iptables6-restore -n`. For `::/0` only.
    /// Based on ip type `<ip_version>` will be equal to `-4` or `-6`.
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        add_peer_routing(peers, &self.ifname)?;
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Removing interface {}. Getting its host configuration first...",
            self.ifname
        );
        let host = netlink::get_host(&self.ifname)?;
        debug!("Host configuration read for interface {}", self.ifname);
        trace!("Host configuration: {host:?}");
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
        info!("Peer {peer:?} configured on interface {}", self.ifname);
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        netlink::delete_peer(&self.ifname, peer_pubkey)?;
        info!(
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
