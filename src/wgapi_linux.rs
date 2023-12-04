use std::{net::IpAddr, str::FromStr};

use crate::{
    netlink,
    utils::{add_peer_routing, clean_fwmark_rules, clear_dns, configure_dns},
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};

/// Manages interfaces created with Linux kernel WireGuard module.
///
/// Communicates with kernel module using `Netlink` IPC protocol.
/// Requires Linux kernel version 5.6+.
#[derive(Clone)]
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
        info!("Creating interface {}", self.ifname);
        netlink::create_interface(&self.ifname)?;
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        netlink::address_interface(&self.ifname, address)?;
        Ok(())
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        info!(
            "Configuring interface {} with config: {config:?}",
            self.ifname
        );

        // assign IP address to interface
        let address = IpAddrMask::from_str(&config.address)?;
        self.assign_address(&address)?;

        // configure interface
        let host = config.try_into()?;
        netlink::set_host(&self.ifname, &host)?;

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
        info!("Removing interface {}", self.ifname);
        let host = netlink::get_host(&self.ifname)?;
        if let Some(fwmark) = host.fwmark {
            if fwmark != 0 {
                clean_fwmark_rules(fwmark)?;
            }
        }
        netlink::delete_interface(&self.ifname)?;
        clear_dns(&self.ifname)?;
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        netlink::set_peer(&self.ifname, peer)?;
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        info!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        netlink::delete_peer(&self.ifname, peer_pubkey)?;
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);
        let host = netlink::get_host(&self.ifname)?;
        Ok(host)
    }

    /// Sets DNS configuration for a Wireguard interface using the `resolvconf` command.
    ///
    /// It executes the `resolvconf` command with appropriate arguments to update DNS
    /// configurations for the specified Wireguard interface. The DNS entries are filtered
    /// for nameservers and search domains before being piped to the `resolvconf` command.
    fn configure_dns(&self, dns: &[IpAddr]) -> Result<(), WireguardInterfaceError> {
        info!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        configure_dns(&self.ifname, dns)?;
        Ok(())
    }
}
