use crate::{
    bsd, check_command_output_status, utils::add_peers_routing, Host, InterfaceConfiguration,
    IpAddrMask, Key, Peer, WireguardInterfaceApi, WireguardInterfaceError,
};
use std::{process::Command, str::FromStr};

/// Manages interfaces created with FreeBSD kernel WireGuard module.
///
/// Requires FreeBSD version 14+.
#[derive(Clone)]
pub struct WireguardApiFreebsd {
    ifname: String,
}

impl WireguardApiFreebsd {
    pub fn new(ifname: String) -> Self {
        WireguardApiFreebsd { ifname }
    }
}

impl WireguardInterfaceApi for WireguardApiFreebsd {
    /// Creates a WireGuard interface using `ifconfig`
    ///
    /// There's no dedicated exit code to indicate that an interface already exists,
    /// so we have to check command output.
    ///
    /// Example error: `CommandExecutionError { stdout: "wg7\n", stderr: "ifconfig: ioctl SIOCSIFNAME (set name): File exists\n" }`
    ///
    /// Additionally since `ifconfig` creates an interface first and then tries to rename it
    /// it leaves a temporary interface that we have to manually destroy.
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Creating interface {}", &self.ifname);
        bsd::create_interface(&self.ifname)?;
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        let output = Command::new("ifconfig")
            .arg(&self.ifname)
            .arg(&address.to_string())
            .output()?;
        check_command_output_status(output)
    }
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
    fn configure_peers_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        add_peers_routing(peers, &self.ifname)?;
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
        bsd::set_host(&self.ifname, &host)?;
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", &self.ifname);
        bsd::delete_interface(&self.ifname)?;
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        bsd::set_peer(&self.ifname, peer)?;
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        info!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        bsd::delete_peer(&self.ifname, peer_pubkey)?;
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);
        let host = bsd::get_host(&self.ifname)?;
        Ok(host)
    }
}
