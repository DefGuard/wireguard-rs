use crate::{
    bsd, check_command_output_status, Host, InterfaceConfiguration, IpAddrMask, Key, Peer,
    WireguardInterfaceApi, WireguardInterfaceError,
};
use std::{process::Command, str::FromStr};

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
        info!("Creating interface {}", self.ifname);
        unimplemented!()
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        let output = Command::new("ifconfig")
            .args([&self.ifname, &address.to_string()])
            .output()?;
        check_command_output_status(output)?;
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
        info!("Removing interface {}", self.ifname);
        todo!()
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
