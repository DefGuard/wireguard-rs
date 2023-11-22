use crate::{
    netlink, Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};
use std::io::Write;
use std::process::{Command, Stdio};
use std::str::FromStr;

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

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", self.ifname);
        netlink::delete_interface(&self.ifname)?;
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

    fn set_dns(&self, dns: Vec<String>) -> Result<(), WireguardInterfaceError> {
        // Build the resolvconf command
        let mut cmd = Command::new("resolvconf");
        cmd.arg("-a").arg(self.ifname).arg("-m").arg("0").arg("-x");

        // Execute resolvconf command and pipe filtered DNS entries
        if let Some(mut child) = cmd.stdin(Stdio::piped()).spawn().ok() {
            if let Some(mut stdin) = child.stdin.take() {
                for entry in &dns {
                    match entry.parse::<std::net::IpAddr>() {
                        Ok(ip) => writeln!(stdin, "nameserver {}", ip),
                        Err(_) => {
                            writeln!(stdin, "search {}", entry)
                        }
                    }?;
                }
            }

            let status = child.wait().expect("Failed to wait for command");
            if status.success() {
                Ok(())
            } else {
                Err(WireguardInterfaceError::UserspaceNotSupported)
            }
        } else {
            Err(WireguardInterfaceError::UserspaceNotSupported)
        }
    }
}
