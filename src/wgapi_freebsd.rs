use crate::{
    bsd, check_command_output_status,
    utils::{clean_dns, set_dns},
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
    WireguardInterfaceError,
};
use std::{net::IpAddr, process::Command, str::FromStr};

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
        info!("Creating interface {}", self.ifname);
        let output = Command::new("ifconfig")
            .args(["wg", "create", "name", &self.ifname])
            .output()?;
        // in case of error check if interface existed already
        if !output.status.success() {
            let stdout = String::from_utf8(output.stdout).expect("Invalid UTF8 sequence in stdout");
            let stderr = String::from_utf8(output.stderr).expect("Invalid UTF8 sequence in stderr");
            if stderr == "ifconfig: ioctl SIOCSIFNAME (set name): File exists\n" {
                debug!("Interface {} already exists", self.ifname);
                let mut temp_ifname = stdout;
                // remove trailing newline from temporary interface name
                if temp_ifname.ends_with('\n') {
                    temp_ifname.pop();
                }
                debug!("Removing temporary interface {temp_ifname}");
                let output = Command::new("ifconfig")
                    .args([&temp_ifname, "destroy"])
                    .output()?;
                return check_command_output_status(output);
            }
            return Err(WireguardInterfaceError::CommandExecutionError { stdout, stderr });
        }
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        let output = Command::new("ifconfig")
            .args([&self.ifname, &address.to_string()])
            .output()?;
        check_command_output_status(output)
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
        let output = Command::new("ifconfig")
            .args(["wg", &self.ifname, "destroy"])
            .output()?;

        clean_dns(&self.ifname);
        check_command_output_status(output)
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

    //// Sets DNS configuration for a Wireguard interface using the `resolvconf` command.
    ///
    /// It executes the `resolvconf` command with appropriate arguments to update DNS
    /// configurations for the specified Wireguard interface. The DNS entries are filtered
    /// for nameservers and search domains before being piped to the `resolvconf` command.
    fn set_dns(&self, dns: Vec<IpAddr>) -> Result<(), WireguardInterfaceError> {
        info!("Configuring dns for interface: {}", self.ifname);
        set_dns(&self.ifname, dns)?;
        Ok(())
    }
}
