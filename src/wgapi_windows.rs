use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Write},
    net::{IpAddr, SocketAddr},
    process::Command,
    str::FromStr,
    thread::sleep,
    time::{Duration, SystemTime},
};

use crate::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    wgapi::{Kernel, WGApi},
    InterfaceConfiguration, WireguardInterfaceApi,
};

/// Manages interfaces created with Windows kernel using https://git.zx2c4.com/wireguard-nt.
impl WireguardInterfaceApi for WGApi<Kernel> {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Opening/creating interface {}", self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        Ok(())
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
        dns: &[IpAddr],
        search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Configuring interface {} with config: {config:?}",
            self.ifname
        );

        // Interface is created here so that there is no need to pass private key only for Windows
        let file_name = format!("{}.conf", &self.ifname);
        let path = env::current_dir()?;
        let file_path_buf = path.join(&file_name);
        let file_path = file_path_buf.to_str().unwrap_or_default();

        debug!("Creating WireGuard configuration file {file_name} in: {file_path}");

        let mut file = File::create(&file_name)?;

        debug!("WireGuard configuration file {file_name} created in {file_path}. Preparing configuration...");

        let address = config
            .addresses
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<String>>()
            .join(",");
        let mut wireguard_configuration = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {address}\n",
            config.prvkey
        );

        if !dns.is_empty() {
            // Format:
            // DNS = <IP>,<IP>
            // If search domains are present:
            // DNS = <IP>,<IP>,<domain>,<domain>
            let dns_addresses = format!(
                "\nDNS = {}{}",
                // DNS addresses part
                dns.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
                // Search domains part, optional
                if !search_domains.is_empty() {
                    format!(
                        ",{}",
                        search_domains
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<String>>()
                            .join(",")
                    )
                } else {
                    "".to_string()
                }
            );
            wireguard_configuration.push_str(dns_addresses.as_str());
        }

        for peer in &config.peers {
            wireguard_configuration.push_str(
                format!("\n[Peer]\nPublicKey = {}", peer.public_key.to_string()).as_str(),
            );

            if let Some(preshared_key) = &peer.preshared_key {
                wireguard_configuration
                    .push_str(format!("\nPresharedKey = {}", preshared_key).as_str());
            }

            if let Some(keep_alive) = peer.persistent_keepalive_interval {
                wireguard_configuration
                    .push_str(format!("\nPersistentKeepalive = {}", keep_alive).as_str());
            }

            if let Some(endpoint) = peer.endpoint {
                wireguard_configuration.push_str(format!("\nEndpoint = {}", endpoint).as_str());
            }

            if !peer.allowed_ips.is_empty() {
                let allowed_ips = format!(
                    "\nAllowedIPs = {}",
                    peer.allowed_ips
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<String>>()
                        .join(",")
                );
                wireguard_configuration.push_str(allowed_ips.as_str());
            }
        }

        debug!(
            "WireGuard configuration prepared: {wireguard_configuration}, writing to the file at {file_path}..."
        );
        file.write_all(wireguard_configuration.as_bytes())?;
        info!("WireGuard configuration written to file: {file_path}",);

        // Check for existing service and remove it
        debug!(
            "Checking for existing wireguard service for interface {}",
            self.ifname
        );
        let output = Command::new("wg")
            .arg("show")
            .arg(&self.ifname)
            .output()
            .map_err(|err| {
                error!("Failed to read interface data. Error: {err}");
                WireguardInterfaceError::ReadInterfaceError(err.to_string())
            })?;
        debug!("WireGuard service check output: {output:?}",);

        // Service already exists
        if output.status.success() {
            debug!("Service already exists, removing it first");
            Command::new("wireguard")
                .arg("/uninstalltunnelservice")
                .arg(&self.ifname)
                .output()?;

            debug!("Waiting for service to be removed");
            let mut counter = 1;
            loop {
                // Occasionally the tunnel is still available even though wg show cannot find it, causing /installtunnelservice to fail
                // This might be excessive as closing the application closes the WireGuard tunnel.
                sleep(Duration::from_secs(1));

                let output = Command::new("wg")
                    .arg("show")
                    .arg(&self.ifname)
                    .output()
                    .map_err(|err| {
                        error!("Failed to read interface data. Error: {err}");
                        WireguardInterfaceError::ReadInterfaceError(err.to_string())
                    })?;

                // Service has been removed
                if !output.status.success() || counter == 5 {
                    break;
                }

                counter = counter + 1;
            }
            debug!("Finished waiting for service to be removed, the service is considered to be removed, proceeding further");
        }

        debug!("Installing the new service for interface {}", self.ifname);
        let service_installation_output = Command::new("wireguard")
            .arg("/installtunnelservice")
            .arg(file_path)
            .output()
            .map_err(|err| {
                error!("Failed to create interface. Error: {err}");
                let message = err.to_string();
                WireguardInterfaceError::ServiceInstallationFailed { err, message }
            })?;

        debug!("Done installing the new service. Service installation output: {service_installation_output:?}",);

        if !service_installation_output.status.success() {
            let message = format!(
                "Failed to install WireGuard tunnel as a Windows service: {:?}",
                service_installation_output.stdout
            );
            return Err(WireguardInterfaceError::ServiceInstallationFailed {
                err: io::Error::new(io::ErrorKind::Other, "Cannot create service"),
                message,
            });
        }

        debug!(
            "Disabling automatic restart for interface {} tunnel service",
            self.ifname
        );
        let service_update_output = Command::new("sc")
            .arg("config")
            .arg(format!("WireGuardTunnel${}", self.ifname))
            .arg("start=demand")
            .output()
            .map_err(|err| {
                error!("Failed to configure tunnel service. Error: {err}");
                let message = err.to_string();
                WireguardInterfaceError::ServiceInstallationFailed { err, message }
            })?;

        debug!("Done disabling automatic restart for the new service. Service update output: {service_update_output:?}",);
        if !service_update_output.status.success() {
            let message = format!(
                "Failed to configure WireGuard tunnel service: {:?}",
                service_update_output.stdout
            );
            return Err(WireguardInterfaceError::ServiceInstallationFailed {
                err: io::Error::new(io::ErrorKind::Other, "Cannot configure service"),
                message,
            });
        }

        // TODO: set maximum transfer unit (MTU)

        info!(
            "Interface {} has been successfully configured.",
            self.ifname
        );
        debug!(
            "Interface {} configured with config: {config:?}",
            self.ifname
        );
        Ok(())
    }

    fn configure_peer_routing(&self, _peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        debug!("Removing interface {}", self.ifname);

        let command_output = Command::new("wireguard")
            .arg("/uninstalltunnelservice")
            .arg(&self.ifname)
            .output()
            .map_err(|err| {
                error!("Failed to remove interface. Error: {err}");
                WireguardInterfaceError::CommandExecutionFailed(err)
            })?;

        if !command_output.status.success() {
            let message = format!(
                "Failed to remove WireGuard tunnel service: {:?}",
                command_output.stdout
            );
            return Err(WireguardInterfaceError::ServiceRemovalError { message });
        }

        info!("Interface {} removed successfully", self.ifname);
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring peer {peer:?} on interface {}", self.ifname);
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);

        let output = Command::new("wg")
            .arg("show")
            .arg(&self.ifname)
            .arg("dump")
            .output()
            .map_err(|err| {
                error!("Failed to read interface. Error: {err}");
                WireguardInterfaceError::CommandExecutionFailed(err)
            })?;

        let reader = BufReader::new(Cursor::new(output.stdout));
        let mut host = Host::default();
        let lines = reader.lines();

        for (index, line_result) in lines.enumerate() {
            let line = match &line_result {
                Ok(line) => line,
                Err(_err) => {
                    continue;
                }
            };

            let data: Vec<&str> = line.split("\t").collect();

            // First line contains [Interface] section data, every other line is a separate [Peer]
            if index == 0 {
                // Interface data: private key, public key, listen port, fwmark
                host.private_key = Key::from_str(data[0]).ok();
                host.listen_port = data[2].parse().unwrap_or_default();

                if data[3] != "off" {
                    host.fwmark = Some(data[3].parse().unwrap());
                }
            } else {
                // Peer data: public key, preshared key, endpoint, allowed ips, latest handshake, transfer-rx, transfer-tx, persistent-keepalive
                if let Ok(public_key) = Key::from_str(data[0]) {
                    let mut peer = Peer::new(public_key.clone());

                    if data[1] != "(none)" {
                        peer.preshared_key = Key::from_str(data[0]).ok();
                    }

                    peer.endpoint = SocketAddr::from_str(data[2]).ok();

                    for allowed_ip in data[3].split(",") {
                        let addr = IpAddrMask::from_str(allowed_ip.trim())?;
                        peer.allowed_ips.push(addr);
                    }

                    let handshake = peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
                    *handshake += Duration::from_secs(data[4].parse().unwrap_or_default());

                    peer.rx_bytes = data[5].parse().unwrap_or_default();
                    peer.tx_bytes = data[6].parse().unwrap_or_default();
                    peer.persistent_keepalive_interval = data[7].parse().ok();

                    host.peers.insert(public_key.clone(), peer);
                }
            }
        }

        debug!("Read interface data: {host:?}");
        Ok(host)
    }

    fn configure_dns(
        &self,
        dns: &[IpAddr],
        _search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        Ok(())
    }
}
