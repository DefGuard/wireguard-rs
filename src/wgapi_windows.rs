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
    InterfaceConfiguration, WireguardInterfaceApi,
};

/// Manages interfaces created with Windows kernel using https://git.zx2c4.com/wireguard-nt.
#[derive(Clone)]
pub struct WireguardApiWindows {
    ifname: String,
}

impl WireguardApiWindows {
    pub fn new(ifname: String) -> Self {
        Self { ifname }
    }
}

impl WireguardInterfaceApi for WireguardApiWindows {
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
    ) -> Result<(), WireguardInterfaceError> {
        info!(
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

        let mut wireguard_configuration = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\n",
            config.prvkey, config.address
        );

        if !dns.is_empty() {
            let dns_addresses = format!(
                "\nDNS = {}",
                dns.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
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

        info!("Prepared WireGuard configuration: {wireguard_configuration}",);
        file.write_all(wireguard_configuration.as_bytes())?;

        // Check for existing service and remove it
        let output = Command::new("wg")
            .arg("show")
            .arg(&self.ifname)
            .output()
            .map_err(|err| {
                error!("Failed to read interface data. Error: {err}");
                WireguardInterfaceError::ReadInterfaceError(err.to_string())
            })?;

        // Service already exists
        if output.status.success() {
            Command::new("wireguard")
                .arg("/uninstalltunnelservice")
                .arg(&self.ifname)
                .output()?;

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
        }

        let service_installation_output = Command::new("wireguard")
            .arg("/installtunnelservice")
            .arg(file_path)
            .output()
            .map_err(|err| {
                error!("Failed to create interface. Error: {err}");
                let message = err.to_string();
                WireguardInterfaceError::ServiceInstallationFailed { err, message }
            })?;

        info!("Service installation output: {service_installation_output:?}",);

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

        Ok(())
    }

    fn configure_peer_routing(&self, _peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", self.ifname);

        Command::new("wireguard")
            .arg("/uninstalltunnelservice")
            .arg(&self.ifname)
            .output()
            .map_err(|err| {
                error!("Failed to remove interface. Error: {err}");
                WireguardInterfaceError::CommandExecutionFailed(err)
            })?;

        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        info!(
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

    fn configure_dns(&self, dns: &[IpAddr]) -> Result<(), WireguardInterfaceError> {
        info!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        Ok(())
    }
}
