use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Write},
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    process::Command,
    str::FromStr,
    thread::sleep,
    time::{Duration, SystemTime},
};

use windows::Win32::NetworkManagement::IpHelper::{
    if_nametoindex, CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
};
use windows_core::PCSTR;

use crate::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    InterfaceConfiguration, WireguardInterfaceApi,
};

fn interface_index(if_name: &str) -> u32 {
    unsafe { if_nametoindex(PCSTR(if_name.as_ptr())) }
}

fn forward_entry(dest: &IpAddrMask, if_index: u32) -> MIB_IPFORWARD_ROW2 {
    let mut row = MaybeUninit::<MIB_IPFORWARD_ROW2>::uninit();
    unsafe { InitializeIpForwardEntry(row.as_mut_ptr()) };
    let mut row = unsafe { row.assume_init() };

    let prefix = &mut row.DestinationPrefix;
    prefix.PrefixLength = dest.cidr;
    match dest.ip {
        IpAddr::V4(ip) => {
            prefix.Prefix.Ipv4 = SocketAddrV4::new(ip, 0).into();
        }
        IpAddr::V6(ip) => {
            prefix.Prefix.Ipv6 = SocketAddrV6::new(ip, 0, 0, 0).into();
        }
    }

    row.InterfaceIndex = if_index;
    row.Metric = 0;

    row
}

fn add_route(dest: &IpAddrMask, if_index: u32) {
    const DUPLICATE_ERR: u32 = 0x80071392;
    let entry = forward_entry(dest, if_index);

    // SAFETY: Windows shouldn't store the reference anywhere, it's just a way to pass lots of arguments at once. And no other thread sees this variable.
    let Err(err) = unsafe { CreateIpForwardEntry2(&entry) }.ok() else {
        debug!("Created new route");
        return;
    };

    // We expect set_routes to call add_route with the same routes always making this error expected
    if err.code().0 as u32 == DUPLICATE_ERR {
        return;
    }

    warn!("Failed to add route: {err}");
}

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

        file.write_all(wireguard_configuration.as_bytes())?;
        info!("WireGuard configuration written to file: {file_path}",);

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

        // TODO: set maximum transfer unit (MTU)

        Ok(())
    }

    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        debug!("Adding peer routing for interface: {}", self.ifname);
        let if_index = interface_index(&self.ifname);
        for peer in peers {
            for addr in &peer.allowed_ips {
                add_route(addr, if_index);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[ignored]
    #[test]
    fn add_route() {
        let if_index = interface_index("wg0");
        eprintln("if_index {if_index}");
        let ip = "10.10.10.0/24".parse::<IpAddrMask>().unwrap();
        add_route(&ip, if_index);
    }
}
