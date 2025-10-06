use std::{
    thread,
    env,
    fs::File,
    io::{BufRead, BufReader, Cursor, Write},
    net::{IpAddr, SocketAddr},
    process::Command,
    str::FromStr,
    thread::sleep,
    time::{Duration, SystemTime},
};

use crate::{
    InterfaceConfiguration, WireguardInterfaceApi,
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    wgapi::{Kernel, WGApi},
};

use base64::{Engine as _, engine::general_purpose};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use std::iter::once;
use windows::{
    core::{self, PCSTR, PCWSTR, PSTR, PWSTR},
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
        NetworkManagement::IpHelper::{
            self, GetAdaptersAddresses, DNS_INTERFACE_SETTINGS,
            DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
            GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, SetInterfaceDnsSettings,
        },
        System::Com::CLSIDFromString,
    },
};

fn key_from_str(key: &str) -> [u8; 32] {
    general_purpose::STANDARD
        .decode(&key)
        .expect("valid base64")
        .try_into()
        .expect("Failed to convert vec to [u8; 32]")
}

fn guid_from_string(s: &str) -> core::Result<windows::core::GUID> {
    let s = s.trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return Err(core::Error::empty()); // Or a more specific error
    }

    let data1 = u32::from_str_radix(parts[0], 16).map_err(|_| core::Error::empty())?;
    let data2 = u16::from_str_radix(parts[1], 16).map_err(|_| core::Error::empty())?;
    let data3 = u16::from_str_radix(parts[2], 16).map_err(|_| core::Error::empty())?;

    let mut data4 = [0u8; 8];

    let d4a = u16::from_str_radix(parts[3], 16).map_err(|_| core::Error::empty())?;
    data4[0] = ((d4a >> 8) & 0xFF) as u8;
    data4[1] = (d4a & 0xFF) as u8;

    let d4b = parts[4];
    if d4b.len() != 12 {
        return Err(core::Error::empty());
    }
    for i in 0..6 {
        let byte_str = &d4b[i * 2..i * 2 + 2];
        data4[i + 2] = u8::from_str_radix(byte_str, 16).map_err(|_| core::Error::empty())?;
    }

    Ok(windows::core::GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn set_dns(adapter_name: &str, dns_servers: &str) -> core::Result<()> {
    // Get the GUID for the adapter
    let mut guid = None;

    let mut buffer_len = 0u32;
    let mut result = unsafe {
        GetAdaptersAddresses(
            0,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buffer_len,
        )
    };

    let mut buffer = vec![0u8; buffer_len as usize];

    loop {
        result = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_len,
            )
        };

        if result == ERROR_BUFFER_OVERFLOW.0 {
            buffer.resize(buffer_len as usize, 0);
            continue;
        } else if result != NO_ERROR.0 {
            return Err(core::Error::empty());
        }
        println!("Found {buffer_len} adapters");
        break;
    }

    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };

        let friendly_name = unsafe { PCWSTR(adapter.FriendlyName.0).to_string()? };

        if friendly_name == adapter_name {
            println!("Found adapter {adapter_name}");
            let adapter_name_str = unsafe { PCSTR(PSTR(adapter.AdapterName.0).0).to_string()? };

            // let wide_guid: Vec<u16> = adapter_name_str.encode_utf16().chain(once(0)).collect();
            // // let interface_guid = core::GUID::default();
            // unsafe {
            //     // CLSIDFromString(PCWSTR(wide_guid.as_ptr()), &mut interface_guid)?;
            //     CLSIDFromString(PCWSTR(wide_guid.as_ptr()))?;
            // }
            // guid = Some(interface_guid);
            guid = Some(guid_from_string(&adapter_name_str)?);
            println!("Interface GUID: {guid:?}");
            break;
        }

        current = unsafe { adapter.Next };
    }

    let Some(interface_guid) = guid else {
        return Err(core::Error::empty()); // Or a custom error
    };

    // Prepare DNS settings
    let mut wide_dns: Vec<u16> = dns_servers.encode_utf16().chain(once(0)).collect();

    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64,
        // NameServer: PCWSTR(wide_dns.as_ptr()),
        NameServer: PWSTR(wide_dns.as_mut_ptr()),
        ..Default::default()
    };

    // Set the DNS settings
    let result = unsafe { SetInterfaceDnsSettings(interface_guid, &settings) };

    if result != NO_ERROR {
        return Err(core::Error::empty());
    }

    Ok(())
}

impl WGApi<Kernel> {
    fn conf_interface(config: InterfaceConfiguration) {

    // Load the wireguard dll file so that we can call the underlying C functions
    // Unsafe because we are loading an arbitrary dll file
    // let wireguard = unsafe { wireguard_nt::load_from_path("lib/wireguard-nt/bin/amd64/wireguard.dll") }
    let wireguard = unsafe { wireguard_nt::load_from_path("C:/Users/Jacek/Documents/workspace/client/wireguard-rs/lib/wireguard-nt/bin/amd64/wireguard.dll") }
        .expect("Failed to load wireguard dll");

    // Try to open an adapter from the given pool with the name "Defguard"
    let adapter = wireguard_nt::Adapter::open(&wireguard, "Defguard").unwrap_or_else(|_| {
        wireguard_nt::Adapter::create(&wireguard, "WireGuard", "Defguard", None)
            .expect("Failed to create wireguard adapter!")
    });
    // let endpoint = match "185.33.37.134:7301".parse() {
    //     Ok(endpoint) => endpoint,
    //     Err(err) => {
    //         eprintln!("Endpoint error: {err:?}");
    //         return;
    //     }
    // };
    // let endpoint = config.peers[0].endpoint.unwrap();
    // let allowed_ips = &[
    //     "10.2.0.0/24",
    //     "10.3.0.0/24",
    //     "10.4.0.0/24",
    //     "185.33.37.32/27",
    //     "10.7.0.0/16",
    //     "fd00::/64",
    // ];
    let peers = config.peers.iter().map(|peer| wireguard_nt::SetPeer {
            public_key: Some(peer.public_key.0),
            //Disable additional AES encryption
            preshared_key: peer.preshared_key.as_ref().map(|key| key.0),
            //Send a keepalive packet every 25 seconds
            keep_alive: peer.persistent_keepalive_interval,
            //Route all traffic through the WireGuard interface
            // allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            // allowed_ips: peer.allowed_ips.iter().map(|ip| if ip.ip.is_ipv4() {
            //     IpNet::V4(Ipv4Net::new(ip.ip, ip.mask()).unwrap())
            // } else {
            //     IpNet::V6(Ipv6Net::new(ip.ip, ip.mask()).unwrap())
            // }).collect(),
            allowed_ips: peer.allowed_ips.iter().map(|ip| match ip.ip {
                IpAddr::V4(addr) => IpNet::V4(Ipv4Net::new(addr, ip.cidr).unwrap()),
                IpAddr::V6(addr) => IpNet::V6(Ipv6Net::new(addr, ip.cidr).unwrap()),
            }).collect(),
            //The peer's ip address
            endpoint: peer.endpoint.unwrap(),
    }).collect();
    // let allowed_ips: Vec<_> = allowed_ips
    //     .iter()
    //     .map(|ip| ip.parse().unwrap())
    //     .collect();
    // let allowed_ips = config.peers[0].allowed_ips
    let interface = wireguard_nt::SetInterface {
        listen_port: Some(config.port as u16),
        //Generated from the private key if not specified
        public_key: None,
        private_key: Some(key_from_str(&config.prvkey)),
        //Add a peer
        // peers: vec![wireguard_nt::SetPeer {
        //     public_key: Some(config.peers[0].public_key.0),
        //     //Disable additional AES encryption
        //     preshared_key: config.peers[0].preshared_key.as_ref().map(|key| key.0),
        //     //Send a keepalive packet every 21 seconds
        //     keep_alive: Some(25),
        //     //Route all traffic through the WireGuard interface
        //     // allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        //     allowed_ips,
        //     //The peer's ip address
        //     endpoint,
        // }],
        peers,
    };

    //Set the config our adapter will use
    //This lets it know about the peers and keys
    adapter.set_config(&interface).unwrap();

    // let internal_ip = "10.6.0.2".parse().unwrap();
    let internal_ip = "10.6.0.69".parse().unwrap();
    let internal_prefix_length = 24;
    let internal_ipnet = ipnet::Ipv4Net::new(internal_ip, internal_prefix_length).unwrap();
    //Set up the routing table with the allowed ips for our peers,
    //and assign an ip to the interface
    adapter
        .set_default_route(&[internal_ipnet.into()], &interface)
        .unwrap();
    adapter.up().expect("Failed to bring the adapter UP");
    set_dns("WireGuard", "10.4.0.1").expect("Setting DNS failed");
    println!("Adapter ready");
    thread::sleep(Duration::MAX);
    //drop(adapter)
    //The adapter closes its resources when dropped
    }
}

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

        let cloned = config.clone();
        thread::spawn(|| Self::conf_interface(cloned));
        return Ok(());

        // Interface is created here so that there is no need to pass private key only for Windows
        let file_name = format!("{}.conf", &self.ifname);
        let path = env::current_dir()?;
        let file_path_buf = path.join(&file_name);
        let file_path = file_path_buf.to_str().unwrap_or_default();

        debug!("Creating WireGuard configuration file {file_name} in: {file_path}");

        let mut file = File::create(&file_name)?;

        debug!(
            "WireGuard configuration file {file_name} created in {file_path}. Preparing configuration..."
        );

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
            wireguard_configuration
                .push_str(format!("\n[Peer]\nPublicKey = {}", peer.public_key).as_str());

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

                counter += 1;
            }
            debug!(
                "Finished waiting for service to be removed, the service is considered to be removed, proceeding further"
            );
        }

        debug!("Installing the new service for interface {}", self.ifname);
        let service_installation_output = Command::new("wireguard")
            .arg("/installtunnelservice")
            .arg(file_path)
            .output()
            .map_err(|err| {
                error!("Failed to create interface. Error: {err}");
                WireguardInterfaceError::ServiceInstallationFailed(err.to_string())
            })?;

        debug!(
            "Done installing the new service. Service installation output: {service_installation_output:?}",
        );

        if !service_installation_output.status.success() {
            let message = format!(
                "Failed to install WireGuard tunnel as a Windows service: {:?}",
                service_installation_output.stdout
            );
            return Err(WireguardInterfaceError::ServiceInstallationFailed(message));
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
                WireguardInterfaceError::ServiceInstallationFailed(err.to_string())
            })?;

        debug!(
            "Done disabling automatic restart for the new service. Service update output: {service_update_output:?}",
        );
        if !service_update_output.status.success() {
            let message = format!(
                "Failed to configure WireGuard tunnel service: {:?}",
                service_update_output.stdout
            );
            return Err(WireguardInterfaceError::ServiceInstallationFailed(message));
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
            return Err(WireguardInterfaceError::ServiceRemovalFailed(message));
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
