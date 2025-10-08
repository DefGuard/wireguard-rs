use std::{
    collections::HashMap, io::{BufRead, BufReader, Cursor}, net::{IpAddr, SocketAddr}, process::Command, str::FromStr, sync::{mpsc::{self, Sender}, LazyLock, Mutex}, thread, time::{Duration, SystemTime}
};

use crate::{
    InterfaceConfiguration, WireguardInterfaceApi,
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    wgapi::{Kernel, WGApi},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use windows::{
    core::{self, PCSTR, PCWSTR, PSTR},
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses, DNS_INTERFACE_SETTINGS,
            DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DNS_SETTING_IPV6,
            GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, SetInterfaceDnsSettings,
        },
    },
};

static DLL_PATH: &str = "resources-windows/binaries/wireguard.dll";
static ADAPTERS: LazyLock<Mutex<HashMap<String, Sender<()>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn guid_from_string(s: &str) -> core::Result<windows::core::GUID> {
    let s = s.trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return Err(core::Error::empty());
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

fn set_dns(adapter_name: &str, dns_servers: &[IpAddr]) -> core::Result<()> {
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
            guid = Some(guid_from_string(&adapter_name_str)?);
            println!("Interface GUID: {guid:?}");
            break;
        }

        current = adapter.Next;
    }

    let Some(interface_guid) = guid else {
        return Err(core::Error::empty());
    };

    let (ipv4_ips, ipv6_ips): (Vec<&IpAddr>, Vec<&IpAddr>) = dns_servers.iter().partition(|ip| ip.is_ipv4());
    let ipv4_servers: Vec<String> = ipv4_ips.iter().map(|ip| ip.to_string()).collect();
    let ipv6_servers: Vec<String> = ipv6_ips.iter().map(|ip| ip.to_string()).collect();

    if !ipv4_servers.is_empty() {
        let dns_str = ipv4_servers.join(",");
        let mut wide: Vec<u16> = dns_str.encode_utf16().chain(std::iter::once(0)).collect();
        let name_server = windows::core::PWSTR(wide.as_mut_ptr());

        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: name_server,
            ..Default::default()
        };

        let status = unsafe { SetInterfaceDnsSettings(interface_guid, &settings) };
        if status != NO_ERROR {
            return Err(core::Error::empty());
        }
    }
    if !ipv6_servers.is_empty() {
        let dns_str = ipv4_servers.join(",");
        let mut wide: Vec<u16> = dns_str.encode_utf16().chain(std::iter::once(0)).collect();
        let name_server = windows::core::PWSTR(wide.as_mut_ptr());

        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6) as u64,
            NameServer: name_server,
            ..Default::default()
        };

        let status = unsafe { SetInterfaceDnsSettings(interface_guid, &settings) };
        if status != NO_ERROR {
            return Err(core::Error::empty());
        }
    }
    Ok(())
}

impl WGApi<Kernel> {
    fn conf_interface(ifname: String, config: InterfaceConfiguration, dns: Vec<IpAddr>) {
    // Load wireguard.dll. Unsafe because we are loading an arbitrary dll file.
    // TODO system path
    let wireguard = unsafe { wireguard_nt::load_from_path(DLL_PATH) }
        .expect("Failed to load wireguard dll");

    // Try to open the adapter. If it's not present create it.
    let adapter = wireguard_nt::Adapter::open(&wireguard, &ifname).unwrap_or_else(|_| {
        wireguard_nt::Adapter::create(&wireguard, "WireGuard", &ifname, None)
            .expect("Failed to create wireguard adapter!")
    });

    // Prepare peers
    let peers = config.peers.iter().map(|peer| wireguard_nt::SetPeer {
            public_key: Some(peer.public_key.0),
            preshared_key: peer.preshared_key.as_ref().map(|key| key.0),
            keep_alive: peer.persistent_keepalive_interval,
            allowed_ips: peer.allowed_ips.iter().map(|ip| match ip.ip {
                IpAddr::V4(addr) => IpNet::V4(Ipv4Net::new(addr, ip.cidr).unwrap()),
                IpAddr::V6(addr) => IpNet::V6(Ipv6Net::new(addr, ip.cidr).unwrap()),
            }).collect(),
            endpoint: peer.endpoint.unwrap(),
    }).collect();

    // Configure the interface
    let interface = wireguard_nt::SetInterface {
        listen_port: Some(config.port as u16), // TODO safety
        public_key: None,  // derived from private key
        private_key: Some(Key::from_str(&config.prvkey).unwrap().as_array()),
        peers,
    };
    adapter.set_config(&interface).unwrap();

    // Set adapter addresses
    let addresses: Vec<_> = config.addresses.iter().map(|ip| match ip.ip {
        IpAddr::V4(addr) => IpNet::V4(Ipv4Net::new(addr, ip.cidr).unwrap()),
        IpAddr::V6(addr) => IpNet::V6(Ipv6Net::new(addr, ip.cidr).unwrap()),
    }).collect();
    adapter
        .set_default_route(&addresses, &interface)
        .unwrap();
    // Configure adapter DNS servers
    // TODO adapter_name - what if we have multiple wireguard adapters?
    set_dns("WireGuard", &dns).expect("Setting DNS failed");

    // Bring the adapter up
    adapter.up().expect("Failed to bring the adapter UP");

    // TODO The adapter closes its resources when dropped
    // thread::sleep(Duration::MAX);
    let (tx, rx) = mpsc::channel();
    ADAPTERS.lock().unwrap().insert(ifname.to_string(), tx);
    rx.recv();
    // TODO log adapter down message
    }
}

impl From<wireguard_nt::WireguardPeer> for Peer {
    fn from(peer: wireguard_nt::WireguardPeer) -> Self {
        Self {
            public_key: Key::new(peer.public_key),
            preshared_key: Some(Key::new(peer.preshared_key)),
            protocol_version: None,
            endpoint: Some(peer.endpoint),
            tx_bytes: peer.tx_bytes,
            rx_bytes: peer.rx_bytes,
            last_handshake: peer.last_handshake,
            persistent_keepalive_interval: Some(peer.persistent_keepalive),
            allowed_ips: peer
                .allowed_ips
                .iter()
                .map(|ip| IpAddrMask::new(ip.addr(), ip.prefix_len()))
                .collect(),
        }
    }
}

impl From<wireguard_nt::WireguardInterface> for Host {
    fn from(iface: wireguard_nt::WireguardInterface) -> Self {
        let mut peers = HashMap::new();
        for peer in iface.peers {
            peers.insert(Key::new(peer.public_key), peer.into());
        }
        Self {
            listen_port: iface.listen_port,
            private_key: Some(Key::new(iface.private_key)),
            // TODO
            fwmark: None,
            peers,
        }
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

        let config = config.clone();
        let dns = dns.iter().cloned().collect();
        let ifname = self.ifname.clone();
        thread::spawn(move || Self::conf_interface(ifname, config, dns));

        info!(
            "Interface {} has been successfully configured.",
            self.ifname
        );
        Ok(())
    }

    fn configure_peer_routing(&self, _peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        debug!("Removing interface {}", self.ifname);
        if let Some(sender) = ADAPTERS.lock().unwrap().remove(&self.ifname) {
            // TODO error handling
            sender.send(()).unwrap();
        } else {
            // TODO
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
