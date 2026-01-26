use std::{
    collections::HashMap,
    ffi::OsStr,
    net::IpAddr,
    os::windows::ffi::OsStrExt,
    str::FromStr,
    sync::{LazyLock, Mutex},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;
use windows::{
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceGuidToLuid, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
                GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, GetIpInterfaceEntry,
                IP_ADAPTER_ADDRESSES_LH, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
                SetInterfaceDnsSettings, SetIpInterfaceEntry,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC},
        System::Com::CLSIDFromString,
    },
    core::{GUID, PCSTR, PCWSTR, PSTR, PWSTR},
};
use wireguard_nt::Wireguard;

use crate::{
    InterfaceConfiguration, WireguardInterfaceApi,
    error::WireguardInterfaceError,
    host::Host,
    key::Key,
    net::IpAddrMask,
    peer::Peer,
    wgapi::{Kernel, WGApi},
};

static WIREGUARD_DLL_PATH: &str = "resources-windows/binaries/wireguard.dll";
// Load wireguard.dll. Unsafe because we are loading an arbitrary dll file.
static WIREGUARD_DLL: LazyLock<Mutex<Wireguard>> = LazyLock::new(|| {
    Mutex::new(
        unsafe { wireguard_nt::load_from_path(WIREGUARD_DLL_PATH) }
            .expect("Failed to load wireguard.dll"),
    )
});

#[derive(Debug, Error)]
pub enum WindowsError {
    #[error("Empty interface array")]
    EmptyInterfaceArrayError,
    #[error("Invalid adapter id: {0}")]
    InvalidAdapterId(String),
    #[error("Non-zero return value: {0}")]
    NonZeroReturnValue(u32),
    #[error("Adapter not found: {0}")]
    AdapterNotFound(String),
    #[error(transparent)]
    WireguardNtError(#[from] wireguard_nt::Error),
    #[error(transparent)]
    FromUtf16Error(#[from] std::string::FromUtf16Error),
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    WindowsCoreError(#[from] windows::core::Error),
    #[error("Missing peer endpoint for peer {0}")]
    MissingPeerEndpoint(String),
}

/// Converts a string representation of a GUID into a `windows::core::GUID`.
/// Example guid string: "{6B29FC40-CA47-1067-B31D-00DD010662DA}".
fn guid_from_str(s: &str) -> Result<GUID, WindowsError> {
    let wide = str_to_wide_null_terminated(s);
    let guid = unsafe { CLSIDFromString(PCWSTR(wide.as_ptr())).map_err(WindowsError::from)? };
    Ok(guid)
}

/// Returns the GUID of a network adapter given its name.
/// Example adapter name: "Ethernet", "WireGuard".
fn get_adapter_guid(adapter_name: &str) -> Result<GUID, WindowsError> {
    debug!("Finding adapter {adapter_name}");
    // We have to call `GetAdaptersAddresses` twice - first call to just get the `buffer_size` to hold the adapters.
    // Before the second call we allocate the buffer with `buffer_size` capacity so that the call can actually
    // store the adapters in the buffer.
    let mut buffer_size: u32 = 0;
    let mut result = unsafe {
        // Sets the `buffer_size`
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buffer_size,
        )
    };

    // We expect the overflow here, since `buffer_size = 0`. No overflow means no adapters.
    if result != ERROR_BUFFER_OVERFLOW.0 {
        return Err(WindowsError::EmptyInterfaceArrayError);
    }

    // Allocate the buffer and actually get the adapters
    let mut buffer = vec![0u8; buffer_size as usize];
    let addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    result = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(addresses),
            &mut buffer_size,
        )
    };
    if result != NO_ERROR.0 {
        return Err(WindowsError::NonZeroReturnValue(result));
    }

    // Find our adapter
    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    let mut guid: Option<GUID> = None;
    while !current.is_null() {
        // SAFETY:
        // `current` comes from the linked list allocated and initialized by
        // `GetAdaptersAddresses`. The pointer is valid, properly aligned,
        // non-null (checked above), and the backing `buffer` lives for the
        // duration of this loop. No concurrent mutation occurs, so aliasing
        // rules are respected.
        let adapter = unsafe { &*current };

        let friendly_name = unsafe { PCWSTR(adapter.FriendlyName.0).to_string()? };
        if friendly_name == adapter_name {
            let adapter_name_str = unsafe { PCSTR(PSTR(adapter.AdapterName.0).0).to_string()? };
            guid = Some(guid_from_str(&adapter_name_str)?);
            info!("Found adapter {adapter_name}, GUID: {guid:?}");
            break;
        }

        current = adapter.Next;
    }

    guid.ok_or_else(|| WindowsError::AdapterNotFound(adapter_name.to_string()))
}

/// Sets both IPv4 and IPv6 MTU on specified interface.
fn set_interface_mtu(interface_name: &str, mtu: u32) -> Result<(), WindowsError> {
    debug!("Setting interface {interface_name} MTU to {mtu}");
    let guid = get_adapter_guid(interface_name)?;

    // Convert interface GUID to LUID.
    let mut luid = NET_LUID_LH::default();
    let res = unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) };
    if res.0 != 0 {
        error!(
            "ConvertInterfaceGuidToLuid call failed, error value: {}",
            res.0
        );
        return Err(WindowsError::NonZeroReturnValue(res.0));
    }

    // Helper function, sets MTU for given IP family.
    fn set_mtu_for_family(luid: NET_LUID_LH, family: u16, mtu: u32) -> Result<(), WindowsError> {
        // InitializeIpInterfaceEntry has to be called before get/set operations.
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };

        // Load current configuration.
        row.InterfaceLuid = luid;
        row.Family = ADDRESS_FAMILY(family);
        let res = unsafe { GetIpInterfaceEntry(&mut row) };
        if res.0 != 0 {
            error!("GetIpInterfaceEntry call failed, error value: {}", res.0);
            return Err(WindowsError::NonZeroReturnValue(res.0));
        }

        // Modify the configuration and apply.
        row.NlMtu = mtu;
        let res = unsafe { SetIpInterfaceEntry(&mut row) };
        if res.0 != 0 {
            error!("SetIpInterfaceEntry call failed, error value: {}", res.0);
            return Err(WindowsError::NonZeroReturnValue(res.0));
        }
        Ok(())
    }

    // Set MTU for both IP addr families.
    set_mtu_for_family(luid, AF_INET.0, mtu)?;
    set_mtu_for_family(luid, AF_INET6.0, mtu)?;

    info!("Set interface {interface_name} MTU to {mtu}");
    Ok(())
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
            fwmark: None,
            peers,
        }
    }
}

/// Converts an str to wide (u16), null-terminated
fn str_to_wide_null_terminated(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Manages interfaces created with Windows kernel using https://git.zx2c4.com/wireguard-nt.
impl WireguardInterfaceApi for WGApi<Kernel> {
    fn create_interface(&mut self) -> Result<(), WireguardInterfaceError> {
        debug!("Opening/creating interface {}", self.ifname);

        // Try to open the adapter. If it's not present create it.
        let wireguard = WIREGUARD_DLL.lock().expect("Failed to lock WIREGUARD_DLL");
        let adapter = match wireguard_nt::Adapter::open(&wireguard, &self.ifname) {
            Ok(adapter) => {
                debug!("Found existing adapter {}", self.ifname);
                adapter
            }
            Err(_) => {
                debug!("Adapter {} does not exist, creating", self.ifname);
                wireguard_nt::Adapter::create(&wireguard, &self.ifname, &self.ifname, None)
                    .map_err(WindowsError::from)?
            }
        };
        self.adapter = Some(adapter);

        info!("Opened/created interface {}", self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        Ok(())
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Configuring interface {} with config: {config:?}",
            self.ifname
        );

        // Retrieve the adapter - should be created by calling `Self::create_interface` first.
        let Some(ref adapter) = self.adapter else {
            Err(WindowsError::AdapterNotFound(self.ifname.clone()))?
        };

        // Prepare peers
        debug!("Preparing peers for adapter {}", self.ifname);
        let peers: Result<Vec<_>, WindowsError> = config
            .peers
            .iter()
            .map(|peer| {
                Ok(wireguard_nt::SetPeer {
                    public_key: Some(peer.public_key.as_array()),
                    preshared_key: peer.preshared_key.as_ref().map(|key| key.as_array()),
                    keep_alive: peer.persistent_keepalive_interval,
                    allowed_ips: peer
                        .allowed_ips
                        .iter()
                        .filter_map(|ip| match ip.address {
                            IpAddr::V4(addr) => Some(IpNet::V4(Ipv4Net::new(addr, ip.cidr).ok()?)),
                            IpAddr::V6(addr) => Some(IpNet::V6(Ipv6Net::new(addr, ip.cidr).ok()?)),
                        })
                        .collect(),
                    endpoint: peer.endpoint.ok_or_else(|| {
                        WindowsError::MissingPeerEndpoint(peer.public_key.to_string())
                    })?,
                })
            })
            .collect();
        let peers = peers?;

        // Configure the interface
        debug!("Applying configuration for adapter {}", self.ifname);
        let interface = wireguard_nt::SetInterface {
            listen_port: Some(config.port),
            public_key: None, // derived from private key
            private_key: Some(Key::from_str(&config.prvkey)?.as_array()),
            peers,
        };
        adapter.set_config(&interface).map_err(WindowsError::from)?;

        // Set adapter addresses
        debug!(
            "Assigning addresses to adapter {}: {:?}",
            self.ifname, config.addresses
        );
        let addresses: Vec<_> = config
            .addresses
            .iter()
            .filter_map(|ip| match ip.address {
                IpAddr::V4(addr) => Some(IpNet::V4(Ipv4Net::new(addr, ip.cidr).ok()?)),
                IpAddr::V6(addr) => Some(IpNet::V6(Ipv6Net::new(addr, ip.cidr).ok()?)),
            })
            .collect();
        adapter
            .set_default_route(&addresses, &interface)
            .map_err(WindowsError::from)?;

        // Set MTU
        if let Some(mtu) = config.mtu {
            set_interface_mtu(&self.ifname, mtu)?;
            // Turn it off and on again.
            adapter.down().map_err(WindowsError::from)?;
        }

        // Bring the adapter up.
        debug!("Bringing up adapter {}", self.ifname);
        adapter.up().map_err(WindowsError::from)?;

        info!(
            "Interface {} has been successfully configured.",
            self.ifname
        );
        Ok(())
    }

    fn configure_peer_routing(&self, _peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        Ok(())
    }

    fn remove_interface(&mut self) -> Result<(), WireguardInterfaceError> {
        debug!("Removing interface {}", self.ifname);
        self.adapter = None;
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

        // Retrieve the adapter - should be created by calling `Self::create_interface` first.
        let Some(ref adapter) = self.adapter else {
            Err(WindowsError::AdapterNotFound(self.ifname.clone()))?
        };
        let host = adapter.get_config().into();
        debug!("Read interface data: {host:?}");
        Ok(host)
    }

    fn configure_dns(
        &self,
        dns: &[IpAddr],
        search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError> {
        debug!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        let guid = get_adapter_guid(&self.ifname)?;
        let (ipv4_dns_ips, ipv6_dns_ips): (Vec<&IpAddr>, Vec<&IpAddr>) =
            dns.iter().partition(|ip| ip.is_ipv4());
        let ipv4_dns_servers: Vec<String> = ipv4_dns_ips.iter().map(|ip| ip.to_string()).collect();
        let ipv6_dns_servers: Vec<String> = ipv6_dns_ips.iter().map(|ip| ip.to_string()).collect();

        let mut search_domains_vec = str_to_wide_null_terminated(&search_domains.join(","));
        let search_domains_wide = PWSTR(search_domains_vec.as_mut_ptr());

        if !ipv4_dns_servers.is_empty() {
            let dns_str = ipv4_dns_servers.join(",");
            let mut wide = str_to_wide_null_terminated(&dns_str);
            let name_server = PWSTR(wide.as_mut_ptr());

            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: DNS_SETTING_NAMESERVER as u64,
                NameServer: name_server,
                SearchList: search_domains_wide,
                ..Default::default()
            };

            let status = unsafe { SetInterfaceDnsSettings(guid, &settings) };
            if status != NO_ERROR {
                Err(WindowsError::NonZeroReturnValue(status.0))?;
            }
        }
        if !ipv6_dns_servers.is_empty() {
            let dns_str = ipv6_dns_servers.join(",");
            let mut wide = str_to_wide_null_terminated(&dns_str);
            let name_server = PWSTR(wide.as_mut_ptr());

            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6) as u64,
                NameServer: name_server,
                SearchList: search_domains_wide,
                ..Default::default()
            };

            let status = unsafe { SetInterfaceDnsSettings(guid, &settings) };
            if status != NO_ERROR {
                Err(WindowsError::NonZeroReturnValue(status.0))?;
            }
        }

        info!(
            "Configured DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        Ok(())
    }
}
