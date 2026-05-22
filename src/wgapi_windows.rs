use std::{
    collections::HashMap,
    ffi::OsStr,
    net::IpAddr,
    os::windows::ffi::OsStrExt,
    str::FromStr,
    sync::{LazyLock, Mutex},
    time::Duration,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;
use windows::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS, NO_ERROR},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceGuidToLuid, CreateIpForwardEntry2, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
                DNS_SETTING_SEARCHLIST, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses,
                GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, InitializeIpForwardEntry,
                InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
                SetInterfaceDnsSettings, SetIpInterfaceEntry,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN6_ADDR},
        System::Com::CLSIDFromString,
        System::SystemInformation::OSVERSIONINFOW,
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

#[cfg(target_arch = "aarch64")]
const WIREGUARD_DLL_PATH: &str = "resources-windows/binaries/wireguard-arm64.dll";
#[cfg(target_arch = "x86_64")]
const WIREGUARD_DLL_PATH: &str = "resources-windows/binaries/wireguard-amd64.dll";
// Load wireguard.dll. Unsafe because we are loading an arbitrary dll file.
static WIREGUARD_DLL: LazyLock<Mutex<Wireguard>> = LazyLock::new(|| {
    let wireguard = unsafe { wireguard_nt::load_from_path(WIREGUARD_DLL_PATH) }
        .expect("Failed to load wireguard.dll");
    info!(
        "Loaded wireguard.dll from {} (architecture: {})",
        WIREGUARD_DLL_PATH,
        std::env::consts::ARCH
    );
    Mutex::new(wireguard)
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

/// Logs all network adapters and their operational status for diagnostics.
/// Helps identify conflicting VPN clients, Hyper-V switches, or filter drivers.
fn log_network_adapters() {
    let mut buffer_size: u32 = 0;
    let result = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC.0),
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buffer_size,
        )
    };
    if result != ERROR_BUFFER_OVERFLOW.0 {
        warn!("Failed to enumerate network adapters: error {}", result);
        return;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let addresses = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let result = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC.0),
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(addresses),
            &mut buffer_size,
        )
    };
    if result != NO_ERROR.0 {
        warn!("Failed to get network adapter list: error {}", result);
        return;
    }

    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    info!("--- Network adapters ---");
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let name = unsafe { PCWSTR(adapter.FriendlyName.0) }
            .to_string()
            .unwrap_or_default();
        let desc = unsafe { PCWSTR(adapter.Description.0) }
            .to_string()
            .unwrap_or_default();
        info!(
            "adapter: \"{name}\" desc=\"{desc}\" oper_status={status} if_type={if_type}",
            status = adapter.OperStatus.0,
            if_type = adapter.IfType
        );
        current = adapter.Next;
    }
    info!("--- End network adapters ---");
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
    let addresses = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    result = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC.0),
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
    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
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
        let adapter = if let Ok(adapter) = wireguard_nt::Adapter::open(&wireguard, &self.ifname) {
            debug!("Found existing adapter {}", self.ifname);
            adapter
        } else {
            debug!("Adapter {} does not exist, creating", self.ifname);
            wireguard_nt::Adapter::create(&wireguard, &self.ifname, &self.ifname, None)
                .map_err(WindowsError::from)?
        };
        self.adapter = Some(adapter);

        // Log the Windows version for diagnostics — CreateIpForwardEntry2 behavior
        // can vary between Windows builds.
        let mut ver = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        // SAFETY: RtlGetVersion reads kernel version info into stack-allocated struct
        unsafe { RtlGetVersion(&mut ver) };
        info!(
            "Opened/created interface {} on Windows build {}.{}.{}",
            self.ifname, ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber
        );
        log_network_adapters();
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
                    preshared_key: peer.preshared_key.as_ref().map(Key::as_array),
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
        // The WireGuard NT adapter may not be visible to the Windows IP routing
        // stack immediately after set_config(). CreateIpForwardEntry2 can fail with
        // ERROR_NOT_FOUND (1168) or ERROR_INVALID_PARAMETER (87) if the LUID is not
        // yet registered with the routing subsystem. Retry with backoff.
        debug!(
            "Applying routing configuration for adapter {}, probing routing stack readiness...",
            self.ifname
        );

        let adapter_luid = adapter.get_luid();

        // Diagnostic: query the IP interface state via GetIpInterfaceEntry before
        // attempting CreateIpForwardEntry2. This tells us whether the routing stack
        // can even see the adapter LUID at all.
        debug!(
            "Querying IP interface state for adapter {ifname} (luid={luid:#018x})",
            ifname = self.ifname,
            luid = adapter_luid
        );
        for (family_name, family) in [("IPv4", AF_INET), ("IPv6", AF_INET6)] {
            let mut row = MIB_IPINTERFACE_ROW::default();
            unsafe { InitializeIpInterfaceEntry(&mut row) };
            row.InterfaceLuid = unsafe { std::mem::transmute::<u64, NET_LUID_LH>(adapter_luid) };
            row.Family = ADDRESS_FAMILY(family.0);
            let err = unsafe { GetIpInterfaceEntry(&mut row) };
            if err.0 == 0 {
                info!(
                    "IP interface {family_name} for {ifname}: connected={conn}, if_index={idx}, mtu={mtu}",
                    ifname = self.ifname,
                    conn = row.Connected,
                    idx = row.InterfaceIndex,
                    mtu = row.NlMtu
                );
            } else {
                warn!(
                    "Cannot query IP interface {family_name} for {ifname} (luid={luid:#018x}): GetIpInterfaceEntry returned error {err:#x}",
                    ifname = self.ifname,
                    luid = adapter_luid,
                    err = err.0
                );
            }
        }

        // Per-prefix route creation with individual retry and logging.
        // CreateIpForwardEntry2 can fail per-prefix; logging which CIDR failed
        // helps narrow down whether the issue is all prefixes or one specific range.
        debug!(
            "Creating routes per-prefix for adapter {ifname} (luid={luid:#018x})",
            ifname = self.ifname,
            luid = adapter_luid
        );
        const PREFIX_MAX_RETRIES: u32 = 50;
        const PREFIX_RETRY_DELAY_MS: u64 = 100;
        for peer in &interface.peers {
            for allowed_ip in &peer.allowed_ips {
                let prefix_str = allowed_ip.to_string();
                let mut route = MIB_IPFORWARD_ROW2::default();
                unsafe { InitializeIpForwardEntry(&mut route) };
                route.InterfaceLuid =
                    unsafe { std::mem::transmute::<u64, NET_LUID_LH>(adapter_luid) };
                route.Metric = 5;

                match allowed_ip {
                    IpNet::V4(v4) => {
                        route.DestinationPrefix.Prefix.si_family = AF_INET;
                        route.DestinationPrefix.Prefix.Ipv4.sin_addr =
                            unsafe { std::mem::transmute::<[u8; 4], IN_ADDR>(v4.addr().octets()) };
                        route.DestinationPrefix.PrefixLength = v4.prefix_len();
                        route.NextHop.si_family = AF_INET;
                    }
                    IpNet::V6(v6) => {
                        route.DestinationPrefix.Prefix.si_family = AF_INET6;
                        route.DestinationPrefix.Prefix.Ipv6.sin6_addr = unsafe {
                            std::mem::transmute::<[u8; 16], IN6_ADDR>(v6.addr().octets())
                        };
                        route.DestinationPrefix.PrefixLength = v6.prefix_len();
                        route.NextHop.si_family = AF_INET6;
                    }
                }

                for attempt in 1..=PREFIX_MAX_RETRIES {
                    let err = unsafe { CreateIpForwardEntry2(&route) };
                    if err == ERROR_SUCCESS || err == ERROR_OBJECT_ALREADY_EXISTS {
                        if attempt > 1 {
                            info!(
                                "route for {prefix} succeeded on attempt {attempt}/{attempt_max} (luid={luid:#018x})",
                                prefix = prefix_str,
                                luid = adapter_luid,
                                attempt_max = PREFIX_MAX_RETRIES
                            );
                        } else {
                            debug!(
                                "route for {prefix} created (luid={luid:#018x})",
                                prefix = prefix_str,
                                luid = adapter_luid
                            );
                        }
                        break;
                    }
                    if attempt == PREFIX_MAX_RETRIES {
                        error!(
                            "route for {prefix} failed after {attempt_max} attempts (luid={luid:#018x}): error {err:#x}",
                            prefix = prefix_str,
                            luid = adapter_luid,
                            attempt_max = PREFIX_MAX_RETRIES,
                            err = err.0
                        );
                        return Err(WireguardInterfaceError::from(
                            WindowsError::NonZeroReturnValue(err.0),
                        ));
                    }
                    warn!(
                        "route for {prefix} attempt {attempt}/{attempt_max} failed (luid={luid:#018x}): error {err:#x}. Retrying in {delay}ms...",
                        prefix = prefix_str,
                        luid = adapter_luid,
                        attempt_max = PREFIX_MAX_RETRIES,
                        err = err.0,
                        delay = PREFIX_RETRY_DELAY_MS
                    );
                    std::thread::sleep(Duration::from_millis(PREFIX_RETRY_DELAY_MS));
                }
            }
        }

        // set_default_route handles unicast address assignment and interface metric
        // configuration. Routes were already created per-prefix above, so the route
        // creation step will get ERROR_OBJECT_ALREADY_EXISTS (harmless).
        adapter
            .set_default_route(&addresses, &interface)
            .map_err(|e| WireguardInterfaceError::from(WindowsError::from(e)))?;
        debug!(
            "Addresses assigned and metric configured for adapter {ifname}",
            ifname = self.ifname
        );

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
        let ipv4_dns_servers: Vec<String> = ipv4_dns_ips.iter().map(ToString::to_string).collect();
        let ipv6_dns_servers: Vec<String> = ipv6_dns_ips.iter().map(ToString::to_string).collect();

        let mut search_domains_vec = str_to_wide_null_terminated(&search_domains.join(","));
        let search_domains_wide = PWSTR(search_domains_vec.as_mut_ptr());

        if !ipv4_dns_servers.is_empty() {
            let dns_str = ipv4_dns_servers.join(",");
            let mut wide = str_to_wide_null_terminated(&dns_str);
            let name_server = PWSTR(wide.as_mut_ptr());

            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST),
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
                Flags: u64::from(
                    DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST | DNS_SETTING_IPV6,
                ),
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
