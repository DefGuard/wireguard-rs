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
        Foundation::{
            ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, FreeLibrary, NO_ERROR,
        },
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceGuidToLuid, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
                DNS_SETTING_SEARCHLIST, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses,
                GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, InitializeIpInterfaceEntry,
                MIB_IPINTERFACE_ROW, SetInterfaceDnsSettings, SetIpInterfaceEntry,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC},
        System::{
            Com::CLSIDFromString,
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
                REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCreateKeyExW,
                RegDeleteTreeW, RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW,
            },
        },
    },
    core::{GUID, Owned, PCSTR, PCWSTR, PSTR, PWSTR},
};
use wireguard_nt::Wireguard;

use crate::{
    InterfaceConfiguration, WireguardInterfaceApi,
    dns::{
        DnsConfig, NRPT_CONFIG_OPTION_OVERRIDE_DNS, NRPT_MAX_NAMESPACES_PER_RULE,
        NRPT_POLICY_CONFIG_PATH, NRPT_RULE_VERSION, multi_sz, nrpt_rule_key_interface_id,
        nrpt_rule_key_name, nrpt_servers_value,
    },
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
    Mutex::new(
        unsafe { wireguard_nt::load_from_path(WIREGUARD_DLL_PATH) }
            .expect("Failed to load wireguard.dll"),
    )
});

const IPV4_LABEL: &str = "IPv4";
const IPV6_LABEL: &str = "IPv6";

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

/// Returns the friendly name and GUID of every network adapter on the host.
fn list_adapters() -> Result<Vec<(String, GUID)>, WindowsError> {
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

    let mut adapters = Vec::new();
    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !current.is_null() {
        // SAFETY:
        // `current` comes from the linked list allocated and initialized by
        // `GetAdaptersAddresses`. The pointer is valid, properly aligned,
        // non-null (checked above), and the backing `buffer` lives for the
        // duration of this loop. No concurrent mutation occurs, so aliasing
        // rules are respected.
        let adapter = unsafe { &*current };

        let friendly_name = unsafe { PCWSTR(adapter.FriendlyName.0).to_string()? };
        let adapter_name = unsafe { PCSTR(PSTR(adapter.AdapterName.0).0).to_string()? };
        adapters.push((friendly_name, guid_from_str(&adapter_name)?));

        current = adapter.Next;
    }

    Ok(adapters)
}

/// Returns the GUID of a network adapter given its name.
/// Example adapter name: "Ethernet", "WireGuard".
fn get_adapter_guid(adapter_name: &str) -> Result<GUID, WindowsError> {
    debug!("Finding adapter {adapter_name}");
    let guid = list_adapters()?
        .into_iter()
        .find_map(|(friendly_name, guid)| (friendly_name == adapter_name).then_some(guid));
    match guid {
        Some(guid) => {
            info!("Found adapter {adapter_name}, GUID: {guid:?}");
            Ok(guid)
        }
        None => Err(WindowsError::AdapterNotFound(adapter_name.to_string())),
    }
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

/// Formats a GUID the way it is written into a registry key name, without the enclosing braces.
fn guid_to_string(guid: &GUID) -> String {
    let [a, b, c, d, e, f, g, h] = guid.data4;
    format!(
        "{:08X}-{:04X}-{:04X}-{a:02X}{b:02X}-{c:02X}{d:02X}{e:02X}{f:02X}{g:02X}{h:02X}",
        guid.data1, guid.data2, guid.data3
    )
}

/// Views a wide string as the bytes the registry API expects.
fn as_bytes(buffer: &[u16]) -> &[u8] {
    // SAFETY: `u16` has no padding and no invalid bit patterns, and `u8` has an alignment of one,
    // so any `[u16]` can be read as twice as many bytes.
    unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size_of_val(buffer)) }
}

/// Creates a registry key under `HKEY_LOCAL_MACHINE`, or opens it if it already exists.
fn create_key(path: &str) -> Result<Owned<HKEY>, WindowsError> {
    let path = str_to_wide_null_terminated(path);
    let mut key = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &raw mut key,
            None,
        )
    };
    if status == NO_ERROR {
        // SAFETY: the key was just opened by this call, so we own the handle.
        Ok(unsafe { Owned::new(key) })
    } else {
        Err(WindowsError::NonZeroReturnValue(status.0))
    }
}

/// Opens a registry key under `HKEY_LOCAL_MACHINE`, returning `None` if it does not exist.
fn open_key(path: &str, access: REG_SAM_FLAGS) -> Result<Option<Owned<HKEY>>, WindowsError> {
    let path = str_to_wide_null_terminated(path);
    let mut key = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            access,
            &raw mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        Ok(None)
    } else if status == NO_ERROR {
        // SAFETY: the key was just opened by this call, so we own the handle.
        Ok(Some(unsafe { Owned::new(key) }))
    } else {
        Err(WindowsError::NonZeroReturnValue(status.0))
    }
}

/// Writes one value into an open registry key.
fn set_value(
    key: HKEY,
    name: &str,
    value_type: REG_VALUE_TYPE,
    data: &[u8],
) -> Result<(), WindowsError> {
    let name = str_to_wide_null_terminated(name);
    let status =
        unsafe { RegSetValueExW(key, PCWSTR(name.as_ptr()), None, value_type, Some(data)) };
    if status == NO_ERROR {
        Ok(())
    } else {
        Err(WindowsError::NonZeroReturnValue(status.0))
    }
}

/// Lists the names of the subkeys of an open registry key.
fn subkey_names(key: HKEY) -> Result<Vec<String>, WindowsError> {
    // Registry key names are limited to 255 characters.
    const MAX_KEY_NAME_LEN: usize = 256;

    let mut names = Vec::new();
    let mut index = 0;
    loop {
        let mut buffer = [0u16; MAX_KEY_NAME_LEN];
        // Holds the buffer size going in and the length of the name coming out, both in
        // characters and without the terminating NUL for the latter.
        let mut length = MAX_KEY_NAME_LEN as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                Some(PWSTR(buffer.as_mut_ptr())),
                &raw mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(names);
        }
        if status != NO_ERROR {
            return Err(WindowsError::NonZeroReturnValue(status.0));
        }
        names.push(String::from_utf16_lossy(&buffer[..length as usize]));
        index += 1;
    }
}

/// Creates the NRPT rules resolving `namespaces` through `servers`.
fn write_nrpt_rules(
    interface_id: &str,
    namespaces: &[String],
    servers: &[IpAddr],
) -> Result<(), WindowsError> {
    let servers = str_to_wide_null_terminated(&nrpt_servers_value(servers));

    for (index, chunk) in namespaces.chunks(NRPT_MAX_NAMESPACES_PER_RULE).enumerate() {
        let rule = nrpt_rule_key_name(interface_id, index);
        debug!("Creating NRPT rule {rule} resolving {chunk:?} through the interface");
        let key = create_key(&format!("{NRPT_POLICY_CONFIG_PATH}\\{rule}"))?;
        set_value(*key, "Name", REG_MULTI_SZ, as_bytes(&multi_sz(chunk)))?;
        set_value(*key, "GenericDNSServers", REG_SZ, as_bytes(&servers))?;
        set_value(
            *key,
            "ConfigOptions",
            REG_DWORD,
            &NRPT_CONFIG_OPTION_OVERRIDE_DNS.to_ne_bytes(),
        )?;
        set_value(*key, "Version", REG_DWORD, &NRPT_RULE_VERSION.to_ne_bytes())?;
    }

    Ok(())
}

/// Removes every NRPT rule belonging to the given interface.
fn clear_nrpt_rules(interface_id: &str) -> Result<(), WindowsError> {
    remove_nrpt_rules(|rule_interface_id| rule_interface_id.eq_ignore_ascii_case(interface_id))
}

/// Removes the NRPT rules of interfaces which no longer exist.
fn sweep_orphaned_nrpt_rules() -> Result<(), WindowsError> {
    let live = list_adapters()?
        .iter()
        .map(|(_, guid)| guid_to_string(guid))
        .collect::<Vec<_>>();
    remove_nrpt_rules(|interface_id| {
        !live
            .iter()
            .any(|guid| guid.eq_ignore_ascii_case(interface_id))
    })
}

/// Removes the NRPT rules of this crate whose interface matches `remove`.
fn remove_nrpt_rules(remove: impl Fn(&str) -> bool) -> Result<(), WindowsError> {
    let Some(policy_config) = open_key(NRPT_POLICY_CONFIG_PATH, KEY_ALL_ACCESS)? else {
        debug!("{NRPT_POLICY_CONFIG_PATH} does not exist, so there is no NRPT rule to remove");
        return Ok(());
    };

    // Collect the names before deleting anything, as removing a subkey shifts the indices of the
    // ones enumerated after it.
    let rules = subkey_names(*policy_config)?
        .into_iter()
        .filter(|name| nrpt_rule_key_interface_id(name).is_some_and(&remove))
        .collect::<Vec<_>>();

    for rule in rules {
        debug!("Removing NRPT rule {rule}");
        let name = str_to_wide_null_terminated(&rule);
        let status = unsafe { RegDeleteTreeW(*policy_config, PCWSTR(name.as_ptr())) };
        if status != NO_ERROR {
            return Err(WindowsError::NonZeroReturnValue(status.0));
        }
    }

    Ok(())
}

/// Flushes the DNS resolver cache.
fn flush_dns_cache() {
    let library = str_to_wide_null_terminated("dnsapi.dll");
    let module = match unsafe { LoadLibraryW(PCWSTR(library.as_ptr())) } {
        Ok(module) => module,
        Err(err) => {
            warn!("Failed to load dnsapi.dll, skipping the DNS cache flush: {err}");
            return;
        }
    };

    if let Some(flush) =
        unsafe { GetProcAddress(module, PCSTR(c"DnsFlushResolverCache".as_ptr().cast())) }
    {
        // SAFETY: `DnsFlushResolverCache` takes no argument and returns a BOOL.
        let flush: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(flush) };
        if unsafe { flush() } == 0 {
            warn!(
                "DnsFlushResolverCache reported a failure. Names looked up before the DNS \
                configuration changed may keep resolving to stale addresses until their TTL \
                expires."
            );
        } else {
            debug!("DNS resolver cache flushed");
        }
    } else {
        warn!("DnsFlushResolverCache was not found in dnsapi.dll, skipping the DNS cache flush");
    }

    if let Err(err) = unsafe { FreeLibrary(module) } {
        debug!("Failed to unload dnsapi.dll: {err}");
    }
}

/// Sets the DNS servers and the search list of an adapter.
fn set_interface_dns(
    guid: GUID,
    servers: &[IpAddr],
    search_domains: &[&str],
) -> Result<(), WindowsError> {
    // The buffer has to outlive every call below, which is why it is kept in its own binding.
    let mut search_list_buffer = str_to_wide_null_terminated(&search_domains.join(","));
    let search_list = PWSTR(search_list_buffer.as_mut_ptr());

    for ipv6 in [false, true] {
        let addresses = servers
            .iter()
            .filter(|address| address.is_ipv6() == ipv6)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut name_server = str_to_wide_null_terminated(&addresses.join(","));
        let mut flags = DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST;
        if ipv6 {
            flags |= DNS_SETTING_IPV6;
        }

        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: u64::from(flags),
            NameServer: PWSTR(name_server.as_mut_ptr()),
            SearchList: search_list,
            ..Default::default()
        };

        let status = unsafe { SetInterfaceDnsSettings(guid, &settings) };
        if status != NO_ERROR {
            return Err(WindowsError::NonZeroReturnValue(status.0));
        }
    }

    Ok(())
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

        if let Err(err) = sweep_orphaned_nrpt_rules() {
            warn!("Failed to remove the NRPT rules of interfaces which no longer exist: {err}");
        }

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
        let mut interface = wireguard_nt::SetInterface {
            listen_port: Some(config.port),
            public_key: None, // derived from private key
            private_key: Some(Key::from_str(&config.prvkey)?.as_array()),
            peers,
        };
        adapter.set_config(&interface).map_err(WindowsError::from)?;

        // Check which IP families are available on this adapter before attempting
        // to create routes.
        let adapter_luid = adapter.get_luid();
        let mut ipv4_available = false;
        let mut ipv6_available = false;
        for (family_name, family) in [(IPV4_LABEL, AF_INET), (IPV6_LABEL, AF_INET6)] {
            let mut row = MIB_IPINTERFACE_ROW::default();
            unsafe { InitializeIpInterfaceEntry(&mut row) };
            row.InterfaceLuid = unsafe { std::mem::transmute::<u64, NET_LUID_LH>(adapter_luid) };
            row.Family = ADDRESS_FAMILY(family.0);
            let err = unsafe { GetIpInterfaceEntry(&mut row) };
            if err.0 == 0 {
                debug!(
                    "IP interface {family_name} for {ifname}: connected={conn}, if_index={idx}, mtu={mtu}",
                    ifname = self.ifname,
                    conn = row.Connected,
                    idx = row.InterfaceIndex,
                    mtu = row.NlMtu
                );
                if family == AF_INET {
                    ipv4_available = true;
                } else {
                    ipv6_available = true;
                }
            } else {
                info!(
                    "IP interface {family_name} unavailable on {ifname} (luid={luid:#018x}): {err:#x} - skipping {family_name} routes",
                    ifname = self.ifname,
                    luid = adapter_luid,
                    err = err.0
                );
            }
        }
        if !ipv4_available && !ipv6_available {
            Err(WindowsError::AdapterNotFound(self.ifname.clone()))?
        }

        // Strip allowed IPs for unavailable families so CreateIpForwardEntry2
        // inside set_default_route only attempts routes that can succeed.
        if !ipv4_available || !ipv6_available {
            for peer in &mut interface.peers {
                peer.allowed_ips.retain(|ip| match ip {
                    IpNet::V4(_) => ipv4_available,
                    IpNet::V6(_) => ipv6_available,
                });
            }
        }

        // Set adapter addresses. Skip addresses for families that are not
        // available on this adapter (e.g. IPv6 disabled system-wide).
        debug!(
            "Assigning addresses to adapter {}: {:?}",
            self.ifname, config.addresses
        );
        let addresses: Vec<_> = config
            .addresses
            .iter()
            .filter_map(|ip| match ip.address {
                IpAddr::V4(addr) => {
                    if ipv4_available {
                        Some(IpNet::V4(Ipv4Net::new(addr, ip.cidr).ok()?))
                    } else {
                        debug!(
                            "Skipping IPv4 address {}: unavailable on adapter",
                            ip.address
                        );
                        None
                    }
                }
                IpAddr::V6(addr) => {
                    if ipv6_available {
                        Some(IpNet::V6(Ipv6Net::new(addr, ip.cidr).ok()?))
                    } else {
                        debug!(
                            "Skipping IPv6 address {}: unavailable on adapter",
                            ip.address
                        );
                        None
                    }
                }
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

        // NRPT rules outlive the adapter they were created for, so they have to be removed.
        match get_adapter_guid(&self.ifname) {
            Ok(guid) => {
                clear_nrpt_rules(&guid_to_string(&guid))?;
                flush_dns_cache();
            }
            Err(err) => debug!(
                "Could not find adapter {} to clean up its NRPT rules, they will be removed the \
                next time an interface is created: {err}",
                self.ifname
            ),
        }

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

    /// Sets the DNS configuration for the interface.
    fn set_dns(&self, config: &DnsConfig<'_>) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring DNS for interface {}: {config:?}", self.ifname);
        let guid = get_adapter_guid(&self.ifname)?;
        let interface_id = guid_to_string(&guid);

        // Replace whatever a previous connection of this interface left behind.
        clear_nrpt_rules(&interface_id)?;

        let namespaces = config.nrpt_namespaces();
        if namespaces.is_empty() {
            debug!(
                "No domain has to be resolved through interface {}, so no NRPT rule is created",
                self.ifname
            );
        } else {
            write_nrpt_rules(&interface_id, &namespaces, config.servers)?;
        }

        // Leaving the servers on the adapter for a split DNS configuration would send unrelated
        // queries to the tunnel, which is exactly what the rules above are there to prevent.
        let servers: &[IpAddr] = if config.default_route {
            config.servers
        } else {
            &[]
        };
        set_interface_dns(guid, servers, config.search_domains)?;

        flush_dns_cache();

        info!(
            "Configured DNS for interface {}, resolving {namespaces:?} through {:?}",
            self.ifname, config.servers
        );
        Ok(())
    }
}
