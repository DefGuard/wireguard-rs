//! DNS leak protection: Windows Filtering Platform filters blocking DNS that goes neither through
//! a tunnel nor to its DNS servers or port-53 peers.
//!
//! NRPT only steers the Windows DNS client; apps resolving by themselves (browsers, `nslookup`)
//! would still reach other adapters' resolvers.
//!
//! One filter set serves all interfaces: a block in any WFP sublayer overrides a permit in
//! another, so per-interface filters would block each other's DNS.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use windows::{
    Win32::{
        Foundation::{HANDLE, WIN32_ERROR},
        NetworkManagement::WindowsFilteringPlatform::{
            FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16,
            FWP_BYTE_ARRAY16_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
            FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
            FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
            FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
            FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
            FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
            FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0,
            FwpmTransactionBegin0, FwpmTransactionCommit0,
        },
        Networking::WinSock::{IPPROTO_TCP, IPPROTO_UDP},
        System::Rpc::RPC_C_AUTHN_DEFAULT,
    },
    core::{GUID, PCWSTR, PWSTR},
};

use super::{WindowsError, check, lock, str_to_wide_null_terminated};
use crate::{
    dns::DnsConfig,
    wgapi::{Kernel, WGApi},
};

const DNS_PORT: u16 = 53;

/// Turns the status a WFP call returns into a `Result`.
fn check_fwp(status: u32) -> Result<(), WindowsError> {
    check(WIN32_ERROR(status))
}

/// A tunnel's leak protection settings.
#[derive(Default)]
struct Tunnel {
    luid: u64,
    servers: Vec<IpAddr>,
    /// Peer endpoints on the DNS port, whose WireGuard traffic must not be blocked.
    endpoints: Vec<IpAddr>,
    /// Full-tunnel DNS, which turns the protection on.
    full: bool,
}

/// Tunnels by `DnsLeakProtection` id, and the filters protecting them.
struct State {
    tunnels: BTreeMap<u64, Tunnel>,
    filters: Option<Filters>,
}

static STATE: Mutex<State> = Mutex::new(State {
    tunnels: BTreeMap::new(),
    filters: None,
});

impl State {
    fn apply(&mut self) -> Result<(), WindowsError> {
        if !self.tunnels.values().any(|tunnel| tunnel.full) {
            if self.filters.take().is_some() {
                debug!("DNS leak protection disabled");
            }
            return Ok(());
        }

        let luids: BTreeSet<u64> = self.tunnels.values().map(|tunnel| tunnel.luid).collect();
        let destinations: BTreeSet<IpAddr> = self
            .tunnels
            .values()
            .flat_map(|tunnel| tunnel.servers.iter().chain(&tunnel.endpoints).copied())
            .collect();
        if self
            .filters
            .as_ref()
            .is_some_and(|filters| filters.luids == luids && filters.destinations == destinations)
        {
            return Ok(());
        }

        // The old filters go only once the new ones are in, and stay if those fail.
        let filters = Filters::new(luids, destinations)?;
        debug!(
            "DNS leak protection enabled for {} interface(s), allowing {:?}",
            filters.luids.len(),
            filters.destinations
        );
        self.filters = Some(filters);
        Ok(())
    }
}

/// An interface's part in the DNS leak protection, withdrawn when dropped.
pub(super) struct DnsLeakProtection {
    id: u64,
}

impl Default for DnsLeakProtection {
    fn default() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl DnsLeakProtection {
    /// Applies `change` to the interface's entry, adding it if needed.
    fn modify(&self, luid: u64, change: impl FnOnce(&mut Tunnel)) -> Result<(), WindowsError> {
        let mut state = lock(&STATE);
        let tunnel = state.tunnels.entry(self.id).or_default();
        tunnel.luid = luid;
        change(tunnel);
        // Also when unchanged, to retry a failed install.
        state.apply()
    }

    /// Exempts the WireGuard traffic of peers listening on the DNS port.
    pub(super) fn set_endpoints(
        &self,
        luid: u64,
        endpoints: impl Iterator<Item = SocketAddr>,
    ) -> Result<(), WindowsError> {
        let endpoints = endpoints
            .filter(|endpoint| endpoint.port() == DNS_PORT)
            .map(|endpoint| endpoint.ip())
            .collect();
        self.modify(luid, |tunnel| tunnel.endpoints = endpoints)
    }

    /// Removes the interface, which then neither enables the protection nor is exempt from it.
    pub(super) fn withdraw(&self) {
        let mut state = lock(&STATE);
        if state.tunnels.remove(&self.id).is_some()
            && let Err(err) = state.apply()
        {
            // The previous filters stay, still exempting this interface.
            warn!("Failed to update DNS leak protection after removing an interface: {err}");
        }
    }
}

impl Drop for DnsLeakProtection {
    fn drop(&mut self) {
        self.withdraw();
    }
}

/// Filters blocking DNS that goes neither through the given interfaces nor to the given
/// destinations. Being in a dynamic WFP session, they go when this is dropped or the process
/// exits, even by crashing.
struct Filters {
    engine: HANDLE,
    luids: BTreeSet<u64>,
    destinations: BTreeSet<IpAddr>,
}

// SAFETY: a WFP engine handle can be used and closed from any thread.
unsafe impl Send for Filters {}

impl Filters {
    fn new(luids: BTreeSet<u64>, destinations: BTreeSet<IpAddr>) -> Result<Self, WindowsError> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = HANDLE::default();
        check_fwp(unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                Some(&raw const session),
                &raw mut engine,
            )
        })?;
        // From here on, dropping `filters` closes the engine and discards what was added.
        let filters = Self {
            engine,
            luids,
            destinations,
        };

        check_fwp(unsafe { FwpmTransactionBegin0(engine, 0) })?;
        filters.add_filters()?;
        check_fwp(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(filters)
    }

    fn add_filters(&self) -> Result<(), WindowsError> {
        let mut name = str_to_wide_null_terminated("Defguard DNS leak protection");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: GUID::new()?,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            weight: u16::MAX,
            ..Default::default()
        };
        check_fwp(unsafe { FwpmSubLayerAdd0(self.engine, &raw const sublayer, None) })?;

        // The filters point to these values, which must outlive them.
        let mut luids = self.luids.iter().copied().collect::<Vec<_>>();
        let mut ipv6_addresses = Vec::new();
        let mut ipv4_destinations = Vec::new();
        for destination in &self.destinations {
            match destination {
                // WFP takes IPv4 addresses in host byte order.
                IpAddr::V4(address) => ipv4_destinations.push(condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from(*address),
                    },
                )),
                IpAddr::V6(address) => ipv6_addresses.push(FWP_BYTE_ARRAY16 {
                    byteArray16: address.octets(),
                }),
            }
        }
        let ipv6_destinations = ipv6_addresses
            .iter_mut()
            .map(|address| {
                condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_BYTE_ARRAY16_TYPE,
                    FWP_CONDITION_VALUE0_0 {
                        byteArray16: address,
                    },
                )
            })
            .collect::<Vec<_>>();
        let tunnels = luids
            .iter_mut()
            .map(|luid| {
                condition(
                    FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 { uint64: luid },
                )
            })
            .collect::<Vec<_>>();

        let [udp, tcp] = [IPPROTO_UDP, IPPROTO_TCP].map(|protocol| {
            condition(
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_UINT8,
                FWP_CONDITION_VALUE0_0 {
                    uint8: protocol.0 as u8,
                },
            )
        });
        let loopback = FWPM_FILTER_CONDITION0 {
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            ..condition(
                FWPM_CONDITION_FLAGS,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            )
        };

        // Conditions on the same field are ORed, conditions on different fields ANDed.
        for (layer, destinations) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, &ipv4_destinations),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, &ipv6_destinations),
        ] {
            self.add_filter(&sublayer, layer, FWP_ACTION_BLOCK, &[udp, tcp])?;
            self.add_filter(&sublayer, layer, FWP_ACTION_PERMIT, &tunnels)?;
            self.add_filter(&sublayer, layer, FWP_ACTION_PERMIT, &[loopback])?;
            if !destinations.is_empty() {
                self.add_filter(&sublayer, layer, FWP_ACTION_PERMIT, destinations)?;
            }
        }
        Ok(())
    }

    /// Adds a filter matching DNS traffic and the `conditions`.
    fn add_filter(
        &self,
        sublayer: &FWPM_SUBLAYER0,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        conditions: &[FWPM_FILTER_CONDITION0],
    ) -> Result<(), WindowsError> {
        let port = condition(
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: DNS_PORT },
        );
        let mut conditions = [&[port], conditions].concat();
        // Within our sublayer, permits outweigh the block.
        let weight = if action == FWP_ACTION_PERMIT { 10 } else { 1 };
        let filter = FWPM_FILTER0 {
            displayData: sublayer.displayData,
            layerKey: layer,
            subLayerKey: sublayer.subLayerKey,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: the filter and everything it points to outlive the call.
        check_fwp(unsafe { FwpmFilterAdd0(self.engine, &raw const filter, None, None) })
    }
}

impl Drop for Filters {
    fn drop(&mut self) {
        if let Err(err) = check_fwp(unsafe { FwpmEngineClose0(self.engine) }) {
            warn!("Failed to close the WFP engine, DNS leak protection may remain active: {err}");
        }
    }
}

/// Builds an equality condition.
fn condition(
    field: GUID,
    data_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: data_type,
            Anonymous: value,
        },
    }
}

impl WGApi<Kernel> {
    /// Adds the interface's DNS settings to the leak protection. Split DNS interfaces join too,
    /// so that a full tunnel elsewhere doesn't block them.
    pub(super) fn update_dns_leak_protection(
        &self,
        config: &DnsConfig<'_>,
    ) -> Result<(), WindowsError> {
        let adapter = self
            .adapter
            .as_ref()
            .ok_or_else(|| WindowsError::AdapterNotFound(self.ifname.clone()))?;
        self.windows_dns
            .leak_protection
            .modify(adapter.get_luid(), |tunnel| {
                tunnel.servers = config.servers.to_vec();
                tunnel.full = config.default_route;
            })
    }
}
