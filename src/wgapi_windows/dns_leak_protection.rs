//! DNS leak protection: Windows Filtering Platform filters blocking DNS queries which neither go
//! through the tunnel nor to its DNS servers.
//!
//! The NRPT catch-all rule only steers the Windows DNS client. Applications sending DNS queries
//! themselves (e.g. browsers' built-in resolvers, `nslookup`) would still reach the resolvers of
//! the other adapters.

use std::net::IpAddr;

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

/// Filters blocking DNS which neither goes through the tunnel nor to its DNS servers.
///
/// They belong to a dynamic WFP session, so Windows removes them when this is dropped, or when
/// the process exits, even if it crashes.
pub(super) struct DnsLeakProtection {
    engine: HANDLE,
    interface_luid: u64,
    servers: Vec<IpAddr>,
}

// SAFETY: a WFP engine handle can be used and closed from any thread.
unsafe impl Send for DnsLeakProtection {}

impl DnsLeakProtection {
    /// Installs the filters for the interface with the given LUID and its DNS `servers`.
    fn new(interface_luid: u64, servers: &[IpAddr]) -> Result<Self, WindowsError> {
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
        // From here on, dropping `protection` closes the engine, discarding whatever was added.
        let protection = Self {
            engine,
            interface_luid,
            servers: servers.to_vec(),
        };

        check_fwp(unsafe { FwpmTransactionBegin0(engine, 0) })?;
        protection.add_filters()?;
        check_fwp(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(protection)
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

        // Condition values pointed to by the filters below have to outlive them.
        let mut interface_luid = self.interface_luid;
        let mut ipv6_addresses = Vec::new();
        let mut ipv4_servers = Vec::new();
        for server in &self.servers {
            match server {
                // WFP takes IPv4 addresses in host byte order.
                IpAddr::V4(address) => ipv4_servers.push(condition(
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
        let ipv6_servers = ipv6_addresses
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

        let port = condition(
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: DNS_PORT },
        );
        let [udp, tcp] = [IPPROTO_UDP, IPPROTO_TCP].map(|protocol| {
            condition(
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_UINT8,
                FWP_CONDITION_VALUE0_0 {
                    uint8: protocol.0 as u8,
                },
            )
        });
        let tunnel = condition(
            FWPM_CONDITION_IP_LOCAL_INTERFACE,
            FWP_UINT64,
            FWP_CONDITION_VALUE0_0 {
                uint64: &raw mut interface_luid,
            },
        );
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
        for (layer, servers) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, &ipv4_servers),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, &ipv6_servers),
        ] {
            self.add_filter(&sublayer, layer, FWP_ACTION_BLOCK, &mut [port, udp, tcp])?;
            self.add_filter(&sublayer, layer, FWP_ACTION_PERMIT, &mut [port, tunnel])?;
            self.add_filter(&sublayer, layer, FWP_ACTION_PERMIT, &mut [port, loopback])?;
            if !servers.is_empty() {
                let mut conditions = vec![port];
                conditions.extend_from_slice(servers);
                self.add_filter(&sublayer, layer, FWP_ACTION_PERMIT, &mut conditions)?;
            }
        }
        Ok(())
    }

    fn add_filter(
        &self,
        sublayer: &FWPM_SUBLAYER0,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<(), WindowsError> {
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

impl Drop for DnsLeakProtection {
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
    /// Blocks DNS outside the tunnel when it answers every query, lifts the block otherwise.
    pub(super) fn update_dns_leak_protection(&self, config: &DnsConfig<'_>) {
        let mut protection = lock(&self.windows_dns.leak_protection);
        if !config.default_route {
            *protection = None;
            return;
        }
        let Some(adapter) = &self.adapter else {
            warn!(
                "Interface {} has no adapter, so DNS leak protection is not enabled",
                self.ifname
            );
            *protection = None;
            return;
        };
        let luid = adapter.get_luid();
        if protection.as_ref().is_some_and(|current| {
            current.interface_luid == luid && current.servers == config.servers
        }) {
            return;
        }
        // The new filters are in place before the old ones go.
        *protection = match DnsLeakProtection::new(luid, config.servers) {
            Ok(new) => {
                debug!("DNS leak protection enabled for interface {}", self.ifname);
                Some(new)
            }
            Err(err) => {
                warn!(
                    "Failed to enable DNS leak protection for interface {}, DNS queries may \
                    bypass the tunnel: {err}",
                    self.ifname
                );
                None
            }
        };
    }
}
