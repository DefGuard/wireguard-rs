//! Peer interface configuration
//!
//! Reference:
//! * WireGuard [Cross-platform Userspace Implementation](https://www.wireguard.com/xplatform/)

use std::{fmt, net::SocketAddr, time::SystemTime};

#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    constants::WGPEER_F_REPLACE_ALLOWEDIPS,
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{error::WireguardInterfaceError, key::Key, net::IpAddrMask, utils::resolve};

/// WireGuard peer representation.
#[derive(Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub protocol_version: Option<u32>,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<SystemTime>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<IpAddrMask>,
}

// implement manually to avoid exposing preshared keys
impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("public_key", &self.public_key)
            .field("protocol_version", &self.protocol_version)
            .field("endpoint", &self.endpoint)
            .field("last_handshake", &self.last_handshake)
            .field("tx_bytes", &self.tx_bytes)
            .field("rx_bytes", &self.rx_bytes)
            .field(
                "persistent_keepalive_interval",
                &self.persistent_keepalive_interval,
            )
            .field("allowed_ips", &self.allowed_ips)
            .finish_non_exhaustive()
    }
}

impl Peer {
    /// Create new `Peer` with a given `public_key`.
    #[must_use]
    pub fn new(public_key: Key) -> Self {
        Self {
            public_key,
            preshared_key: None,
            protocol_version: None,
            endpoint: None,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive_interval: None,
            allowed_ips: Vec::new(),
        }
    }

    pub fn set_allowed_ips(&mut self, allowed_ips: Vec<IpAddrMask>) {
        self.allowed_ips = allowed_ips;
    }

    /// Resolves endpoint address to [`SocketAddr`] and sets the field
    pub fn set_endpoint(&mut self, endpoint: &str) -> Result<(), WireguardInterfaceError> {
        self.endpoint = Some(resolve(endpoint)?);
        Ok(())
    }

    #[must_use]
    pub fn as_uapi_update(&self) -> String {
        let mut output = format!("public_key={}\n", self.public_key.to_lower_hex());
        if let Some(key) = &self.preshared_key {
            output.push_str("preshared_key=");
            output.push_str(&key.to_lower_hex());
            output.push('\n');
        }
        if let Some(endpoint) = &self.endpoint {
            output.push_str("endpoint=");
            output.push_str(&endpoint.to_string());
            output.push('\n');
        }
        if let Some(interval) = &self.persistent_keepalive_interval {
            output.push_str("persistent_keepalive_interval=");
            output.push_str(&interval.to_string());
            output.push('\n');
        }
        output.push_str("replace_allowed_ips=true\n");
        for allowed_ip in &self.allowed_ips {
            output.push_str("allowed_ip=");
            output.push_str(&allowed_ip.to_string());
            output.push('\n');
        }

        output
    }

    #[must_use]
    pub fn as_uapi_remove(&self) -> String {
        format!(
            "public_key={}\nremove=true\n",
            self.public_key.to_lower_hex()
        )
    }
}

#[cfg(target_os = "linux")]
impl Peer {
    #[must_use]
    pub(crate) fn from_nlas(nlas: &[WgPeerAttrs]) -> Self {
        let mut peer = Self::default();

        for nla in nlas {
            match nla {
                WgPeerAttrs::PublicKey(value) => peer.public_key = Key::new(*value),
                WgPeerAttrs::PresharedKey(value) => peer.preshared_key = Some(Key::new(*value)),
                WgPeerAttrs::Endpoint(value) => peer.endpoint = Some(*value),
                WgPeerAttrs::PersistentKeepalive(value) => {
                    peer.persistent_keepalive_interval = Some(*value);
                }
                WgPeerAttrs::LastHandshake(value) => peer.last_handshake = Some(*value),
                WgPeerAttrs::RxBytes(value) => peer.rx_bytes = *value,
                WgPeerAttrs::TxBytes(value) => peer.tx_bytes = *value,
                WgPeerAttrs::AllowedIps(nlas) => {
                    for nla in nlas {
                        let ip = nla.iter().find_map(|nla| match nla {
                            WgAllowedIpAttrs::IpAddr(ip) => Some(*ip),
                            _ => None,
                        });
                        let cidr = nla.iter().find_map(|nla| match nla {
                            WgAllowedIpAttrs::Cidr(cidr) => Some(*cidr),
                            _ => None,
                        });
                        if let (Some(ip), Some(cidr)) = (ip, cidr) {
                            peer.allowed_ips.push(IpAddrMask::new(ip, cidr));
                        }
                    }
                }
                _ => (),
            }
        }

        peer
    }

    #[must_use]
    pub(crate) fn as_nlas(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::Peers(vec![self.as_nlas_peer()]),
        ]
    }

    #[must_use]
    pub(crate) fn as_nlas_peer(&self) -> WgPeer {
        let mut attrs = vec![WgPeerAttrs::PublicKey(self.public_key.as_array())];
        if let Some(keepalive) = self.persistent_keepalive_interval {
            attrs.push(WgPeerAttrs::PersistentKeepalive(keepalive));
        }

        if let Some(endpoint) = self.endpoint {
            attrs.push(WgPeerAttrs::Endpoint(endpoint));
        }

        if let Some(preshared_key) = &self.preshared_key {
            attrs.push(WgPeerAttrs::PresharedKey(preshared_key.as_array()));
        }

        attrs.push(WgPeerAttrs::Flags(WGPEER_F_REPLACE_ALLOWEDIPS));
        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(IpAddrMask::to_nlas_allowed_ip)
            .collect();
        attrs.push(WgPeerAttrs::AllowedIps(allowed_ips));

        WgPeer(attrs)
    }
}
