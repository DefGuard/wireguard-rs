use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Read},
    net::SocketAddr,
    str::FromStr,
    time::{Duration, SystemTime},
};

#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    constants::{WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REPLACE_ALLOWEDIPS},
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs},
};

use crate::{key::Key, net::IpAddrMask};

#[derive(Debug, Default, PartialEq, Clone)]
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

impl Peer {
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
    pub fn from_nlas(nlas: &[WgPeerAttrs]) -> Self {
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
    pub fn as_nlas(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::Peers(vec![self.as_nlas_peer()]),
        ]
    }

    #[must_use]
    pub fn as_nlas_peer(&self) -> WgPeer {
        let mut attrs = vec![WgPeerAttrs::PublicKey(self.public_key.as_array())];
        if let Some(keepalive) = self.persistent_keepalive_interval {
            attrs.push(WgPeerAttrs::PersistentKeepalive(keepalive));
        }

        if let Some(endpoint) = self.endpoint {
            attrs.push(WgPeerAttrs::Endpoint(endpoint));
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

#[derive(Debug, Default)]
pub struct Host {
    pub listen_port: u16,
    pub private_key: Option<Key>,
    pub(super) fwmark: Option<u32>,
    pub peers: HashMap<Key, Peer>,
}

impl Host {
    #[must_use]
    pub fn new(listen_port: u16, private_key: Key) -> Self {
        Self {
            listen_port,
            private_key: Some(private_key),
            fwmark: None,
            peers: HashMap::new(),
        }
    }

    #[must_use]
    pub fn as_uapi(&self) -> String {
        let mut output = format!("listen_port={}\n", self.listen_port);
        if let Some(key) = &self.private_key {
            output.push_str("private_key=");
            output.push_str(&key.to_lower_hex());
            output.push('\n');
        }
        if let Some(fwmark) = &self.fwmark {
            output.push_str("fwmark=");
            output.push_str(&fwmark.to_string());
            output.push('\n');
        }
        output.push_str("replace_peers=true\n");
        for peer in self.peers.values() {
            output.push_str(peer.as_uapi_update().as_ref());
        }

        output
    }

    // TODO: use custom Error
    pub fn parse_uapi(buf: impl Read) -> io::Result<Self> {
        let reader = BufReader::new(buf);
        let mut host = Self::default();
        let mut peer_ref = None;

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(line) => line,
                Err(err) => {
                    error!("Error parsing buffer line: {err}");
                    continue;
                }
            };
            if let Some((keyword, value)) = line.split_once('=') {
                match keyword {
                    "listen_port" => host.listen_port = value.parse().unwrap_or_default(),
                    "fwmark" => host.fwmark = value.parse().ok(),
                    "private_key" => host.private_key = Key::decode(value).ok(),
                    // "public_key" starts new peer definition
                    "public_key" => {
                        if let Ok(key) = Key::decode(value) {
                            let peer = Peer::new(key.clone());
                            host.peers.insert(key.clone(), peer);
                            peer_ref = host.peers.get_mut(&key);
                        } else {
                            peer_ref = None;
                        }
                    }
                    "preshared_key" => {
                        if let Some(ref mut peer) = peer_ref {
                            peer.preshared_key = Key::decode(value).ok();
                        }
                    }
                    "protocol_version" => {
                        if let Some(ref mut peer) = peer_ref {
                            peer.protocol_version = value.parse().ok();
                        }
                    }
                    "endpoint" => {
                        if let Some(ref mut peer) = peer_ref {
                            peer.endpoint = SocketAddr::from_str(value).ok();
                        }
                    }
                    "persistent_keepalive_interval" => {
                        if let Some(ref mut peer) = peer_ref {
                            peer.persistent_keepalive_interval = value.parse().ok();
                        }
                    }
                    "allowed_ip" => {
                        if let Some(ref mut peer) = peer_ref {
                            if let Ok(addr) = value.parse() {
                                peer.allowed_ips.push(addr);
                            }
                        }
                    }
                    "last_handshake_time_sec" => {
                        if let Some(ref mut peer) = peer_ref {
                            let handshake =
                                peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
                            *handshake += Duration::from_secs(value.parse().unwrap_or_default());
                        }
                    }
                    "last_handshake_time_nsec" => {
                        if let Some(ref mut peer) = peer_ref {
                            let handshake =
                                peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
                            *handshake += Duration::from_nanos(value.parse().unwrap_or_default());
                        }
                    }
                    "rx_bytes" => {
                        if let Some(ref mut peer) = peer_ref {
                            peer.rx_bytes = value.parse().unwrap_or_default();
                        }
                    }
                    "tx_bytes" => {
                        if let Some(ref mut peer) = peer_ref {
                            peer.tx_bytes = value.parse().unwrap_or_default();
                        }
                    }
                    // "errno" ends config
                    "errno" => {
                        if let Ok(errno) = value.parse::<u32>() {
                            if errno == 0 {
                                // Break here, or BufReader will wait for EOF.
                                break;
                            }
                        }
                        return Err(io::Error::new(io::ErrorKind::Other, "error reading UAPI"));
                    }
                    _ => error!("Unknown UAPI keyword {}", keyword),
                }
            }
        }

        Ok(host)
    }
}

#[cfg(target_os = "linux")]
impl Host {
    pub fn append_nlas(&mut self, nlas: &[WgDeviceAttrs]) {
        for nla in nlas {
            match nla {
                WgDeviceAttrs::PrivateKey(value) => self.private_key = Some(Key::new(*value)),
                WgDeviceAttrs::ListenPort(value) => self.listen_port = *value,
                WgDeviceAttrs::Fwmark(value) => self.fwmark = Some(*value),
                WgDeviceAttrs::Peers(nlas) => {
                    for nla in nlas {
                        let peer = Peer::from_nlas(nla);
                        self.peers.insert(peer.public_key.clone(), peer);
                    }
                }
                _ => (),
            }
        }
    }

    #[must_use]
    pub fn as_nlas(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        let mut nlas = vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::ListenPort(self.listen_port),
        ];
        if let Some(key) = &self.private_key {
            nlas.push(WgDeviceAttrs::PrivateKey(key.as_array()));
        }
        if let Some(fwmark) = &self.fwmark {
            nlas.push(WgDeviceAttrs::Fwmark(*fwmark));
        }
        nlas.push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS));
        let peers = self.peers.values().map(Peer::as_nlas_peer).collect();
        nlas.push(WgDeviceAttrs::Peers(peers));
        nlas
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_parse_config() {
        let uapi_output =
            b"private_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            listen_port=7301\n\
            public_key=100102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            last_handshake_time_sec=0\n\
            last_handshake_time_nsec=0\n\
            tx_bytes=0\n\
            rx_bytes=0\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.12/32\n\
            public_key=200102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            endpoint=83.11.218.160:51421\n\
            last_handshake_time_sec=1654631933\n\
            last_handshake_time_nsec=862977251\n\
            tx_bytes=52759980\n\
            rx_bytes=3683056\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.25/32\n\
            public_key=300102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            endpoint=31.135.163.194:37712\n\
            last_handshake_time_sec=1654776419\n\
            last_handshake_time_nsec=732507856\n\
            tx_bytes=1009094476\n\
            rx_bytes=76734328\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.23/32\n\
            errno=0\n";
        let buf = Cursor::new(uapi_output);
        let host = Host::parse_uapi(buf).unwrap();
        assert_eq!(host.listen_port, 7301);
        assert_eq!(host.peers.len(), 3);

        assert_eq!(3683056, 3683056);
        assert_eq!(52759980, 52759980);
        assert_eq!(1654631933, 1654631933);
    }

    #[test]
    fn test_host_uapi() {
        let key_str = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();

        let host = Host::new(12345, key);
        assert_eq!(
            "listen_port=12345\n\
            private_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            replace_peers=true\n",
            host.as_uapi()
        );
    }

    #[test]
    fn test_peer_uapi() {
        let key_str = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();

        let peer = Peer::new(key);
        assert_eq!(
            "public_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            replace_allowed_ips=true\n",
            peer.as_uapi_update()
        );

        let key_str = "00112233445566778899aaabbcbddeeff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();
        let peer = Peer::new(key);
        assert_eq!(
            "public_key=00112233445566778899aaabbcbddeeff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            remove=true\n",
            peer.as_uapi_remove()
        );
    }
}
