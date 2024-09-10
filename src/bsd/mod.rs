mod ifconfig;
mod nvlist;
mod route;
mod sockaddr;
mod timespec;
mod wgio;

use std::{
    collections::HashMap, ffi::CString, mem::size_of, net::IpAddr, os::fd::OwnedFd, ptr::from_ref,
    slice::from_raw_parts,
};

use nix::{
    errno::Errno,
    sys::socket::{socket, AddressFamily, SockFlag, SockType},
};
use route::{DestAddrMask, GatewayLink};
use sockaddr::{SockAddrDl, SockAddrIn, SockAddrIn6};
use thiserror::Error;

use self::{
    ifconfig::{IfMtu, IfReq, IfReq6, IfReqFlags, In6AliasReq, InAliasReq},
    nvlist::NvList,
    route::{GatewayAddr, RtMessage},
    sockaddr::{pack_sockaddr, unpack_sockaddr},
    timespec::{pack_timespec, unpack_timespec},
    wgio::{WgReadIo, WgWriteIo},
};
use crate::{
    host::{Host, Peer},
    net::IpAddrMask,
    IpVersion, Key, WireguardInterfaceError,
};

// nvlist key names
static NV_LISTEN_PORT: &str = "listen-port";
static NV_FWMARK: &str = "user-cookie";
static NV_PUBLIC_KEY: &str = "public-key";
static NV_PRIVATE_KEY: &str = "private-key";
static NV_PEERS: &str = "peers";
static NV_REPLACE_PEERS: &str = "replace-peers";

static NV_PRESHARED_KEY: &str = "preshared-key";
static NV_KEEPALIVE_INTERVAL: &str = "persistent-keepalive-interval";
static NV_ENDPOINT: &str = "endpoint";
static NV_RX_BYTES: &str = "rx-bytes";
static NV_TX_BYTES: &str = "tx-bytes";
static NV_LAST_HANDSHAKE: &str = "last-handshake-time";
static NV_ALLOWED_IPS: &str = "allowed-ips";
static NV_REPLACE_ALLOWED_IPS: &str = "replace-allowed-ips";
static NV_REMOVE: &str = "remove";

static NV_CIDR: &str = "cidr";
static NV_IPV4: &str = "ipv4";
static NV_IPV6: &str = "ipv6";

/// Cast bytes to `T`.
unsafe fn cast_ref<T>(bytes: &[u8]) -> &T {
    bytes.as_ptr().cast::<T>().as_ref().unwrap()
}

/// Cast `T' to bytes.
unsafe fn cast_bytes<T: Sized>(p: &T) -> &[u8] {
    from_raw_parts(from_ref::<T>(p).cast::<u8>(), size_of::<T>())
}

/// Create socket for ioctl communication.
fn create_socket(address_family: AddressFamily) -> Result<OwnedFd, Errno> {
    socket(address_family, SockType::Datagram, SockFlag::empty(), None)
}

#[derive(Debug, Error)]
pub enum IoError {
    #[error("Memory allocation error")]
    MemAlloc,
    #[error("Read error {0}")]
    ReadIo(Errno),
    #[error("Write error {0}")]
    WriteIo(Errno),
    #[error("Network interface does not exist")]
    NetworkInterface,
    #[error("Not enough bytes to unpack")]
    Unpack,
}

impl From<IoError> for WireguardInterfaceError {
    fn from(error: IoError) -> Self {
        WireguardInterfaceError::BsdError(error.to_string())
    }
}

impl IpAddrMask {
    #[must_use]
    fn try_from_nvlist(nvlist: &NvList) -> Option<Self> {
        // cidr is mendatory
        nvlist.get_number(NV_CIDR).and_then(|cidr| {
            match nvlist.get_binary(NV_IPV4) {
                Some(ipv4) => <[u8; 4]>::try_from(ipv4).ok().map(IpAddr::from),
                None => nvlist
                    .get_binary(NV_IPV6)
                    .and_then(|ipv6| <[u8; 16]>::try_from(ipv6).ok().map(IpAddr::from)),
            }
            .map(|ip| Self {
                ip,
                cidr: cidr as u8,
            })
        })
    }
}

impl<'a> IpAddrMask {
    #[must_use]
    fn as_nvlist(&'a self) -> NvList<'a> {
        let mut nvlist = NvList::new();

        nvlist.append_number(NV_CIDR, u64::from(self.cidr));

        match self.ip {
            IpAddr::V4(ipv4) => nvlist.append_bytes(NV_IPV4, ipv4.octets().into()),
            IpAddr::V6(ipv6) => nvlist.append_bytes(NV_IPV6, ipv6.octets().into()),
        }

        nvlist.append_nvlist_array_next();
        nvlist
    }
}

impl Host {
    #[must_use]
    fn from_nvlist(nvlist: &NvList) -> Self {
        let listen_port = nvlist.get_number(NV_LISTEN_PORT).unwrap_or_default();
        let private_key = nvlist
            .get_binary(NV_PRIVATE_KEY)
            .and_then(|value| (*value).try_into().ok());

        let mut peers = HashMap::new();
        if let Some(peer_array) = nvlist.get_nvlist_array(NV_PEERS) {
            for peer_list in peer_array {
                if let Some(peer) = Peer::try_from_nvlist(peer_list) {
                    peers.insert(peer.public_key.clone(), peer);
                }
            }
        }

        Self {
            listen_port: listen_port as u16,
            private_key,
            fwmark: nvlist.get_number(NV_FWMARK).map(|num| num as u32),
            peers,
        }
    }
}

impl<'a> Host {
    #[must_use]
    fn as_nvlist(&'a self) -> NvList<'a> {
        let mut nvlist = NvList::new();

        nvlist.append_number(NV_LISTEN_PORT, u64::from(self.listen_port));
        if let Some(private_key) = self.private_key.as_ref() {
            nvlist.append_binary(NV_PRIVATE_KEY, private_key.as_slice());
        }
        if let Some(fwmark) = self.fwmark {
            nvlist.append_number(NV_FWMARK, u64::from(fwmark));
        }

        nvlist.append_bool(NV_REPLACE_PEERS, true);
        if !self.peers.is_empty() {
            let peers = self.peers.values().map(Peer::as_nvlist).collect();
            nvlist.append_nvlist_array(NV_PEERS, peers);
        }

        nvlist
    }
}

impl Peer {
    #[must_use]
    fn try_from_nvlist(nvlist: &NvList) -> Option<Self> {
        if let Some(public_key) = nvlist
            .get_binary(NV_PUBLIC_KEY)
            .and_then(|value| (*value).try_into().ok())
        {
            let preshared_key = nvlist
                .get_binary(NV_PRESHARED_KEY)
                .and_then(|value| (*value).try_into().ok());
            let mut allowed_ips = Vec::new();
            if let Some(ip_array) = nvlist.get_nvlist_array(NV_ALLOWED_IPS) {
                for ip_list in ip_array {
                    if let Some(ip) = IpAddrMask::try_from_nvlist(ip_list) {
                        allowed_ips.push(ip);
                    }
                }
            }

            Some(Self {
                public_key,
                preshared_key,
                protocol_version: None,
                endpoint: nvlist.get_binary(NV_ENDPOINT).and_then(unpack_sockaddr),
                last_handshake: nvlist
                    .get_binary(NV_LAST_HANDSHAKE)
                    .and_then(unpack_timespec),
                tx_bytes: nvlist.get_number(NV_TX_BYTES).unwrap_or_default(),
                rx_bytes: nvlist.get_number(NV_RX_BYTES).unwrap_or_default(),
                persistent_keepalive_interval: nvlist
                    .get_number(NV_KEEPALIVE_INTERVAL)
                    .map(|value| value as u16),
                allowed_ips,
            })
        } else {
            None
        }
    }
}

impl<'a> Peer {
    #[must_use]
    fn as_nvlist(&'a self) -> NvList<'a> {
        let mut nvlist = NvList::new();

        nvlist.append_binary(NV_PUBLIC_KEY, self.public_key.as_slice());
        if let Some(preshared_key) = self.preshared_key.as_ref() {
            nvlist.append_binary(NV_PRESHARED_KEY, preshared_key.as_slice());
        }
        if let Some(endpoint) = self.endpoint.as_ref() {
            nvlist.append_bytes(NV_ENDPOINT, pack_sockaddr(endpoint));
        }
        if let Some(last_handshake) = self.last_handshake.as_ref() {
            nvlist.append_bytes(NV_LAST_HANDSHAKE, pack_timespec(last_handshake));
        }
        nvlist.append_number(NV_TX_BYTES, self.tx_bytes);
        nvlist.append_number(NV_RX_BYTES, self.rx_bytes);
        if let Some(keepalive_interval) = self.persistent_keepalive_interval {
            nvlist.append_number(NV_KEEPALIVE_INTERVAL, u64::from(keepalive_interval));
        }

        nvlist.append_bool(NV_REPLACE_ALLOWED_IPS, true);
        if !self.allowed_ips.is_empty() {
            let allowed_ips = self.allowed_ips.iter().map(IpAddrMask::as_nvlist).collect();
            nvlist.append_nvlist_array(NV_ALLOWED_IPS, allowed_ips);
        }

        nvlist.append_nvlist_array_next();
        nvlist
    }
}

impl<'a> Key {
    #[must_use]
    fn as_nvlist_for_removal(&'a self) -> NvList<'a> {
        let mut nvlist = NvList::new();

        nvlist.append_binary(NV_PUBLIC_KEY, self.as_slice());
        nvlist.append_bool(NV_REMOVE, true);

        nvlist.append_nvlist_array_next();
        nvlist
    }
}

pub fn get_host(if_name: &str) -> Result<Host, IoError> {
    let mut wg_data = WgReadIo::new(if_name);
    wg_data.read_data()?;

    let mut nvlist = NvList::new();
    // FIXME: use proper error, here and above
    nvlist
        .unpack(wg_data.as_slice())
        .map_err(|_| IoError::MemAlloc)?;

    Ok(Host::from_nvlist(&nvlist))
}

pub fn set_host(if_name: &str, host: &Host) -> Result<(), IoError> {
    let nvlist = host.as_nvlist();
    // FIXME: use proper error, here and above
    let mut buf = nvlist.pack().map_err(|_| IoError::MemAlloc)?;

    let mut wg_data = WgWriteIo::new(if_name, &mut buf);
    wg_data.write_data()
}

pub fn set_peer(if_name: &str, peer: &Peer) -> Result<(), IoError> {
    let mut nvlist = NvList::new();
    nvlist.append_nvlist_array(NV_PEERS, vec![peer.as_nvlist()]);
    // FIXME: use proper error, here and above
    let mut buf = nvlist.pack().map_err(|_| IoError::MemAlloc)?;

    let mut wg_data = WgWriteIo::new(if_name, &mut buf);
    wg_data.write_data()
}

pub fn delete_peer(if_name: &str, public_key: &Key) -> Result<(), IoError> {
    let mut nvlist = NvList::new();
    nvlist.append_nvlist_array(NV_PEERS, vec![public_key.as_nvlist_for_removal()]);
    // FIXME: use proper error, here and above
    let mut buf = nvlist.pack().map_err(|_| IoError::MemAlloc)?;

    let mut wg_data = WgWriteIo::new(if_name, &mut buf);
    wg_data.write_data()
}

pub fn create_interface(if_name: &str) -> Result<(), IoError> {
    let mut ifreq = IfReq::new(if_name);
    ifreq.create()?;
    // Put the interface up here as it is done on Linux.
    let mut ifreq = IfReqFlags::new(if_name);
    ifreq.up()
}

pub fn delete_interface(if_name: &str) -> Result<(), IoError> {
    let ifreq = IfReq::new(if_name);
    ifreq.destroy()
}

pub fn assign_address(if_name: &str, address: &IpAddrMask) -> Result<(), IoError> {
    let broadcast = address.broadcast();
    let mask = address.mask();

    match (address.ip, broadcast, mask) {
        (IpAddr::V4(address), IpAddr::V4(broadcast), IpAddr::V4(mask)) => {
            let inaliasreq = InAliasReq::new(if_name, address, broadcast, mask);
            inaliasreq.add_address()
        }
        (IpAddr::V6(address), IpAddr::V6(_broadcast), IpAddr::V6(mask)) => {
            let inaliasreq = In6AliasReq::new(if_name, address, mask);
            inaliasreq.add_address()
        }
        _ => unreachable!(),
    }
}

pub fn remove_address(if_name: &str, address: &IpAddrMask) -> Result<(), IoError> {
    match address.ip {
        IpAddr::V4(address) => {
            let mut ifreq = IfReq::new(if_name);
            ifreq.delete_address(address)
        }
        IpAddr::V6(address) => {
            let mut ifreq6 = IfReq6::new(if_name);
            ifreq6.delete_address(address)
        }
    }
}

pub fn get_mtu(if_name: &str) -> Result<u32, IoError> {
    let mut ifmtu = IfMtu::new(if_name);
    ifmtu.get_mtu()
}

pub fn set_mtu(if_name: &str, mtu: u32) -> Result<(), IoError> {
    let mut ifmtu = IfMtu::new(if_name);
    ifmtu.set_mtu(mtu)
}

/// Get (default) gateway for a given IP address version.
pub fn get_gateway(ip_version: IpVersion) -> Result<Option<IpAddr>, IoError> {
    match ip_version {
        IpVersion::IPv4 => {
            let rtmsg = RtMessage::<GatewayAddr<SockAddrIn>>::new_for_gateway();
            rtmsg.get_gateway()
        }
        IpVersion::IPv6 => {
            let rtmsg = RtMessage::<GatewayAddr<SockAddrIn6>>::new_for_gateway();
            rtmsg.get_gateway()
        }
    }
}

/// Add link layaer address gateway.
pub fn add_gateway(dest: &IpAddrMask, if_name: &str) -> Result<(), IoError> {
    let name = CString::new(if_name).unwrap();
    let if_index = unsafe { libc::if_nametoindex(name.as_ptr()) as u16 };
    if if_index == 0 {
        return Err(IoError::NetworkInterface);
    }
    match (dest.ip, dest.mask()) {
        (IpAddr::V4(ip), IpAddr::V4(mask)) => {
            let link = SockAddrDl::new(if_index);
            let payload = GatewayLink::<SockAddrIn>::new(ip.into(), mask.into(), link);
            let rtmsg = RtMessage::new_for_gateway_link(if_index, payload);
            return rtmsg.execute();
        }
        (IpAddr::V6(ip), IpAddr::V6(mask)) => {
            let link = SockAddrDl::new(if_index);
            let payload = GatewayLink::<SockAddrIn6>::new(ip.into(), mask.into(), link);
            let rtmsg = RtMessage::new_for_gateway_link(if_index, payload);
            return rtmsg.execute();
        }
        _ => error!("Unsupported address for add route"),
    }

    Ok(())
}

/// Add a route to the routing table for a named network interface.
pub fn add_route(dest: &IpAddrMask, if_name: &str) -> Result<(), IoError> {
    let name = CString::new(if_name).unwrap();
    let if_index = unsafe { libc::if_nametoindex(name.as_ptr()) as u16 };
    if if_index == 0 {
        return Err(IoError::NetworkInterface);
    }
    match (dest.ip, dest.mask()) {
        (IpAddr::V4(ip), IpAddr::V4(mask)) => {
            let payload = DestAddrMask::<SockAddrIn>::new(ip.into(), mask.into(), if_name);
            let rtmsg = RtMessage::new_for_add(if_index, payload);
            return rtmsg.execute();
        }
        (IpAddr::V6(ip), IpAddr::V6(mask)) => {
            let payload = DestAddrMask::<SockAddrIn6>::new(ip.into(), mask.into(), if_name);
            let rtmsg = RtMessage::new_for_add(if_index, payload);
            return rtmsg.execute();
        }
        _ => error!("Unsupported address for add route"),
    }

    Ok(())
}

/// Add a route from the routing table for a named network interface.
pub fn delete_route(dest: &IpAddrMask, if_name: &str) -> Result<(), IoError> {
    let name = CString::new(if_name).unwrap();
    let if_index = unsafe { libc::if_nametoindex(name.as_ptr()) as u16 };
    if if_index == 0 {
        return Err(IoError::NetworkInterface);
    }
    match (dest.ip, dest.mask()) {
        (IpAddr::V4(ip), IpAddr::V4(mask)) => {
            let payload = DestAddrMask::<SockAddrIn>::new(ip.into(), mask.into(), if_name);
            let rtmsg = RtMessage::new_for_delete(if_index, payload);
            return rtmsg.execute();
        }
        (IpAddr::V6(ip), IpAddr::V6(mask)) => {
            let payload = DestAddrMask::<SockAddrIn6>::new(ip.into(), mask.into(), if_name);
            let rtmsg = RtMessage::new_for_delete(if_index, payload);
            return rtmsg.execute();
        }
        _ => error!("Unsupported address for add route"),
    }

    Ok(())
}
