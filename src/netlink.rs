//! Netlink utilities for controlling network interfaces on Linux
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlFamily, GenlMessage,
};
use netlink_packet_route::{
    address,
    link::nlas::{Info, InfoKind, Nla},
    route::nlas::Nla as RouteNla,
    rule::nlas::Nla as RuleNla,
    AddressMessage, LinkHeader, LinkMessage, RouteHeader, RouteMessage, RtnlMessage, RuleHeader,
    RuleMessage, AF_INET, AF_INET6, FIB_RULE_INVERT, FR_ACT_TO_TBL, FR_ACT_UNSPEC, IFF_UP,
    RTN_UNICAST, RTPROT_BOOT, RT_SCOPE_LINK, RT_TABLE_MAIN, RT_TABLE_UNSPEC,
};
use netlink_packet_utils::errors::DecodeError;
use netlink_packet_wireguard::{
    constants::WGPEER_F_REMOVE_ME,
    nlas::{WgDeviceAttrs, WgPeer, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_sys::{constants::NETLINK_GENERIC, protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{
    fmt::Debug,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
};
use thiserror::Error;

use crate::{
    host::{Host, Peer},
    net::IpAddrMask,
    utils::IpVersion,
    Key, WireguardInterfaceError,
};

const SOCKET_BUFFER_LENGTH: usize = 12288;

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("Unexpected netlink payload")]
    UnexpectedPayload,
    #[error("Failed to send netlink request")]
    SendFailure,
    #[error(
        "Serialized netlink packet ({0} bytes) larger than maximum size {SOCKET_BUFFER_LENGTH}"
    )]
    InvalidPacketLength(usize),
    #[error("Attribute value not found")]
    AttributeNotFound,
    #[error("Socket error: {0}")]
    SocketError(String),
    #[error("Invalid Netlink data")]
    InvalidData,
    #[error("Failed to read response")]
    ResponseError(#[from] DecodeError),
    #[error("Netlink payload error: {0}")]
    PayloadError(netlink_packet_core::ErrorMessage),
    #[error("Failed to create WireGuard interface")]
    CreateInterfaceError,
    #[error("Failed to delete WireGuard interface")]
    DeleteInterfaceError,
    #[error("File already exists")]
    FileAlreadyExists,
    #[error("Add route error")]
    AddRouteError,
    #[error("No such file")]
    NotFound,
    #[error("Failed to add rule")]
    AddRuleError,
    #[error("Failed to delete rule")]
    DeleteRuleError,
}

impl From<NetlinkError> for WireguardInterfaceError {
    fn from(error: NetlinkError) -> Self {
        WireguardInterfaceError::NetlinkError(error.to_string())
    }
}

/// Wrapper `Result` type for Netlink operations
pub type NetlinkResult<T> = Result<T, NetlinkError>;

macro_rules! get_nla_value {
    ($nlas:expr, $e:ident, $v:ident) => {
        $nlas.iter().find_map(|attr| match attr {
            $e::$v(value) => Some(value),
            _ => None,
        })
    };
}

impl Key {
    #[must_use]
    pub fn as_nlas_remove(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::Peers(vec![WgPeer(vec![
                WgPeerAttrs::PublicKey(self.as_array()),
                WgPeerAttrs::Flags(WGPEER_F_REMOVE_ME),
            ])]),
        ]
    }
}

fn netlink_request_genl<F>(
    mut message: GenlMessage<F>,
    flags: u16,
) -> NetlinkResult<Vec<NetlinkMessage<GenlMessage<F>>>>
where
    F: GenlFamily + Clone + Debug + Eq,
    GenlMessage<F>: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    if message.family_id() == 0 {
        let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName(F::family_name().to_string())],
        });
        let responses = netlink_request_genl::<GenlCtrl>(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;

        match responses.first() {
            Some(NetlinkMessage {
                payload:
                    NetlinkPayload::InnerMessage(GenlMessage {
                        payload: GenlCtrl { nlas, .. },
                        ..
                    }),
                ..
            }) => {
                let family_id = get_nla_value!(nlas, GenlCtrlAttrs, FamilyId)
                    .ok_or_else(|| NetlinkError::AttributeNotFound)?;
                message.set_resolved_family_id(*family_id);
            }
            _ => return Err(NetlinkError::UnexpectedPayload),
        };
    }
    netlink_request(message, flags, NETLINK_GENERIC)
}

fn netlink_request<I>(
    message: I,
    flags: u16,
    socket: isize,
) -> NetlinkResult<Vec<NetlinkMessage<I>>>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    let mut req = NetlinkMessage::from(message);

    if req.buffer_len() > SOCKET_BUFFER_LENGTH {
        error!(
                "Serialized netlink packet ({} bytes) larger than maximum size {SOCKET_BUFFER_LENGTH}: {req:?}",
                req.buffer_len(),
            );
        return Err(NetlinkError::InvalidPacketLength(req.buffer_len()));
    }

    req.header.flags = flags;
    req.finalize();
    let mut buf = [0; SOCKET_BUFFER_LENGTH];
    req.serialize(&mut buf);
    let len = req.buffer_len();

    let socket = Socket::new(socket).map_err(|err| {
        error!("Failed to open socket: {err}");
        NetlinkError::SocketError(err.to_string())
    })?;
    let kernel_addr = SocketAddr::new(0, 0);
    socket.connect(&kernel_addr).map_err(|err| {
        error!("Failed to connect to socket: {err}");
        NetlinkError::SocketError(err.to_string())
    })?;
    let n_sent = socket.send(&buf[..len], 0).map_err(|err| {
        error!("Failed to send to socket: {err}");
        NetlinkError::SocketError(err.to_string())
    })?;
    if n_sent != len {
        return Err(NetlinkError::SendFailure);
    }

    let mut responses = Vec::new();
    loop {
        let n_received = socket.recv(&mut &mut buf[..], 0).map_err(|err| {
            error!("Failed to receive from socket: {err}");
            NetlinkError::SocketError(err.to_string())
        })?;
        let mut offset = 0;
        loop {
            let response = NetlinkMessage::<I>::deserialize(&buf[offset..])?;
            debug!("Read netlink response from socket: {response:?}");
            match response.payload {
                // We've parsed all parts of the response and can leave the loop.
                NetlinkPayload::Error(msg) if msg.code.is_none() => return Ok(responses),
                NetlinkPayload::Done(_) => return Ok(responses),
                NetlinkPayload::Error(msg) => {
                    return match msg.to_io().kind() {
                        ErrorKind::AlreadyExists => Err(NetlinkError::FileAlreadyExists),
                        ErrorKind::NotFound => Err(NetlinkError::NotFound),
                        _ => Err(NetlinkError::PayloadError(msg)),
                    }
                }
                _ => {}
            }
            let header_length = response.header.length as usize;
            offset += header_length;
            responses.push(response);
            if offset == n_received || header_length == 0 {
                // We've fully parsed the datagram, but there may be further datagrams
                // with additional netlink response parts.
                break;
            }
        }
    }
}

/// Create WireGuard interface.
pub fn create_interface(ifname: &str) -> NetlinkResult<()> {
    let mut message = LinkMessage::default();
    message.header.flags = IFF_UP;
    message.header.change_mask = IFF_UP;
    message.nlas.push(Nla::IfName(ifname.into()));
    message
        .nlas
        .push(Nla::Info(vec![Info::Kind(InfoKind::Wireguard)]));

    match netlink_request(
        RtnlMessage::NewLink(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    ) {
        Ok(_msg) => Ok(()),
        Err(NetlinkError::FileAlreadyExists) => Ok(()),
        Err(err) => {
            error!("Failed to create WireGuard interface: {err}");
            Err(NetlinkError::CreateInterfaceError)
        }
    }
}

fn set_address(ifindex: u32, address: &IpAddrMask) -> NetlinkResult<()> {
    let mut message = AddressMessage::default();

    message.header.prefix_len = address.cidr;
    message.header.index = ifindex;

    let address_vec = match address.ip {
        IpAddr::V4(ipv4) => {
            message.header.family = AF_INET as u8;
            ipv4.octets().to_vec()
        }
        IpAddr::V6(ipv6) => {
            message.header.family = AF_INET6 as u8;
            ipv6.octets().to_vec()
        }
    };

    if address.ip.is_multicast() {
        message.nlas.push(address::Nla::Multicast(address_vec));
    } else if address.ip.is_unspecified() {
        message.nlas.push(address::Nla::Unspec(address_vec));
    } else if address.ip.is_ipv6() {
        message.nlas.push(address::Nla::Address(address_vec));
    } else {
        message
            .nlas
            .push(address::Nla::Address(address_vec.clone()));
        // for IPv4 the IFA_LOCAL address can be set to the same value as IFA_ADDRESS
        message.nlas.push(address::Nla::Local(address_vec.clone()));
        // set the IFA_BROADCAST address as well (IPv6 does not support broadcast)
        if address.cidr == 32 {
            message.nlas.push(address::Nla::Broadcast(address_vec));
        } else if let IpAddrMask {
            ip: IpAddr::V4(ipv4),
            ..
        } = address
        {
            let broadcast =
                Ipv4Addr::from((0xffff_ffff_u32) >> u32::from(address.cidr) | u32::from(*ipv4));
            message
                .nlas
                .push(address::Nla::Broadcast(broadcast.octets().to_vec()));
        };
    }

    netlink_request(
        RtnlMessage::NewAddress(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        NETLINK_ROUTE,
    )?;
    Ok(())
}

/// Set IP address of a WireGuard network interface
pub fn address_interface(ifname: &str, address: &IpAddrMask) -> NetlinkResult<()> {
    if let Some(index) = get_interface_index(ifname)? {
        return set_address(index, address);
    }
    Ok(())
}

/// Delete WireGuard interface
pub fn delete_interface(ifname: &str) -> NetlinkResult<()> {
    let mut message = LinkMessage::default();
    message.nlas.push(Nla::IfName(ifname.into()));
    message
        .nlas
        .push(Nla::Info(vec![Info::Kind(InfoKind::Wireguard)]));

    netlink_request(
        RtnlMessage::DelLink(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    )
    .map_err(|err| {
        error!("Failed to delete WireGuard interface: {err}");
        NetlinkError::DeleteInterfaceError
    })?;
    Ok(())
}

/// Read host interface data
pub fn get_host(ifname: &str) -> NetlinkResult<Host> {
    debug!("Reading Netlink data for interface {ifname}");
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(ifname.into())],
    });
    let responses = netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_DUMP)?;

    let mut host = Host::default();
    for nlmsg in responses {
        if let NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(ref message),
            ..
        } = nlmsg
        {
            host.append_nlas(&message.payload.nlas);
        } else {
            return Err(NetlinkError::UnexpectedPayload);
        }
    }

    Ok(host)
}

/// Perform interface configuration
pub fn set_host(ifname: &str, host: &Host) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: host.as_nlas(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

/// Save or update WireGuard peer configuration
pub fn set_peer(ifname: &str, peer: &Peer) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: peer.as_nlas(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

/// Delete a WireGuard peer from interface
pub fn delete_peer(ifname: &str, public_key: &Key) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: public_key.as_nlas_remove(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

/// Get interface index by name.
fn get_interface_index(ifname: &str) -> NetlinkResult<Option<u32>> {
    let mut message = LinkMessage::default();
    message.nlas.push(Nla::IfName(ifname.into()));
    message
        .nlas
        .push(Nla::Info(vec![Info::Kind(InfoKind::Wireguard)]));

    let responses = netlink_request(
        RtnlMessage::GetLink(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    )?;

    for nlmsg in responses {
        match nlmsg {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(message),
                ..
            } => {
                if let RtnlMessage::NewLink(LinkMessage {
                    header: LinkHeader { index, .. },
                    ..
                }) = message
                {
                    return Ok(Some(index));
                }
            }
            _ => debug!("unknown nlmsg response"),
        }
    }

    Ok(None)
}

/// Add route for interface.
pub fn add_route(ifname: &str, address: &IpAddrMask, table: Option<u32>) -> NetlinkResult<()> {
    let mut message = RouteMessage::default();
    let mut route_msg_header = RouteHeader {
        table: RT_TABLE_MAIN,
        scope: RT_SCOPE_LINK,
        kind: RTN_UNICAST,
        protocol: RTPROT_BOOT,
        ..Default::default()
    };
    let address_vec = match address.ip {
        IpAddr::V4(ipv4) => {
            route_msg_header.address_family = AF_INET as u8;
            route_msg_header.destination_prefix_length = address.cidr;
            ipv4.octets().to_vec()
        }
        IpAddr::V6(ipv6) => {
            route_msg_header.address_family = AF_INET6 as u8;
            route_msg_header.destination_prefix_length = address.cidr;
            ipv6.octets().to_vec()
        }
    };
    message.header = route_msg_header;
    if let Some(interface_index) = get_interface_index(ifname)? {
        message.nlas.push(RouteNla::Oif(interface_index));
        message
            .nlas
            .push(RouteNla::Destination(address_vec.clone()));
        if let Some(table) = table {
            message.nlas.push(RouteNla::Table(table));
        }
        match netlink_request(
            RtnlMessage::NewRoute(message),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            NETLINK_ROUTE,
        ) {
            Ok(_msg) => Ok(()),
            Err(NetlinkError::FileAlreadyExists) => Ok(()),
            Err(err) => {
                error!("Failed to add WireGuard interface route: {err}");
                Err(NetlinkError::AddRouteError)
            }
        }
    } else {
        error!("Failed to add WireGuard interface route interface {ifname} index not found");
        Err(NetlinkError::AddRouteError)
    }
}

/// Add rule for fwmark.
pub fn add_rule(address: &IpAddrMask, fwmark: u32) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let mut rule_msg_hdr = RuleHeader {
        table: RT_TABLE_UNSPEC,
        action: FR_ACT_TO_TBL,
        flags: FIB_RULE_INVERT,
        ..Default::default()
    };
    match address.ip {
        IpAddr::V4(_) => {
            rule_msg_hdr.family = AF_INET as u8;
        }
        IpAddr::V6(_) => {
            rule_msg_hdr.family = AF_INET6 as u8;
        }
    };

    message.header = rule_msg_hdr;
    message.nlas.push(RuleNla::FwMark(fwmark));
    message.nlas.push(RuleNla::Table(fwmark));
    match netlink_request(
        RtnlMessage::NewRule(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    ) {
        Ok(_msg) => Ok(()),
        Err(NetlinkError::FileAlreadyExists) => Ok(()),
        Err(err) => {
            error!("Failed to add fwmark rule: {err}");
            Err(NetlinkError::AddRuleError)
        }
    }
}

/// Delete rule for fwmark.
pub fn delete_rule(ip_version: IpVersion, fwmark: u32) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let mut rule_msg_hdr = RuleHeader {
        table: RT_TABLE_UNSPEC,
        action: FR_ACT_UNSPEC,
        ..Default::default()
    };
    match ip_version {
        IpVersion::IPv4 => {
            rule_msg_hdr.family = AF_INET as u8;
        }
        IpVersion::IPv6 => {
            rule_msg_hdr.family = AF_INET6 as u8;
        }
    };

    message.header = rule_msg_hdr;
    message.nlas.push(RuleNla::FwMark(fwmark));
    message.nlas.push(RuleNla::Table(fwmark));
    match netlink_request(
        RtnlMessage::DelRule(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    ) {
        Ok(_msg) => Ok(()),
        Err(NetlinkError::NotFound) => Ok(()),
        Err(err) => {
            error!("Failed to delete {fwmark} rule: {err}");
            Err(NetlinkError::DeleteRuleError)
        }
    }
}
/// Add rule for main table.
pub fn add_main_table_rule(address: &IpAddrMask, suppress_prefix_len: u32) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let mut rule_msg_hdr = RuleHeader {
        table: RT_TABLE_MAIN,
        action: FR_ACT_TO_TBL,
        flags: FIB_RULE_INVERT,
        ..Default::default()
    };
    match address.ip {
        IpAddr::V4(_) => {
            rule_msg_hdr.family = AF_INET as u8;
        }
        IpAddr::V6(_) => {
            rule_msg_hdr.family = AF_INET6 as u8;
        }
    };

    message.header = rule_msg_hdr;
    message
        .nlas
        .push(RuleNla::SuppressPrefixLen(suppress_prefix_len));
    match netlink_request(
        RtnlMessage::NewRule(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    ) {
        Ok(_msg) => Ok(()),
        Err(NetlinkError::FileAlreadyExists) => Ok(()),
        Err(err) => {
            error!("Failed to add main table rule: {err}");
            Err(NetlinkError::AddRuleError)
        }
    }
}

/// Delete rule for main table.
pub fn delete_main_table_rule(
    ip_version: IpVersion,
    suppress_prefix_len: u32,
) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let mut rule_msg_hdr = RuleHeader {
        table: RT_TABLE_MAIN,
        action: FR_ACT_TO_TBL,
        flags: FIB_RULE_INVERT,
        ..Default::default()
    };
    match ip_version {
        IpVersion::IPv4 => {
            rule_msg_hdr.family = AF_INET as u8;
        }
        IpVersion::IPv6 => {
            rule_msg_hdr.family = AF_INET6 as u8;
        }
    };

    message.header = rule_msg_hdr;
    message
        .nlas
        .push(RuleNla::SuppressPrefixLen(suppress_prefix_len));
    match netlink_request(
        RtnlMessage::DelRule(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    ) {
        Ok(_msg) => Ok(()),
        Err(NetlinkError::NotFound) => Ok(()),
        Err(err) => {
            error!("Failed to delete WireGuard interface rule: {err}");
            Err(NetlinkError::DeleteRuleError)
        }
    }
}
