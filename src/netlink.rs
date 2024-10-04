//! Netlink utilities for controlling network interfaces on Linux
use std::{fmt::Debug, io::ErrorKind, net::IpAddr};

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlFamily, GenlMessage,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{InfoKind, LinkAttribute, LinkFlags, LinkHeader, LinkInfo, LinkMessage},
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
    rule::{RuleAction, RuleAttribute, RuleFlags, RuleHeader, RuleMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_packet_utils::errors::DecodeError;
use netlink_packet_wireguard::{
    constants::WGPEER_F_REMOVE_ME,
    nlas::{WgDeviceAttrs, WgPeer, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_sys::{
    constants::{NETLINK_GENERIC, NETLINK_ROUTE},
    Socket, SocketAddr,
};
use thiserror::Error;

use crate::{
    host::{Host, Peer},
    net::IpAddrMask,
    IpVersion, Key, WireguardInterfaceError,
};

const SOCKET_BUFFER_LENGTH: usize = 12288;

#[derive(Debug, Error)]
pub(crate) enum NetlinkError {
    #[error("Unexpected netlink payload")]
    UnexpectedPayload,
    #[error("Failed to send netlink request")]
    SendFailure,
    #[error("Attribute value not found")]
    AttributeNotFound,
    #[error("Socket error: {0}")]
    SocketError(String),
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
type NetlinkResult<T> = Result<T, NetlinkError>;

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

impl IpAddrMask {
    #[must_use]
    fn address_family(&self) -> AddressFamily {
        match self.ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        }
    }
}

impl IpVersion {
    #[must_use]
    fn address_family(self) -> AddressFamily {
        match self {
            Self::IPv4 => AddressFamily::Inet,
            Self::IPv6 => AddressFamily::Inet6,
        }
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
    protocol: isize,
) -> NetlinkResult<Vec<NetlinkMessage<I>>>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    let mut req = NetlinkMessage::from(message);

    req.header.flags = flags;
    req.finalize();
    let len = req.buffer_len();
    let mut buf = vec![0u8; len];
    req.serialize(&mut buf);

    let socket = Socket::new(protocol).map_err(|err| {
        error!("Failed to open socket: {err}");
        NetlinkError::SocketError(err.to_string())
    })?;
    let kernel_addr = SocketAddr::new(0, 0);
    socket.connect(&kernel_addr).map_err(|err| {
        error!("Failed to connect to socket: {err}");
        NetlinkError::SocketError(err.to_string())
    })?;
    let n_sent = socket.send(&buf, 0).map_err(|err| {
        error!("Failed to send to socket: {err}");
        NetlinkError::SocketError(err.to_string())
    })?;
    if n_sent != len {
        return Err(NetlinkError::SendFailure);
    }

    let mut responses = Vec::new();
    loop {
        let mut recv_buf = [0; SOCKET_BUFFER_LENGTH];
        let n_received = socket.recv(&mut &mut recv_buf[..], 0).map_err(|err| {
            error!("Failed to receive from socket: {err}");
            NetlinkError::SocketError(err.to_string())
        })?;
        let mut offset = 0;
        loop {
            let response = NetlinkMessage::<I>::deserialize(&recv_buf[offset..])?;
            trace!("Read netlink response from socket: {response:?}");
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
pub(crate) fn create_interface(ifname: &str) -> NetlinkResult<()> {
    let mut message = LinkMessage::default();
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;
    message
        .attributes
        .push(LinkAttribute::IfName(ifname.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));

    match netlink_request(
        RouteNetlinkMessage::NewLink(message),
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

/// Set `address` for a network interface with `index`.
fn set_address(index: u32, address: &IpAddrMask) -> NetlinkResult<()> {
    let mut message = AddressMessage::default();

    message.header.prefix_len = address.cidr;
    message.header.index = index;
    message.header.family = address.address_family();

    if address.ip.is_multicast() {
        if let IpAddr::V6(addr) = address.ip {
            message.attributes.push(AddressAttribute::Multicast(addr));
        }
    } else {
        message
            .attributes
            .push(AddressAttribute::Address(address.ip));

        // For IPv4 the Local address can be set to the same value as
        // Address.
        message.attributes.push(AddressAttribute::Local(address.ip));

        // Set the broadcast address as well (IPv6 does not support
        // broadcast).
        if let IpAddr::V4(addr) = address.broadcast() {
            message.attributes.push(AddressAttribute::Broadcast(addr));
        }
    }

    // Note: always try to replace.
    netlink_request(
        RouteNetlinkMessage::NewAddress(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        NETLINK_ROUTE,
    )?;
    Ok(())
}

/// Remove all addresses from a network interface with `index`.
fn flush_addresses(index: u32) -> NetlinkResult<()> {
    let mut message = AddressMessage::default();
    // FIXME: Probably this is ignored; `index` must be matched from received messages.
    message.header.index = index;

    let responses = netlink_request(
        RouteNetlinkMessage::GetAddress(message),
        NLM_F_REQUEST | NLM_F_DUMP,
        NETLINK_ROUTE,
    )?;

    for nlmsg in responses {
        if let NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(message),
            ..
        } = nlmsg
        {
            if let RouteNetlinkMessage::NewAddress(msg) = message {
                if msg.header.index != index {
                    continue;
                }
                netlink_request(
                    RouteNetlinkMessage::DelAddress(msg),
                    NLM_F_REQUEST | NLM_F_ACK,
                    NETLINK_ROUTE,
                )?;
            }
        } else {
            debug!("unknown nlmsg response");
        }
    }

    Ok(())
}

/// Remove IP addresses from a WireGuard network interface.
pub(crate) fn flush_interface(ifname: &str) -> NetlinkResult<()> {
    if let Some(index) = get_interface_index(ifname)? {
        flush_addresses(index)
    } else {
        Ok(())
    }
}

/// Set IP address of a WireGuard network interface.
pub(crate) fn address_interface(ifname: &str, address: &IpAddrMask) -> NetlinkResult<()> {
    if let Some(index) = get_interface_index(ifname)? {
        set_address(index, address)
    } else {
        Ok(())
    }
}

/// Delete WireGuard interface.
pub(crate) fn delete_interface(ifname: &str) -> NetlinkResult<()> {
    let mut message = LinkMessage::default();
    message
        .attributes
        .push(LinkAttribute::IfName(ifname.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));

    netlink_request(
        RouteNetlinkMessage::DelLink(message),
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
pub(crate) fn get_host(ifname: &str) -> NetlinkResult<Host> {
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
pub(crate) fn set_host(ifname: &str, host: &Host) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: host.as_nlas(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    // Add peers one by one to avoid packet buffer overflow.
    for peer in host.peers.values() {
        set_peer(ifname, peer)?;
    }

    Ok(())
}

/// Save or update WireGuard peer configuration
pub(crate) fn set_peer(ifname: &str, peer: &Peer) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: peer.as_nlas(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

/// Delete a WireGuard peer from interface
pub(crate) fn delete_peer(ifname: &str, public_key: &Key) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: public_key.as_nlas_remove(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

/// Get WireGuard interface index by name.
fn get_interface_index(ifname: &str) -> NetlinkResult<Option<u32>> {
    let mut message = LinkMessage::default();
    message
        .attributes
        .push(LinkAttribute::IfName(ifname.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));

    let responses = netlink_request(
        RouteNetlinkMessage::GetLink(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    )?;

    for nlmsg in responses {
        if let NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(message),
            ..
        } = nlmsg
        {
            if let RouteNetlinkMessage::NewLink(LinkMessage {
                header: LinkHeader { index, .. },
                ..
            }) = message
            {
                return Ok(Some(index));
            }
        } else {
            debug!("unknown nlmsg response");
        }
    }

    Ok(None)
}

/// Get default route for a given address family.
pub(crate) fn get_gateway(address_family: AddressFamily) -> NetlinkResult<Option<IpAddr>> {
    let header = RouteHeader {
        address_family,
        table: RouteHeader::RT_TABLE_MAIN,
        // protocol: RouteProtocol::Boot, // doesn't filter
        // scope: RouteScope::Universe,   // doesn't filter
        ..Default::default()
    };
    let mut message = RouteMessage::default();
    message.header = header;
    let responses = netlink_request(
        RouteNetlinkMessage::GetRoute(message),
        NLM_F_REQUEST | NLM_F_DUMP,
        NETLINK_ROUTE,
    )?;

    for nlmsg in responses {
        if let NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(message),
            ..
        } = nlmsg
        {
            // Because messages can't be properly filtered, find the first `Gateway`.
            if let RouteNetlinkMessage::NewRoute(RouteMessage { attributes, .. }) = message {
                for nla in attributes {
                    match nla {
                        RouteAttribute::Gateway(address) => {
                            debug!("Found gateway {address:?}");
                            match address {
                                RouteAddress::Inet(ipv4) => return Ok(Some(IpAddr::V4(ipv4))),
                                RouteAddress::Inet6(ipv6) => return Ok(Some(IpAddr::V6(ipv6))),
                                _ => (),
                            }
                        }
                        _ => (),
                    }
                }
            }
        } else {
            debug!("unknown nlmsg response")
        }
    }

    Ok(None)
}

/// Add a route for an interface.
pub(crate) fn add_route(
    ifname: &str,
    address: &IpAddrMask,
    table: Option<u32>,
) -> NetlinkResult<()> {
    let mut message = RouteMessage::default();
    let mut header = RouteHeader {
        table: RouteHeader::RT_TABLE_MAIN,
        scope: RouteScope::Link,
        kind: RouteType::Unicast,
        protocol: RouteProtocol::Boot,
        ..Default::default()
    };
    header.address_family = address.address_family();
    header.destination_prefix_length = address.cidr;
    let route_address = match address.ip {
        IpAddr::V4(ipv4) => RouteAddress::Inet(ipv4),
        IpAddr::V6(ipv6) => RouteAddress::Inet6(ipv6),
    };
    message.header = header;
    if let Some(interface_index) = get_interface_index(ifname)? {
        message
            .attributes
            .push(RouteAttribute::Oif(interface_index));
        message
            .attributes
            .push(RouteAttribute::Destination(route_address));
        if let Some(table) = table {
            message.attributes.push(RouteAttribute::Table(table));
        }
        match netlink_request(
            RouteNetlinkMessage::NewRoute(message),
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
pub(crate) fn add_fwmark_rule(address: &IpAddrMask, fwmark: u32) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let rule_msg_hdr = RuleHeader {
        family: address.address_family(),
        table: RouteHeader::RT_TABLE_UNSPEC,
        action: RuleAction::ToTable,
        flags: RuleFlags::Invert,
        ..Default::default()
    };

    message.header = rule_msg_hdr;
    message.attributes.push(RuleAttribute::FwMark(fwmark));
    message.attributes.push(RuleAttribute::Table(fwmark));
    match netlink_request(
        RouteNetlinkMessage::NewRule(message),
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
pub(crate) fn delete_rule(ip_version: IpVersion, fwmark: u32) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let rule_msg_hdr = RuleHeader {
        table: RouteHeader::RT_TABLE_UNSPEC,
        action: RuleAction::Unspec,
        family: ip_version.address_family(),
        ..Default::default()
    };

    message.header = rule_msg_hdr;
    message.attributes.push(RuleAttribute::FwMark(fwmark));
    message.attributes.push(RuleAttribute::Table(fwmark));
    match netlink_request(
        RouteNetlinkMessage::DelRule(message),
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
pub(crate) fn add_main_table_rule(
    address: &IpAddrMask,
    suppress_prefix_len: u32,
) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let rule_msg_hdr = RuleHeader {
        family: address.address_family(),
        table: RouteHeader::RT_TABLE_MAIN,
        action: RuleAction::ToTable,
        ..Default::default()
    };

    message.header = rule_msg_hdr;
    message
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(suppress_prefix_len));
    match netlink_request(
        RouteNetlinkMessage::NewRule(message),
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
pub(crate) fn delete_main_table_rule(
    ip_version: IpVersion,
    suppress_prefix_len: u32,
) -> NetlinkResult<()> {
    let mut message = RuleMessage::default();
    let rule_msg_hdr = RuleHeader {
        table: RouteHeader::RT_TABLE_MAIN,
        action: RuleAction::ToTable,
        flags: RuleFlags::Invert,
        family: ip_version.address_family(),
        ..Default::default()
    };

    message.header = rule_msg_hdr;
    message
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(suppress_prefix_len));
    match netlink_request(
        RouteNetlinkMessage::DelRule(message),
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

pub(crate) fn set_mtu(if_name: &str, mtu: u32) -> NetlinkResult<()> {
    if let Some(index) = get_interface_index(if_name)? {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.attributes.push(LinkAttribute::Mtu(mtu));

        netlink_request(
            RouteNetlinkMessage::SetLink(message),
            NLM_F_REQUEST | NLM_F_ACK,
            NETLINK_ROUTE,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Get IP addresses for an interface.
    fn get_address(index: u32) -> NetlinkResult<Vec<IpAddrMask>> {
        let mut message = AddressMessage::default();
        message.header.index = index;

        let responses = netlink_request(
            RouteNetlinkMessage::GetAddress(message),
            NLM_F_REQUEST | NLM_F_DUMP,
            NETLINK_ROUTE,
        )?;

        let mut addresses = Vec::new();
        for nlmsg in responses {
            if let NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(message),
                ..
            } = nlmsg
            {
                if let RouteNetlinkMessage::NewAddress(AddressMessage {
                    header, attributes, ..
                }) = message
                {
                    if header.index != index {
                        continue;
                    }
                    let mut address = None;
                    let mut broadcast = None;
                    for nla in attributes {
                        match nla {
                            AddressAttribute::Address(addr) => address = Some(addr),
                            AddressAttribute::Local(_) => {
                                // ignore, should be the same as Address
                            }
                            // | AddressAttribute::Multicast(addr)
                            // | AddressAttribute::Anycast(addr) => address = Some(addr),
                            AddressAttribute::Broadcast(addr) => broadcast = Some(addr),
                            _ => (),
                        }
                    }
                    if let Some(addr) = address {
                        match addr {
                            IpAddr::V4(ipv4) => {
                                let cidr = if let Some(br) = broadcast {
                                    (u32::from(ipv4) ^ u32::from(br)).leading_zeros() as u8
                                } else {
                                    32
                                };
                                addresses.push(IpAddrMask::new(addr, cidr));
                            }
                            IpAddr::V6(_) => {
                                // FIXME: where to get CIDR from?
                                addresses.push(IpAddrMask::new(addr, 128));
                            }
                        }
                    }
                }
            } else {
                debug!("unknown nlmsg response")
            }
        }

        Ok(addresses)
    }

    fn get_mtu(index: u32) -> NetlinkResult<u32> {
        let mut message = LinkMessage::default();
        message.header.index = index;

        let responses = netlink_request(
            RouteNetlinkMessage::GetLink(message),
            NLM_F_REQUEST | NLM_F_ACK,
            NETLINK_ROUTE,
        )?;

        for nlmsg in responses {
            if let NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(message),
                ..
            } = nlmsg
            {
                if let RouteNetlinkMessage::NewLink(LinkMessage { attributes, .. }) = message {
                    for nla in attributes {
                        if let LinkAttribute::Mtu(mtu) = nla {
                            return Ok(mtu);
                        }
                    }
                }
            } else {
                debug!("unknown nlmsg response")
            }
        }

        Err(NetlinkError::AttributeNotFound)
    }

    #[ignore]
    #[test]
    fn docker_networking() {
        const IF_NAME: &str = "wg0";

        create_interface(IF_NAME).unwrap();

        let index = get_interface_index(IF_NAME).unwrap().unwrap();

        let ip = "fe80::20c:29ff:fe1a:adac/96".parse::<IpAddrMask>().unwrap();
        set_address(index, &ip).unwrap();
        let ip = "192.168.11.38/24".parse::<IpAddrMask>().unwrap();
        set_address(index, &ip).unwrap();

        set_mtu(IF_NAME, 1400).unwrap();

        let addrs = get_address(index).unwrap();
        assert_eq!(addrs.len(), 2);

        let mtu = get_mtu(index).unwrap();
        assert_eq!(mtu, 1400);

        flush_addresses(index).unwrap();
        let addrs = get_address(index).unwrap();
        assert_eq!(addrs.len(), 0);

        delete_interface(IF_NAME).unwrap();
    }

    #[ignore]
    #[test]
    fn docker_peers() {
        use x25519_dalek::{EphemeralSecret, PublicKey};

        const MAX_PEERS: usize = 1600;

        let secret = EphemeralSecret::random();
        let key = PublicKey::from(&secret);
        // Peer secret key
        let key: Key = key.as_ref().try_into().unwrap();
        let mut host = Host::new(1234, key);

        for _ in 0..MAX_PEERS {
            let secret = EphemeralSecret::random();
            let key = PublicKey::from(&secret);
            let key: Key = key.as_ref().try_into().unwrap();
            let peer = Peer::new(key.clone());
            host.peers.insert(key, peer);
        }

        const IF_NAME: &str = "wg0";
        create_interface(IF_NAME).unwrap();
        set_host(IF_NAME, &host).unwrap();

        let host = get_host(IF_NAME).unwrap();
        assert_eq!(host.peers.len(), MAX_PEERS);

        // With many peers, this takes a long time.
        delete_interface(IF_NAME).unwrap();
    }

    #[ignore]
    #[test]
    fn docker_gateway() {
        let gateway = get_gateway(AddressFamily::Inet).unwrap();
        assert!(gateway.is_some());
    }
}
