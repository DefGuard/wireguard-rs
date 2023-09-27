use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr},
};

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
    AddressMessage, LinkHeader, LinkMessage, RtnlMessage, AF_INET, AF_INET6, IFF_UP,
};
use netlink_packet_utils::errors::DecodeError;
use netlink_packet_wireguard::{
    constants::WGPEER_F_REMOVE_ME,
    nlas::{WgDeviceAttrs, WgPeer, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_sys::{constants::NETLINK_GENERIC, protocols::NETLINK_ROUTE, Socket, SocketAddr};
use thiserror::Error;

use crate::{
    host::{Host, Peer},
    net::IpAddrMask,
    Key,
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
}

pub type NetlinkResult<T> = Result<T, NetlinkError>;

macro_rules! get_nla_value {
    ($nlas:expr, $e:ident, $v:ident) => {
        $nlas.iter().find_map(|attr| match attr {
            $e::$v(value) => Some(value),
            _ => None,
        })
    };
}

pub fn netlink_request_genl<F>(
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

        match responses.get(0) {
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

pub fn netlink_request<I>(
    message: I,
    flags: u16,
    socket: isize,
) -> NetlinkResult<Vec<NetlinkMessage<I>>>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    debug!("Sending Netlink request: {message:?}, flags: {flags}, socket: {socket}",);
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
                NetlinkPayload::Error(msg) => return Err(NetlinkError::PayloadError(msg)),
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

    netlink_request(
        RtnlMessage::NewLink(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    )
    .map_err(|err| {
        error!("Failed to create WireGuard interface: {err}");
        NetlinkError::CreateInterfaceError
    })?;
    Ok(())
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

pub fn address_interface(ifname: &str, address: &IpAddrMask) -> NetlinkResult<()> {
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
                    return set_address(index, address);
                }
            }
            _ => debug!("unknown nlmsg response"),
        }
    }

    Ok(())
}

/// Delete WireGuard interface.
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

pub fn set_host(ifname: &str, host: &Host) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: host.as_nlas(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

pub fn set_peer(ifname: &str, peer: &Peer) -> NetlinkResult<()> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: peer.as_nlas(ifname),
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

pub fn delete_peer(ifname: &str, public_key: &Key) -> NetlinkResult<()> {
    let nlas_remove = vec![
        WgDeviceAttrs::IfName(ifname.into()),
        WgDeviceAttrs::Peers(vec![WgPeer(vec![
            WgPeerAttrs::PublicKey(public_key.as_array()),
            WgPeerAttrs::Flags(WGPEER_F_REMOVE_ME),
        ])]),
    ];
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: nlas_remove,
    });
    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}
