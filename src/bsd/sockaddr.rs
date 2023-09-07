//! Convert binary `sockaddr_in` or `sockaddr_in6` (see netinet/in.h) to `SocketAddr`.
use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use super::{cast_bytes, cast_ref};

const AF_INET: u8 = 2; // IPv4
const AF_INET6: u8 = 30; // IPv6
const SA_IN_SIZE: usize = size_of::<SockAddrIn>();
const SA_IN6_SIZE: usize = size_of::<SockAddrIn6>();

// netinet/in.h
#[repr(C)]
struct SockAddrIn {
    len: u8,
    family: u8,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

impl From<&SockAddrIn> for SocketAddr {
    fn from(sa: &SockAddrIn) -> Self {
        Self::V4(SocketAddrV4::new(
            Ipv4Addr::from(sa.addr),
            u16::from_be(sa.port),
        ))
    }
}

impl From<&SocketAddrV4> for SockAddrIn {
    fn from(sa: &SocketAddrV4) -> Self {
        Self {
            len: SA_IN_SIZE as u8,
            family: AF_INET,
            port: sa.port().to_be(),
            addr: sa.ip().octets(),
            zero: [0u8; 8],
        }
    }
}

// netinet6/in6.h
#[repr(C)]
struct SockAddrIn6 {
    len: u8,
    family: u8,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

impl From<&SockAddrIn6> for SocketAddr {
    fn from(sa: &SockAddrIn6) -> Self {
        Self::V6(SocketAddrV6::new(
            Ipv6Addr::from(sa.addr),
            u16::from_be(sa.port),
            u32::from_be(sa.flowinfo),
            u32::from_be(sa.scope_id),
        ))
    }
}

impl From<&SocketAddrV6> for SockAddrIn6 {
    fn from(sa: &SocketAddrV6) -> Self {
        Self {
            len: SA_IN6_SIZE as u8,
            family: AF_INET6,
            port: sa.port().to_be(),
            flowinfo: sa.flowinfo().to_be(),
            addr: sa.ip().octets(),
            scope_id: sa.scope_id().to_be(),
        }
    }
}

pub(super) fn pack_sockaddr(sockaddr: &SocketAddr) -> Vec<u8> {
    match sockaddr {
        SocketAddr::V4(sockaddr_v4) => {
            let sockaddr_in: SockAddrIn = sockaddr_v4.into();
            let bytes = unsafe { cast_bytes(&sockaddr_in) };
            Vec::from(bytes)
        }
        SocketAddr::V6(sockaddr_v6) => {
            let sockaddr_in6: SockAddrIn6 = sockaddr_v6.into();
            let bytes = unsafe { cast_bytes(&sockaddr_in6) };
            Vec::from(bytes)
        }
    }
}

pub(super) fn unpack_sockaddr(buf: &[u8]) -> Option<SocketAddr> {
    match buf.len() {
        SA_IN_SIZE => {
            let sockaddr_in = unsafe { cast_ref::<SockAddrIn>(buf) };
            // sanity checks
            if sockaddr_in.len == SA_IN_SIZE as u8 && sockaddr_in.family == AF_INET {
                Some(sockaddr_in.into())
            } else {
                None
            }
        }

        SA_IN6_SIZE => {
            let sockaddr_in6 = unsafe { cast_ref::<SockAddrIn6>(buf) };
            // sanity checks
            if sockaddr_in6.len == SA_IN6_SIZE as u8 && sockaddr_in6.family == AF_INET6 {
                Some(sockaddr_in6.into())
            } else {
                None
            }
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn ip4() {
        let buf = [16, 2, 28, 133, 192, 168, 12, 34, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = unpack_sockaddr(&buf).unwrap();
        assert_eq!(addr.port(), 7301);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 12, 34)));
    }

    #[test]
    fn ip6() {
        let buf = [
            28, 30, 28, 133, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 12, 34,
            0, 0, 0, 0,
        ];
        let addr = unpack_sockaddr(&buf).unwrap();
        assert_eq!(addr.port(), 7301);
        assert_eq!(
            addr.ip(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0c22))
        );
    }
}
