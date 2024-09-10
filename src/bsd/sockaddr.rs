//! Convert binary `sockaddr_in` or `sockaddr_in6` (see netinet/in.h) to `SocketAddr`.
use std::{
    mem::{size_of, zeroed},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ptr::{copy, from_mut},
};

use super::{cast_bytes, cast_ref};

// Note: these values differ across different platforms.
const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;
const AF_LINK: u8 = libc::AF_LINK as u8;
const SA_IN_SIZE: u8 = size_of::<SockAddrIn>() as u8;
const SA_IN6_SIZE: u8 = size_of::<SockAddrIn6>() as u8;

pub(super) trait SocketFromRaw {
    unsafe fn from_raw(addr: *const libc::sockaddr) -> Option<Self>
    where
        Self: Sized;
}

/// `struct sockaddr_in` from `netinet/in.h`
#[repr(C)]
pub(super) struct SockAddrIn {
    len: u8,
    family: u8,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

impl SocketFromRaw for SockAddrIn {
    /// Construct `SockAddrIn` from `libc::sockaddr`.
    unsafe fn from_raw(addr: *const libc::sockaddr) -> Option<Self> {
        if addr.is_null() || (*addr).sa_family != AF_INET {
            None
        } else {
            let mut sockaddr: Self = zeroed();
            copy(
                addr.cast::<u8>(),
                from_mut::<Self>(&mut sockaddr).cast::<u8>(),
                (*addr).sa_len as usize,
            );
            Some(sockaddr)
        }
    }
}

impl Default for SockAddrIn {
    fn default() -> Self {
        Self {
            len: SA_IN_SIZE,
            family: AF_INET,
            port: 0,
            addr: [0u8; 4],
            zero: [0u8; 8],
        }
    }
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
            len: SA_IN_SIZE,
            family: AF_INET,
            port: sa.port().to_be(),
            addr: sa.ip().octets(),
            zero: [0u8; 8],
        }
    }
}

impl From<Ipv4Addr> for SockAddrIn {
    fn from(ip: Ipv4Addr) -> Self {
        Self {
            len: SA_IN_SIZE,
            family: AF_INET,
            port: 0,
            addr: ip.octets(),
            zero: [0u8; 8],
        }
    }
}

/// `struct sockaddr_in6` from `netinet6/in6.h`
#[repr(C)]
pub(super) struct SockAddrIn6 {
    len: u8,
    family: u8,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

impl SockAddrIn6 {
    /// This is needed for assigning IPv6 address to a network interface.
    /// Note, `len` and `family` fields are zero.
    #[must_use]
    pub(super) fn zeroed() -> Self {
        Self {
            len: 0,
            family: 0,
            port: 0,
            flowinfo: 0,
            addr: [0u8; 16],
            scope_id: 0,
        }
    }
}

impl SocketFromRaw for SockAddrIn6 {
    /// Construct `SockAddrIn6` from `libc::sockaddr`.
    unsafe fn from_raw(addr: *const libc::sockaddr) -> Option<Self> {
        if addr.is_null() || (*addr).sa_family != AF_INET6 {
            None
        } else {
            let mut sockaddr: Self = zeroed();
            copy(
                addr.cast::<u8>(),
                from_mut::<Self>(&mut sockaddr).cast::<u8>(),
                (*addr).sa_len as usize,
            );
            Some(sockaddr)
        }
    }
}

impl Default for SockAddrIn6 {
    fn default() -> Self {
        Self {
            len: SA_IN6_SIZE,
            family: AF_INET6,
            port: 0,
            flowinfo: 0,
            addr: [0u8; 16],
            scope_id: 0,
        }
    }
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
            len: SA_IN6_SIZE,
            family: AF_INET6,
            port: sa.port().to_be(),
            flowinfo: sa.flowinfo().to_be(),
            addr: sa.ip().octets(),
            scope_id: sa.scope_id().to_be(),
        }
    }
}

impl From<Ipv6Addr> for SockAddrIn6 {
    fn from(ip: Ipv6Addr) -> Self {
        Self {
            len: SA_IN6_SIZE,
            family: AF_INET6,
            port: 0,
            flowinfo: 0,
            addr: ip.octets(),
            scope_id: 0,
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
    match buf.first() {
        Some(&SA_IN_SIZE) => {
            let sockaddr_in = unsafe { cast_ref::<SockAddrIn>(buf) };
            // sanity checks
            if sockaddr_in.family == AF_INET {
                Some(sockaddr_in.into())
            } else {
                None
            }
        }
        Some(&SA_IN6_SIZE) => {
            let sockaddr_in6 = unsafe { cast_ref::<SockAddrIn6>(buf) };
            // sanity checks
            if sockaddr_in6.family == AF_INET6 {
                Some(sockaddr_in6.into())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `struct sockaddr_dl` from `net/if_dl.h`
#[derive(Clone)]
#[repr(C)]
pub(super) struct SockAddrDl {
    len: u8,
    family: u8,
    index: u16,
    r#type: u8,
    nlen: u8,
    alen: u8,
    slen: u8,
    data: [u8; 12],
}

impl SockAddrDl {
    #[must_use]
    pub(super) fn new(index: u16) -> Self {
        Self {
            len: size_of::<Self>() as u8,
            family: AF_LINK,
            index,
            r#type: 0,
            nlen: 0,
            alen: 0,
            slen: 0,
            data: [0u8; 12],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn pack_ip4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 12, 34)), 7301);
        let buf = pack_sockaddr(&addr);
        assert_eq!(
            buf,
            [16, 2, 28, 133, 192, 168, 12, 34, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn unpack_ip4() {
        let buf = [16, 2, 28, 133, 192, 168, 12, 34, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = unpack_sockaddr(&buf).unwrap();
        assert_eq!(addr.port(), 7301);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 12, 34)));
    }

    #[test]
    fn pack_ip6() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0c22)),
            7301,
        );
        let buf = pack_sockaddr(&addr);
        assert_eq!(
            buf,
            [
                28, AF_INET6, 28, 133, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192,
                168, 12, 34, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn unpack_ip6() {
        let buf = [
            28, AF_INET6, 28, 133, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168,
            12, 34, 0, 0, 0, 0,
        ];
        let addr = unpack_sockaddr(&buf).unwrap();
        assert_eq!(addr.port(), 7301);
        assert_eq!(
            addr.ip(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0c22))
        );
    }
}
