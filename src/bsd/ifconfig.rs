use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
};

use libc::{AF_INET, AF_INET6, AF_UNIX, IF_NAMESIZE, IFF_UP, c_ulong, ioctl};

use super::{
    IoError, c_int_to_error, create_socket,
    ioctl::{iow, iowr},
    sockaddr::{SockAddrIn, SockAddrIn6},
};

// From `netinet6/in6.h`.
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;

// From `sys/sockio.h`.
const SIOCIFDESTROY: c_ulong = iow::<IfReq>(b'i', 121);

// Note: SIOCIFCREATE on NetBSD should work as SIOCIFCREATE2 on FreeBSD.
#[cfg(target_os = "netbsd")]
const SIOCIFCREATE: c_ulong = iowr::<IfReq>(b'i', 122);

// SIOCIFCREATE2 works as SIOCIFCREATE, but let the caller speficy the interface name.
#[cfg(target_os = "freebsd")]
const SIOCIFCREATE2: c_ulong = iowr::<IfReq>(b'i', 124);
#[cfg(target_os = "macos")]
const SIOCIFCREATE2: c_ulong = iowr::<IfReq>(b'i', 124);

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
const SIOCGIFMTU: c_ulong = iowr::<IfMtu>(b'i', 51);
#[cfg(target_os = "netbsd")]
const SIOCGIFMTU: c_ulong = iowr::<IfMtu>(b'i', 126);

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
const SIOCSIFMTU: c_ulong = iow::<IfMtu>(b'i', 52);
#[cfg(target_os = "netbsd")]
const SIOCSIFMTU: c_ulong = iow::<IfMtu>(b'i', 127);

const SIOCSIFADDR: c_ulong = iow::<IfReq>(b'i', 12);

#[cfg(target_os = "freebsd")]
const SIOCAIFADDR: c_ulong = iow::<InAliasReq>(b'i', 43);
#[cfg(any(target_os = "macos", target_os = "netbsd"))]
const SIOCAIFADDR: c_ulong = iow::<InAliasReq>(b'i', 26);

const SIOCDIFADDR: c_ulong = iow::<IfReq>(b'i', 25);
const SIOCSIFADDR_IN6: c_ulong = iow::<IfReq6>(b'i', 12);

#[cfg(target_os = "freebsd")]
const SIOCAIFADDR_IN6: c_ulong = iow::<In6AliasReq>(b'i', 27);
#[cfg(target_os = "macos")]
const SIOCAIFADDR_IN6: c_ulong = iow::<In6AliasReq>(b'i', 26);
#[cfg(target_os = "netbsd")]
const SIOCAIFADDR_IN6: c_ulong = iow::<In6AliasReq>(b'i', 107);

const SIOCDIFADDR_IN6: c_ulong = iow::<IfReq6>(b'i', 25);
const SIOCSIFFLAGS: c_ulong = iow::<IfReqFlags>(b'i', 16);
const SIOCGIFFLAGS: c_ulong = iowr::<IfReqFlags>(b'i', 17);

type IfName = [u8; IF_NAMESIZE];

fn make_ifr_name(if_name: &str) -> IfName {
    let mut ifr_name = [0; IF_NAMESIZE];
    let len = if_name.len().min(IF_NAMESIZE - 1);
    ifr_name[..len].copy_from_slice(&if_name.as_bytes()[..len]);
    ifr_name
}

/// Represent `struct ifreq` as defined in `net/if.h`.
#[repr(C)]
pub struct IfReq {
    ifr_name: IfName,
    ifr_ifru: SockAddrIn,
}

impl IfReq {
    #[must_use]
    pub(super) fn new_with_address(if_name: &str, address: Ipv4Addr) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifr_ifru: address.into(),
        }
    }

    #[must_use]
    pub(super) fn new(if_name: &str) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifr_ifru: SockAddrIn::default(),
        }
    }

    pub(super) fn create(&mut self) -> Result<(), IoError> {
        let socket = create_socket(AF_UNIX)?;
        #[cfg(target_os = "netbsd")]
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCIFCREATE, &*self) };
        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCIFCREATE2, &*self) };
        c_int_to_error(result)?;

        Ok(())
    }

    pub(super) fn destroy(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_UNIX)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCIFDESTROY, self) };
        c_int_to_error(result)?;

        Ok(())
    }

    pub(super) fn set_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_INET)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCSIFADDR, self) };
        c_int_to_error(result)?;

        Ok(())
    }

    pub(super) fn delete_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_INET)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCDIFADDR, self) };
        c_int_to_error(result)?;

        Ok(())
    }
}

/// Represent `struct ifreq` as defined in `net/if.h` - ifr_mtu variant.
#[derive(Debug)]
#[repr(C)]
pub struct IfMtu {
    ifr_name: IfName,
    ifru_mtu: u32,
    _padding: [u8; 12],
}

impl IfMtu {
    #[must_use]
    pub(super) fn new(if_name: &str) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifru_mtu: 0,
            _padding: [0u8; 12],
        }
    }

    pub(super) fn get_mtu(&mut self) -> Result<u32, IoError> {
        let socket = create_socket(AF_UNIX)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCGIFMTU, &*self) };
        c_int_to_error(result)?;

        Ok(self.ifru_mtu)
    }

    pub(super) fn set_mtu(&mut self, mtu: u32) -> Result<(), IoError> {
        self.ifru_mtu = mtu;
        let socket = create_socket(AF_UNIX)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCSIFMTU, &*self) };
        c_int_to_error(result)?;

        Ok(())
    }
}

/// Represent `struct in6_ifreq` as defined in `netinet6/in6_var.h`.
#[repr(C)]
pub struct IfReq6 {
    ifr_name: IfName,
    ifr_ifru: SockAddrIn6,
    _padding: [u8; 244],
}

impl IfReq6 {
    #[must_use]
    pub(super) fn new_with_address(if_name: &str, address: Ipv6Addr) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifr_ifru: address.into(),
            _padding: [0u8; 244],
        }
    }

    pub(super) fn set_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_INET6)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCSIFADDR_IN6, self) };
        c_int_to_error(result)?;

        Ok(())
    }

    pub(super) fn delete_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_INET6)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCDIFADDR_IN6, self) };
        c_int_to_error(result)?;

        Ok(())
    }
}

/// Respresent `in_aliasreq` as defined in <netinet/in_var.h>.
#[repr(C)]
pub struct InAliasReq {
    ifr_name: IfName,
    ifra_addr: SockAddrIn,
    ifra_broadaddr: SockAddrIn,
    ifra_mask: SockAddrIn,
    #[cfg(target_os = "freebsd")]
    ifra_vhid: u32,
}

impl InAliasReq {
    #[must_use]
    pub(super) fn new(
        if_name: &str,
        address: Ipv4Addr,
        broadcast: Ipv4Addr,
        mask: Ipv4Addr,
    ) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifra_addr: address.into(),
            ifra_broadaddr: broadcast.into(),
            ifra_mask: mask.into(),
            #[cfg(target_os = "freebsd")]
            ifra_vhid: 0,
        }
    }

    pub(super) fn add_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_INET)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCAIFADDR, self) };
        c_int_to_error(result)?;

        Ok(())
    }
}

/// Respresent `in6_aliasreq` as defined in <netinet/in6_var.h>.
#[repr(C)]
pub struct In6AliasReq {
    ifr_name: IfName,
    ifra_addr: SockAddrIn6,
    ifra_dstaddr: SockAddrIn6,
    ifra_prefixmask: SockAddrIn6,
    ifra_flags: u32,
    // ifra_lifetime:
    ia6t_expire: u64,
    ia6t_preferred: u64,
    ia6t_vltime: u32,
    ia6t_pltime: u32,
    #[cfg(target_os = "freebsd")]
    ifra_vhid: u32,
}

impl In6AliasReq {
    #[must_use]
    pub(super) fn new(
        if_name: &str,
        address: Ipv6Addr,
        // FIXME: currenlty unused: dstaddr: Ipv6Addr,
        prefixmask: Ipv6Addr,
    ) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifra_addr: address.into(),
            ifra_dstaddr: SockAddrIn6::zeroed(),
            ifra_prefixmask: prefixmask.into(),
            ifra_flags: 0,
            ia6t_expire: 0,
            ia6t_preferred: 0,
            ia6t_vltime: ND6_INFINITE_LIFETIME,
            ia6t_pltime: ND6_INFINITE_LIFETIME,
            #[cfg(target_os = "freebsd")]
            ifra_vhid: 0,
        }
    }

    pub(super) fn add_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AF_INET6)?;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCAIFADDR_IN6, self) };
        c_int_to_error(result)?;

        Ok(())
    }
}

/// Represent `struct ifreq` as defined in `net/if.h`.
#[repr(C)]
pub struct IfReqFlags {
    ifr_name: IfName,
    ifr_flags: u64,
    ifr_zero: u64, // fill in for size of SockAddrIn
}

impl IfReqFlags {
    #[must_use]
    pub(super) fn new(if_name: &str) -> Self {
        Self {
            ifr_name: make_ifr_name(if_name),
            ifr_flags: 0,
            ifr_zero: 0,
        }
    }

    pub(super) fn up(&mut self) -> Result<(), IoError> {
        let socket = create_socket(AF_UNIX)?;

        // Get current interface flags.
        let _result = unsafe { ioctl(socket.as_raw_fd(), SIOCGIFFLAGS, &*self) };

        // Set interface up flag.
        self.ifr_flags |= IFF_UP as u64;
        let result = unsafe { ioctl(socket.as_raw_fd(), SIOCSIFFLAGS, &*self) };
        c_int_to_error(result)?;

        Ok(())
    }
}
