use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
};

use libc::{IFF_UP, IF_NAMESIZE};
use nix::{ioctl_readwrite, ioctl_write_ptr, sys::socket::AddressFamily};

use super::{
    create_socket,
    sockaddr::{SockAddrIn, SockAddrIn6},
    IoError,
};

// From `netinet6/in6.h`.
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;

// SIOCIFDESTROY
ioctl_write_ptr!(destroy_clone_if, b'i', 121, IfReq);

// SIOCIFCREATE2
// FIXME: not on NetBSD
ioctl_readwrite!(create_clone_if, b'i', 124, IfReq);

// SIOCGIFMTU
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
ioctl_readwrite!(get_if_mtu, b'i', 51, IfMtu);
#[cfg(target_os = "netbsd")]
ioctl_readwrite!(get_if_mtu, b'i', 126, IfMtu);

// SIOCSIFMTU
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
ioctl_write_ptr!(set_if_mtu, b'i', 52, IfMtu);
#[cfg(target_os = "netbsd")]
ioctl_write_ptr!(set_if_mtu, b'i', 127, IfMtu);

// SIOCSIFADDR
ioctl_write_ptr!(set_addr_if, b'i', 12, IfReq);

// SIOCAIFADDR
#[cfg(target_os = "freebsd")]
ioctl_write_ptr!(add_addr_if, b'i', 43, InAliasReq);
#[cfg(any(target_os = "macos", target_os = "netbsd"))]
ioctl_write_ptr!(add_addr_if, b'i', 26, InAliasReq);

// SIOCDIFADDR
ioctl_write_ptr!(del_addr_if, b'i', 25, IfReq);

// SIOCSIFADDR_IN6
ioctl_write_ptr!(set_addr_if_in6, b'i', 12, IfReq6);

// SIOCAIFADDR_IN6
#[cfg(target_os = "freebsd")]
ioctl_write_ptr!(add_addr_if_in6, b'i', 27, In6AliasReq);
#[cfg(target_os = "macos")]
ioctl_write_ptr!(add_addr_if_in6, b'i', 26, In6AliasReq);
#[cfg(target_os = "netbsd")]
ioctl_write_ptr!(add_addr_if_in6, b'i', 107, In6AliasReq);

// SIOCDIFADDR_IN6
ioctl_write_ptr!(del_addr_if_in6, b'i', 25, IfReq6);

// SIOCSIFFLAGS
ioctl_write_ptr!(set_if_flags, b'i', 16, IfReqFlags);

// SIOCGIFFLAGS
ioctl_readwrite!(get_if_flags, b'i', 17, IfReqFlags);

type IfName = [u8; IF_NAMESIZE];

fn make_ifr_name(if_name: &str) -> IfName {
    let mut ifr_name = [0u8; IF_NAMESIZE];
    if_name
        .bytes()
        .take(IF_NAMESIZE - 1)
        .enumerate()
        .for_each(|(i, b)| ifr_name[i] = b);
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
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::WriteIo)?;

        unsafe {
            create_clone_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }

    pub(super) fn destroy(&self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::WriteIo)?;

        unsafe {
            destroy_clone_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }

    pub(super) fn set_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Inet).map_err(IoError::WriteIo)?;
        unsafe {
            set_addr_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }

    pub(super) fn delete_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Inet).map_err(IoError::WriteIo)?;
        unsafe {
            del_addr_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }
}

/// Represent `struct ifreq` as defined in `net/if.h` - ifr_mtu variant.
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
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::WriteIo)?;

        unsafe {
            get_if_mtu(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(self.ifru_mtu)
    }

    pub(super) fn set_mtu(&mut self, mtu: u32) -> Result<(), IoError> {
        self.ifru_mtu = mtu;
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::WriteIo)?;

        unsafe {
            set_if_mtu(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

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

    // #[must_use]
    // pub(super) fn new(if_name: &str) -> Self {
    //     Self {
    //         ifr_name: make_ifr_name(if_name),
    //         ifr_ifru: SockAddrIn6::default(),
    //         _padding: [0u8; 244],
    //     }
    // }

    pub(super) fn set_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Inet6).map_err(IoError::WriteIo)?;

        unsafe {
            set_addr_if_in6(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }

    pub(super) fn delete_address(&self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Inet6).map_err(IoError::WriteIo)?;
        unsafe {
            del_addr_if_in6(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

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
        let socket = create_socket(AddressFamily::Inet).map_err(IoError::WriteIo)?;

        unsafe {
            add_addr_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

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
        let socket = create_socket(AddressFamily::Inet6).map_err(IoError::WriteIo)?;

        unsafe {
            add_addr_if_in6(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

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
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::WriteIo)?;

        // Get current interface flags.
        unsafe {
            get_if_flags(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        // Set interface up flag.
        self.ifr_flags |= IFF_UP as u64;
        unsafe {
            set_if_flags(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }
}
