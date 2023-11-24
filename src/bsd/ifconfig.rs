use std::os::fd::AsRawFd;

use libc::kld_load;
use nix::{ioctl_readwrite, ioctl_write_ptr};

use super::{create_socket, IoError};

// SIOCIFDESTROY
ioctl_write_ptr!(destroy_clone_if, b'i', 121, IfReq);
// SIOCIFCREATE2
ioctl_readwrite!(create_clone_if, b'i', 124, IfReq);

/// Represent `struct ifreq` as defined in <net/if.h>.
#[repr(C)]
pub struct IfReq {
    ifr_name: [u8; 16],
    ifr_ifru: [u8; 16],
}

impl IfReq {
    #[must_use]
    pub fn new(if_name: &str) -> Self {
        let mut ifr_name = [0u8; 16];
        if_name
            .bytes()
            .take(15)
            .enumerate()
            .for_each(|(i, b)| ifr_name[i] = b);
        Self {
            ifr_name,
            ifr_ifru: [0u8; 16],
        }
    }

    pub(super) fn create(&mut self) -> Result<(), IoError> {
        let socket = create_socket().map_err(IoError::WriteIo)?;

        unsafe {
            // First, try to load kernel module with WireGuard support.
            kld_load("if_wg".as_ptr());
            create_clone_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }

    pub(crate) fn destroy(&self) -> Result<(), IoError> {
        let socket = create_socket().map_err(IoError::WriteIo)?;

        unsafe {
            // First, try to load kernel module with WireGuard support.
            kld_load("if_wg".as_ptr());
            destroy_clone_if(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }
}
