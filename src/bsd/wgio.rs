use std::{
    alloc::{Layout, alloc, dealloc},
    os::fd::AsRawFd,
    ptr::null_mut,
    slice::from_raw_parts,
};

use libc::IF_NAMESIZE;
use nix::{ioctl_readwrite, sys::socket::AddressFamily};

use super::{IoError, create_socket};

// FIXME: `WgReadIo` and `WgWriteIo` have to be declared public.
ioctl_readwrite!(write_wireguard_data, b'i', 210, WgWriteIo);
ioctl_readwrite!(read_wireguard_data, b'i', 211, WgReadIo);

/// Represent `struct wg_data_io` defined in
/// https://github.com/freebsd/freebsd-src/blob/main/sys/dev/wg/if_wg.h
#[repr(C)]
pub struct WgReadIo {
    wgd_name: [u8; IF_NAMESIZE],
    wgd_data: *mut u8, // *void
    wgd_size: usize,
}

impl WgReadIo {
    /// Create `WgReadIo` without data buffer.
    #[must_use]
    pub fn new(if_name: &str) -> Self {
        let mut wgd_name = [0u8; IF_NAMESIZE];
        if_name
            .bytes()
            .take(IF_NAMESIZE - 1)
            .enumerate()
            .for_each(|(i, b)| wgd_name[i] = b);
        Self {
            wgd_name,
            wgd_data: null_mut(),
            wgd_size: 0,
        }
    }

    /// Allocate data buffer.
    fn alloc_data(&mut self) -> Result<(), IoError> {
        if self.wgd_data.is_null() {
            if let Ok(layout) = Layout::array::<u8>(self.wgd_size) {
                unsafe {
                    self.wgd_data = alloc(layout);
                }
                return Ok(());
            }
        }
        Err(IoError::MemAlloc)
    }

    /// Return buffer as slice.
    pub(super) fn as_slice<'a>(&self) -> &'a [u8] {
        unsafe { from_raw_parts(self.wgd_data, self.wgd_size) }
    }

    pub(super) fn read_data(&mut self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::ReadIo)?;
        unsafe {
            // First do ioctl with empty `wg_data` to obtain buffer size.
            if let Err(err) = read_wireguard_data(socket.as_raw_fd(), self) {
                error!("WgReadIo first read error {err}");
                return Err(IoError::ReadIo(err));
            }
            // Allocate buffer.
            self.alloc_data()?;
            // Second call to ioctl with allocated buffer.
            if let Err(err) = read_wireguard_data(socket.as_raw_fd(), self) {
                error!("WgReadIo second read error {err}");
                return Err(IoError::ReadIo(err));
            }
        }

        Ok(())
    }
}

impl Drop for WgReadIo {
    fn drop(&mut self) {
        if self.wgd_size != 0 {
            let layout = Layout::array::<u8>(self.wgd_size).expect("Bad layout");
            unsafe {
                dealloc(self.wgd_data, layout);
            }
        }
    }
}

/// Same data layout as `WgReadIo`, but avoid `Drop`.
#[repr(C)]
pub struct WgWriteIo {
    wgd_name: [u8; IF_NAMESIZE],
    wgd_data: *mut u8, // *void
    wgd_size: usize,
}

impl WgWriteIo {
    /// Create `WgWriteIo` from slice.
    #[must_use]
    pub fn new(if_name: &str, buf: &mut [u8]) -> Self {
        let mut wgd_name = [0u8; IF_NAMESIZE];
        if_name
            .bytes()
            .take(IF_NAMESIZE - 1)
            .enumerate()
            .for_each(|(i, b)| wgd_name[i] = b);
        Self {
            wgd_name,
            wgd_data: buf.as_mut_ptr(),
            wgd_size: buf.len(),
        }
    }

    pub(super) fn write_data(&mut self) -> Result<(), IoError> {
        let socket = create_socket(AddressFamily::Unix).map_err(IoError::WriteIo)?;
        unsafe {
            if let Err(err) = write_wireguard_data(socket.as_raw_fd(), self) {
                error!("WgWriteIo write error {err}");
                return Err(IoError::WriteIo(err));
            }
        }

        Ok(())
    }
}
