use std::{
    alloc::{alloc, dealloc, Layout},
    os::fd::AsRawFd,
    ptr::null_mut,
    slice::from_raw_parts,
};

use nix::ioctl_readwrite;

use super::{create_socket, IoError};

// FIXME: `WgDataIo` has to be declared as public
ioctl_readwrite!(write_wireguard_data, b'i', 210, WgDataIo);
ioctl_readwrite!(read_wireguard_data, b'i', 211, WgDataIo);

/// Represent `struct wg_data_io` defined in
/// https://github.com/freebsd/freebsd-src/blob/main/sys/dev/wg/if_wg.h
#[repr(C)]
pub struct WgDataIo {
    pub(super) wgd_name: [u8; 16],
    pub(super) wgd_data: *mut u8, // *void
    pub(super) wgd_size: usize,
}

impl WgDataIo {
    /// Create `WgDataIo` without data buffer.
    #[must_use]
    pub fn new(if_name: &str) -> Self {
        let mut wgd_name = [0u8; 16];
        if_name
            .bytes()
            .take(15)
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
        let socket = create_socket().map_err(IoError::ReadIo)?;
        unsafe {
            // First do ioctl with empty `wg_data` to obtain buffer size.
            read_wireguard_data(socket.as_raw_fd(), self).map_err(IoError::ReadIo)?;
            // Allocate buffer.
            self.alloc_data()?;
            // Second call to ioctl with allocated buffer.
            read_wireguard_data(socket.as_raw_fd(), self).map_err(IoError::ReadIo)?;
        }

        Ok(())
    }

    pub(super) fn write_data(&mut self) -> Result<(), IoError> {
        let socket = create_socket().map_err(IoError::WriteIo)?;
        unsafe {
            write_wireguard_data(socket.as_raw_fd(), self).map_err(IoError::WriteIo)?;
        }

        Ok(())
    }
}

impl Drop for WgDataIo {
    fn drop(&mut self) {
        if self.wgd_size != 0 {
            let layout = Layout::array::<u8>(self.wgd_size).expect("Bad layout");
            unsafe {
                dealloc(self.wgd_data, layout);
            }
        }
    }
}
