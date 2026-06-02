//! Compute values for ioctl.
//!
//! Same as libc::{_IOR, _IOW, IOWR}, but these are not available for all platforms.
//!
//! | dir    | size    | type   | nr     |
//! |--------|---------|--------|--------|
//! | 31–30  | 29–16   | 15–8   | 7–0    |
//! | 2 bits | 14 bits | 8 bits | 8 bits |

use std::mem;

use libc::c_ulong;

/// Direction (out = read, in = write).
// const IOC_VOID: u32 = 0x2000_0000;
const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;

/// Equivalent to the C _IOC() macro.
const fn ioc(dir: u32, ty: u8, nr: u32, size: u32) -> c_ulong {
    (dir | (size << 16) | ((ty as u32) << 8) | nr) as c_ulong
}

/// IO  — no data transfer
// pub(super) const fn io(ty: u8, nr: u32) -> c_ulong {
//     ioc(IOC_VOID, ty, nr, 0)
// }

/// IOR — kernel to userspace (read)
// pub(super) const fn ior<T>(ty: u8, nr: u32) -> c_ulong {
//     ioc(IOC_IN, ty, nr, mem::size_of::<T>() as u32)
// }

/// IOW — userspace to kernel (write)
pub(super) const fn iow<T>(ty: u8, nr: u32) -> c_ulong {
    ioc(IOC_IN, ty, nr, mem::size_of::<T>() as u32)
}

/// IOWR — bidirectional communication (write-read)
pub(super) const fn iowr<T>(ty: u8, nr: u32) -> c_ulong {
    ioc(IOC_OUT | IOC_IN, ty, nr, mem::size_of::<T>() as u32)
}
