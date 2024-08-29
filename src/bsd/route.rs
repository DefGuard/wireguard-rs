use std::{
    mem::size_of,
    net::IpAddr,
    os::fd::{AsFd, AsRawFd},
};

use nix::{
    errno::Errno,
    sys::socket::{socket, AddressFamily, SockFlag, SockType},
    unistd::{read, write},
};

use super::{cast_bytes, cast_ref, sockaddr::unpack_sockaddr, IoError};

// Routing data types are not defined in libc crate, so define then here.

#[allow(dead_code)]
/// Message types for use with `RtMsgHdr`.
#[non_exhaustive]
#[repr(u8)]
enum MessageType {
    Add = 1,
    Delete,
    Change,
    Get,
    Losing,
    Redirect,
    Miss,
    Lock,
    OldAdd,  // not defined on FreeBSD
    OldDel,  // not defined on FreeBSD
    Resolve, // commented out on NetBSD
}

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
const RTM_VERSION: u8 = 5;
#[cfg(target_os = "netbsd")]
const RTM_VERSION: u8 = 4;

/// Route message flags.
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
// const RTF_HOST: i32 = 0x4;
// const RTF_REJECT: i32 = 0x8;
// const RTF_DYNAMIC: i32 = 0x10;
// const RTF_MODIFIED: i32 = 0x20;
// const RTF_DONE: i32 = 0x40;
// const RTF_DELCLONE: i32 = 0x80; // RTF_MASK on NetBSD
// const RTF_CLONING: i32 = 0x100;
// const RTF_XRESOLVE: i32 = 0x200;
// const RTF_LLINFO: i32 = 0x400;
// const RTF_LLDATA: i32 = 0x400;
const RTF_STATIC: i32 = 0x800;
// const RTF_BLACKHOLE: i32 = 0x1000;

/// Bitmask values for rtm_addrs.
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
// const RTA_NETMASK: i32 = 0x4;
// const RTA_GENMASK: i32 = 0x8;
// const RTA_IFP: i32 = 0x10;
// const RTA_IFA: i32 = 0x20;
// const RTA_AUTHOR: i32 = 0x40;
// const RTA_BRD: i32 = 0x80;

/// FreeBSD version of `struct rt_metrics` from <net/route.h>
#[cfg(target_os = "freebsd")]
#[derive(Default)]
#[repr(C)]
struct RtMetrics {
    rmx_locks: u64,
    rmx_mtu: u64,
    rmx_hopcount: u64,
    rmx_expire: u64,
    rmx_recvpipe: u64,
    rmx_sendpipe: u64,
    rmx_ssthresh: u64,
    rmx_rtt: u64,
    rmx_rttvar: u64,
    rmx_pksent: u64,
    rmx_weight: u64,
    rmx_nhidx: u64,
    rmx_filler: [u64; 2],
}

/// macOS version of `struct rt_metrics` from <net/route.h>
#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct RtMetrics {
    rmx_locks: u32,
    rmx_mtu: u32,
    rmx_hopcount: u32,
    rmx_expire: i32,
    rmx_recvpipe: u32,
    rmx_sendpipe: u32,
    rmx_ssthresh: u32,
    rmx_rtt: u32,
    rmx_rttvar: u32,
    rmx_pksent: u32,
    rmx_filler: [u32; 4],
}

/// NetBSD version of `struct rt_metrics` from <net/route.h>
#[cfg(target_os = "netbsd")]
#[derive(Default)]
#[repr(C)]
struct RtMetrics {
    rmx_locks: u64,
    rmx_mtu: u64,
    rmx_hopcount: u64,
    rmx_recvpipe: u64,
    rmx_sendpipe: u64,
    rmx_ssthresh: u64,
    rmx_rtt: u64,
    rmx_rttvar: u64,
    rmx_expire: i64,
    rmx_pksent: i64,
}

/// `struct rt_msghdr` from <net/route.h>
#[repr(C)]
struct RtMsgHdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    #[cfg(target_os = "freebsd")]
    _rtm_spare1: i16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    #[cfg(target_os = "freebsd")]
    rtm_fmask: i32,
    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    rtm_use: i32,
    rtm_inits: u32,
    rtm_rmx: RtMetrics,
}

impl RtMsgHdr {
    #[must_use]
    fn new(message_length: u16, message_type: MessageType, flags: i32, addrs: i32) -> Self {
        Self {
            rtm_msglen: message_length,
            rtm_version: RTM_VERSION,
            rtm_type: message_type as u8,
            rtm_index: 0, // interface index if RTF_IFSCOPE
            #[cfg(target_os = "freebsd")]
            _rtm_spare1: 0,
            rtm_flags: flags,
            rtm_addrs: addrs,
            rtm_pid: 0, //unsafe { libc::getpid() },
            rtm_seq: 1,
            rtm_errno: 0,
            #[cfg(target_os = "freebsd")]
            rtm_fmask: 0,
            #[cfg(any(target_os = "macos", target_os = "netbsd"))]
            rtm_use: 0,
            rtm_inits: 0,
            rtm_rmx: RtMetrics::default(),
        }
    }
}

#[repr(C)]
pub(super) struct RtMessage<Payload> {
    header: RtMsgHdr,
    payload: Payload,
}

impl<Payload: Default> RtMessage<Payload> {
    #[must_use]
    pub(super) fn new() -> Self {
        let header = RtMsgHdr::new(
            size_of::<Self>() as u16,
            MessageType::Get,
            RTF_UP | RTF_GATEWAY | RTF_STATIC,
            RTA_DST,
        );

        Self {
            header,
            payload: Payload::default(),
        }
    }

    pub(super) fn default_route(&self) -> Result<Option<IpAddr>, IoError> {
        let socket = socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
            .map_err(IoError::WriteIo)?;
        let buf = unsafe { cast_bytes(self) };
        match write(socket.as_fd(), buf) {
            Ok(_) => (),
            Err(Errno::ESRCH) => return Ok(None), // not in table
            Err(err) => return Err(IoError::WriteIo(err)),
        }

        let mut buf = [0u8; 256]; // FIXME: fixed buffer size
        let len = read(socket.as_raw_fd(), &mut buf).map_err(IoError::ReadIo)?;
        if len < size_of::<Self>() {
            return Err(IoError::Unpack);
        }

        let header = unsafe { cast_ref::<RtMsgHdr>(&buf) };

        let mut offset = size_of::<RtMsgHdr>();
        if header.rtm_addrs & RTA_DST != 0 {
            let len = (&buf[offset..])[0] as usize;
            // let dst = unpack_sockaddr(&buf[offset..]);
            // eprintln!("{dst:?}");
            offset += if len > 0 { len } else { 4 };
        }
        if header.rtm_addrs & RTA_GATEWAY != 0 {
            // let len = (&buf[offset..])[0] as usize;
            return Ok(unpack_sockaddr(&buf[offset..]).map(|addr| addr.ip()));
            // offset += if len > 0 { len } else { 4 };
        }
        // if header.rtm_addrs & RTA_NETMASK != 0 {
        //     let len = (&buf[offset..])[0] as usize;
        //     let mask = unpack_sockaddr(&buf[offset..]);
        //     eprintln!("{mask:?}");
        //     offset += if len > 0 { len } else { 4 };
        // }
        // if header.rtm_addrs & RTA_GENMASK != 0 {
        //     let len = (&buf[offset..])[0] as usize;
        //     let mask = unpack_sockaddr(&buf[offset..]);
        //     eprintln!("{mask:?}");
        // offset += if len > 0 { len } else { 4 };
        // }
        // if header.rtm_addrs & RTA_IFP != 0 {
        //     let len = (&buf[offset..])[0] as usize;
        //     let ifp = unsafe { cast_ref::<sockaddr_dl>(&buf[offset..]) };
        //     eprintln!("{ifp:?}");
        //     offset += if len > 0 { len } else { 4 };
        // }
        // if header.rtm_addrs & RTA_IFA != 0 {
        //     let len = (&buf[offset..])[0] as usize;
        //     let ifa = unpack_sockaddr(&buf[offset..]);
        //     eprintln!("{ifa:?}");
        // }

        Ok(None)
    }
}
