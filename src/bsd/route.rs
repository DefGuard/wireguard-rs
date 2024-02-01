use std::{mem::size_of, os::fd::AsRawFd, slice::from_raw_parts};

use libc::{
    c_uchar, getpid, in_addr, rt_metrics, rt_msghdr, sockaddr_dl, sockaddr_in, AF_INET, AF_LINK,
    RTA_DST, RTA_IFP, RTA_NETMASK, RTF_GATEWAY, RTF_STATIC, RTF_UP, RTM_GET, RTM_VERSION,
};
use nix::{
    sys::socket::{shutdown, socket, AddressFamily, Shutdown, SockFlag, SockType},
    unistd::{read, write},
};

use crate::net::IpAddrMask;

use super::{cast_bytes, sockaddr::SockAddrIn};

struct SockAddr {
    
}

struct RouteMessage {
    header: rt_msghdr,
    buffer: Vec<u8>,
}

impl RouteMessage {
    fn get() -> Self {
        let header = rt_msghdr {
            rtm_msglen: size_of::<rt_msghdr>() as u16,
            rtm_version: RTM_VERSION as u8,
            rtm_type: RTM_GET as u8,
            rtm_index: 0, // interface index if RTF_IFSCOPE
            rtm_flags: RTF_UP | RTF_GATEWAY | RTF_STATIC,
            rtm_addrs: RTA_DST | RTA_NETMASK | RTA_IFP,
            rtm_pid: unsafe { getpid() },
            rtm_seq: 1,
            rtm_errno: 0,
            rtm_use: 0,
            rtm_inits: 0,
            rtm_rmx: rt_metrics {
                rmx_locks: 0,
                rmx_mtu: 0,
                rmx_hopcount: 0,
                rmx_expire: 0,
                rmx_recvpipe: 0,
                rmx_sendpipe: 0,
                rmx_ssthresh: 0,
                rmx_rtt: 0,
                rmx_rttvar: 0,
                rmx_pksent: 0,
                rmx_state: 0,
                rmx_filler: [0u32; 3],
            },
        };
        Self { header, buffer: Vec::new() }
    }

    fn add_dst(&mut self, addr: &SockAddrIn) {
        self.header.rtm_flags |= RTA_DST;
        let bytes = unsafe { cast_bytes(addr) };
        self.buffer.extend_from_slice(bytes);
    }
}

/// Get route to the given address.
pub fn get_route() {
    //dest: &IpAddrMask) -> IpAddrMask {
    let pid = unsafe { getpid() };
    println!("Pid {pid}");
    let mut rtmsg = RouteMessage::get();
    rtmsg.add_dst(&SockAddrIn::default());
}
