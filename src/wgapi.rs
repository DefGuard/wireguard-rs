use std::{
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

#[cfg(target_os = "freebsd")]
use crate::bsd::{delete_peer, get_host, set_host, set_peer};
use crate::host::{Host, Peer};
#[cfg(target_os = "linux")]
use crate::netlink::{delete_peer, get_host, set_host, set_peer};

pub struct WGApi {
    ifname: String,
    userspace: bool,
}

impl WGApi {
    #[must_use]
    pub fn new(ifname: String, userspace: bool) -> Self {
        Self { ifname, userspace }
    }

    fn socket(&self) -> io::Result<UnixStream> {
        let path = format!("/var/run/wireguard/{}.sock", self.ifname);
        let socket = UnixStream::connect(path)?;
        socket.set_read_timeout(Some(Duration::new(3, 0)))?;
        Ok(socket)
    }

    // FIXME: currenty other errors are ignored and result in 0 being returned.
    fn parse_errno(buf: impl Read) -> u32 {
        let reader = BufReader::new(buf);
        for line_result in reader.lines() {
            let line = match line_result {
                Ok(line) => line,
                Err(err) => {
                    error!("Error parsing buffer line: {err}");
                    continue;
                }
            };
            if let Some((keyword, value)) = line.split_once('=') {
                if keyword == "errno" {
                    return value.parse().unwrap_or_default();
                }
            }
        }
        0
    }

    pub fn read_host(&self) -> io::Result<Host> {
        debug!("Reading host interface info");
        if self.userspace {
            let mut socket = self.socket()?;
            socket.write_all(b"get=1\n\n")?;
            Host::parse_uapi(socket)
        } else {
            #[cfg(target_os = "freebsd")]
            {
                // FIXME: use proper error
                get_host(&self.ifname).map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, format!("kernel support error: {err}"))
                })
            }
            #[cfg(target_os = "linux")]
            {
                get_host(&self.ifname)
            }
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            Err(io::Error::new(
                io::ErrorKind::Other,
                "kernel support is not available on this platform",
            ))
        }
    }

    pub fn write_host(&self, host: &Host) -> io::Result<()> {
        if self.userspace {
            let mut socket = self.socket()?;
            socket.write_all(b"set=1\n")?;
            socket.write_all(host.as_uapi().as_bytes())?;
            socket.write_all(b"\n")?;

            if Self::parse_errno(socket) != 0 {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "write configuration error",
                ))
            } else {
                Ok(())
            }
        } else {
            #[cfg(target_os = "freebsd")]
            {
                // FIXME: use proper error
                set_host(&self.ifname, host).map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, format!("kernel support error: {err}"))
                })
            }
            #[cfg(target_os = "linux")]
            {
                set_host(&self.ifname, host)
            }
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            Err(io::Error::new(
                io::ErrorKind::Other,
                "kernel support is not available on this platform",
            ))
        }
    }

    pub fn write_peer(&self, peer: &Peer) -> io::Result<()> {
        if self.userspace {
            let mut socket = self.socket()?;
            socket.write_all(b"set=1\n")?;
            socket.write_all(peer.as_uapi_update().as_bytes())?;
            socket.write_all(b"\n")?;

            if Self::parse_errno(socket) != 0 {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "write configuration error",
                ))
            } else {
                Ok(())
            }
        } else {
            #[cfg(target_os = "freebsd")]
            {
                // FIXME: use proper error
                set_peer(&self.ifname, peer).map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, format!("kernel support error: {err}"))
                })
            }
            #[cfg(target_os = "linux")]
            {
                set_peer(&self.ifname, peer)
            }
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            Err(io::Error::new(
                io::ErrorKind::Other,
                "kernel support is not available on this platform",
            ))
        }
    }

    pub fn delete_peer(&self, peer: &Peer) -> io::Result<()> {
        if self.userspace {
            let mut socket = self.socket()?;
            socket.write_all(b"set=1\n")?;
            socket.write_all(peer.as_uapi_remove().as_bytes())?;
            socket.write_all(b"\n")?;

            if Self::parse_errno(socket) != 0 {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "write configuration error",
                ))
            } else {
                Ok(())
            }
        } else {
            #[cfg(target_os = "freebsd")]
            {
                // FIXME: use proper error
                delete_peer(&self.ifname, peer).map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, format!("kernel support error: {err}"))
                })
            }
            #[cfg(target_os = "linux")]
            {
                delete_peer(&self.ifname, peer)
            }
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            Err(io::Error::new(
                io::ErrorKind::Other,
                "kernel support is not available on this platform",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_parse_errno() {
        let buf = Cursor::new(b"errno=0\n");
        assert_eq!(WGApi::parse_errno(buf), 0);

        let buf = Cursor::new(b"errno=12345\n");
        assert_eq!(WGApi::parse_errno(buf), 12345);
    }
}
