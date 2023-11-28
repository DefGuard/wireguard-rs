#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::utils::{clean_dns, set_dns};
use crate::{
    check_command_output_status, error::WireguardInterfaceError, Host, InterfaceConfiguration,
    IpAddrMask, Key, Peer, WireguardInterfaceApi,
};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Shutdown},
    os::unix::net::UnixStream,
    process::Command,
    str::FromStr,
    time::Duration,
};

const USERSPACE_EXECUTABLE: &str = "wireguard-go";

/// Manages interfaces created with `wireguard-go`.
///
/// We assume that `wireguard-go` executable is managed externally and available in `PATH`.
/// Currently works on Unix platforms.
#[derive(Clone)]
pub struct WireguardApiUserspace {
    ifname: String,
}

impl WireguardApiUserspace {
    /// Create new instance of `WireguardApiUserspace`.
    ///
    /// # Errors
    /// Will return `WireguardInterfaceError` if `wireguard-go` can't be found.
    pub fn new(ifname: String) -> Result<Self, WireguardInterfaceError> {
        // check that `wireguard-go` is available
        Command::new(USERSPACE_EXECUTABLE).arg("--version").output().map_err(|err| {
            error!("Failed to create userspace API. {USERSPACE_EXECUTABLE} executable not found in PATH. Error: {err}");
            WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        })?;

        Ok(WireguardApiUserspace { ifname })
    }

    fn socket_path(&self) -> String {
        format!("/var/run/wireguard/{}.sock", self.ifname)
    }

    /// Create UNIX socket to communicate with `wireguard-go`.
    fn socket(&self) -> io::Result<UnixStream> {
        let path = self.socket_path();
        let socket = UnixStream::connect(path)?;
        socket.set_read_timeout(Some(Duration::new(3, 0)))?;
        Ok(socket)
    }

    // FIXME: currently other errors are ignored and result in 0 being returned.
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

    /// Read host information using user-space API.
    pub fn read_host(&self) -> io::Result<Host> {
        debug!("Reading host interface info");
        let mut socket = self.socket()?;
        socket.write_all(b"get=1\n\n")?;
        Host::parse_uapi(socket)
    }

    /// Write host information using user-space API.
    pub fn write_host(&self, host: &Host) -> io::Result<()> {
        let mut socket = self.socket()?;
        socket.write_all(b"set=1\n")?;
        socket.write_all(host.as_uapi().as_bytes())?;
        socket.write_all(b"\n")?;

        if Self::parse_errno(socket) == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "write configuration error",
            ))
        }
    }
}

impl WireguardInterfaceApi for WireguardApiUserspace {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Creating userspace interface {}", self.ifname);
        let output = Command::new(USERSPACE_EXECUTABLE)
            .arg(&self.ifname)
            .output()?;
        check_command_output_status(output)?;
        Ok(())
    }
    /// Sets DNS configuration for a Wireguard interface using the `resolvconf` command.
    ///
    /// This function is platform-specific and is intended for use on Linux and FreeBSD.
    /// It executes the `resolvconf -a <if_name> -m -0 -x` command with appropriate arguments to update DNS
    /// configurations for the specified Wireguard interface. The DNS entries are filtered
    /// for nameservers and search domains before being piped to the `resolvconf` command.
    ///
    /// # Errors
    ///
    /// Returns a `WireguardInterfaceError::DnsError` if there is an error in setting the DNS configuration.
    ///
    /// # Platform Support
    ///
    /// - Linux
    /// - FreeBSD
    fn set_dns(&self, dns: Vec<IpAddr>) -> Result<(), WireguardInterfaceError> {
        info!("Configuring dns for interface: {}", self.ifname);
        // Setting dns is unsupported for macos
        #[cfg(target_os = "macos")]
        {
            error!("MacOS is not supported");
            Err(WireguardInterfaceError::DnsError)
        }
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            Ok(set_dns(&self.ifname, dns)?)
        }
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        let output = if cfg!(target_os = "macos") {
            // On macOS, interface is point-to-point and requires a pair of addresses
            let address_string = address.ip.to_string();
            Command::new("ifconfig")
                .args([&self.ifname, &address_string, &address_string])
                .output()?
        } else {
            Command::new("ifconfig")
                .args([&self.ifname, &address.to_string()])
                .output()?
        };
        check_command_output_status(output)?;
        Ok(())
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        info!(
            "Configuring interface {} with config: {config:?}",
            self.ifname
        );

        // assign IP address to interface
        let address = IpAddrMask::from_str(&config.address)?;
        self.assign_address(&address)?;

        // configure interface
        let host = config.try_into()?;
        self.write_host(&host)?;
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", self.ifname);
        // 'wireguard-go` should by design shut down if the socket is removed
        let socket = self.socket()?;
        socket.shutdown(Shutdown::Both).map_err(|err| {
            error!("Failed to shutdown socket: {err}");
            WireguardInterfaceError::UnixSockerError(err.to_string())
        })?;
        fs::remove_file(self.socket_path())?;
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            clean_dns(&self.ifname);
        }

        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        let mut socket = self.socket()?;
        socket.write_all(b"set=1\n")?;
        socket.write_all(peer.as_uapi_update().as_bytes())?;
        socket.write_all(b"\n")?;

        if Self::parse_errno(socket) == 0 {
            Ok(())
        } else {
            Err(WireguardInterfaceError::PeerConfigurationError)
        }
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        info!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        let mut socket = self.socket()?;
        socket.write_all(b"set=1\n")?;
        socket.write_all(
            format!("public_key={}\nremove=true\n", peer_pubkey.to_lower_hex()).as_bytes(),
        )?;
        socket.write_all(b"\n")?;

        if Self::parse_errno(socket) == 0 {
            Ok(())
        } else {
            Err(WireguardInterfaceError::PeerConfigurationError)
        }
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);
        match self.read_host() {
            Ok(host) => Ok(host),
            Err(err) => {
                error!("Failed to read interface {} data: {err}", self.ifname);
                Err(WireguardInterfaceError::ReadInterfaceError(err.to_string()))
            }
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
        assert_eq!(WireguardApiUserspace::parse_errno(buf), 0);

        let buf = Cursor::new(b"errno=12345\n");
        assert_eq!(WireguardApiUserspace::parse_errno(buf), 12345);
    }
}
