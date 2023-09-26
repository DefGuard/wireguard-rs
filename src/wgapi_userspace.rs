use crate::error::WireguardInterfaceError;
use crate::wireguard_interface::WireguardInterfaceApi;
use crate::{Host, InterfaceConfiguration, IpAddrMask, Key, Peer};
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

const USERSPACE_EXECUTABLE: &str = "wireguard-go";

/// Manages interfaces created with `wireguard-go`.
///
/// We assume that `wireguard-go` executable is managed externally and available in `PATH`.
/// Currently works on Unix platforms.
pub struct WireguardApiUserspace {
    ifname: String,
}

impl WireguardApiUserspace {
    pub fn new(ifname: String) -> Result<Self, WireguardInterfaceError> {
        // check that `wireguard-go` is available
        Command::new(USERSPACE_EXECUTABLE).arg("--version").output().map_err(|err| {
            error!("Failed to create userspace API. {USERSPACE_EXECUTABLE} executable not found in PATH. Error: {err}");
            WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        })?;

        Ok(WireguardApiUserspace { ifname })
    }

    fn socket(&self) -> io::Result<UnixStream> {
        let path = format!("/var/run/wireguard/{}.sock", self.ifname);
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

    pub fn read_host(&self) -> io::Result<Host> {
        debug!("Reading host interface info");
        let mut socket = self.socket()?;
        socket.write_all(b"get=1\n\n")?;
        Host::parse_uapi(socket)
    }

    pub fn write_host(&self, host: &Host) -> io::Result<()> {
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
    }
}

impl WireguardInterfaceApi for WireguardApiUserspace {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Creating userspace interface {}", self.ifname);
        Command::new(USERSPACE_EXECUTABLE)
            .arg(&self.ifname)
            .output()?;
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        if cfg!(target_os = "macos") {
            // On macOS, interface is point-to-point and requires a pair of addresses
            let address_string = address.ip.to_string();
            Command::new("ifconfig")
                .args([&self.ifname, &address_string, &address_string])
                .output()?;
        } else {
            Command::new("ifconfig")
                .args([&self.ifname, &address.to_string()])
                .output()?;
        };
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
        // create interface
        self.create_interface()?;

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
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        let mut socket = self.socket()?;
        socket.write_all(b"set=1\n")?;
        socket.write_all(peer.as_uapi_update().as_bytes())?;
        socket.write_all(b"\n")?;

        if Self::parse_errno(socket) != 0 {
            Err(WireguardInterfaceError::PeerConfigurationError)
        } else {
            Ok(())
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

        if Self::parse_errno(socket) != 0 {
            Err(WireguardInterfaceError::PeerConfigurationError)
        } else {
            Ok(())
        }
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host interface info");
        match self.read_host() {
            Ok(host) => Ok(host),
            Err(err) => {
                error!("Failed to read interface {} data: {err}", self.ifname);
                Err(WireguardInterfaceError::ReadInterfaceError(err.to_string()))
            }
        }
    }
}
