use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    marker::PhantomData,
    net::{IpAddr, Shutdown},
    os::unix::net::UnixStream,
    process::Command,
    str::FromStr,
    time::Duration,
};

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use crate::bsd;
#[cfg(target_os = "linux")]
use crate::netlink;
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use crate::utils::clear_dns;
use crate::{
    check_command_output_status,
    error::WireguardInterfaceError,
    utils::{add_peer_routing, configure_dns},
    wgapi::{Userspace, WGApi},
    wireguard_interface::WireguardInterfaceApi,
    Host, InterfaceConfiguration, IpAddrMask, Key, Peer,
};

const USERSPACE_EXECUTABLE: &str = "wireguard-go";

/// Manages interfaces created with `wireguard-go`.
///
/// We assume that `wireguard-go` executable is managed externally and available in `PATH`.
/// Currently works on Unix platforms.
impl WGApi<Userspace> {
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

        Ok(WGApi {
            ifname,
            _api: PhantomData,
        })
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

impl WireguardInterfaceApi for WGApi<Userspace> {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Creating userspace interface {}", self.ifname);
        let output = Command::new(USERSPACE_EXECUTABLE)
            .arg(&self.ifname)
            .output()?;
        check_command_output_status(output)?;
        Ok(())
    }

    /// Sets DNS configuration for a WireGuard interface using the `resolvconf` command.
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
    fn configure_dns(
        &self,
        dns: &[IpAddr],
        search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError> {
        if dns.is_empty() {
            warn!("Received empty DNS server list. Skipping DNS configuration...");
            return Ok(());
        }
        info!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        // Setting DNS is not supported for macOS.
        #[cfg(target_os = "macos")]
        {
            configure_dns(dns, search_domains)
        }
        #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
        {
            configure_dns(&self.ifname, dns, search_domains)
        }
    }

    /// Assign IP address to network interface.
    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
        bsd::assign_address(&self.ifname, address)?;
        #[cfg(target_os = "linux")]
        netlink::address_interface(&self.ifname, address)?;

        Ok(())
    }

    /// Configure network interface.
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

        // Set maximum transfer unit (MTU).
        if let Some(mtu) = config.mtu {
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
            bsd::set_mtu(&self.ifname, mtu)?;
            #[cfg(target_os = "linux")]
            netlink::set_mtu(&self.ifname, mtu)?;
        }

        Ok(())
    }

    /// Add peer addresses to network routing table.
    ///
    /// # Linux:
    /// On a Linux system, the `sysctl` command is required to work if using `0.0.0.0/0` or `::/0`.
    /// For every allowed IP, it runs:
    /// `ip <ip_version> route add <allowed_ip> dev <ifname>`
    /// `<ifname>` - interface name while creating api
    /// `<ip_version>` - `-4` or `-6` based on allowed ip type
    /// `<allowed_ip>`- one of [Peer](crate::Peer) allowed ip
    ///
    /// For `0.0.0.0/0` or `::/0` allowed IP, it runs belowed additional commands in order:
    /// - `ip <ip_version> route add 0.0.0.0/0 dev <ifname> table <fwmark>`
    ///   `<fwmark>` - fwmark attribute of [Host](crate::Host) or 51820 default if value is `None`.
    ///   `<ifname>` - Interface name.
    /// - `ip <ip_version> rule add not fwmark <fwmark> table <fwmark>`.
    /// - `ip <ip_version> rule add table main suppress_prefixlength 0`.
    /// - `sysctl -q net.ipv4.conf.all.src_valid_mark=1` - runs only for `0.0.0.0/0`.
    /// - `iptables-restore -n`. For `0.0.0.0/0` only.
    /// - `iptables6-restore -n`. For `::/0` only.
    ///
    /// Based on IP type `<ip_version>` will be equal to `-4` or `-6`.
    ///
    ///
    /// # macOS, FreeBSD:
    /// For every allowed IP, it runs:
    /// - `route -q -n add <inet> allowed_ip -interface if_name`
    ///   `ifname` - interface name while creating api
    ///   `allowed_ip`- one of [Peer](crate::Peer) allowed ip
    ///
    /// For `0.0.0.0/0` or `::/0`  allowed IP, it adds default routing and skips other routings.
    /// - `route -q -n add <inet> 0.0.0.0/1 -interface if_name`.
    /// - `route -q -n add <inet> 128.0.0.0/1 -interface if_name`.
    /// - `route -q -n add <inet> <endpoint> -gateway <gateway>`
    ///   `<endpoint>` - Add routing for every unique Peer endpoint.
    ///   `<gateway>`- Gateway extracted using `netstat -nr -f <inet>`.
    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        add_peer_routing(peers, &self.ifname)?;
        Ok(())
    }

    /// Remove WireGuard network interface.
    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", self.ifname);
        // `wireguard-go` should by design shut down if the socket is removed
        let socket = self.socket()?;
        socket.shutdown(Shutdown::Both).map_err(|err| {
            error!("Failed to shutdown socket: {err}");
            WireguardInterfaceError::UnixSockerError(err.to_string())
        })?;
        fs::remove_file(self.socket_path())?;
        #[cfg(target_os = "macos")]
        {
            configure_dns(&[], &[])?;
        }
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            clear_dns(&self.ifname)?;
        }

        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        let mut socket = self.socket()?;
        socket.write_all(b"set=1\n")?;
        socket.write_all(peer.as_uapi_update().as_bytes())?;
        socket.write_all(b"\n")?;
        let errno = Self::parse_errno(socket);

        if errno == 0 {
            Ok(())
        } else {
            Err(WireguardInterfaceError::PeerConfigurationError(format!(
                "Failed to configure peer {peer:?} on interface {}, errno: {errno}",
                self.ifname
            )))
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

        let errno = Self::parse_errno(socket);

        if errno == 0 {
            Ok(())
        } else {
            Err(WireguardInterfaceError::PeerConfigurationError(format!(
                "Failed to remove peer with public key {peer_pubkey} from interface {}, errno: {errno}",
                self.ifname
            )))
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
        assert_eq!(WGApi::<Userspace>::parse_errno(buf), 0);

        let buf = Cursor::new(b"errno=12345\n");
        assert_eq!(WGApi::<Userspace>::parse_errno(buf), 12345);
    }
}
