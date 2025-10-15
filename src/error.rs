//! Interface management errors

use thiserror::Error;

#[cfg(target_os = "windows")]
use crate::wgapi_windows::WindowsError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireguardInterfaceError {
    #[error("Interface setup error: {0}")]
    Interface(String),
    #[error("Command execution failed")]
    CommandExecutionFailed(#[from] std::io::Error),
    #[error("WireGuard key error")]
    KeyDecode(#[from] base64::DecodeError),
    #[error("Command returned error status: `{stdout}`")]
    CommandExecutionError { stdout: String, stderr: String },
    #[error("IP address/mask error")]
    IpAddrMask(#[from] crate::net::IpAddrParseError),
    #[error("Required dependency not found, details: {0}")]
    MissingDependency(String),
    #[error("Unix socket error: {0}")]
    UnixSockerError(String),
    #[error("Peer configuration error: {0}")]
    PeerConfigurationError(String),
    #[error("Interface data read error: {0}")]
    ReadInterfaceError(String),
    #[error("Netlink error: {0}")]
    NetlinkError(String),
    #[error("BSD error: {0}")]
    BsdError(String),
    #[error("Userspace support is not available on this platform")]
    UserspaceNotSupported,
    #[error("Kernel support is not available on this platform")]
    KernelNotSupported,
    #[error("DNS error: {0}")]
    DnsError(String),
    #[cfg(target_os = "windows")]
    #[error("Service installation failed: `{0}`")]
    ServiceInstallationFailed(String),
    #[cfg(target_os = "windows")]
    #[error("Tunnel service removal failed: `{0}`")]
    ServiceRemovalFailed(String),
    #[error("Socket is closed: {0}")]
    SocketClosed(String),
    #[cfg(target_os = "windows")]
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
}
