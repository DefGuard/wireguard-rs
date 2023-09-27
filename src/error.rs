use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireguardInterfaceError {
    #[error("Interface setup error: {0}")]
    Interface(String),
    #[error("Command execution failed")]
    CommandExecutionFailed(#[from] std::io::Error),
    #[error("WireGuard key error")]
    KeyDecode(#[from] base64::DecodeError),
    #[error("Command returned error status")]
    CommandExecutionError { stdout: String, stderr: String },
    #[error("IP address/mask error")]
    IpAddrMask(#[from] crate::net::IpAddrParseError),
    #[error("{0} executable not found in system PATH")]
    ExecutableNotFound(String),
    #[error("Unix socket error: {0}")]
    UnixSockerError(String),
    #[error("Peer configuration error")]
    PeerConfigurationError,
    #[error("Interface data read error: {0}")]
    ReadInterfaceError(String),
    #[error("Netlink error: {0}")]
    NetlinkError(String),
    #[error("BSD error: {0}")]
    BsdError(String),
}
