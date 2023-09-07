use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireguardError {
    #[error("Interface setup error: {0}")]
    Interface(String),
    #[cfg(feature = "boringtun")]
    #[error("BorningTun error")]
    BorningTun(boringtun::device::Error),
    #[error("Command execution failed")]
    CommandExecutionFailed(#[from] std::io::Error),
    #[error("WireGuard key error")]
    KeyDecode(#[from] base64::DecodeError),

    #[error("Command returned error status")]
    CommandExecutionError { stderr: String },
    #[error("IP address/mask error")]
    IpAddrMask(#[from] crate::net::IpAddrParseError),
}
