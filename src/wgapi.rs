//! Shared multi-platform management API abstraction
use std::marker::PhantomData;

use crate::error::WireguardInterfaceError;

pub struct Kernel;
pub struct Userspace;

/// Shared multi-platform WireGuard management API
///
/// This struct adds an additional level of abstraction and can be used
/// to detect the correct API implementation for most common platforms.
pub struct WGApi<API = Kernel> {
    pub(super) ifname: String,
    pub(super) _api: PhantomData<API>,
}

impl WGApi {
    /// Create new instance of `WGApi`.
    pub fn new(ifname: String) -> Result<Self, WireguardInterfaceError> {
        Ok(WGApi {
            ifname,
            _api: PhantomData,
        })
    }
}
