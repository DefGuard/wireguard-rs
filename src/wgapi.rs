//! Shared multi-platform management API abstraction
use std::marker::PhantomData;

use boringtun::device::DeviceHandle;

#[cfg(feature = "check_dependencies")]
use crate::dependencies::check_external_dependencies;
use crate::error::WireguardInterfaceError;

pub struct Kernel;
pub struct Userspace;

/// Shared multi-platform WireGuard management API
///
/// This struct adds an additional level of abstraction and can be used
/// to detect the correct API implementation for most common platforms.
pub struct WGApi<API = Kernel> {
    pub(super) ifname: String,
    pub(super) device_handle: Option<DeviceHandle>,
    pub(super) _api: PhantomData<API>,
}

impl<API> WGApi<API> {
    /// Create new instance of `WGApi`.
    pub fn new(ifname: String) -> Result<Self, WireguardInterfaceError> {
        #[cfg(feature = "check_dependencies")]
        check_external_dependencies()?;
        Ok(WGApi {
            ifname,
            device_handle: None,
            _api: PhantomData,
        })
    }
}
