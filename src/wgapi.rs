//! Shared multi-platform management API abstraction
use std::marker::PhantomData;

#[cfg(unix)]
use defguard_boringtun::device::DeviceHandle;
#[cfg(target_os = "windows")]
use wireguard_nt::Adapter;

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
    #[cfg(unix)]
    pub(super) device_handle: Option<DeviceHandle>,
    #[cfg(target_os = "windows")]
    pub(super) adapter: Option<Adapter>,
    pub(super) _api: PhantomData<API>,
}

impl<API> WGApi<API> {
    /// Create new instance of `WGApi`.
    pub fn new<S: Into<String>>(ifname: S) -> Result<Self, WireguardInterfaceError> {
        #[cfg(feature = "check_dependencies")]
        check_external_dependencies()?;
        Ok(WGApi {
            ifname: ifname.into(),
            #[cfg(unix)]
            device_handle: None,
            #[cfg(target_os = "windows")]
            adapter: None,
            _api: PhantomData,
        })
    }
}
