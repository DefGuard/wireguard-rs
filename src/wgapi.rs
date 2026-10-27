//! Shared multi-platform management API abstraction
use std::marker::PhantomData;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Mutex, MutexGuard, PoisonError},
};

#[cfg(unix)]
use defguard_boringtun::device::DeviceHandle;
#[cfg(target_os = "windows")]
use wireguard_nt::Adapter;

#[cfg(feature = "check_dependencies")]
use crate::dependencies::check_external_dependencies;
use crate::error::WireguardInterfaceError;
#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use crate::{
    Peer,
    utils::{configure_endpoints, remove_endpoint_route, remove_endpoint_routes, resolve},
};

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
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    endpoint_routes: Mutex<HashSet<IpAddr>>,
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
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
            endpoint_routes: Mutex::default(),
            _api: PhantomData,
        })
    }

    /// Routes to peer endpoints added by `configure_peer_routing`.
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    fn endpoint_routes(&self) -> MutexGuard<'_, HashSet<IpAddr>> {
        self.endpoint_routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Route peer endpoints outside the tunnel. See [`configure_endpoints`].
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    pub(super) fn add_endpoint_routes(&self, peers: &[Peer]) {
        configure_endpoints(peers, &mut self.endpoint_routes());
    }

    /// Remove the route to `endpoint`, if it has been added by `add_endpoint_routes`.
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    pub(super) fn delete_endpoint_route(
        &self,
        endpoint: &str,
    ) -> Result<(), WireguardInterfaceError> {
        debug!("Removing routing to {endpoint}, interface: {}", self.ifname);
        let endpoint_addr = resolve(endpoint)?;
        remove_endpoint_route(endpoint_addr.ip(), &mut self.endpoint_routes());
        Ok(())
    }

    /// Remove all routes added by `add_endpoint_routes`.
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    pub(super) fn delete_endpoint_routes(&self) {
        remove_endpoint_routes(&mut self.endpoint_routes());
    }
}
