#[cfg(target_os = "freebsd")]
use crate::bsd::{delete_peer, get_host, set_host, set_peer};
use crate::{WireguardApiUserspace, WireguardInterfaceApi, WireguardInterfaceError};

pub struct WGApi(Box<dyn WireguardInterfaceApi>);

impl WGApi {
    #[must_use]
    pub fn new(ifname: String, userspace: bool) -> Result<Self, WireguardInterfaceError> {
        Ok(Self(Box::new(WireguardApiUserspace::new(ifname)?)))
    }
}
