use std::{net::IpAddr, str::FromStr, env};

use crate::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    InterfaceConfiguration, WireguardInterfaceApi,
};

const ADAPTER_POOL: &str = "WireGuard";

#[cfg(target_arch = "x86")]
const DLL_PATH: &str = "wireguard-nt/bin/x86/wireguard.dll";
#[cfg(target_arch = "x86_64")]
const DLL_PATH: &str = "wireguard-nt/bin/amd64/wireguard.dll";
#[cfg(target_arch = "arm")]
const DLL_PATH: &str = "wireguard-nt/bin/arm/wireguard.dll";
#[cfg(target_arch = "aarch64")]
const DLL_PATH: &str = "wireguard-nt/bin/arm64/wireguard.dll";

/// Manages interfaces created with Windows kernel using https://git.zx2c4.com/wireguard-nt.
#[derive(Clone)]
pub struct WireguardApiWindows {
    ifname: String,
}

impl WireguardApiWindows {
    pub fn new(ifname: String) -> Self {
        WireguardApiWindows { ifname }
    }
}

impl WireguardInterfaceApi for WireguardApiWindows {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Opening/creating interface {}", self.ifname);
        debug!("Loading DDL from {}", DLL_PATH);
        let wireguard = unsafe { wireguard_nt::load_from_path(DLL_PATH) }
            .expect("Failed to load wireguard dll");

        debug!("Opening adapter with name {}", self.ifname);
        
        match wireguard_nt::Adapter::open(wireguard, &self.ifname) {
            Ok(a) => a,
            Err((_, wireguard)) =>
            // If loading failed (most likely it didn't exist), create a new one
            {
                debug!("Creating adapter with name {}", self.ifname);
                wireguard_nt::Adapter::create(wireguard, ADAPTER_POOL, &self.ifname, None)
                    .map_err(|e| e.0)
                    .expect(format!("Failed to create adapter {}", self.ifname).as_str())
            }
        };
        info!("Opened/created interface {}", self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
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
        Ok(())
    }

    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", self.ifname);
        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        info!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);
        Ok(Host::new(12345, Key::from_str("s").unwrap()))
    }

    fn configure_dns(&self, dns: &[IpAddr]) -> Result<(), WireguardInterfaceError> {
        info!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        Ok(())
    }
}
