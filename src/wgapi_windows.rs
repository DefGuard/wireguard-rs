use std::{env, net::IpAddr, str::FromStr, sync::Arc};

use wireguard_nt::dll;

use crate::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    InterfaceConfiguration, WireguardInterfaceApi,
};

use ipnet::{Ipv4Net, Ipv6Net};

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
        debug!("Loading DDL from {}", DLL_PATH);
        Self { ifname }
    }

    fn convert_key(key: &String) -> [u8; 32] {
        let mut interface_private = [0; 32];
        interface_private.copy_from_slice(key.as_bytes());
        interface_private
    }

    fn load_dll() -> Arc<dll> {
        unsafe { wireguard_nt::load_from_path(DLL_PATH) }.expect("Failed to load wireguard dll")
    }
}

impl WireguardInterfaceApi for WireguardApiWindows {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Opening/creating interface {}", self.ifname);
        debug!("Opening adapter with name {}", self.ifname);

        let wireguard = Self::load_dll();

        match wireguard_nt::Adapter::open(wireguard.clone(), &self.ifname) {
            Ok(a) => a,
            Err((_, __)) =>
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

        let wireguard = Self::load_dll();

        let adapter = match wireguard_nt::Adapter::open(wireguard, &self.ifname) {
            Ok(a) => a,
            Err((_, __)) => panic!("Cannot open adapter {}", self.ifname),
        };

        let interface = wireguard_nt::SetInterface {
            listen_port: Some(u16::try_from(config.port).unwrap()),
            public_key: None, // will be generated from the private key
            private_key: Some(Self::convert_key(&config.prvkey)),
            peers: config
                .peers
                .iter()
                .map(|peer| wireguard_nt::SetPeer {
                    public_key: Some(peer.public_key.as_array()),
                    preshared_key: match peer.preshared_key.clone() {
                        Some(k) => Some(k.as_array()),
                        None => None,
                    },
                    keep_alive: peer.persistent_keepalive_interval,
                    endpoint: match peer.endpoint {
                        Some(a) => a,
                        None => panic!("Cannot set peer without an endpoint!"),
                    },
                    allowed_ips: peer
                        .allowed_ips
                        .iter()
                        .map(|allowed_ip| match allowed_ip.ip {
                            IpAddr::V4(v4) => Ipv4Net::new(v4, 32).unwrap().into(),
                            IpAddr::V6(v6) => Ipv6Net::new(v6, 128).unwrap().into(),
                        })
                        .collect::<Vec<_>>(),
                })
                .collect::<Vec<_>>(),
        };

        assert!(adapter.set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix));

        adapter.set_config(&interface).unwrap();
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
