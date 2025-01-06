use std::{net::SocketAddr, str::FromStr};

use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, Kernel, Userspace, WGApi,
    WireguardInterfaceApi,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create new API object for interface
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun3".into()
    };

    #[cfg(not(target_os = "macos"))]
    let wgapi = WGApi::<Kernel>::new(ifname.clone())?;
    #[cfg(target_os = "macos")]
    let wgapi = WGApi::<Userspace>::new(ifname.clone())?;

    // create interface
    wgapi.create_interface()?;

    // Peer configuration
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    // Peer secret key
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());

    log::info!("endpoint");
    // Your WireGuard server endpoint which client connects to
    let endpoint: SocketAddr = "10.10.10.10:55001".parse().unwrap();
    // Peer endpoint and interval
    peer.endpoint = Some(endpoint);
    peer.persistent_keepalive_interval = Some(25);
    peer.allowed_ips.push(IpAddrMask::from_str("10.6.0.0/24")?);
    peer.allowed_ips
        .push(IpAddrMask::from_str("192.168.22.0/24")?);

    // interface configuration
    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
        addresses: vec!["10.6.0.30".parse().unwrap()],
        port: 12345,
        peers: vec![peer],
        mtu: None,
    };

    #[cfg(not(windows))]
    wgapi.configure_interface(&interface_config)?;
    #[cfg(windows)]
    wgapi.configure_interface(&interface_config, &[], &[])?;
    wgapi.configure_peer_routing(&interface_config.peers)?;

    Ok(())
}
