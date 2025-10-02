use std::str::FromStr;

use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create new api object for interface management
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun3".into()
    };

    #[cfg(not(target_os = "macos"))]
    let mut wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
    #[cfg(target_os = "macos")]
    let mut wgapi = WGApi::<defguard_wireguard_rs::Userspace>::new(ifname.clone())?;

    // create host interface
    wgapi.create_interface()?;

    // read current interface status
    let host = wgapi.read_interface_data()?;
    println!("WireGuard interface before configuration: {host:#?}");

    // store peer keys to remove peers later
    let mut peer_keys = Vec::new();

    // prepare initial WireGuard interface configuration with one client
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    let peer_key: Key = key.as_ref().try_into().unwrap();
    peer_keys.push(peer_key.clone());
    let mut peer = Peer::new(peer_key);
    let addr = IpAddrMask::from_str("10.20.30.2/32").unwrap();
    peer.allowed_ips.push(addr);

    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
        addresses: vec!["10.6.0.30".parse().unwrap()],
        port: 12345,
        peers: vec![peer],
        mtu: None,
    };
    println!("Prepared interface configuration: {interface_config:?}");

    // apply initial interface configuration
    #[cfg(not(windows))]
    wgapi.configure_interface(&interface_config)?;
    #[cfg(windows)]
    wgapi.configure_interface(&interface_config, &[])?;

    // read current interface status
    let host = wgapi.read_interface_data()?;
    println!("WireGuard interface after configuration: {host:#?}");

    // add more WireGuard clients
    for peer_id in 3..13 {
        let secret = EphemeralSecret::random();
        let key = PublicKey::from(&secret);
        let peer_key: Key = key.as_ref().try_into().unwrap();
        peer_keys.push(peer_key.clone());
        let mut peer = Peer::new(peer_key);
        let addr = IpAddrMask::from_str(&format!("10.20.30.{peer_id}/32")).unwrap();
        peer.allowed_ips.push(addr);
        // add peer to WireGuard interface
        wgapi.configure_peer(&peer)?;
    }

    // read current interface status
    let host = wgapi.read_interface_data()?;
    println!("WireGuard interface with peers: {host:#?}");

    // remove all peers
    for peer_key in peer_keys {
        wgapi.remove_peer(&peer_key)?;
    }

    // read current interface status
    let host = wgapi.read_interface_data()?;
    println!("WireGuard interface without peers: {host:#?}");

    // remove interface
    wgapi.remove_interface()?;

    Ok(())
}
