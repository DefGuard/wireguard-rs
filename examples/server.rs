use std::str::FromStr;

use wireguard_rs::{
    wgapi::WGApi, InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardInterfaceApi,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create new api object for interface
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun3".into()
    };
    let wgapi = WGApi::new(ifname.clone(), false)?;
    let host = wgapi.read_interface_data()?;
    log::debug!("{host:#?}");

    // host
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());
    let addr = IpAddrMask::from_str("10.20.30.40/24").unwrap();
    peer.allowed_ips.push(addr);

    // Create host interfaces
    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
        address: "10.6.0.30".to_string(),
        port: 12345,
        peers: vec![peer],
    };

    wgapi.configure_interface(&interface_config)?;

    // Create peers
    for _ in 0..32 {
        let secret = EphemeralSecret::random();
        let key = PublicKey::from(&secret);
        let peer = Peer::new(key.as_ref().try_into().unwrap());
        wgapi.configure_peer(&peer)?;
        wgapi.remove_peer(&peer.public_key)?;
    }

    Ok(())
}
