use std::str::FromStr;

use log;
#[cfg(target_os = "linux")]
use wireguard_rs::netlink::{address_interface, create_interface};
use wireguard_rs::{wgapi::WGApi, Host, IpAddrMask, Key, Peer};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        log::debug!("create interface");
        create_interface("wg0")?;
        log::debug!("address interface");
        let addr = IpAddrMask::from_str("10.20.30.40/24").unwrap();
        address_interface("wg0", &addr)?;
    }
    let api = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        WGApi::new("wg0".into(), false)
    } else {
        WGApi::new("utun3".into(), true)
    };
    let host = api.read_host()?;
    log::debug!("{host:#?}");

    // host
    let secret = StaticSecret::random();
    let mut host = Host::new(12345, secret.to_bytes().as_ref().try_into().unwrap());

    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());
    let addr = IpAddrMask::from_str("10.20.30.40/24").unwrap();
    peer.allowed_ips.push(addr);
    // Insert peers to host
    host.peers.insert(peer_key, peer);

    // Create host interfaces
    api.write_host(&host)?;

    // Create peers
    for _ in 0..32 {
        let secret = EphemeralSecret::random();
        let key = PublicKey::from(&secret);
        let peer = Peer::new(key.as_ref().try_into().unwrap());
        api.write_peer(&peer)?;
        api.delete_peer(&peer)?;
    }

    Ok(())
}
