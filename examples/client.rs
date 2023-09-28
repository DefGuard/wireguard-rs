use std::{net::SocketAddr, str::FromStr};

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

    // Peer configuration
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    // Peer secret key
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());

    log::info!("endpoint");
    // Your wireguard server endpoint which peer connects too
    let endpoint: SocketAddr = "<server_ip>:<server_port>".parse().unwrap();
    // Peer endpoint and interval
    peer.endpoint = Some(endpoint);
    peer.persistent_keepalive_interval = Some(25);

    // Peer allowed ips
    let allowed_ips = vec!["10.6.0.0/24", "192.168.2.0/24"];
    for allowed_ip in allowed_ips {
        let addr = IpAddrMask::from_str(allowed_ip)?;
        peer.allowed_ips.push(addr);
        // Add a route for the allowed IP using the `ip -4 route add` command
        let output = std::process::Command::new("ip")
            .args(["-4", "route", "add", allowed_ip, "dev", "wg0"])
            .output()?;

        if output.status.success() {
            log::info!("Added route for {}", allowed_ip);
        } else {
            log::error!("Failed to add route for {}: {:?}", allowed_ip, output);
        }
    }

    // interface configuration
    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
        address: "10.6.0.30".to_string(),
        port: 12345,
        peers: vec![peer],
    };

    wgapi.configure_interface(&interface_config)?;

    Ok(())
}
