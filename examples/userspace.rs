use std::{net::SocketAddr, str::FromStr};
use wireguard_rs::{
    InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardApiUserspace, WireguardInterfaceApi,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup API struct for interface management
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun3".into()
    };
    let api = WireguardApiUserspace::new(ifname.clone())?;

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
            .args(&["-4", "route", "add", allowed_ip, "dev", "wg0"])
            .output()?;

        if output.status.success() {
            log::info!("Added route for {}", allowed_ip);
        } else {
            log::error!("Failed to add route for {}: {:?}", allowed_ip, output);
        }
    }

    // interface configuration
    let prvkey: Key = StaticSecret::random()
        .to_bytes()
        .as_ref()
        .try_into()
        .unwrap();
    let interface_config = InterfaceConfiguration {
        name: ifname,
        prvkey: prvkey.to_lower_hex(),
        address: "10.6.0.30".to_string(),
        port: 12345,
        peers: vec![peer],
    };

    api.configure_interface(&interface_config)?;

    Ok(())
}
