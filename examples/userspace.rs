use std::{
    io::{stdin, stdout, Read, Write},
    net::SocketAddr,
    str::FromStr,
};
use wireguard_rs::{
    InterfaceConfiguration, IpAddrMask, Key, Peer, WireguardApiUserspace, WireguardInterfaceApi,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

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
    let endpoint: SocketAddr = "10.20.30.40:55001".parse().unwrap();
    // Peer endpoint and interval
    peer.endpoint = Some(endpoint);
    peer.persistent_keepalive_interval = Some(25);

    // Peer allowed ips
    let allowed_ips = vec!["10.6.0.0/24", "192.168.2.0/24"];
    for allowed_ip in allowed_ips {
        let addr = IpAddrMask::from_str(allowed_ip)?;
        peer.allowed_ips.push(addr);
    }

    // interface configuration
    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=".to_string(),
        address: "10.6.0.30".to_string(),
        port: 12345,
        peers: vec![peer],
    };

    api.configure_interface(&interface_config)?;

    println!("Interface {ifname} configured.");
    pause();

    api.remove_interface()?;

    println!("Interface {ifname} removed.");

    Ok(())
}
