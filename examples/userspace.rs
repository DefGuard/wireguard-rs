use std::{
    io::{stdin, stdout, Read, Write},
    net::SocketAddr,
    str::FromStr,
};

use defguard_wireguard_rs::{host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration};
#[cfg(target_os = "macos")]
use defguard_wireguard_rs::{Userspace, WGApi, WireguardInterfaceApi};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn pause() {
    let mut stdout = stdout();
    stdout.write_all(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup API struct for interface management
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun5".into()
    };
    let api = WGApi::<Userspace>::new(ifname.clone())?;

    // create interface
    api.create_interface()?;

    // Peer configuration
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    // Peer secret key
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());

    println!("endpoint");
    // Your WireGuard server endpoint which peer connects too
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
        addresses: vec![
            "10.6.0.30".parse().unwrap(),
            "fc00:def9::0a1d".parse().unwrap(),
        ],
        port: 12345,
        peers: vec![peer],
        mtu: None,
    };

    #[cfg(not(windows))]
    api.configure_interface(&interface_config)?;
    #[cfg(windows)]
    api.configure_interface(&interface_config, &[])?;

    println!("Interface {ifname} configured.");
    pause();

    api.remove_interface()?;

    println!("Interface {ifname} removed.");

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}
