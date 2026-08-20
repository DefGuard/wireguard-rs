use std::{
    io::{self, Read, Write, stdin, stdout},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use defguard_wireguard_rs::{
    InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi, key::Key, net::IpAddrMask,
    peer::Peer,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn pause() -> io::Result<()> {
    let mut stdout = stdout();
    stdout.write_all(b"Press Enter to continue...")?;
    stdout.flush()?;
    stdin().read_exact(&mut [0])?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    #[cfg(not(target_os = "macos"))]
    let ifname = String::from("tun0");
    #[cfg(target_os = "macos")]
    let ifname = String::from("utun5");
    let mut api = WGApi::<Userspace>::new(ifname.clone())?;

    api.create_interface()?;

    // Peer configuration
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    // Peer secret key
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());

    // WireGuard server endpoint which peer connects to.
    let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 55001);
    // Peer endpoint and interval.
    peer.endpoint = Some(endpoint);
    peer.persistent_keepalive_interval = Some(25);

    // Peer allowed ips
    let allowed_ips = ["10.6.0.0/24", "192.168.2.0/24"];
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
        fwmark: None,
    };

    #[cfg(not(windows))]
    api.configure_interface(&interface_config)?;
    #[cfg(windows)]
    api.configure_interface(&interface_config, &[])?;

    println!("Interface {ifname} configured.");
    pause().unwrap();

    api.remove_interface()?;

    println!("Interface {ifname} removed.");

    Ok(())
}
