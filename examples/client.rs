use std::{net::SocketAddr, str::FromStr};

#[cfg(target_os = "linux")]
use wireguard_rs::netlink::{address_interface, create_interface};
use wireguard_rs::{wgapi::WGApi, Host, IpAddrMask, Key, Peer};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        println!("create interface");
        create_interface("wg0")?;
        println!("address interface");
        let addr = IpAddrMask::from_str("10.6.0.30").unwrap();
        address_interface("wg0", &addr)?;
    }
    let api = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        WGApi::new("wg0".into(), false)
    } else {
        WGApi::new("utun3".into(), true)
    };
    // host
    let secret = StaticSecret::random();
    let host = Host::new(12345, secret.to_bytes().as_ref().try_into().unwrap());

    // Peer configuration
    let secret = EphemeralSecret::random();
    let key = PublicKey::from(&secret);
    let peer_key: Key = key.as_ref().try_into().unwrap();
    let mut peer = Peer::new(peer_key.clone());

    println!("endpoint");
    let endpoint: SocketAddr = "<server_ip>:<server_port>".parse().unwrap();
    peer.endpoint = Some(endpoint);

    let allowed_ips = vec!["10.6.0.0/24", "192.168.2.0/24"];
    for allowed_ip in allowed_ips {
        let addr = IpAddrMask::from_str(allowed_ip)?;
        peer.allowed_ips.push(addr);
        // Add a route for the allowed IP using the `ip -4 route add` command
        let output = std::process::Command::new("ip")
            .args(&["-4", "route", "add", allowed_ip, "dev", "wg0"])
            .output()?;

        if output.status.success() {
            println!("Added route for {}", allowed_ip);
        } else {
            eprintln!("Failed to add route for {}: {:?}", allowed_ip, output);
        }
    }
    api.write_host(&host)?;
    api.write_peer(&peer)?;

    Ok(())
}
