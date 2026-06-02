use std::net::Ipv4Addr;

use super::*;

#[ignore = "requires root access"]
#[test]
fn test_assign_address() {
    let ifname = "lo0";
    let address = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(127, 1, 1, 1)), 8);
    assign_address(ifname, &address).unwrap();
    // TODO: get_address()
    remove_address(ifname, &address).unwrap();
}

#[test]
fn test_get_mtu() {
    let ifname = "lo0";
    let mtu = get_mtu(ifname).unwrap();
    assert_eq!(mtu, 16384);
}
