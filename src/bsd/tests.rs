use super::*;

#[test]
fn test_get_mtu() {
    let mtu = get_mtu("lo0").unwrap();
    assert_eq!(mtu, 16384);
}
