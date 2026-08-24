use super::*;

const SERVERS: [IpAddr; 1] = [IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))];

#[test]
fn legacy_config_without_search_domains_resolves_everything() {
    let config = DnsConfig::from_legacy(&SERVERS, &[]);
    assert!(config.default_route);
    assert!(!config.has_domains());
    assert!(!config.is_unused());
}

#[test]
fn legacy_config_with_search_domains_is_not_a_default_route() {
    let config = DnsConfig::from_legacy(&SERVERS, &["corp.example.com"]);
    assert!(!config.default_route);
    assert!(config.has_domains());
    assert!(!config.is_unused());
}

#[test]
fn config_without_domains_and_without_default_route_is_unused() {
    assert!(DnsConfig::split_dns(&SERVERS, &[], &[]).is_unused());
    assert!(!DnsConfig::full_tunnel(&SERVERS).is_unused());
}

#[cfg(target_os = "linux")]
#[test]
fn resolved_domains_mark_routing_only_domains() {
    let config = DnsConfig::split_dns(&SERVERS, &["corp.example.com"], &["example.net"]);
    assert_eq!(
        config.resolved_domain_args(),
        ["corp.example.com", "~example.net"]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn resolved_domains_route_everything_for_a_full_tunnel() {
    assert_eq!(
        DnsConfig::full_tunnel(&SERVERS).resolved_domain_args(),
        ["~."]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn resolved_domains_are_cleared_explicitly() {
    // `resolvectl domain <link>` without any argument would print the current settings
    // instead of clearing them.
    assert_eq!(
        DnsConfig::split_dns(&SERVERS, &[], &[]).resolved_domain_args(),
        [""]
    );
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
#[test]
fn resolvconf_stdin_holds_a_single_search_line() {
    let config = DnsConfig::split_dns(&SERVERS, &["corp.example.com"], &["example.net"]);
    assert_eq!(
        config.resolvconf_stdin(),
        "nameserver 10.0.0.1\nsearch corp.example.com example.net\n"
    );
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
#[test]
fn resolvconf_stdin_omits_an_empty_search_line() {
    assert_eq!(
        DnsConfig::full_tunnel(&SERVERS).resolvconf_stdin(),
        "nameserver 10.0.0.1\n"
    );
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
#[test]
fn resolvconf_marks_a_full_tunnel_exclusive() {
    let config = DnsConfig::full_tunnel(&SERVERS);
    assert_eq!(config.resolvconf_mode_args(false), ["-m", "0", "-x"]);
    assert_eq!(config.resolvconf_mode_args(true), ["-m", "0", "-x"]);
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
#[test]
fn resolvconf_marks_a_split_dns_interface_private_when_possible() {
    let config = DnsConfig::split_dns(&SERVERS, &["corp.example.com"], &[]);
    assert_eq!(config.resolvconf_mode_args(true), ["-p"]);
    // Without a local resolver the servers have to stay first, or the internal zones
    // would not resolve at all.
    assert_eq!(config.resolvconf_mode_args(false), ["-m", "0"]);
}

#[test]
fn nrpt_namespaces_match_suffixes() {
    let config = DnsConfig::split_dns(&SERVERS, &["Corp.Example.COM"], &["10.in-addr.arpa."]);
    // Lower cased, trailing dot dropped, leading dot added so the rule matches every name
    // below the suffix rather than the suffix itself.
    assert_eq!(
        config.nrpt_namespaces(),
        [".corp.example.com", ".10.in-addr.arpa"]
    );
}

#[test]
fn nrpt_namespaces_of_a_full_tunnel_are_the_whole_namespace() {
    // A catch-all rule already covers the configured domains, so it replaces them.
    let mut config = DnsConfig::full_tunnel(&SERVERS);
    assert_eq!(config.nrpt_namespaces(), ["."]);
    config.search_domains = &["corp.example.com"];
    assert_eq!(config.nrpt_namespaces(), ["."]);
}

#[test]
fn nrpt_namespaces_are_deduplicated_and_skip_empty_domains() {
    let config = DnsConfig::split_dns(
        &SERVERS,
        &["corp.example.com", "  "],
        &[".CORP.example.com", ""],
    );
    assert_eq!(config.nrpt_namespaces(), [".corp.example.com"]);
}

#[test]
fn nrpt_namespaces_are_empty_without_domains() {
    assert!(
        DnsConfig::split_dns(&SERVERS, &[], &[])
            .nrpt_namespaces()
            .is_empty()
    );
}

#[test]
fn nrpt_rule_keys_name_the_interface_they_belong_to() {
    let key = nrpt::rule_key_name("A1B2C3D4-0000-0000-0000-000000000000", 2);
    assert_eq!(
        key,
        "defguard-wireguard-A1B2C3D4-0000-0000-0000-000000000000-2"
    );
    assert_eq!(
        nrpt::rule_key_interface_id(&key),
        Some("A1B2C3D4-0000-0000-0000-000000000000")
    );
    // Registry key names are case insensitive.
    assert_eq!(
        nrpt::rule_key_interface_id("DEFGUARD-WIREGUARD-abc-0"),
        Some("abc")
    );
}

#[test]
fn rules_of_other_software_are_not_recognized_as_ours() {
    assert_eq!(nrpt::rule_key_interface_id("{some-other-rule}"), None);
    assert_eq!(nrpt::rule_key_interface_id("defguard-wireguard-"), None);
    // No trailing rule index.
    assert_eq!(nrpt::rule_key_interface_id("defguard-wireguard-abc"), None);
    assert_eq!(
        nrpt::rule_key_interface_id("defguard-wireguard-abc-notanindex"),
        None
    );
    // Shorter than the prefix, and not a char boundary panic either.
    assert_eq!(nrpt::rule_key_interface_id("defguard"), None);
    assert_eq!(nrpt::rule_key_interface_id("ł"), None);
}

#[test]
fn nrpt_servers_are_semicolon_separated() {
    let servers = [
        IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ];
    assert_eq!(nrpt::servers_value(&servers), "10.0.0.1;::1");
    assert_eq!(nrpt::servers_value(&[]), "");
}

#[test]
fn multi_sz_terminates_every_string_and_the_list() {
    assert_eq!(
        nrpt::multi_sz(&["ab".to_string(), "c".to_string()]),
        [0x61, 0x62, 0, 0x63, 0, 0]
    );
    // An empty list is just the list terminator.
    assert_eq!(nrpt::multi_sz(&[]), [0]);
}

#[test]
fn every_domain_becomes_a_namespace_of_its_own() {
    // Long domain lists are what the per-rule limit has to spread over several rules, so
    // none of them may be lost or merged on the way in.
    let domains = (0..120)
        .map(|index| format!("d{index}.example.com"))
        .collect::<Vec<_>>();
    let domains = domains.iter().map(String::as_str).collect::<Vec<_>>();
    let namespaces = DnsConfig::split_dns(&SERVERS, &domains, &[]).nrpt_namespaces();
    assert_eq!(namespaces.len(), 120);
    assert_eq!(namespaces[119], ".d119.example.com");
}
