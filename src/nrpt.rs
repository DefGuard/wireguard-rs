use std::net::IpAddr;

use uuid::Uuid;

/// Namespace UUID for deriving NRPT rule GUIDs via UUIDv5. Arbitrary but fixed
/// so derived GUIDs stay stable across builds; has no meaning beyond that.
const NRPT_RULE_NAMESPACE: Uuid = Uuid::from_bytes([
    0x45, 0x91, 0x5b, 0x78, 0xfd, 0x48, 0x40, 0xa5, 0x92, 0x74, 0x17, 0xcb, 0x15, 0x80, 0x32, 0x13,
]);

/// Prefix written to each rule's `Comment` value so we can find and remove only
/// the rules we created for a given interface.
pub(crate) const NRPT_COMMENT_PREFIX: &str = "defguard:";

/// Marker written to the `Comment` value of every NRPT rule created for `ifname`.
pub(crate) fn nrpt_comment(ifname: &str) -> String {
    format!("{NRPT_COMMENT_PREFIX}{ifname}")
}

/// Normalizes a search domain into an NRPT namespace in suffix-match form.
/// `example.com` becomes `.example.com`; an already dotted value is kept as is.
pub(crate) fn nrpt_namespace(domain: &str) -> String {
    let trimmed = domain.trim();
    if trimmed.starts_with('.') {
        trimmed.to_string()
    } else {
        format!(".{trimmed}")
    }
}

/// Joins DNS server IPs into the `;`-separated form NRPT stores in
/// `GenericDNSServers`.
pub(crate) fn nrpt_dns_servers(dns: &[IpAddr]) -> String {
    dns.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

/// Derives a stable registry subkey GUID (in brace form) for an interface +
/// namespace pair. Deterministic so reconnecting overwrites the same subkey
/// instead of accumulating duplicates.
pub(crate) fn nrpt_rule_guid(ifname: &str, namespace: &str) -> String {
    let seed = format!("{ifname}\u{0}{namespace}");
    let uuid = Uuid::new_v5(&NRPT_RULE_NAMESPACE, seed.as_bytes());
    format!("{{{uuid}}}")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn namespace_gets_leading_dot() {
        assert_eq!(nrpt_namespace("example.com"), ".example.com");
        assert_eq!(nrpt_namespace("corp.local"), ".corp.local");
    }

    #[test]
    fn namespace_preserves_existing_dot_and_trims() {
        assert_eq!(nrpt_namespace(".example.com"), ".example.com");
        assert_eq!(nrpt_namespace("  example.com  "), ".example.com");
    }

    #[test]
    fn dns_servers_are_semicolon_joined() {
        let dns = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 54)),
        ];
        assert_eq!(nrpt_dns_servers(&dns), "10.0.0.53;10.0.0.54");
    }

    #[test]
    fn dns_servers_handles_ipv6() {
        let dns = vec![IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))];
        assert_eq!(nrpt_dns_servers(&dns), "fd00::1");
    }

    #[test]
    fn dns_servers_empty() {
        assert_eq!(nrpt_dns_servers(&[]), "");
    }

    #[test]
    fn comment_marker_includes_interface() {
        assert_eq!(nrpt_comment("wg0"), "defguard:wg0");
        assert!(nrpt_comment("wg0").starts_with(NRPT_COMMENT_PREFIX));
    }

    #[test]
    fn guid_is_stable_for_same_inputs() {
        let a = nrpt_rule_guid("wg0", ".example.com");
        let b = nrpt_rule_guid("wg0", ".example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn guid_differs_by_namespace_and_interface() {
        let base = nrpt_rule_guid("wg0", ".example.com");
        assert_ne!(base, nrpt_rule_guid("wg0", ".other.com"));
        assert_ne!(base, nrpt_rule_guid("wg1", ".example.com"));
    }

    #[test]
    fn guid_has_registry_brace_form() {
        let guid = nrpt_rule_guid("wg0", ".example.com");
        assert!(guid.starts_with('{') && guid.ends_with('}'));
        // 32 hex digits + 4 dashes + 2 braces = 38 chars.
        assert_eq!(guid.len(), 38);
        assert_eq!(guid.matches('-').count(), 4);
    }
}
