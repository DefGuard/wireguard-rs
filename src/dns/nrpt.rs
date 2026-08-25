//! The Windows Name Resolution Policy Table, the one mechanism on that platform which picks a
//! resolver per namespace.

use std::net::IpAddr;

/// Registry path holding the local (as opposed to group policy) Name Resolution Policy Table.
pub(crate) const POLICY_CONFIG_PATH: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// `ConfigOptions` bit telling the DNS client to resolve the rule's namespaces through the
/// servers listed in its `GenericDNSServers` value.
pub(crate) const CONFIG_OPTION_OVERRIDE_DNS: u32 = 0x8;

/// Value of the `Version` entry every NRPT rule carries.
pub(crate) const RULE_VERSION: u32 = 1;

/// Windows ignores the whole policy table when a single rule carries more namespaces than this,
/// so longer domain lists have to be spread over several rules.
pub(crate) const MAX_NAMESPACES_PER_RULE: usize = 50;

/// Prefix of every NRPT rule key owned by this crate.
///
/// Rule keys are named after the interface they belong to, which makes it possible to replace or
/// remove exactly the rules of one interface, and to recognize the ones left behind by a process
/// which did not get to clean up after itself.
const RULE_KEY_PREFIX: &str = "defguard-wireguard-";

/// Normalizes a domain into an NRPT namespace, returning `None` for an empty one.
pub(crate) fn namespace(domain: &str) -> Option<String> {
    let domain = domain.trim();
    // A lone dot already is the whole namespace.
    if domain == "." {
        return Some(domain.to_string());
    }
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    let mut namespace = domain.to_lowercase();
    // Without a leading dot a rule matches only that exact name, not the names below it.
    if !namespace.starts_with('.') {
        namespace.insert(0, '.');
    }
    Some(namespace)
}

/// Builds the registry key name of one of an interface's NRPT rules.
pub(crate) fn rule_key_name(interface_id: &str, index: usize) -> String {
    format!("{RULE_KEY_PREFIX}{interface_id}-{index}")
}

/// Returns the interface a rule key belongs to, or `None` if the key is not one of ours.
pub(crate) fn rule_key_interface_id(key: &str) -> Option<&str> {
    // Registry key names are case insensitive, so the case they come back in is not guaranteed
    // to be the one they were written with.
    let head = key.get(..RULE_KEY_PREFIX.len())?;
    if !head.eq_ignore_ascii_case(RULE_KEY_PREFIX) {
        return None;
    }
    let (interface_id, index) = key[RULE_KEY_PREFIX.len()..].rsplit_once('-')?;
    // Anything without the trailing rule index was named by something else.
    index.parse::<usize>().ok()?;
    (!interface_id.is_empty()).then_some(interface_id)
}

/// Formats the DNS servers for a rule's `GenericDNSServers` value.
pub(crate) fn servers_value(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

/// Encodes strings into the `REG_MULTI_SZ` representation: every string NUL terminated, followed
/// by one more NUL closing the list.
pub(crate) fn multi_sz(values: &[String]) -> Vec<u16> {
    let mut buffer = Vec::new();
    for value in values {
        buffer.extend(value.encode_utf16());
        buffer.push(0);
    }
    buffer.push(0);
    buffer
}
