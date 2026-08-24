//! DNS configuration for WireGuard interfaces.
//!
//! The entry point is [`DnsConfig`], which describes *what* should be resolved through the
//! tunnel, not merely which servers to use. Unlike the `resolvconf` stdin protocol, it can
//! express proper split DNS: a set of suffixes resolved by the tunnel's DNS servers while every
//! other name keeps using the resolvers already configured on the system.
//!
//! How much of that can actually be honored depends on the platform's DNS backend, see
//! [`DnsBackend`] and [`detect_dns_backend`].

#[cfg(target_os = "macos")]
use std::io::{Cursor, Error as IoError};
use std::net::IpAddr;
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use std::{
    fs::{File, read_dir},
    io::Write,
    path::Path,
    process::Stdio,
};
#[cfg(not(target_os = "windows"))]
use std::{
    io::{BufRead, BufReader},
    process::Command,
};

use crate::error::WireguardInterfaceError;
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
use crate::{check_command_output_status, utils::get_command_path};

/// DNS settings for a WireGuard interface.
///
/// Three concepts are kept apart here, because platform DNS backends treat them differently:
///
/// * [`search_domains`](Self::search_domains) - suffixes appended to unqualified names. On
///   backends capable of split DNS they are *also* routed to [`servers`](Self::servers).
/// * [`routing_domains`](Self::routing_domains) - suffixes routed to [`servers`](Self::servers)
///   without being used to complete unqualified names (systemd-resolved's `~domain`).
/// * [`default_route`](Self::default_route) - whether [`servers`](Self::servers) should also
///   answer names matching none of the domains above (systemd-resolved's `~.`,
///   `resolvconf -x`).
///
/// # Examples
///
/// Resolve everything through the tunnel, which is what `wg-quick` does for a `DNS =` line
/// without any search domain:
///
/// ```
/// # use std::net::IpAddr;
/// # use defguard_wireguard_rs::dns::DnsConfig;
/// let servers = ["10.0.0.1".parse::<IpAddr>().unwrap()];
/// let config = DnsConfig::full_tunnel(&servers);
/// ```
///
/// Resolve only the internal zones through the tunnel and leave every other name to the
/// resolvers of the network the host is currently attached to:
///
/// ```
/// # use std::net::IpAddr;
/// # use defguard_wireguard_rs::dns::DnsConfig;
/// let servers = ["10.0.0.1".parse::<IpAddr>().unwrap()];
/// let config = DnsConfig::split_dns(&servers, &["corp.example.com"], &["10.in-addr.arpa"]);
/// ```
#[derive(Debug, Default)]
pub struct DnsConfig<'a> {
    /// DNS servers reachable through the tunnel.
    pub servers: &'a [IpAddr],
    /// Suffixes used to complete unqualified names, and resolved by `servers`.
    pub search_domains: &'a [&'a str],
    /// Suffixes resolved by `servers`, but never used to complete unqualified names.
    pub routing_domains: &'a [&'a str],
    /// Whether `servers` should answer names matching none of the configured domains.
    pub default_route: bool,
}

impl<'a> DnsConfig<'a> {
    /// Resolves the whole DNS namespace through `servers`.
    #[must_use]
    pub const fn full_tunnel(servers: &'a [IpAddr]) -> Self {
        Self {
            servers,
            search_domains: &[],
            routing_domains: &[],
            default_route: true,
        }
    }

    /// Resolves only the given domains through `servers`, leaving every other name to the
    /// resolvers already configured on the system.
    #[must_use]
    pub const fn split_dns(
        servers: &'a [IpAddr],
        search_domains: &'a [&'a str],
        routing_domains: &'a [&'a str],
    ) -> Self {
        Self {
            servers,
            search_domains,
            routing_domains,
            default_route: false,
        }
    }

    /// Reproduces the behaviour of
    /// [`configure_dns`](crate::WireguardInterfaceApi::configure_dns): the servers become the
    /// preferred route for every domain if, and only if, no search domain was given.
    #[must_use]
    pub const fn from_legacy(servers: &'a [IpAddr], search_domains: &'a [&'a str]) -> Self {
        Self {
            servers,
            search_domains,
            routing_domains: &[],
            default_route: search_domains.is_empty(),
        }
    }

    /// Returns `true` if any domain is routed to `servers`.
    #[must_use]
    pub const fn has_domains(&self) -> bool {
        !self.search_domains.is_empty() || !self.routing_domains.is_empty()
    }

    /// Returns `true` if this configuration can never route a query to `servers`.
    #[must_use]
    pub const fn is_unused(&self) -> bool {
        !self.default_route && !self.has_domains()
    }

    /// Builds the domain list for `resolvectl domain`.
    ///
    /// Search domains are passed as-is, routing-only domains are prefixed with `~`, and `~.` is
    /// appended when the servers should also answer everything else. `resolvectl` needs an explicit
    /// empty argument to clear a link's domain list.
    #[cfg(target_os = "linux")]
    fn resolved_domain_args(&self) -> Vec<String> {
        let mut domains = self
            .search_domains
            .iter()
            .map(|domain| (*domain).to_string())
            .chain(
                self.routing_domains
                    .iter()
                    .map(|domain| format!("~{domain}")),
            )
            .collect::<Vec<_>>();
        if self.default_route {
            domains.push("~.".to_string());
        }
        if domains.is_empty() {
            domains.push(String::new());
        }
        domains
    }

    /// Configures DNS through `systemd-resolved`.
    ///
    /// This is the only backend on which [`DnsConfig`] can be honored in full.
    #[cfg(target_os = "linux")]
    fn configure_dns_resolved(&self, ifname: &str) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring DNS for interface {ifname} through systemd-resolved");

        let servers = self
            .servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut args = vec!["dns", ifname];
        args.extend(servers.iter().map(String::as_str));
        resolvectl(&args)?;

        let domains = self.resolved_domain_args();
        let mut args = vec!["domain", ifname];
        args.extend(domains.iter().map(String::as_str));
        resolvectl(&args)?;

        // Set this explicitly instead of relying on the implicit default, which depends on whether
        // the link has routing domains configured.
        let default_route = if self.default_route { "yes" } else { "no" };
        resolvectl(&["default-route", ifname, default_route])?;

        flush_resolved_caches();

        debug!("DNS configured successfully for interface {ifname} through systemd-resolved");
        Ok(())
    }

    /// Applies `config` to the given interface, using whichever DNS backend this host provides.
    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
    pub(crate) fn configure_dns(&self, ifname: &str) -> Result<(), WireguardInterfaceError> {
        debug!("Starting DNS configuration for interface {ifname}: {self:?}");
        if self.servers.is_empty() {
            warn!("Received empty DNS server list. Skipping DNS configuration...");
            return Ok(());
        }
        if self.is_unused() {
            warn!(
                "DNS servers {:?} have been configured for interface {ifname} without any domain \
                and without the default route flag, so no query will ever be sent to them.",
                self.servers
            );
        }

        match detect_dns_backend()? {
            #[cfg(target_os = "linux")]
            DnsBackend::SystemdResolved => self.configure_dns_resolved(ifname),
            DnsBackend::Openresolv { local_resolver } => {
                self.configure_dns_resolvconf(ifname, local_resolver)
            }
        }
    }

    /// Configures DNS through `resolvconf`.
    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
    fn configure_dns_resolvconf(
        &self,
        ifname: &str,
        local_resolver: bool,
    ) -> Result<(), WireguardInterfaceError> {
        if !self.default_route && !local_resolver {
            warn!(
                "Split DNS has been requested for interface {ifname}, but this host configures DNS \
                through resolvconf without a local resolver, and the resolv.conf format cannot \
                express which resolver answers which domain. The DNS servers of the interface will \
                be used for every query instead, and names which only the resolvers of the local \
                network know may stop resolving. Install systemd-resolved, or let resolvconf drive \
                a local resolver ({}), to get split DNS on this host.",
                LOCAL_RESOLVERS.join(", ")
            );
        }
        if !self.routing_domains.is_empty() {
            debug!(
                "resolvconf cannot express routing-only domains, so {:?} will also be used to \
                complete unqualified names on interface {ifname}",
                self.routing_domains
            );
        }

        let resolvconf_ifname = construct_resolvconf_ifname(ifname);
        let mut args = vec!["-a", resolvconf_ifname.as_str()];
        args.extend(self.resolvconf_mode_args(local_resolver));
        debug!("Executing {RESOLVCONF} with args: {args:?}");

        let mut child = Command::new(RESOLVCONF)
            .args(&args)
            .stdin(Stdio::piped())
            .spawn()?;
        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                WireguardInterfaceError::DnsError(format!(
                    "Failed to open the stdin of the `{RESOLVCONF}` command"
                ))
            })?;
            let contents = self.resolvconf_stdin();
            trace!("Writing the following configuration to {RESOLVCONF} stdin: {contents}");
            stdin.write_all(contents.as_bytes())?;
            // Dropping stdin closes the pipe, which lets resolvconf proceed.
        }

        let status = child.wait()?;
        if status.success() {
            debug!("DNS configured successfully for interface {ifname} through {RESOLVCONF}");
            Ok(())
        } else {
            Err(WireguardInterfaceError::DnsError(format!(
                "Failed to execute the `{RESOLVCONF}` command while setting DNS servers and search \
                domains: {status}"
            )))
        }
    }

    /// Picks the `resolvconf` flags matching the intent of `config`.
    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
    fn resolvconf_mode_args(&self, local_resolver: bool) -> &'static [&'static str] {
        if self.default_route {
            // Highest priority nameservers, and the preferred route for every domain.
            &["-m", "0", "-x"]
        } else if local_resolver {
            // A local resolver can forward per domain, so mark the interface private: its
            // nameservers are then used only for the domains it declares.
            &["-p"]
        } else {
            // Nothing here can express per-domain resolution, so keep the tunnel's nameservers
            // first to make sure the internal zones resolve at all.
            &["-m", "0"]
        }
    }

    /// Builds the `resolv.conf`-formatted configuration piped to `resolvconf` on stdin.
    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
    fn resolvconf_stdin(&self) -> String {
        let mut stdin = String::new();
        for server in self.servers {
            stdin.push_str(&format!("nameserver {server}\n"));
        }
        // Routing-only domains have to be declared as search domains here, as that is the only way
        // of telling resolvconf which domains this interface resolves.
        let domains = self
            .search_domains
            .iter()
            .chain(self.routing_domains)
            .copied()
            .collect::<Vec<_>>();
        if !domains.is_empty() {
            // resolv.conf(5) holds a single search list, and a second `search` line overrides the
            // first one rather than extending it.
            stdin.push_str(&format!("search {}\n", domains.join(" ")));
        }
        stdin
    }

    /// Applies `config` to every macOS network service.
    ///
    /// `networksetup` only knows global resolvers, so [`DnsConfig::routing_domains`] and
    /// [`DnsConfig::default_route`] cannot be honored here: the DNS servers of the tunnel answer
    /// every query for as long as it is up. Scoped resolvers (`/etc/resolver/<domain>`) would be
    /// needed for split DNS on this platform.
    #[cfg(target_os = "macos")]
    pub(crate) fn configure_dns(&self) -> Result<(), WireguardInterfaceError> {
        debug!("Configuring DNS: {self:?}");
        if !self.routing_domains.is_empty() {
            warn!(
                "Routing-only domains {:?} have been requested, but macOS DNS servers are \
                configured globally, so these domains cannot be resolved separately and will be \
                ignored.",
                self.routing_domains
            );
        }
        if !self.default_route && !self.servers.is_empty() {
            debug!(
                "Split DNS has been requested, but macOS DNS servers are configured globally, so \
                {:?} will answer every query while the interface is up.",
                self.servers
            );
        }

        debug!("Setting DNS servers and search domains for all network services");
        for service in network_services()? {
            debug!(
                "Setting DNS entries (search domains and DNS servers) for network service {service}"
            );
            let mut cmd = Command::new("networksetup");
            cmd.arg("-setdnsservers").arg(&service);
            if self.servers.is_empty() {
                // This clears all DNS entries.
                cmd.arg("Empty");
            } else {
                cmd.args(self.servers.iter().map(ToString::to_string));
            }

            let status = cmd.status()?;
            if !status.success() {
                return Err(WireguardInterfaceError::DnsError(format!(
                    "Command `networksetup` failed while setting DNS servers for {service}: {status}"
                )));
            }
            debug!("DNS servers set successfully for {service}");

            // Set search domains, if empty, clear all search domains.
            debug!("Setting search domains for {service}");
            let mut cmd = Command::new("networksetup");
            cmd.arg("-setsearchdomains").arg(&service);
            if self.search_domains.is_empty() {
                // This clears all search domains.
                cmd.arg("Empty");
            } else {
                cmd.args(self.search_domains.iter());
            }

            let status = cmd.status()?;
            if !status.success() {
                return Err(WireguardInterfaceError::DnsError(format!(
                    "Command `networksetup` failed \
                    while setting search domains for {service}: {status}"
                )));
            }

            debug!("Search domains set successfully for {service}");
        }

        debug!("The following DNS configuration was applied successfully: {self:?}");
        Ok(())
    }

    /// Builds the list of NRPT namespaces which have to be resolved through `servers`.
    ///
    /// A namespace with a leading dot matches every name under that suffix, while `.` on its own
    /// matches the whole DNS namespace. Since a catch-all rule already covers every configured
    /// domain, it replaces them rather than being added next to them.
    #[cfg(any(target_os = "windows", test))]
    pub(crate) fn nrpt_namespaces(&self) -> Vec<String> {
        if self.default_route {
            return vec![".".to_string()];
        }
        let mut namespaces = Vec::new();
        for domain in self.search_domains.iter().chain(self.routing_domains) {
            if let Some(namespace) = nrpt_namespace(domain)
                && !namespaces.contains(&namespace)
            {
                namespaces.push(namespace);
            }
        }
        namespaces
    }
}

/// Registry path holding the local (as opposed to group policy) Name Resolution Policy Table.
#[cfg(any(target_os = "windows", test))]
pub(crate) const NRPT_POLICY_CONFIG_PATH: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// `ConfigOptions` bit telling the DNS client to resolve the rule's namespaces through the
/// servers listed in its `GenericDNSServers` value.
#[cfg(any(target_os = "windows", test))]
pub(crate) const NRPT_CONFIG_OPTION_OVERRIDE_DNS: u32 = 0x8;

/// Value of the `Version` entry every NRPT rule carries.
#[cfg(any(target_os = "windows", test))]
pub(crate) const NRPT_RULE_VERSION: u32 = 1;

/// Windows ignores the whole policy table when a single rule carries more namespaces than this,
/// so longer domain lists have to be spread over several rules.
#[cfg(any(target_os = "windows", test))]
pub(crate) const NRPT_MAX_NAMESPACES_PER_RULE: usize = 50;

/// Prefix of every NRPT rule key owned by this crate.
///
/// Rule keys are named after the interface they belong to, which makes it possible to replace or
/// remove exactly the rules of one interface, and to recognize the ones left behind by a process
/// which did not get to clean up after itself.
#[cfg(any(target_os = "windows", test))]
pub(crate) const NRPT_RULE_KEY_PREFIX: &str = "defguard-wireguard-";

/// Normalizes a domain into an NRPT namespace, returning `None` for an empty one.
#[cfg(any(target_os = "windows", test))]
fn nrpt_namespace(domain: &str) -> Option<String> {
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
#[cfg(any(target_os = "windows", test))]
pub(crate) fn nrpt_rule_key_name(interface_id: &str, index: usize) -> String {
    format!("{NRPT_RULE_KEY_PREFIX}{interface_id}-{index}")
}

/// Returns the interface a rule key belongs to, or `None` if the key is not one of ours.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn nrpt_rule_key_interface_id(key: &str) -> Option<&str> {
    // Registry key names are case insensitive, so the case they come back in is not guaranteed
    // to be the one they were written with.
    let head = key.get(..NRPT_RULE_KEY_PREFIX.len())?;
    if !head.eq_ignore_ascii_case(NRPT_RULE_KEY_PREFIX) {
        return None;
    }
    let (interface_id, index) = key[NRPT_RULE_KEY_PREFIX.len()..].rsplit_once('-')?;
    // Anything without the trailing rule index was named by something else.
    index.parse::<usize>().ok()?;
    (!interface_id.is_empty()).then_some(interface_id)
}

/// Formats the DNS servers for a rule's `GenericDNSServers` value.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn nrpt_servers_value(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

/// Encodes strings into the `REG_MULTI_SZ` representation: every string NUL terminated, followed
/// by one more NUL closing the list.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn multi_sz(values: &[String]) -> Vec<u16> {
    let mut buffer = Vec::new();
    for value in values {
        buffer.extend(value.encode_utf16());
        buffer.push(0);
    }
    buffer.push(0);
    buffer
}

/// Mechanism used to apply DNS settings on the current host.
///
/// Only a subset of these can express split DNS, so this is exposed to let callers warn their
/// users up front instead of having a silently degraded configuration. Use
/// [`detect_dns_backend`] to obtain it.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum DnsBackend {
    /// `systemd-resolved` is running and is configured through `resolvectl`.
    /// This is thee only backend which implements per-domain resolution natively, so the whole of
    /// [`DnsConfig`] can be honored.
    #[cfg(target_os = "linux")]
    SystemdResolved,
    /// DNS is configured through `resolvconf`.
    Openresolv {
        /// Whether a subscriber capable of per-domain forwarding (`dnsmasq`, `unbound`,
        /// `pdnsd`) is configured.
        ///
        /// Without one, `resolvconf` can only merge every nameserver into a single
        /// `/etc/resolv.conf`, whose format has no way of expressing which resolver answers
        /// which domain. Split DNS is then impossible, no matter which flags are used.
        local_resolver: bool,
    },
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
impl DnsBackend {
    /// Whether this backend can resolve some domains through the tunnel while leaving the rest
    /// to the resolvers already configured on the system.
    #[must_use]
    pub const fn supports_split_dns(self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::SystemdResolved => true,
            Self::Openresolv { local_resolver } => local_resolver,
        }
    }
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
const RESOLVCONF: &str = "resolvconf";
#[cfg(target_os = "linux")]
const RESOLVECTL: &str = "resolvectl";
#[cfg(target_os = "linux")]
/// Runtime directory of `systemd-resolved`; created when it starts, removed when it stops.
const RESOLVED_RUNTIME_DIR: &str = "/run/systemd/resolve";
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
const IFACE_ORDER_PATH: &str = "/etc/resolvconf/interface-order";
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
const OPENRESOLV_CONF: &str = "/etc/resolvconf.conf";
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
const RESOLVCONF_UPDATE_DIR: &str = "/etc/resolvconf/update.d";
/// Local resolvers `resolvconf` can drive, all of which support per-domain forwarding.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
const LOCAL_RESOLVERS: [&str; 3] = ["dnsmasq", "unbound", "pdnsd"];

/// Detects how DNS should be configured on this host.
///
/// # Errors
///
/// Returns [`WireguardInterfaceError::DnsError`] if no supported backend was found.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
pub fn detect_dns_backend() -> Result<DnsBackend, WireguardInterfaceError> {
    #[cfg(target_os = "linux")]
    if systemd_resolved_available() {
        debug!("Detected systemd-resolved as the DNS backend");
        return Ok(DnsBackend::SystemdResolved);
    }

    if get_command_path(RESOLVCONF)?.is_some() {
        let local_resolver = local_resolver_configured();
        debug!(
            "Detected resolvconf as the DNS backend, local resolver capable of per-domain \
            forwarding configured: {local_resolver}"
        );
        return Ok(DnsBackend::Openresolv { local_resolver });
    }

    Err(WireguardInterfaceError::DnsError(format!(
        "No supported DNS backend found. Neither systemd-resolved nor the `{RESOLVCONF}` \
        command is available on this host."
    )))
}

/// Checks whether `systemd-resolved` is running and can be talked to.
#[cfg(target_os = "linux")]
fn systemd_resolved_available() -> bool {
    if !Path::new(RESOLVED_RUNTIME_DIR).is_dir() {
        debug!("{RESOLVED_RUNTIME_DIR} does not exist, assuming systemd-resolved is not running");
        return false;
    }
    match get_command_path(RESOLVECTL) {
        Ok(Some(_)) => true,
        _ => {
            warn!(
                "systemd-resolved appears to be running, but the `{RESOLVECTL}` command could \
                not be found in PATH. Falling back to `{RESOLVCONF}`, which cannot configure \
                split DNS on this host."
            );
            false
        }
    }
}

/// Checks whether `resolvconf` drives a local resolver, which is what makes per-domain
/// forwarding possible on this backend.
///
/// This is best-effort: it looks for the configuration which enables one of openresolv's
/// subscribers, and for the equivalent hook scripts used by Debian's `resolvconf`.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
fn local_resolver_configured() -> bool {
    // openresolv enables a subscriber by pointing it at the configuration file it should write,
    // e.g. `dnsmasq_conf=/etc/dnsmasq.d/resolvconf`.
    if let Ok(file) = File::open(OPENRESOLV_CONF) {
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if let Some((key, _)) = line.split_once('=')
                && let Some(resolver) = key.trim().strip_suffix("_conf")
                && LOCAL_RESOLVERS.contains(&resolver)
            {
                debug!("Found {resolver} configured as a local resolver in {OPENRESOLV_CONF}");
                return true;
            }
        }
    }

    // Debian's resolvconf ships its subscribers as update hooks instead.
    if let Ok(entries) = read_dir(RESOLVCONF_UPDATE_DIR) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && LOCAL_RESOLVERS.contains(&name)
            {
                debug!("Found {name} update hook in {RESOLVCONF_UPDATE_DIR}");
                return true;
            }
        }
    }

    false
}

/// Removes the DNS configuration from every macOS network service.
#[cfg(target_os = "macos")]
pub(crate) fn clear_dns() -> Result<(), WireguardInterfaceError> {
    DnsConfig::default().configure_dns()
}

/// Removes the DNS configuration of the given interface.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
pub(crate) fn clear_dns(ifname: &str) -> Result<(), WireguardInterfaceError> {
    debug!("Removing DNS configuration for interface {ifname}");

    match detect_dns_backend()? {
        #[cfg(target_os = "linux")]
        DnsBackend::SystemdResolved => {
            // systemd-resolved drops the configuration of a link on its own once the link is
            // gone, and reverting a link which no longer exists is an error.
            if link_exists(ifname) {
                resolvectl(&["revert", ifname])?;
            } else {
                debug!(
                    "Interface {ifname} no longer exists, so systemd-resolved has already \
                    dropped its DNS configuration"
                );
            }
            flush_resolved_caches();
        }
        DnsBackend::Openresolv { .. } => {
            let ifname = construct_resolvconf_ifname(ifname);
            let args = ["-d", &ifname, "-f"];
            debug!("Executing {RESOLVCONF} with args: {args:?}");
            let output = Command::new(RESOLVCONF).args(args).output()?;
            check_command_output_status(output)?;
        }
    }

    debug!("DNS configuration removed successfully for interface {ifname}");
    Ok(())
}

/// Checks whether a network interface still exists.
#[cfg(target_os = "linux")]
fn link_exists(ifname: &str) -> bool {
    Path::new("/sys/class/net").join(ifname).exists()
}

#[cfg(target_os = "linux")]
fn resolvectl(args: &[&str]) -> Result<(), WireguardInterfaceError> {
    debug!("Executing {RESOLVECTL} with args: {args:?}");
    let output = Command::new(RESOLVECTL).args(args).output()?;
    check_command_output_status(output)
}

/// Flushes the resolver caches, so that answers cached before the tunnel came up do not shadow
/// the zones which are now resolved through it.
#[cfg(target_os = "linux")]
fn flush_resolved_caches() {
    if let Err(err) = resolvectl(&["flush-caches"]) {
        warn!(
            "Failed to flush systemd-resolved caches: {err}. Names looked up before the DNS \
            configuration changed may keep resolving to stale addresses until their TTL expires."
        );
    }
}

/// Constructs the `resolvconf` interface name for manipulating DNS settings.
///
/// On systems which don't use systemd-resolved (Debian 13), `resolvconf` orders the nameservers
/// of all interfaces by the prefixes listed in its interface-order file. This reads that file to
/// find the highest priority prefix and prepends it to the base interface name. Systems without
/// the file just use the interface name as-is.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
fn construct_resolvconf_ifname(base_ifname: &str) -> String {
    let iface_order = Path::new(IFACE_ORDER_PATH);
    if iface_order.exists() {
        let iface_regex = regex::Regex::new(r"^([A-Za-z0-9-]+)\*$").unwrap();
        if let Ok(file) = File::open(iface_order) {
            let reader = BufReader::new(file);
            if let Some(constructed_ifname) =
                reader.lines().map_while(Result::ok).find_map(|line| {
                    let iface = line.trim();
                    iface_regex.captures(iface).and_then(|captures| {
                        captures.get(1).map(|matched_iface| {
                            // Output format: <highest_priority_iface>.<base_ifname>
                            let constructed_ifname =
                                format!("{}.{base_ifname}", matched_iface.as_str());
                            debug!(
                                "Constructed interface name from interface_order: \
                            {constructed_ifname}"
                            );
                            constructed_ifname
                        })
                    })
                })
            {
                return constructed_ifname;
            }
        }
    }

    base_ifname.into()
}

/// Obtains the list of macOS network services.
#[cfg(target_os = "macos")]
fn network_services() -> Result<Vec<String>, IoError> {
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()?;

    if output.status.success() {
        let buf = BufReader::new(Cursor::new(output.stdout));
        // Get all lines from stdout without asterisk (*).
        // An asterisk (*) denotes that a network service is disabled.
        let lines = buf
            .lines()
            .filter_map(|line| line.ok().filter(|line| !line.contains('*')))
            .collect();
        debug!("Found following network services: {lines:?}");
        Ok(lines)
    } else {
        Err(IoError::other(format!(
            "network setup command failed: {}",
            output.status
        )))
    }
}

#[cfg(test)]
mod tests {
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
        let key = nrpt_rule_key_name("A1B2C3D4-0000-0000-0000-000000000000", 2);
        assert_eq!(
            key,
            "defguard-wireguard-A1B2C3D4-0000-0000-0000-000000000000-2"
        );
        assert_eq!(
            nrpt_rule_key_interface_id(&key),
            Some("A1B2C3D4-0000-0000-0000-000000000000")
        );
        // Registry key names are case insensitive.
        assert_eq!(
            nrpt_rule_key_interface_id("DEFGUARD-WIREGUARD-abc-0"),
            Some("abc")
        );
    }

    #[test]
    fn rules_of_other_software_are_not_recognized_as_ours() {
        assert_eq!(nrpt_rule_key_interface_id("{some-other-rule}"), None);
        assert_eq!(nrpt_rule_key_interface_id("defguard-wireguard-"), None);
        // No trailing rule index.
        assert_eq!(nrpt_rule_key_interface_id("defguard-wireguard-abc"), None);
        assert_eq!(
            nrpt_rule_key_interface_id("defguard-wireguard-abc-notanindex"),
            None
        );
        // Shorter than the prefix, and not a char boundary panic either.
        assert_eq!(nrpt_rule_key_interface_id("defguard"), None);
        assert_eq!(nrpt_rule_key_interface_id("ł"), None);
    }

    #[test]
    fn nrpt_servers_are_semicolon_separated() {
        let servers = [
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ];
        assert_eq!(nrpt_servers_value(&servers), "10.0.0.1;::1");
        assert_eq!(nrpt_servers_value(&[]), "");
    }

    #[test]
    fn multi_sz_terminates_every_string_and_the_list() {
        assert_eq!(
            multi_sz(&["ab".to_string(), "c".to_string()]),
            [0x61, 0x62, 0, 0x63, 0, 0]
        );
        // An empty list is just the list terminator.
        assert_eq!(multi_sz(&[]), [0]);
    }

    #[test]
    fn nrpt_rules_stay_within_the_namespace_limit() {
        let domains: Vec<String> = (0..120)
            .map(|index| format!("d{index}.example.com"))
            .collect();
        let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
        let config = DnsConfig::split_dns(&SERVERS, &domains, &[]);
        let namespaces = config.nrpt_namespaces();
        assert_eq!(namespaces.len(), 120);
        let chunks: Vec<_> = namespaces.chunks(NRPT_MAX_NAMESPACES_PER_RULE).collect();
        assert_eq!(chunks.len(), 3);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.len() <= NRPT_MAX_NAMESPACES_PER_RULE)
        );
    }

    #[test]
    fn nrpt_rules_carry_the_values_the_dns_client_expects() {
        // The rules live in the local policy table, not the group policy one.
        assert_eq!(
            NRPT_POLICY_CONFIG_PATH,
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"
        );
        // `ConfigOptions` has to carry the bit which makes the DNS client use the servers of the
        // rule, otherwise the namespaces are matched but resolved through the usual resolvers.
        assert_eq!(NRPT_CONFIG_OPTION_OVERRIDE_DNS, 0x8);
        assert_eq!(NRPT_RULE_VERSION, 1);
    }
}
