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
    fmt::Write as _,
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

#[cfg(not(windows))]
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
        resolvectl_link("dns", ifname, &servers)?;
        resolvectl_link("domain", ifname, &self.resolved_domain_args())?;

        // Set this explicitly instead of relying on the implicit default, which depends on whether
        // the link has routing domains configured.
        let default_route = if self.default_route { "yes" } else { "no" };
        resolvectl(&["default-route", ifname, default_route])?;

        flush_resolved_caches();

        debug!("DNS configured successfully for interface {ifname} through systemd-resolved");
        Ok(())
    }

    /// Applies this configuration to the given interface, using whichever DNS backend this host
    /// provides.
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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

        check_command_output_status(child.wait_with_output()?)?;

        debug!("DNS configured successfully for interface {ifname} through {RESOLVCONF}");
        Ok(())
    }

    /// Picks the `resolvconf` flags matching the intent of this configuration.
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
            let _ = writeln!(stdin, "nameserver {server}");
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
            let _ = writeln!(stdin, "search {}", domains.join(" "));
        }
        stdin
    }

    /// Applies this configuration to every macOS network service.
    ///
    /// `networksetup` only knows global resolvers, so [`DnsConfig::routing_domains`] and
    /// [`DnsConfig::default_route`] cannot be honored here: the DNS servers of the tunnel answer
    /// every query for as long as it is up, whichever interface they belong to. Scoped resolvers
    /// (`/etc/resolver/<domain>`) would be needed for split DNS on this platform.
    #[cfg(target_os = "macos")]
    pub(crate) fn configure_dns(&self, ifname: &str) -> Result<(), WireguardInterfaceError> {
        debug!("Starting DNS configuration for interface {ifname}: {self:?}");
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
                {:?} will answer every query while interface {ifname} is up.",
                self.servers
            );
        }

        // An empty list clears the entries of that kind instead of setting them.
        let servers = self.servers.iter().map(ToString::to_string).collect();
        let search_domains = self
            .search_domains
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let entries = [
            ("-setdnsservers", "DNS servers", &servers),
            ("-setsearchdomains", "search domains", &search_domains),
        ];

        debug!("Setting DNS servers and search domains for all network services");
        for service in network_services()? {
            for (option, description, values) in entries {
                debug!("Setting {description} for network service {service}");
                let mut cmd = Command::new("networksetup");
                cmd.arg(option).arg(&service);
                if values.is_empty() {
                    cmd.arg("Empty");
                } else {
                    cmd.args(values);
                }

                let status = cmd.status()?;
                if !status.success() {
                    return Err(WireguardInterfaceError::DnsError(format!(
                        "Command `networksetup` failed while setting {description} for \
                        {service}: {status}"
                    )));
                }
                debug!("{description} set successfully for {service}");
            }
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
            if let Some(namespace) = nrpt::namespace(domain)
                && !namespaces.contains(&namespace)
            {
                namespaces.push(namespace);
            }
        }
        namespaces
    }
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
    /// This is the only backend which implements per-domain resolution natively, so the whole of
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
    if let Ok(Some(_)) = get_command_path(RESOLVECTL) {
        true
    } else {
        warn!(
            "systemd-resolved appears to be running, but the `{RESOLVECTL}` command could not be \
            found in PATH. Falling back to `{RESOLVCONF}`, which cannot configure split DNS on \
            this host."
        );
        false
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
///
/// `networksetup` configures resolvers globally rather than per interface, so this clears the
/// entries of every network service, whichever interface set them.
#[cfg(target_os = "macos")]
pub(crate) fn clear_dns(ifname: &str) -> Result<(), WireguardInterfaceError> {
    DnsConfig::default().configure_dns(ifname)
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

/// Runs a `resolvectl` subcommand which takes a link followed by a list of values.
///
/// `resolvectl` needs at least one value to distinguish setting a link's list from printing it,
/// which is why the callers pass an explicit empty string to clear one.
#[cfg(target_os = "linux")]
fn resolvectl_link(
    subcommand: &str,
    ifname: &str,
    values: &[String],
) -> Result<(), WireguardInterfaceError> {
    let mut args = vec![subcommand, ifname];
    args.extend(values.iter().map(String::as_str));
    resolvectl(&args)
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
    let Ok(file) = File::open(IFACE_ORDER_PATH) else {
        return base_ifname.into();
    };

    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .find_map(|line| {
            // Entries look like `tun*`; the prefix is what has to be prepended.
            let prefix = line.trim().strip_suffix('*')?;
            if prefix.is_empty()
                || !prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return None;
            }
            // Output format: <highest_priority_iface>.<base_ifname>
            let ifname = format!("{prefix}.{base_ifname}");
            debug!("Constructed interface name from {IFACE_ORDER_PATH}: {ifname}");
            Some(ifname)
        })
        .unwrap_or_else(|| base_ifname.into())
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

#[cfg(any(target_os = "windows", test))]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) mod nrpt;
#[cfg(test)]
mod tests;
