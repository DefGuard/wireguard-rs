//! DNS dynamic update of the host's name, which Windows doesn't do for split DNS. See the
//! [`registration`] module.

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError},
    },
    thread,
    time::Duration,
};

use windows::{
    Win32::{
        Foundation::{NO_ERROR, WIN32_ERROR},
        NetworkManagement::Dns::{
            DNS_A_DATA, DNS_AAAA_DATA, DNS_RECORDW, DNS_RECORDW_0, DNS_RECORDW_1, DNS_TYPE,
            DNS_TYPE_A, DNS_TYPE_AAAA, DNS_UPDATE_SECURITY_USE_DEFAULT, DnsCharSetUnicode,
            DnsModifyRecordsInSet_W, IP6_ADDRESS,
        },
        System::{
            Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW},
            SystemInformation::{ComputerNameDnsFullyQualified, GetComputerNameExW},
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{WindowsError, check, lock, str_to_wide_null_terminated};
use crate::{
    dns::{DnsConfig, registration},
    wgapi::{Kernel, WGApi},
};

/// Delays before each registration attempt. Early attempts may race the first handshake.
const REGISTRATION_DELAYS: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(10),
    Duration::from_secs(30),
];

/// How long disconnecting waits for the registered records to be deleted.
const DEREGISTRATION_TIMEOUT: Duration = Duration::from_secs(3);

/// Reads a `REG_DWORD` value under `HKEY_LOCAL_MACHINE`.
fn read_dword(path: &str, name: &str) -> Option<u32> {
    let path = str_to_wide_null_terminated(path);
    let name = str_to_wide_null_terminated(name);
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&raw mut size),
        )
    };
    (status == NO_ERROR).then_some(value)
}

/// Tells whether the policy and the host's settings allow DNS registration.
fn registration_enabled() -> bool {
    registration::registration_enabled(
        read_dword(
            registration::POLICY_PATH,
            registration::POLICY_REGISTRATION_ENABLED,
        ),
        read_dword(
            registration::TCPIP_PARAMETERS_PATH,
            registration::DISABLE_DYNAMIC_UPDATE,
        ),
    )
}

/// Returns the host's FQDN, the name the Windows DNS client registers.
fn computer_fqdn() -> Result<String, WindowsError> {
    // The first call only reports the buffer size, NUL included.
    let mut size = 0u32;
    let _ = unsafe { GetComputerNameExW(ComputerNameDnsFullyQualified, None, &raw mut size) };
    let mut buffer = vec![0u16; size as usize];
    unsafe {
        GetComputerNameExW(
            ComputerNameDnsFullyQualified,
            Some(PWSTR(buffer.as_mut_ptr())),
            &raw mut size,
        )?;
    }
    // Now `size` excludes the NUL.
    buffer.truncate(size as usize);
    Ok(String::from_utf16(&buffer)?)
}

/// Returns the record type, data length and data of an address record.
fn record_data(address: IpAddr) -> (DNS_TYPE, usize, DNS_RECORDW_1) {
    match address {
        IpAddr::V4(address) => (
            DNS_TYPE_A,
            size_of::<DNS_A_DATA>(),
            DNS_RECORDW_1 {
                A: DNS_A_DATA {
                    IpAddress: u32::from_ne_bytes(address.octets()),
                },
            },
        ),
        IpAddr::V6(address) => (
            DNS_TYPE_AAAA,
            size_of::<DNS_AAAA_DATA>(),
            DNS_RECORDW_1 {
                AAAA: DNS_AAAA_DATA {
                    Ip6Address: IP6_ADDRESS {
                        IP6Byte: address.octets(),
                    },
                },
            },
        ),
    }
}

/// Builds a linked list of address records of `name`.
fn record_list<'a>(name: PWSTR, addresses: impl Iterator<Item = &'a IpAddr>) -> Vec<DNS_RECORDW> {
    let mut records = addresses
        .map(|address| {
            let (record_type, length, data) = record_data(*address);
            DNS_RECORDW {
                pName: name,
                wType: record_type.0,
                wDataLength: length as u16,
                // `CharSet` is bits 3-4.
                Flags: DNS_RECORDW_0 {
                    DW: (DnsCharSetUnicode.0 as u32) << 3,
                },
                dwTtl: registration::RECORD_TTL,
                Data: data,
                ..Default::default()
            }
        })
        .collect::<Vec<_>>();
    // The buffer stays put when the vector itself moves.
    let base = records.as_mut_ptr();
    for index in 1..records.len() {
        // SAFETY: both indices are within the vector.
        unsafe { (*base.add(index - 1)).pNext = base.add(index) };
    }
    records
}

/// Address records of the host in DNS.
#[derive(PartialEq)]
pub(super) struct DnsRecords {
    name: String,
    addresses: Vec<IpAddr>,
    /// DNS servers to update, as an `IP4_ARRAY`.
    servers: Vec<u32>,
}

impl DnsRecords {
    /// Adds and deletes address records of the name, in one update per address family. The
    /// name's other records, e.g. of other adapters, stay.
    ///
    /// Uses the process credentials: the computer account under LocalSystem, as secure AD updates
    /// need.
    fn update(&self, add: &[IpAddr], delete: &[IpAddr]) -> Result<(), WindowsError> {
        let mut name = str_to_wide_null_terminated(&self.name);
        let name = PWSTR(name.as_mut_ptr());
        let servers = Some(self.servers.as_ptr().cast_mut().cast());
        for ipv4 in [true, false] {
            let add = record_list(name, add.iter().filter(|a| a.is_ipv4() == ipv4));
            let delete = record_list(name, delete.iter().filter(|a| a.is_ipv4() == ipv4));
            if add.is_empty() && delete.is_empty() {
                continue;
            }
            let head =
                |records: &[DNS_RECORDW]| (!records.is_empty()).then(|| records.as_ptr().cast());
            // SAFETY: all buffers outlive the call, and the server list is only read. The `W`
            // variant reads `DNS_RECORDW`s.
            let status = unsafe {
                DnsModifyRecordsInSet_W(
                    head(&add),
                    head(&delete),
                    DNS_UPDATE_SECURITY_USE_DEFAULT,
                    None,
                    servers,
                    None,
                )
            };
            check(WIN32_ERROR(status as u32))?;
        }
        Ok(())
    }

    /// Tells whether `other` is registered under the same name with the same servers.
    fn same_target(&self, other: &Self) -> bool {
        self.name.eq_ignore_ascii_case(&other.name) && self.servers == other.servers
    }

    /// Deletes the records, logging the outcome.
    fn delete(&self) {
        let (name, addresses) = (&self.name, &self.addresses);
        match self.update(&[], addresses) {
            Ok(()) => info!("Deleted {name} {addresses:?} from DNS"),
            Err(err) => warn!("Failed to delete {name} {addresses:?} from DNS: {err}"),
        }
    }
}

/// Deletes the `registered` records.
fn retire(registered: &mut Option<DnsRecords>) {
    if let Some(old) = registered.take() {
        old.delete();
    }
}

/// DNS registration state of an interface.
#[derive(Default)]
pub(super) struct DnsRegistration {
    /// Dropping it cancels the update in progress.
    cancel: Mutex<Option<Sender<()>>>,
    /// Records currently registered. Held locked across every DNS update, so that whoever takes
    /// them sees the outcome of an update in flight.
    registered: Arc<Mutex<Option<DnsRecords>>>,
}

impl DnsRegistration {
    /// Tells whether there is nothing registered, without waiting for an update in flight.
    fn is_idle(&self) -> bool {
        self.registered
            .try_lock()
            .is_ok_and(|registered| registered.is_none())
    }
}

/// Locks `registered`, unless the update was cancelled meanwhile.
fn lock_unless_cancelled<'a>(
    registered: &'a Mutex<Option<DnsRecords>>,
    cancelled: &Receiver<()>,
) -> Option<MutexGuard<'a, Option<DnsRecords>>> {
    let guard = lock(registered);
    (cancelled.try_recv() != Err(TryRecvError::Disconnected)).then_some(guard)
}

/// Spawns a named thread, logging a failure to start it.
fn spawn(name: &str, body: impl FnOnce() + Send + 'static) -> bool {
    match thread::Builder::new().name(name.to_string()).spawn(body) {
        Ok(_) => true,
        Err(err) => {
            warn!("Failed to start the {name} thread: {err}");
            false
        }
    }
}

/// Registers `records` in the background. Registered records under the same name on the same
/// servers are updated in the same step, others deleted first.
fn register(
    records: DnsRecords,
    registered: Arc<Mutex<Option<DnsRecords>>>,
    cancelled: Receiver<()>,
) {
    let Some(mut current) = lock_unless_cancelled(&registered, &cancelled) else {
        return;
    };
    if current
        .as_ref()
        .is_some_and(|old| !old.same_target(&records))
    {
        retire(&mut current);
    }
    drop(current);

    let name = &records.name;
    for (attempt, delay) in REGISTRATION_DELAYS.into_iter().enumerate() {
        // Anything but a timeout means cancelled.
        if cancelled.recv_timeout(delay) != Err(RecvTimeoutError::Timeout) {
            debug!("Registration of {name} in DNS cancelled");
            return;
        }
        let Some(mut current) = lock_unless_cancelled(&registered, &cancelled) else {
            debug!("Registration of {name} in DNS cancelled");
            return;
        };
        let stale = current.as_ref().map_or_else(Vec::new, |old| {
            old.addresses
                .iter()
                .filter(|address| !records.addresses.contains(address))
                .copied()
                .collect()
        });
        // Adding the registered addresses again restores them if they were lost meanwhile.
        match records.update(&records.addresses, &stale) {
            Ok(()) => {
                info!(
                    "Registered {name} in DNS with addresses {:?}",
                    records.addresses
                );
                *current = Some(records);
                return;
            }
            Err(err) if attempt + 1 < REGISTRATION_DELAYS.len() => {
                debug!("Failed to register {name} in DNS, retrying: {err}");
            }
            Err(err) => warn!(
                "Gave up registering {name} in DNS, so the host may not be reachable by name \
                over the tunnel: {err}"
            ),
        }
    }
}

impl WGApi<Kernel> {
    /// Returns the records to register for the interface: its addresses with the tunnel's
    /// servers, if they serve the host's zone.
    fn dns_records(
        &self,
        interface_id: &str,
        config: &DnsConfig<'_>,
        namespaces: &[String],
    ) -> Option<DnsRecords> {
        if config.default_route {
            debug!("Full-tunnel DNS puts the servers on the adapter, so Windows registers itself");
            return None;
        }
        let addresses = registration::registrable_addresses(&lock(&self.windows_dns.addresses));
        if addresses.is_empty() {
            debug!("Interface {interface_id} has no address to register in DNS");
            return None;
        }
        let Some(servers) = registration::ip4_array(config.servers) else {
            warn!(
                "None of the DNS servers {:?} has an IPv4 address, which the DNS dynamic update \
                API requires, so the host is not registered in DNS",
                config.servers
            );
            return None;
        };
        if !registration_enabled() {
            debug!("DNS registration is disabled on this host");
            return None;
        }
        let fqdn = match computer_fqdn() {
            Ok(fqdn) => fqdn,
            Err(err) => {
                warn!("Failed to read the host name, so it cannot be registered in DNS: {err}");
                return None;
            }
        };
        let Some(name) = registration::registration_name(&fqdn) else {
            debug!("Host name {fqdn} has no primary DNS suffix, so it is not registered in DNS");
            return None;
        };
        if !registration::name_in_namespaces(name, namespaces) {
            debug!(
                "{name} is outside the domains {namespaces:?} resolved through interface \
                {interface_id}, so it is not registered with their DNS servers"
            );
            return None;
        }
        Some(DnsRecords {
            name: name.to_string(),
            addresses,
            servers,
        })
    }

    /// Registers the interface in DNS as `config` requires, cancelling the update in progress and
    /// deleting the registered records the new ones don't include.
    pub(super) fn update_dns_registration(
        &self,
        interface_id: &str,
        config: &DnsConfig<'_>,
        namespaces: &[String],
    ) {
        let records = self.dns_records(interface_id, config, namespaces);
        let state = &self.windows_dns.registration;
        let mut cancel = lock(&state.cancel);
        // Dropping the sender cancels the update in progress.
        *cancel = None;

        let registered = Arc::clone(&state.registered);
        match records {
            Some(records) => {
                if registered
                    .try_lock()
                    .is_ok_and(|registered| registered.as_ref() == Some(&records))
                {
                    debug!("{} is already registered in DNS", records.name);
                    return;
                }
                let (sender, cancelled) = mpsc::channel();
                if spawn("dns-registration", move || {
                    register(records, registered, cancelled);
                }) {
                    *cancel = Some(sender);
                }
            }
            None if state.is_idle() => {}
            None => {
                let (sender, cancelled) = mpsc::channel();
                if spawn("dns-registration", move || {
                    if let Some(mut current) = lock_unless_cancelled(&registered, &cancelled) {
                        retire(&mut current);
                    }
                }) {
                    *cancel = Some(sender);
                }
            }
        }
    }

    /// Cancels the update in progress and deletes the registered records, waiting at most
    /// [`DEREGISTRATION_TIMEOUT`]. Has to run while the tunnel is still up.
    pub(super) fn deregister_from_dns(&self) {
        let state = &self.windows_dns.registration;
        *lock(&state.cancel) = None;
        if state.is_idle() {
            return;
        }

        let registered = Arc::clone(&state.registered);
        let (done, finished) = mpsc::channel();
        let spawned = spawn("dns-deregistration", move || {
            // Waits for an update in flight.
            retire(&mut lock(&registered));
            let _ = done.send(());
        });
        if spawned && finished.recv_timeout(DEREGISTRATION_TIMEOUT).is_err() {
            warn!("Deleting the host's records from DNS is taking too long, disconnecting anyway");
        }
    }
}
