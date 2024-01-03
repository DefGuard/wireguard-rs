use std::{env, net::{IpAddr, SocketAddr}, str::FromStr, sync::Arc, process::Command, fs::File, io::{Write, BufReader, Cursor, BufRead, self}, thread::sleep, time::{Duration, SystemTime}};

use wireguard_nt::dll;

use crate::{
    error::WireguardInterfaceError,
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
    InterfaceConfiguration, WireguardInterfaceApi, utils::add_peer_routing,
};

use ipnet::{Ipv4Net, Ipv6Net};

const ADAPTER_POOL: &str = "WireGuard";

#[cfg(target_arch = "x86")]
const DLL_PATH: &str = "wireguard-nt/bin/x86/wireguard.dll";
#[cfg(target_arch = "x86_64")]
const DLL_PATH: &str = "wireguard-nt/bin/amd64/wireguard.dll";
#[cfg(target_arch = "arm")]
const DLL_PATH: &str = "wireguard-nt/bin/arm/wireguard.dll";
#[cfg(target_arch = "aarch64")]
const DLL_PATH: &str = "wireguard-nt/bin/arm64/wireguard.dll";


const USERSPACE_EXECUTABLE: &str = "wg";

/// Manages interfaces created with Windows kernel using https://git.zx2c4.com/wireguard-nt.
#[derive(Clone)]
pub struct WireguardApiWindows {
    ifname: String,
}

impl WireguardApiWindows {
    pub fn new(ifname: String) -> Self {
    // pub fn new(ifname: String) -> Result<Self, WireguardInterfaceError> {
        debug!("Loading DDL from {}", DLL_PATH);
        // TODO: check that wireguard is available

        // Ok(Self { ifname })
        Self { ifname }
    }

    fn convert_key(key: &String) -> [u8; 32] {
        let mut interface_private = [0; 32];
        interface_private.copy_from_slice(key.as_bytes());
        interface_private
    }

    fn load_dll() -> Arc<dll> {
        unsafe { wireguard_nt::load_from_path(DLL_PATH) }.expect("Failed to load wireguard dll")
    }
}

impl WireguardInterfaceApi for WireguardApiWindows {
    fn create_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Opening/creating interface {}", self.ifname);
        debug!("Opening adapter with name {}", self.ifname);



        // // let interface_name = &self.ifname;
        // let file_name = format!("{}.conf", &self.ifname);
        // let path = env::current_dir()?;
        // let file_path = path.join(&file_name).display().to_string();
        // println!("File path {:?}", file_path);

        // // TODO: file naming; pass private key
        // // let mut file = File::create(&file_path)?;
        // println!("Creating file {:?}", file_name);
        // let mut file = File::create(&file_name)?;

        // // TODO: pass private key
        // file.write_all(b"[Interface]\nPrivateKey = wM6n6yt+i3X94cR1wAQZ5M18Iajw13Rwljcz7LGwNnI=")?;

        // let service_installation_output = Command::new("wireguard").arg("/installtunnelservice").arg(file_path).output().map_err(|err| {
        //     error!("Failed to create interface. Error: {err}");
        //     WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        // })?;

        // println!("service_installation_output {:?}", service_installation_output);
        // // TODO: output can return an already running error. It shouldn't interfere with the rest of the program.
        // // TODO: try to update the running instance.

        // // TODO: Service is not immediately available, we need to wait a few seconds.
        // // sleep(Duration::from_secs(5));

        // Command::new("sc.exe").arg("queryex").arg("type=service").arg("state=all").output().map_err(|err| {
        //     error!("Failed to update interface. Error: {err}");
        //     WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        // })?;

        // Command::new("wg").arg("show").arg(&self.ifname).output().map_err(|err| {
        //     error!("Failed to update interface. Error: {err}");
        //     WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        // })?;






        // let wireguard = Self::load_dll();

        // let adapter = match wireguard_nt::Adapter::open(wireguard.clone(), &self.ifname) {
        //     Ok(a) => a,
        //     Err((_, __)) =>
        //     // If loading failed (most likely it didn't exist), create a new one
        //     {
        //         debug!("Creating adapter with name {}", self.ifname);
        //         wireguard_nt::Adapter::create(wireguard, ADAPTER_POOL, &self.ifname, None)
        //             .map_err(|e| e.0)
        //             .expect(format!("Failed to create adapter {}", self.ifname).as_str())
        //     }
        // };
        // assert!(adapter.up());
        info!("Opened/created interface {}", self.ifname);
        Ok(())
    }

    fn assign_address(&self, address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        debug!("Assigning address {address} to interface {}", self.ifname);
        Ok(())
    }

    fn configure_interface(
        &self,
        config: &InterfaceConfiguration,
        dns: &[IpAddr],
    ) -> Result<(), WireguardInterfaceError> {
        info!(
            "Configuring interface {} with config: {config:?}",
            self.ifname
        );

        // let output = Command::new("wg").arg("show").arg(&self.ifname).output().map_err(|err| {
        //     error!("Failed to read interface data. Error: {err}");
        //     // WireguardInterfaceError::CommandExecutionFailed(err)
        //     WireguardInterfaceError::ReadInterfaceError(err.to_string())
        // })?;

        let output = Command::new("wg").arg("--help").output().map_err(|err| {
            error!("Failed to read interface data. Error: {err}");
            // WireguardInterfaceError::CommandExecutionFailed(err)
            WireguardInterfaceError::ReadInterfaceError(err.to_string())
        })?;

        if !output.stderr.is_empty() {
            let x = String::from_utf8(output.stdout).expect("Invalid UTF8 sequence in stdout");
            // panic!("Not empty {:?}", message=output.stdout);
            return Err(WireguardInterfaceError::ReadInterfaceError(x));
        }

        // return Ok(());

        // Interface is created here so that there is no need to pass private key only for Windows
        let file_name = format!("{}.conf", &self.ifname);
        // let path = env::current_dir()?;
        let path = env::current_dir()?;

        // if path.is_err() {
        //     let i = path.unwrap_err();
        //     return Err(WireguardInterfaceError::ReadInterfaceError(i.to_string()));
        // }

        let file_path = path.join(&file_name).display().to_string();
        // let file_path = "";

        let p = "C:/".to_string() + "defguard-rs-log.txt";

        debug!("Creating WireGuard configuration file {} in: {}", file_name, file_path);



        // return Ok(());

        let mut ff = File::create(p)?;
        ff.write_all(file_path.as_bytes())?;


        // return Ok(());

        let mut file = File::create(&file_name)?;
        let dns_addresses = format!("{}", dns.iter().map(|v| v.to_string()).collect::<Vec<String>>().join(","));
        println!("dns dns {:?}", dns);

        // return Ok(());


        let mut wireguard_configuration = format!("[Interface]\nPrivateKey = {}\nDNS = {}\nAddress = {}\n", config.prvkey, dns_addresses, config.address);

        for peer in &config.peers {
            println!("Adding a new peer {:?}", peer);
            println!("Peer pubkey {:?}", peer.public_key);
            println!("Peer pubkey to string {:?}", peer.public_key.to_string());
            println!("Peer pubkey lower hex {:?}", peer.public_key.to_lower_hex());

            let mut arg_list = Vec::new();
            // TODO: Handle errors; refactor

            wireguard_configuration.push_str("\n[Peer]");
            wireguard_configuration.push_str(format!("\nPublicKey = {}", peer.public_key.to_string()).as_str());

            arg_list.push(format!("{}", peer.public_key.to_string()));
            // arg_list.push(format!("{}", peer.public_key.to_lower_hex()));
            println!("Pubkey pushed {:?}", arg_list);

            if let Some(preshared_key) = &peer.preshared_key {
                arg_list.push(format!("preshared-key {}", preshared_key));
                wireguard_configuration.push_str(format!("\nPresharedKey = {}", preshared_key).as_str());
            }

            if let Some(keep_alive) = peer.persistent_keepalive_interval {
                arg_list.push("persistent-keepalive".to_string());
                arg_list.push(keep_alive.to_string());
                wireguard_configuration.push_str(format!("\nPersistentKeepalive = {}", keep_alive).as_str());
            }

            if let Some(endpoint) = peer.endpoint {
                arg_list.push("endpoint".to_string());
                arg_list.push(endpoint.to_string());
                wireguard_configuration.push_str(format!("\nEndpoint = {}", endpoint).as_str());
            }

            arg_list.push("allowed-ips".to_string());

            let allowed_ips = format!("{}", peer.allowed_ips.iter().map(|v| v.to_string()).collect::<Vec<String>>().join(","));
            println!("allowed_ips {}", allowed_ips);

            wireguard_configuration.push_str(format!("\nAllowedIPs = {}", allowed_ips).as_str());

            arg_list.push(allowed_ips);

            println!("Peer: {:?}", arg_list);
        }

        println!("!!!wireguard_configuration {:?}", wireguard_configuration);

        info!("Setting Address {}, DNS: {}", config.address, dns_addresses);
        // file.write_all(format!("[Interface]\nPrivateKey = {}\nDNS = {}\nAddress = {}", config.prvkey, dns_addresses, config.address).as_bytes())?;
        file.write_all(wireguard_configuration.as_bytes())?;
 
        let service_installation_output = Command::new("wireguard").arg("/installtunnelservice").arg(file_path).output().map_err(|err| {
            // error!("Failed to create interface. Error: {err}");
        // return Err(WireguardInterfaceError::CommandExecutionError { stdout, stderr });
            // WireguardInterfaceError::CommandExecutionError { stdout, stderr }
            // WireguardInterfaceError::CommandExecutionFailed(err)
            let message = err.to_string();
            WireguardInterfaceError::ServiceInstallationFailed { err, message }
        })?;

        ff.write_all(format!("Install service output: {:?}", service_installation_output.stdout).as_bytes())?;

        if !service_installation_output.status.success() {
            let message = format!("Failed to install tunnel as a Windows service: {:?}", service_installation_output.stdout);
            return Err(WireguardInterfaceError::ServiceInstallationFailed { err: io::Error::new(io::ErrorKind::Other, "Cannot create service"), message });
        }
 
        println!("service_installation_output {:?}", service_installation_output);
        // TODO: output can return an already running error. It shouldn't interfere with the rest of the program.

        // Windows service is not immediately available after the /installtunnelservice command.
        let mut counter = 1;
        loop {
            let output = Command::new("wg").arg("show").arg(&self.ifname).output().map_err(|err| {
                error!("Failed to read interface data. Error: {err}");
                // WireguardInterfaceError::CommandExecutionFailed(err)
                WireguardInterfaceError::ReadInterfaceError(err.to_string())
            })?;
    
            println!("iteration: {}, {:?}", counter, output.stderr.is_empty());
    
            if output.stderr.is_empty() || counter == 10 {
                break;
                // TODO: throw error if counter reaches threshold
            }
    
            sleep(Duration::from_secs(1));
            counter = counter + 1;
        }

        // TODO: is it needed?
        // Command::new("sc.exe").arg("queryex").arg("type=service").arg("state=all").output().map_err(|err| {
        //     error!("Failed to update interface. Error: {err}");
        //     WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        // })?;

        // Command::new("wg").arg("show").arg(&self.ifname).output().map_err(|err| {
        //     error!("Failed to update interface. Error: {err}");
        //     WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        // })?;

        // let wireguard = Self::load_dll();

        // let adapter = match wireguard_nt::Adapter::open(wireguard, &self.ifname) {
        //     Ok(a) => a,
        //     Err((_, __)) => panic!("Cannot open adapter {}", self.ifname),
        // };

        // TODO: uncomment
        // for peer in &config.peers {
        //     println!("Adding a new peer {:?}", peer);
        //     println!("Peer pubkey {:?}", peer.public_key);
        //     println!("Peer pubkey to string {:?}", peer.public_key.to_string());
        //     println!("Peer pubkey lower hex {:?}", peer.public_key.to_lower_hex());

        //     let mut arg_list = Vec::new();
        //     // TODO: Handle errors; refactor

        //     arg_list.push(format!("{}", peer.public_key.to_string()));
        //     // arg_list.push(format!("{}", peer.public_key.to_lower_hex()));
        //     println!("Pubkey pushed {:?}", arg_list);

        //     if let Some(preshared_key) = &peer.preshared_key {
        //         arg_list.push(format!("preshared-key {}", preshared_key));
        //     }

        //     if let Some(keep_alive) = peer.persistent_keepalive_interval {
        //         arg_list.push("persistent-keepalive".to_string());
        //         arg_list.push(keep_alive.to_string());
        //     }

        //     if let Some(endpoint) = peer.endpoint {
        //         arg_list.push("endpoint".to_string());
        //         arg_list.push(endpoint.to_string());
        //     }

        //     arg_list.push("allowed-ips".to_string());

        //     let allowed_ips = format!("{}", peer.allowed_ips.iter().map(|v| v.to_string()).collect::<Vec<String>>().join(","));
        //     println!("allowed_ips {}", allowed_ips);

        //     arg_list.push(allowed_ips);

        //     println!("Peer: {:?}", arg_list);

        //     // let y = Command::new("wg").arg("show").arg(&self.ifname).output().map_err(|err| {
        //     //     error!("Failed to update interface. Error: {err}");
        //     //     WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        //     // })?;

        //     // println!("Output wg show {:?}", y);
            

        //     let add_peer_output = Command::new("wg").arg("set").arg(&self.ifname).arg("peer").args(&arg_list).output().map_err(|err| {
        //         error!("Failed to update interface. Error: {err}");
        //         WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        //     })?;
    
        //     info!("Add peer with arguments {:?} output {:?}", arg_list, add_peer_output);
        // }


        // let interface = wireguard_nt::SetInterface {
        //     listen_port: Some(u16::try_from(config.port).unwrap()),
        //     public_key: None, // will be generated from the private key
        //     private_key: Some(Self::convert_key(&config.prvkey)),
        //     peers: config
        //         .peers
        //         .iter()
        //         .map(|peer| wireguard_nt::SetPeer {
        //             public_key: Some(peer.public_key.as_array()),
        //             preshared_key: match peer.preshared_key.clone() {
        //                 Some(k) => Some(k.as_array()),
        //                 None => None,
        //             },
        //             keep_alive: peer.persistent_keepalive_interval,
        //             endpoint: match peer.endpoint {
        //                 Some(a) => a,
        //                 None => panic!("Cannot set peer without an endpoint!"),
        //             },
        //             allowed_ips: peer
        //                 .allowed_ips
        //                 .iter()
        //                 .map(|allowed_ip| match allowed_ip.ip {
        //                     IpAddr::V4(v4) => Ipv4Net::new(v4, 32).unwrap().into(),
        //                     IpAddr::V6(v6) => Ipv6Net::new(v6, 128).unwrap().into(),
        //                 })
        //                 .collect::<Vec<_>>(),
        //         })
        //         .collect::<Vec<_>>(),
        // };

        // assert!(adapter.set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix));

        // adapter.set_config(&interface).unwrap();
        Ok(())
    }

    fn configure_peer_routing(&self, peers: &[Peer]) -> Result<(), WireguardInterfaceError> {
        // add_peer_routing(peers, &self.ifname)
        Ok(())
    }

    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        info!("Removing interface {}", self.ifname);

        Command::new("wireguard").arg("/uninstalltunnelservice").arg(&self.ifname).output().map_err(|err| {
            error!("Failed to remove interface. Error: {err}");
            WireguardInterfaceError::CommandExecutionFailed(err)
        })?;

        Ok(())
    }

    fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        info!("Configuring peer {peer:?} on interface {}", self.ifname);
        Ok(())
    }

    fn remove_peer(&self, peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        info!(
            "Removing peer with public key {peer_pubkey} from interface {}",
            self.ifname
        );
        Ok(())
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        debug!("Reading host info for interface {}", self.ifname);

        let output = Command::new("wg").arg("show").arg(&self.ifname).arg("dump").output().map_err(|err| {
            error!("Failed to update interface. Error: {err}");
            WireguardInterfaceError::ExecutableNotFound(USERSPACE_EXECUTABLE.into())
        })?;

        println!("Read interface output: {:?}", output);

        let reader = BufReader::new(Cursor::new(output.stdout));
        let mut host = Host::default();
        // let mut peer_ref: Option<&mut Peer> = None;
        // reader.buffer().lines();
    
        let lines = reader.lines();

        for (index, line_result) in lines.enumerate() {
            let line = match &line_result {
                Ok(line) => line,
                Err(_err) => {
                    continue;
                }
            };

            let data: Vec<&str> = line.split("\t").collect();
            println!("Data: {:?}", data);

            // First line contains [Interface] section data, every other line is a separate [Peer]
            if index == 0 {
                // Interface data: private key, public key, listen port, fwmark
                println!("Interface data - index 0");

                host.private_key = Key::from_str(data[0]).ok();
                host.listen_port = data[2].parse().unwrap_or_default();

                if data[3] != "off" {
                    host.fwmark = Some(data[3].parse().unwrap());
                }
            } else {
                // Peer data: public key, preshared key, endpoint, allowed ips, latest handshake, transfer-rx, transfer-tx, persistent-keepalive
                println!("Peer data - index {:?}", index);

                if let Ok(public_key) = Key::from_str(data[0]) {
                    let mut peer = Peer::new(public_key.clone());
                    
                    if data[1] != "(none)" {
                        peer.preshared_key = Key::from_str(data[0]).ok();
                    }

                    peer.endpoint = SocketAddr::from_str(data[2]).ok();

                    for allowed_ip in data[3].split(",") {
                        println!("allowed ip: {:?}", allowed_ip);
                        let addr = IpAddrMask::from_str(allowed_ip.trim())?;
                        peer.allowed_ips.push(addr);
                    }

                    let handshake =
                        peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
                        println!("SystemTime::UNIX_EPOCH {:?}", SystemTime::UNIX_EPOCH);
                        *handshake += Duration::from_secs(data[4].parse().unwrap_or_default());

                    peer.rx_bytes = data[5].parse().unwrap_or_default();
                    peer.tx_bytes = data[6].parse().unwrap_or_default();

                    peer.persistent_keepalive_interval = data[7].parse().ok();

                    host.peers.insert(public_key.clone(), peer);
                }
            }


            // if let Some((key, val)) = line.split_once(' ') {
            //     println!("Split line: {:?}; value: {:?}", key, val);
            //     let keyword: &str = key.trim();
            //     let value = val.trim();

            //     // println!("Trimmed: {:?} {:?}", keyword, value);

            //     match keyword {
            //         "ListenPort" => host.listen_port = value.parse().unwrap_or_default(),
            //         // "ListenPort" => println!("port: {:?}", value.parse().unwrap_or_default()),
            //         // "fwmark" => host.fwmark = value.parse().ok(),
            //         "PrivateKey" => {
            //             // host.private_key = Key::decode(value).ok();
            //             let key = Key::from_str(value);
            //             host.private_key = key.ok();
            //         },
            //         // "PrivateKey" => println!("prv key {:?}", Key::decode(value).ok()),
            //         // "public_key" starts new peer definition
            //         "PublicKey" => {
            //             // println!("Public key entered {:?}", value);
            //             // print!("decode pub key {:?}", Key::from_str(value));
            //             if let Ok(key) = Key::from_str(value) {
            //                 // println!("public KEY: {:?}", key);
            //                 let peer = Peer::new(key.clone());
            //                 host.peers.insert(key.clone(), peer);
            //                 peer_ref = host.peers.get_mut(&key);
            //             } else {
            //                 peer_ref = None;
            //             }
            //             // if let Ok(key) = Key::decode(value) {
            //             //     println!("public KEY: {:?}", key);
            //             //     let peer = Peer::new(key.clone());
            //             //     host.peers.insert(key.clone(), peer);
            //             //     peer_ref = host.peers.get_mut(&key);
            //             // } else {
            //             //     peer_ref = None;
            //             // }
            //         }
            //         "preshared_key" => {
            //             if let Some(ref mut peer) = peer_ref {
            //                 // peer.preshared_key = Key::decode(value).ok();
            //                 // println!("PRE: {:?}", Key::decode(value).ok());
            //             }
            //         }
            //         "protocol_version" => {
            //             if let Some(ref mut peer) = peer_ref {
            //                 // peer.protocol_version = value.parse().ok();
            //             }
            //         }
            //         "Endpoint" => {
            //             if let Some(ref mut peer) = peer_ref {
            //                 peer.endpoint = SocketAddr::from_str(value).ok();
            //                 // println!("PRE: {:?}", SocketAddr::from_str(value).ok());
    
            //             }
            //         }
            //         "PersistentKeepalive" => {
            //             if let Some(ref mut peer) = peer_ref {
            //                 peer.persistent_keepalive_interval = value.parse().ok();
            //             }
            //         }
            //         "AllowedIPs" => {
            //             // println!("Allowed ips entered");
            //             if let Some(ref mut peer) = peer_ref {
            //                 // println!("AllowedIps: {:?}", value);
            //                 // let mut split_ips = value.split(",").map(|v| IpAddrMask::from_str(v).unwrap());

            //                 for allowed_ip in value.split(",") {
            //                     // println!("allowed ip: {:?}", allowed_ip);
            //                     let addr = IpAddrMask::from_str(allowed_ip.trim())?;
            //                     peer.allowed_ips.push(addr);
            //                 }

            //                 // peer.allowed_ips.append(&split_ips);
            //                 // IpAddrMask()

            //                 // if let Ok(addr) = value.parse() {
            //                 //     let split_ips = addr.split(",");
            //                 //     println!("ips: {:?}", split_ips);
            //                 //     // peer.allowed_ips.push(addr);
            //                 //     peer.allowed_ips.append(&split_ips);
            //                 // }
            //             }
            //         }
            //         "last_handshake_time_sec" => {
            //             if let Some(ref mut peer) = peer_ref {
            //                 // let handshake =
            //                 //     peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
            //                 // *handshake += Duration::from_secs(value.parse().unwrap_or_default());
            //             }
            //         }
            //         "last_handshake_time_nsec" => {
            //             if let Some(ref mut peer) = peer_ref {
            //                 // let handshake =
            //                 //     peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
            //                 // *handshake += Duration::from_nanos(value.parse().unwrap_or_default());
            //             }
            //         }
            //         // "rx_bytes" => {
            //         //     if let Some(ref mut peer) = peer_ref {
            //         //         peer.rx_bytes = value.parse().unwrap_or_default();
            //         //     }
            //         // }
            //         // "tx_bytes" => {
            //         //     if let Some(ref mut peer) = peer_ref {
            //         //         peer.tx_bytes = value.parse().unwrap_or_default();
            //         //     }
            //         // }
            //         // // "errno" ends config
            //         // "errno" => {
            //         //     if let Ok(errno) = value.parse::<u32>() {
            //         //         if errno == 0 {
            //         //             // Break here, or BufReader will wait for EOF.
            //         //             break;
            //         //         }
            //         //     }
            //         //     return;
            //         // }
            //         _ => println!("Unknown UAPI keyword {}", keyword),
            //     }
            // }
        }


        //     if let Some((key, val)) = line.split_once(' ') {
        //         println!("Split line: {:?}; value: {:?}", key, val);
        //         let keyword: &str = key.trim();
        //         let value = val.trim();

        //         // println!("Trimmed: {:?} {:?}", keyword, value);

        //         match keyword {
        //             "ListenPort" => host.listen_port = value.parse().unwrap_or_default(),
        //             // "ListenPort" => println!("port: {:?}", value.parse().unwrap_or_default()),
        //             // "fwmark" => host.fwmark = value.parse().ok(),
        //             "PrivateKey" => {
        //                 // host.private_key = Key::decode(value).ok();
        //                 let key = Key::from_str(value);
        //                 host.private_key = key.ok();
        //             },
        //             // "PrivateKey" => println!("prv key {:?}", Key::decode(value).ok()),
        //             // "public_key" starts new peer definition
        //             "PublicKey" => {
        //                 // println!("Public key entered {:?}", value);
        //                 // print!("decode pub key {:?}", Key::from_str(value));
        //                 if let Ok(key) = Key::from_str(value) {
        //                     // println!("public KEY: {:?}", key);
        //                     let peer = Peer::new(key.clone());
        //                     host.peers.insert(key.clone(), peer);
        //                     peer_ref = host.peers.get_mut(&key);
        //                 } else {
        //                     peer_ref = None;
        //                 }
        //                 // if let Ok(key) = Key::decode(value) {
        //                 //     println!("public KEY: {:?}", key);
        //                 //     let peer = Peer::new(key.clone());
        //                 //     host.peers.insert(key.clone(), peer);
        //                 //     peer_ref = host.peers.get_mut(&key);
        //                 // } else {
        //                 //     peer_ref = None;
        //                 // }
        //             }
        //             "preshared_key" => {
        //                 if let Some(ref mut peer) = peer_ref {
        //                     // peer.preshared_key = Key::decode(value).ok();
        //                     // println!("PRE: {:?}", Key::decode(value).ok());
        //                 }
        //             }
        //             "protocol_version" => {
        //                 if let Some(ref mut peer) = peer_ref {
        //                     // peer.protocol_version = value.parse().ok();
        //                 }
        //             }
        //             "Endpoint" => {
        //                 if let Some(ref mut peer) = peer_ref {
        //                     peer.endpoint = SocketAddr::from_str(value).ok();
        //                     // println!("PRE: {:?}", SocketAddr::from_str(value).ok());
    
        //                 }
        //             }
        //             "PersistentKeepalive" => {
        //                 if let Some(ref mut peer) = peer_ref {
        //                     peer.persistent_keepalive_interval = value.parse().ok();
        //                 }
        //             }
        //             "AllowedIPs" => {
        //                 // println!("Allowed ips entered");
        //                 if let Some(ref mut peer) = peer_ref {
        //                     // println!("AllowedIps: {:?}", value);
        //                     // let mut split_ips = value.split(",").map(|v| IpAddrMask::from_str(v).unwrap());

        //                     for allowed_ip in value.split(",") {
        //                         // println!("allowed ip: {:?}", allowed_ip);
        //                         let addr = IpAddrMask::from_str(allowed_ip.trim())?;
        //                         peer.allowed_ips.push(addr);
        //                     }

        //                     // peer.allowed_ips.append(&split_ips);
        //                     // IpAddrMask()

        //                     // if let Ok(addr) = value.parse() {
        //                     //     let split_ips = addr.split(",");
        //                     //     println!("ips: {:?}", split_ips);
        //                     //     // peer.allowed_ips.push(addr);
        //                     //     peer.allowed_ips.append(&split_ips);
        //                     // }
        //                 }
        //             }
        //             "last_handshake_time_sec" => {
        //                 if let Some(ref mut peer) = peer_ref {
        //                     // let handshake =
        //                     //     peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
        //                     // *handshake += Duration::from_secs(value.parse().unwrap_or_default());
        //                 }
        //             }
        //             "last_handshake_time_nsec" => {
        //                 if let Some(ref mut peer) = peer_ref {
        //                     // let handshake =
        //                     //     peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
        //                     // *handshake += Duration::from_nanos(value.parse().unwrap_or_default());
        //                 }
        //             }
        //             // "rx_bytes" => {
        //             //     if let Some(ref mut peer) = peer_ref {
        //             //         peer.rx_bytes = value.parse().unwrap_or_default();
        //             //     }
        //             // }
        //             // "tx_bytes" => {
        //             //     if let Some(ref mut peer) = peer_ref {
        //             //         peer.tx_bytes = value.parse().unwrap_or_default();
        //             //     }
        //             // }
        //             // // "errno" ends config
        //             // "errno" => {
        //             //     if let Ok(errno) = value.parse::<u32>() {
        //             //         if errno == 0 {
        //             //             // Break here, or BufReader will wait for EOF.
        //             //             break;
        //             //         }
        //             //     }
        //             //     return;
        //             // }
        //             _ => println!("Unknown UAPI keyword {}", keyword),
        //         }
        //     }


        // }



        // TODO: this needs to be updated
        // thread 'tokio-runtime-worker' panicked at C:\Users\User\.cargo\git\checkouts\wireguard-rs-fba7499ea125cbe3\d135a53\src\wgapi_windows.rs:288:48:
// called `Result::unwrap()` on an `Err` value: InvalidLength

        // wg showconf Szczecin
        // port, private key
        // peer somewhere else?
        println!("HOST: {:?}", host);
        Ok(host)
        // Ok(Host::new(12345, Key::from_str("s").unwrap()))
    }

    fn configure_dns(&self, dns: &[IpAddr]) -> Result<(), WireguardInterfaceError> {
        // netsh interface ipv4 set dns name="Szczecin" static 10.4.0.1
        info!(
            "Configuring DNS for interface {}, using address: {dns:?}",
            self.ifname
        );
        Ok(())
    }
}
