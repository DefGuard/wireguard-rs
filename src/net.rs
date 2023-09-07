use std::{error, fmt, net::IpAddr, str::FromStr};

#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    constants::{AF_INET, AF_INET6},
    nlas::{WgAllowedIp, WgAllowedIpAttrs},
};

#[derive(Debug, PartialEq, Clone)]
pub struct IpAddrMask {
    // IP v4 or v6
    pub ip: IpAddr,
    // Classless Inter-Domain Routing
    pub cidr: u8,
}

impl IpAddrMask {
    #[must_use]
    pub fn new(ip: IpAddr, cidr: u8) -> Self {
        Self { ip, cidr }
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn to_nlas_allowed_ip(&self) -> WgAllowedIp {
        let mut attrs = Vec::new();
        attrs.push(WgAllowedIpAttrs::Family(if self.ip.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        }));
        attrs.push(WgAllowedIpAttrs::IpAddr(self.ip));
        attrs.push(WgAllowedIpAttrs::Cidr(self.cidr));
        WgAllowedIp(attrs)
    }
}

impl fmt::Display for IpAddrMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.cidr)
    }
}

#[derive(Debug, PartialEq)]
pub struct IpAddrParseError;

impl error::Error for IpAddrParseError {}

impl fmt::Display for IpAddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IP address/mask parse error")
    }
}

impl FromStr for IpAddrMask {
    type Err = IpAddrParseError;

    fn from_str(ip_str: &str) -> Result<Self, Self::Err> {
        if let Some((left, right)) = ip_str.split_once('/') {
            Ok(IpAddrMask {
                ip: left.parse().map_err(|_| IpAddrParseError)?,
                cidr: right.parse().map_err(|_| IpAddrParseError)?,
            })
        } else {
            let ip: IpAddr = ip_str.parse().map_err(|_| IpAddrParseError)?;
            Ok(IpAddrMask {
                ip,
                cidr: if ip.is_ipv4() { 32 } else { 128 },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn parse_ip_addr() {
        assert_eq!(
            "192.168.0.1/24".parse::<IpAddrMask>(),
            Ok(IpAddrMask::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                24
            ))
        );

        assert_eq!(
            "10.11.12.13".parse::<IpAddrMask>(),
            Ok(IpAddrMask::new(
                IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13)),
                32
            ))
        );

        assert_eq!(
            "2001:0db8::1428:57ab/96".parse::<IpAddrMask>(),
            Ok(IpAddrMask::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x1428, 0x57ab)),
                96
            ))
        );

        assert_eq!(
            "::1".parse::<IpAddrMask>(),
            Ok(IpAddrMask::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                128
            ))
        );

        assert_eq!(
            "172.168.0.256/24".parse::<IpAddrMask>(),
            Err(IpAddrParseError)
        );

        assert_eq!(
            "172.168.0.0/256".parse::<IpAddrMask>(),
            Err(IpAddrParseError)
        );
    }
}
