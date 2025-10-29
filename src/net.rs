//! Network address utilities

use std::{
    error, fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    constants::{AF_INET, AF_INET6},
    nlas::{WgAllowedIp, WgAllowedIpAttrs},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// IP address with CIDR.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct IpAddrMask {
    // IP v4 or v6
    pub address: IpAddr,
    // Classless Inter-Domain Routing
    pub cidr: u8,
}

impl IpAddrMask {
    #[must_use]
    pub fn new(address: IpAddr, cidr: u8) -> Self {
        Self { address, cidr }
    }

    #[must_use]
    pub fn host(address: IpAddr) -> Self {
        let cidr = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { address, cidr }
    }

    /// Returns broadcast address as `IpAddr`.
    /// Note: IPv6 does not really use broadcast.
    #[must_use]
    pub fn broadcast(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(ip) => {
                let addr = u32::from(ip);
                let bits = if self.cidr >= 32 {
                    0
                } else {
                    u32::MAX >> self.cidr
                };
                IpAddr::V4(Ipv4Addr::from(addr | bits))
            }
            IpAddr::V6(ip) => {
                let addr = u128::from(ip);
                let bits = if self.cidr >= 128 {
                    0
                } else {
                    u128::MAX >> self.cidr
                };
                IpAddr::V6(Ipv6Addr::from(addr | bits))
            }
        }
    }

    /// Returns network mask as `IpAddr`.
    #[must_use]
    pub fn mask(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(_) => {
                let mask = if self.cidr == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.cidr)
                };
                IpAddr::V4(Ipv4Addr::from(mask))
            }
            IpAddr::V6(_) => {
                let mask = if self.cidr == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.cidr)
                };
                IpAddr::V6(Ipv6Addr::from(mask))
            }
        }
    }

    /// Returns `true` if the address defines a host, `false` if it is a network.
    #[must_use]
    pub fn is_host(&self) -> bool {
        if self.address.is_ipv4() {
            self.cidr == 32
        } else {
            self.cidr == 128
        }
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn to_nlas_allowed_ip(&self) -> WgAllowedIp {
        let mut attrs = Vec::new();
        attrs.push(WgAllowedIpAttrs::Family(if self.address.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        }));
        attrs.push(WgAllowedIpAttrs::IpAddr(self.address));
        attrs.push(WgAllowedIpAttrs::Cidr(self.cidr));
        WgAllowedIp(attrs)
    }
}

impl fmt::Display for IpAddrMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.cidr)
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
            let ip = left.parse().map_err(|_| IpAddrParseError)?;
            let cidr = right.parse().map_err(|_| IpAddrParseError)?;
            let max_cidr = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if cidr > max_cidr {
                return Err(IpAddrParseError);
            }
            Ok(IpAddrMask { address: ip, cidr })
        } else {
            let ip = ip_str.parse().map_err(|_| IpAddrParseError)?;
            Ok(IpAddrMask {
                address: ip,
                cidr: if ip.is_ipv4() { 32 } else { 128 },
            })
        }
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn valid_cidr() {
        assert!("192.168.0.1/32".parse::<IpAddrMask>().is_ok());
        assert!("192.168.0.1/33".parse::<IpAddrMask>().is_err());
        assert!("2001:0db8::1428:57ab/128".parse::<IpAddrMask>().is_ok());
        assert!("2001:0db8::1428:57ab/129".parse::<IpAddrMask>().is_err());
    }

    #[test]
    fn addr_mask() {
        let ip = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 24);
        assert_eq!(ip.broadcast(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)));
        assert_eq!(ip.mask(), IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));

        let ip = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8);
        assert_eq!(
            ip.broadcast(),
            IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))
        );
        assert_eq!(ip.mask(), IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)));

        let ip = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(169, 254, 219, 59)), 16);
        assert_eq!(
            ip.broadcast(),
            IpAddr::V4(Ipv4Addr::new(169, 254, 255, 255))
        );
        assert_eq!(ip.mask(), IpAddr::V4(Ipv4Addr::new(255, 255, 0, 0)));

        let ip = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(
            ip.broadcast(),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))
        );
        assert_eq!(ip.mask(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));

        let ip = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(12, 34, 56, 78)), 32);
        assert_eq!(ip.broadcast(), IpAddr::V4(Ipv4Addr::new(12, 34, 56, 78)));
        assert_eq!(ip.mask(), IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn addr_mask_v6() {
        let ip = IpAddrMask::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x1428, 0x57ab)),
            96,
        );
        assert_eq!(
            ip.broadcast(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0xffff, 0xffff))
        );
        assert_eq!(
            ip.mask(),
            IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0
            ))
        );
    }
}
