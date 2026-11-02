// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `-rpcallowip`, as ycashd: loopback is always allowed; each entry is an address, an
//! `address/prefix` or an `address/netmask`. A peer outside them gets HTTP 403.

use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Net {
    addr: u128,
    mask: u128,
    v4: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowIp(Vec<Net>);

fn bits(ip: IpAddr) -> (u128, bool) {
    match ip {
        IpAddr::V4(a) => (u32::from(a) as u128, true),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => (u32::from(v4) as u128, true),
            None => (u128::from(a), false),
        },
    }
}

fn prefix_mask(len: u32, width: u32) -> Option<u128> {
    if len > width {
        return None;
    }
    let full: u128 = if width == 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    Some(if len == 0 {
        0
    } else {
        full & !((1u128 << (width - len)) - 1)
    })
}

impl AllowIp {
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut nets = Vec::new();
        for e in entries {
            let (a, m) = match e.split_once('/') {
                Some((a, m)) => (a, Some(m)),
                None => (e.as_str(), None),
            };
            let ip: IpAddr = a
                .parse()
                .map_err(|_| format!("-rpcallowip={e} is not an address or subnet"))?;
            let (addr, v4) = bits(ip);
            let width = if v4 { 32 } else { 128 };
            let mask = match m {
                None => prefix_mask(width, width),
                Some(m) => match m.parse::<u32>() {
                    Ok(len) => prefix_mask(len, width),
                    Err(_) => match m.parse::<IpAddr>().map(bits) {
                        Ok((mask, mv4)) if mv4 == v4 => Some(mask),
                        _ => None,
                    },
                },
            }
            .ok_or_else(|| format!("-rpcallowip={e} has a bad prefix or netmask"))?;
            nets.push(Net {
                addr: addr & mask,
                mask,
                v4,
            });
        }
        Ok(AllowIp(nets))
    }

    pub fn allows(&self, peer: IpAddr) -> bool {
        let peer = match peer {
            IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
            p => p,
        };
        if peer.is_loopback() {
            return true;
        }
        let (p, v4) = bits(peer);
        self.0.iter().any(|n| n.v4 == v4 && p & n.mask == n.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> AllowIp {
        AllowIp::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn loopback_always() {
        let x = a(&[]);
        assert!(x.allows("127.0.0.1".parse().unwrap()));
        assert!(x.allows("::1".parse().unwrap()));
        assert!(x.allows("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!x.allows("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn subnets() {
        let x = a(&[
            "10.1.0.0/16",
            "192.168.1.7",
            "172.16.0.0/255.240.0.0",
            "fd00::/8",
        ]);
        assert!(x.allows("10.1.200.3".parse().unwrap()));
        assert!(!x.allows("10.2.0.1".parse().unwrap()));
        assert!(x.allows("192.168.1.7".parse().unwrap()));
        assert!(!x.allows("192.168.1.8".parse().unwrap()));
        assert!(x.allows("172.31.255.1".parse().unwrap()));
        assert!(x.allows("fd12::1".parse().unwrap()));
        assert!(!x.allows("fe80::1".parse().unwrap()));
        assert!(x.allows("::ffff:10.1.0.9".parse().unwrap()));
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["nothost", "10.0.0.0/33", "10.0.0.0/ffff::"] {
            assert!(AllowIp::parse(&[bad.to_string()]).is_err(), "{bad}");
        }
    }
}
