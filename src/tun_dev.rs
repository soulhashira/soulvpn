use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use tun::Configuration;

/// Create an async TUN device with the given address/prefix/MTU.
pub fn create(
    name_hint: &str,
    address: Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> Result<tun::AsyncDevice> {
    let mut config = Configuration::default();
    config
        .tun_name(name_hint)
        .address(address)
        .netmask(prefix_to_netmask(prefix))
        .mtu(mtu)
        .up();

    let dev = tun::create_as_async(&config)
        .with_context(|| format!("create TUN {name_hint} (need CAP_NET_ADMIN / root)"))?;
    Ok(dev)
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_24() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn netmask_32() {
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }
}
