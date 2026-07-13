//! IPv4 header helpers for policy checks.

use std::net::Ipv4Addr;

/// True if buffer looks like a minimal IPv4 header.
pub fn is_ipv4(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4
}

pub fn ipv4_src(packet: &[u8]) -> Option<Ipv4Addr> {
    if !is_ipv4(packet) {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

pub fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if !is_ipv4(packet) {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet(src: [u8; 4], dst: [u8; 4]) -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = 0x45; // v4, ihl=5
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn parses_src_dst() {
        let p = sample_packet([10, 66, 66, 2], [1, 2, 3, 4]);
        assert_eq!(ipv4_src(&p), Some(Ipv4Addr::new(10, 66, 66, 2)));
        assert_eq!(ipv4_dst(&p), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn rejects_non_v4() {
        let mut p = sample_packet([1, 1, 1, 1], [2, 2, 2, 2]);
        p[0] = 0x60;
        assert!(ipv4_src(&p).is_none());
    }
}
