//! Merges, orders, and encodes the listener announcement.

use super::{Listener, MAX_ANNOUNCED, MAX_TRACKED};

/// Magic that opens every announcement, without which OpenVMM's gateway ignores the datagram.
///
/// It and the other constants of the NVXL format must equal those of OpenVMM's
/// `net_backend_resources::ingress`, which parses the announcement.
const MAGIC: [u8; 4] = *b"NVXL";

/// Version of the announcement format, the only one that OpenVMM's gateway accepts.
const VERSION: u8 = 1;

/// Flag of an announcement that omits listeners beyond `MAX_ANNOUNCED`; OpenVMM then warns that
/// it publishes only the lowest. The gateway rejects an announcement with any other flag.
const FLAG_OMITTED: u8 = 0x01;

/// Length of an announcement's header: the magic, the version, the flags, and the big-endian
/// 16-bit count of the entries that follow.
const HEADER_LENGTH: usize = 8;

/// Length of each entry: the IP protocol number, the family mask, and the big-endian 16-bit
/// port.
const ENTRY_LENGTH: usize = 4;

/// Bounded listener set merged by protocol and port.
#[derive(Default)]
pub(super) struct ListenerTable {
    /// Distinct listener entries in discovery order.
    entries: Vec<Listener>,
}

impl ListenerTable {
    /// Adds reachable families to one protocol and port, subject to the tracking bound.
    pub(super) fn add(&mut self, protocol: u8, port: u16, families: u8) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.protocol == protocol && entry.port == port)
        {
            entry.families |= families;
        } else if self.entries.len() < MAX_TRACKED {
            self.entries.push(Listener {
                protocol,
                families,
                port,
            });
        }
    }

    /// Sorts, bounds, and encodes this table as one NVXL version-1 payload.
    fn encode(mut self) -> Vec<u8> {
        self.entries
            .sort_unstable_by_key(|entry| (entry.protocol, entry.port));
        let announced = self.entries.len();
        let count = announced.min(MAX_ANNOUNCED);
        let flags = if announced > MAX_ANNOUNCED {
            FLAG_OMITTED
        } else {
            0
        };
        let mut payload = Vec::with_capacity(HEADER_LENGTH + count * ENTRY_LENGTH);
        payload.extend_from_slice(&MAGIC);
        payload.push(VERSION);
        payload.push(flags);
        payload.extend_from_slice(&(count as u16).to_be_bytes());
        for entry in &self.entries[..count] {
            payload.push(entry.protocol);
            payload.push(entry.families);
            payload.extend_from_slice(&entry.port.to_be_bytes());
        }
        payload
    }
}

/// Consumes and encodes one listener table.
pub(super) fn encode(table: ListenerTable) -> Vec<u8> {
    table.encode()
}

#[cfg(test)]
mod tests {
    //! Canonical ordering, merging, truncation, and framing tests.

    use super::*;
    use crate::guest::ingress::{FAMILY_IPV4, FAMILY_IPV6, PROTOCOL_TCP, PROTOCOL_UDP};

    /// Exercises hundreds of deterministic input sets against every payload invariant.
    #[test]
    fn encoding_is_always_sorted_bounded_and_well_formed() {
        let mut random = 0x4e56_584c_u64;
        for case in 0..512 {
            let mut table = ListenerTable::default();
            let additions = case * 5 % 1_400;
            for _ in 0..additions {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let protocol = if random & 1 == 0 {
                    PROTOCOL_TCP
                } else {
                    PROTOCOL_UDP
                };
                let port = ((random >> 16) as u16).max(1);
                let families = if random & 2 == 0 {
                    FAMILY_IPV4
                } else {
                    FAMILY_IPV6
                };
                table.add(protocol, port, families);
            }
            let total = table.entries.len();
            let payload = encode(table);
            assert!(payload.len() <= 8 + MAX_ANNOUNCED * 4);
            assert_eq!(&payload[..4], b"NVXL");
            assert_eq!(payload[4], 1);
            assert_eq!(payload[5], u8::from(total > MAX_ANNOUNCED));
            let count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
            assert_eq!(count, total.min(MAX_ANNOUNCED));
            assert_eq!(payload.len(), 8 + count * 4);
            let mut previous = None;
            for entry in payload[8..].chunks_exact(4) {
                let key = (entry[0], u16::from_be_bytes([entry[2], entry[3]]));
                assert!(matches!(entry[0], PROTOCOL_TCP | PROTOCOL_UDP));
                assert!([FAMILY_IPV4, FAMILY_IPV6, FAMILY_IPV4 | FAMILY_IPV6].contains(&entry[1]));
                assert_ne!(key.1, 0);
                assert!(previous.is_none_or(|previous| previous < key));
                previous = Some(key);
            }
        }
    }

    /// Verifies duplicate protocol/port entries merge their family masks.
    #[test]
    fn duplicate_protocol_and_port_merge_families() {
        let mut table = ListenerTable::default();
        table.add(PROTOCOL_TCP, 8080, FAMILY_IPV4);
        table.add(PROTOCOL_TCP, 8080, FAMILY_IPV6);
        assert_eq!(encode(table), b"NVXL\x01\x00\x00\x01\x06\x03\x1f\x90");
    }
}
