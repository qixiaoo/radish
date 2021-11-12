use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::Duration;
use timer::{Guard, Timer};

use crate::ipv4::builder::PacketBuilder;
use crate::ipv4::packet::Packet;

mod consts {
    pub const DEFAULT_TLB: u8 = 15; // Default Timer Lower Bound
    pub const DEFAULT_HDUB: u16 = u16::MAX; // Default Hole Descriptor Upper Bound
}

/// The datagram being reassembled.
struct IncompleteDatagram {
    reassembly_timer: ReassemblyTimer,
    holes: Vec<HoleDescriptor>,
    fragments: Vec<Packet<Vec<u8>>>,
    total_data_len: usize,
}

impl IncompleteDatagram {
    /// Insert fragment into the incomplete datagram.
    /// This is a simple but inefficient implementation of RFC 815.
    pub fn insert(&mut self, fragment: Packet<Vec<u8>>) {
        let more_fragments = fragment.more_fragments();
        let first_octet_of_fragment = fragment.first();
        let last_octet_of_fragment = fragment.last();

        let mut filled = false; // Whether the fragment overlaps with some hole.

        let find_hole_fn =
            |hole: &HoleDescriptor| first_octet_of_fragment <= hole.last && last_octet_of_fragment >= hole.first;

        if !more_fragments {
            self.total_data_len =
                (fragment.total_len() - (fragment.header_len() as u16 * 4) + fragment.first()) as usize;
        }

        while let Some(position) = self.holes.iter().position(find_hole_fn) {
            let hole = self.holes.get(position).unwrap(); // The hole to be filled.

            let mut new_holes = Vec::new();

            if first_octet_of_fragment > hole.first {
                new_holes.push(HoleDescriptor::new(hole.first, first_octet_of_fragment - 1));
            }

            if last_octet_of_fragment < hole.last && more_fragments {
                new_holes.push(HoleDescriptor::new(last_octet_of_fragment + 1, hole.last));
            }

            // Remove the hole to be filled and insert new holes.
            self.holes.splice(position..=position, new_holes);

            filled = true;
        }

        if filled {
            let fragment_position = self.fragments.iter().position(|frag| frag.first() > fragment.first());

            match fragment_position {
                Some(position) => self.fragments.insert(position, fragment),
                None => self.fragments.push(fragment),
            }
        }
    }

    /// Returns the reassembled complete datagram.
    pub fn complete(&self) -> Option<Packet<Vec<u8>>> {
        if !self.holes.is_empty() {
            return None;
        }

        let mut start;
        let mut end = 0u16;
        let mut payload = vec![];

        for fragment in &self.fragments {
            let (first, last) = (fragment.first(), fragment.last());

            debug_assert!(first <= end, "`first` should be less than or equal to `end`.");

            if last < end {
                continue; // Discard redundant fragment.
            }

            start = end;
            end = last + 1;

            payload.extend_from_slice(&fragment.payload()[(start - first) as usize..(end - first) as usize]);
        }

        debug_assert!(
            self.total_data_len == payload.len(),
            "`total_data_len` should be equal to payload length."
        );

        let first_fragment = self.fragments.get(0)?;

        let datagram = PacketBuilder::default()
            .header_len(first_fragment.header_len())
            .tos(first_fragment.tos())
            .total_len(((first_fragment.header_len() * 4) as usize + self.total_data_len) as u16)
            .identification(first_fragment.identification())
            .flags(first_fragment.flags() & 0xfe)
            .offset(0)
            .ttl(first_fragment.ttl())
            .protocol(first_fragment.protocol())
            .src_addr(first_fragment.src_addr())
            .dest_addr(first_fragment.dest_addr())
            .payload(payload)
            .build();

        Some(datagram)
    }
}

impl Default for IncompleteDatagram {
    fn default() -> Self {
        Self {
            reassembly_timer: ReassemblyTimer::default(),
            holes: vec![HoleDescriptor::default()],
            fragments: Vec::new(),
            total_data_len: 0,
        }
    }
}

/// A timer used to manage reassembly timeout.
struct ReassemblyTimer {
    timeout: u8,
    guard: Option<Guard>,
}

impl Default for ReassemblyTimer {
    fn default() -> Self {
        Self {
            timeout: consts::DEFAULT_TLB,
            guard: None,
        }
    }
}

/// A HoleDescriptor represents an area that has not been filled in the datagram.
struct HoleDescriptor {
    first: u16,
    last: u16,
}

impl HoleDescriptor {
    fn new(first: u16, last: u16) -> Self {
        Self { first, last }
    }
}

impl Default for HoleDescriptor {
    fn default() -> Self {
        Self {
            first: 0,
            last: consts::DEFAULT_HDUB,
        }
    }
}

/// The id of the datagram being reassembled.
type DatagramId = u128;

impl<Buf> Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    pub fn datagram_id(&self) -> DatagramId {
        let identification: u16 = self.identification();
        let protocol: u8 = self.protocol().into();
        let src_addr: u32 = self.src_addr().into();
        let dest_addr: u32 = self.dest_addr().into();

        (identification as u128) << 72 | (protocol as u128) << 64 | (src_addr as u128) << 32 | (dest_addr as u128)
    }

    /// Returns the index of the first octet.
    fn first(&self) -> u16 {
        self.offset() * 8
    }

    /// Returns the index of the last octet.
    fn last(&self) -> u16 {
        self.first() + self.payload().len() as u16 - 1
    }
}

/// Reassembler is used to reconstruct complete datagram from fragments.
pub struct Reassembler {
    /// A timer used to execute timed tasks.
    task_timer: Timer,
    /// A hash map to store datagrams being reassembled.
    datagram_map: Arc<Mutex<HashMap<DatagramId, IncompleteDatagram>>>,
}

impl Reassembler {
    /// Discard the datagram that is being reassembled.
    pub fn release(&self, datagram_id: DatagramId) {
        self.datagram_map.lock().unwrap().remove(&datagram_id);
    }

    /// Reassemble fragments.
    pub fn reassemble(&self, fragment: Packet<Vec<u8>>) -> Option<Packet<Vec<u8>>> {
        let ttl = fragment.ttl();
        let datagram_id = fragment.datagram_id();

        let mut datagram_map = self.datagram_map.lock().unwrap();
        let datagram = datagram_map
            .entry(datagram_id)
            .or_insert_with(IncompleteDatagram::default);

        datagram.insert(fragment);

        let timeout = datagram.reassembly_timer.timeout.max(ttl);
        let cloned_datagram_map = self.datagram_map.clone();
        let guard = self
            .task_timer
            .schedule_with_delay(Duration::seconds(timeout as i64), move || {
                cloned_datagram_map.lock().unwrap().remove(&datagram_id);
            });

        datagram.reassembly_timer.timeout = timeout;
        datagram.reassembly_timer.guard = Some(guard);

        datagram.complete().map(|complete_datagram| {
            datagram_map.remove(&datagram_id);
            complete_datagram
        })
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self {
            task_timer: Timer::new(),
            datagram_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::thread::sleep;
    use std::time::Duration;

    use crate::ipv4::builder::PacketBuilder;
    use crate::ipv4::packet::consts::MIN_HEADER_LEN;
    use crate::ipv4::packet::{Packet, Protocol};
    use crate::ipv4::reassembly::Reassembler;

    const IDENTIFICATION: u16 = 0x1001;
    const PROTOCOL: Protocol = Protocol::Udp;
    const TTL: u8 = 20;
    const SRC_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 233, 233);
    const DEST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 233, 234);

    fn get_fragments(payload_len: u8) -> Vec<Packet<Vec<u8>>> {
        let min_mtu = 68;
        let header_len = MIN_HEADER_LEN;
        let payload: Vec<u8> = (0..payload_len).collect();

        let origin_packet = PacketBuilder::default()
            .header_len(header_len)
            .tos(0)
            .total_len((header_len * 4 + payload_len) as u16)
            .identification(IDENTIFICATION)
            .flags(0b000)
            .offset(0)
            .ttl(TTL)
            .protocol(PROTOCOL)
            .src_addr(SRC_ADDR)
            .dest_addr(DEST_ADDR)
            .payload(payload)
            .build();

        origin_packet.fragments(min_mtu).collect()
    }

    #[test]
    fn reassemble() {
        let payload_len = 100;
        let mut fragments = get_fragments(payload_len);

        let first = fragments.remove(0);
        let second = fragments.remove(0);
        let third = fragments.remove(0);

        let reassembler = Reassembler::default();

        assert_eq!(reassembler.reassemble(second).is_none(), true);
        assert_eq!(reassembler.reassemble(third).is_none(), true);

        let datagram = reassembler.reassemble(first).unwrap();

        assert_eq!(datagram.payload(), (0..payload_len).collect::<Vec<u8>>().as_slice());
        assert_eq!(datagram.identification(), IDENTIFICATION);
    }

    #[test]
    fn task_timer() {
        let payload_len = 100;
        let mut fragments = get_fragments(payload_len);

        let first = fragments.remove(0);
        let _second = fragments.remove(0);
        let third = fragments.remove(0);

        let datagram_id = first.datagram_id();
        let reassembler = Reassembler::default();

        reassembler.reassemble(third);

        {
            let datagram_map = reassembler.datagram_map.lock().unwrap();
            let incomplete_datagram = datagram_map.get(&datagram_id).unwrap();

            assert_eq!(incomplete_datagram.reassembly_timer.timeout, TTL);
            assert_eq!(incomplete_datagram.reassembly_timer.guard.is_some(), true);
            assert_eq!(incomplete_datagram.total_data_len, payload_len as usize);
        }

        sleep(Duration::new((TTL + 1) as u64, 0)); // Wait for timeout.

        {
            let datagram_map = reassembler.datagram_map.lock().unwrap();
            assert_eq!(datagram_map.contains_key(&datagram_id), false);
        }
    }
}
