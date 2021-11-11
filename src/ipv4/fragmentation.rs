use crate::ipv4::builder::PacketBuilder;
use crate::ipv4::packet::consts::MIN_HEADER_LEN;
use crate::ipv4::packet::Packet;

impl<Buf> Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    pub fn fragments(&self, mtu: usize) -> FragmentIterator {
        let total_len = self.total_len() as usize;
        FragmentIterator::new(&self.as_ref()[..total_len], mtu)
    }
}

pub struct FragmentIterator<'buf> {
    buffer: &'buf [u8],
    cursor: usize,
    mtu: usize,
}

impl<'buf> FragmentIterator<'buf> {
    pub fn new(buffer: &'buf [u8], mtu: usize) -> Self {
        let packet = Packet::new_unchecked(buffer);
        let header_bytes_len = (packet.header_len() * 4) as usize;

        FragmentIterator {
            buffer,
            cursor: header_bytes_len,
            mtu,
        }
    }
}

impl<'buf> Iterator for FragmentIterator<'buf> {
    type Item = Packet<Vec<u8>>;

    /// Returns next fragment, without ip options currently.
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.buffer.len() {
            return None;
        }

        let min_header_bytes_len = (MIN_HEADER_LEN * 4) as usize;
        let remaining_bytes_len = self.buffer.len() - self.cursor;
        let is_last = remaining_bytes_len < (self.mtu - min_header_bytes_len);

        let nfb = (self.mtu - min_header_bytes_len) / 8; // number of fragment blocks
        let payload_len = if is_last { remaining_bytes_len } else { nfb * 8 };
        let payload = self.buffer[self.cursor..(self.cursor + payload_len)].to_vec();

        let origin_packet = Packet::new_unchecked(self.buffer);

        let oflags = origin_packet.flags();
        let flags = if !is_last { oflags | 0b001 } else { oflags };

        let real_header_bytes_len = origin_packet.header_len() as usize * 4;
        let fragment_offset = origin_packet.offset() as usize + (self.cursor - real_header_bytes_len) / 8;

        let fragment_vec = PacketBuilder::default()
            .header_len(MIN_HEADER_LEN)
            .tos(origin_packet.tos())
            .total_len(((MIN_HEADER_LEN * 4) as usize + payload_len) as u16)
            .identification(origin_packet.identification())
            .flags(flags)
            .offset(fragment_offset as u16)
            .ttl(origin_packet.ttl())
            .protocol(origin_packet.protocol())
            .src_addr(origin_packet.src_addr())
            .dest_addr(origin_packet.dest_addr())
            .payload(payload)
            .build_vec();

        self.cursor += payload_len;

        Some(Packet::new_unchecked(fragment_vec))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::ipv4::builder::PacketBuilder;
    use crate::ipv4::packet::consts::MIN_HEADER_LEN;
    use crate::ipv4::packet::Protocol;

    #[test]
    fn fragment() {
        let min_mtu = 68;
        let header_len = MIN_HEADER_LEN;
        let payload_len = 100;
        let payload: Vec<u8> = (0..payload_len).collect();

        let origin_packet = PacketBuilder::default()
            .header_len(header_len)
            .tos(0)
            .total_len(120)
            .identification(0x1001)
            .flags(0b000)
            .offset(0)
            .ttl(64)
            .protocol(Protocol::Udp)
            .src_addr(Ipv4Addr::new(192, 168, 233, 233))
            .dest_addr(Ipv4Addr::new(192, 168, 233, 234))
            .payload(payload)
            .build();

        let mut iterator = origin_packet.fragments(min_mtu);

        let first_fragment = iterator.next().unwrap();
        let second_fragment = iterator.next().unwrap();
        let third_fragment = iterator.next().unwrap();

        assert_eq!(iterator.next().is_none(), true);
        assert_eq!(iterator.mtu, min_mtu);
        assert_eq!(iterator.cursor, (payload_len + header_len * 4) as usize);

        assert_eq!(first_fragment.total_len(), min_mtu as u16);
        assert_eq!(first_fragment.flags(), 0b001);
        assert_eq!(first_fragment.offset(), 0);
        assert_eq!(first_fragment.payload(), (0..48).collect::<Vec<u8>>().as_slice());

        assert_eq!(second_fragment.total_len(), min_mtu as u16);
        assert_eq!(second_fragment.flags(), 0b001);
        assert_eq!(second_fragment.offset(), 6);
        assert_eq!(second_fragment.payload(), (48..96).collect::<Vec<u8>>().as_slice());

        assert_eq!(third_fragment.total_len(), 24);
        assert_eq!(third_fragment.flags(), 0b000);
        assert_eq!(third_fragment.offset(), 12);
        assert_eq!(third_fragment.payload(), (96..100).collect::<Vec<u8>>().as_slice());
    }
}
