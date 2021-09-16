use std::net::Ipv4Addr;

use crate::checksum::checksum;
use crate::ipv4::packet::{consts, Packet, Protocol};

pub struct PacketBuilder {
    version: u8,
    header_len: u8,
    tos: u8,
    total_len: u16,
    identification: u16,
    flags: u8,
    offset: u16,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    payload: Vec<u8>,
}

impl PacketBuilder {
    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    pub fn header_len(mut self, header_len: u8) -> Self {
        self.header_len = header_len;
        self
    }

    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = tos;
        self
    }

    pub fn total_len(mut self, total_len: u16) -> Self {
        self.total_len = total_len;
        self
    }

    pub fn identification(mut self, identification: u16) -> Self {
        self.identification = identification;
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn offset(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = checksum;
        self
    }

    pub fn src_addr(mut self, src_addr: Ipv4Addr) -> Self {
        self.src_addr = src_addr;
        self
    }

    pub fn dest_addr(mut self, dest_addr: Ipv4Addr) -> Self {
        self.dest_addr = dest_addr;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build_vec(mut self) -> Vec<u8> {
        if self.total_len == 0 {
            self.total_len = ((self.header_len * 4) as usize + self.payload.len()) as u16;
        }

        let mut buffer: Vec<u8> = vec![0; (self.header_len * 4) as usize];
        buffer.append(&mut self.payload);

        let mut packet = Packet::new_unchecked(buffer.as_mut_slice());
        packet.set_version(self.version);
        packet.set_header_len(self.header_len);
        packet.set_tos(self.tos);
        packet.set_total_len(self.total_len);
        packet.set_identification(self.identification);
        packet.set_flags(self.flags);
        packet.set_offset(self.offset);
        packet.set_ttl(self.ttl);
        packet.set_protocol(self.protocol);
        packet.set_checksum(self.checksum);
        packet.set_src_addr(self.src_addr);
        packet.set_dest_addr(self.dest_addr);

        if self.checksum == 0 {
            packet.set_checksum(checksum(packet.as_ref()));
        }

        buffer
    }

    pub fn build(self) -> Packet<Vec<u8>> {
        Packet::new_unchecked(self.build_vec())
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self {
            version: consts::VERSION,
            header_len: consts::MIN_HEADER_LEN,
            tos: 0,
            total_len: 0,
            identification: 0,
            flags: 0,
            offset: 0,
            ttl: 0,
            protocol: Protocol::Unknown(0),
            checksum: 0,
            src_addr: Ipv4Addr::new(0, 0, 0, 0),
            dest_addr: Ipv4Addr::new(0, 0, 0, 0),
            payload: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::ipv4::packet::{consts, Protocol};

    #[test]
    fn build() {
        let tos = 0;
        let identification = 0x1122;
        let flags = 0b010;
        let ttl = 100;
        let protocol = Protocol::Icmp;
        let src_addr = Ipv4Addr::new(127, 0, 0, 1);
        let dest_addr = Ipv4Addr::new(192, 168, 233, 233);
        let payload = vec![0; 20];

        let expected_total_len = (consts::MIN_HEADER_LEN * 4) as usize + payload.len();
        let expected_payload = payload.clone();

        let packet = super::PacketBuilder::default()
            .tos(tos)
            .identification(identification)
            .flags(flags)
            .ttl(ttl)
            .protocol(protocol)
            .src_addr(src_addr)
            .dest_addr(dest_addr)
            .payload(payload)
            .build();

        assert_eq!(packet.version(), consts::VERSION);
        assert_eq!(packet.header_len(), consts::MIN_HEADER_LEN);
        assert_eq!(packet.tos(), tos);
        assert_eq!(packet.total_len() as usize, expected_total_len);
        assert_eq!(packet.identification(), identification);
        assert_eq!(packet.flags(), flags);
        assert_eq!(packet.ttl(), ttl);
        assert_eq!(packet.protocol(), protocol);
        assert_eq!(packet.src_addr(), src_addr);
        assert_eq!(packet.dest_addr(), dest_addr);
        assert_eq!(packet.payload(), expected_payload.clone());
    }
}
