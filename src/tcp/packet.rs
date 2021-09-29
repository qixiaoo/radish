use std::fmt::{Debug, Formatter};

use crate::error::Result;
use crate::tcp::error::Error;

pub struct Packet<Buf> {
    buffer: Buf,
}

impl<Buf> Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    pub fn new_unchecked(buffer: Buf) -> Self {
        Packet { buffer }
    }

    pub fn new_checked(buffer: Buf) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub fn check_len(&self) -> Result<()> {
        let header_bytes_len: usize = (self.data_offset() * 4) as usize;

        if header_bytes_len > self.buffer.as_ref().len() {
            return Err(Error::InvalidDataOffset.into());
        }

        Ok(())
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[0], self.buffer.as_ref()[1]])
    }

    pub fn dest_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[2], self.buffer.as_ref()[3]])
    }

    pub fn seq_number(&self) -> u32 {
        u32::from_be_bytes([
            self.buffer.as_ref()[4],
            self.buffer.as_ref()[5],
            self.buffer.as_ref()[6],
            self.buffer.as_ref()[7],
        ])
    }

    pub fn ack_number(&self) -> u32 {
        u32::from_be_bytes([
            self.buffer.as_ref()[8],
            self.buffer.as_ref()[9],
            self.buffer.as_ref()[10],
            self.buffer.as_ref()[11],
        ])
    }

    pub fn data_offset(&self) -> u8 {
        self.buffer.as_ref()[12] >> 4
    }

    pub fn reserved(&self) -> u8 {
        ((self.buffer.as_ref()[12] & 0x0f) << 2) | (self.buffer.as_ref()[13] >> 6)
    }

    pub fn urg(&self) -> bool {
        ((self.buffer.as_ref()[13] & 0x20) >> 5) == 1
    }

    pub fn ack(&self) -> bool {
        ((self.buffer.as_ref()[13] & 0x10) >> 4) == 1
    }

    pub fn psh(&self) -> bool {
        ((self.buffer.as_ref()[13] & 0x08) >> 3) == 1
    }

    pub fn rst(&self) -> bool {
        ((self.buffer.as_ref()[13] & 0x04) >> 2) == 1
    }

    pub fn syn(&self) -> bool {
        ((self.buffer.as_ref()[13] & 0x02) >> 1) == 1
    }

    pub fn fin(&self) -> bool {
        (self.buffer.as_ref()[13] & 0x01) == 1
    }

    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[14], self.buffer.as_ref()[15]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[16], self.buffer.as_ref()[17]])
    }

    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[18], self.buffer.as_ref()[19]])
    }

    // TODO: option method

    pub fn payload(&self) -> &[u8] {
        let header_bytes_len: usize = (self.data_offset() * 4) as usize;
        &self.buffer.as_ref()[header_bytes_len..]
    }
}

impl<Buf> Packet<Buf>
where
    Buf: AsMut<[u8]>,
{
    pub fn set_src_port(&mut self, src_port: u16) {
        self.buffer.as_mut()[0..=1].copy_from_slice(src_port.to_be_bytes().as_ref());
    }

    pub fn set_dest_port(&mut self, dest_port: u16) {
        self.buffer.as_mut()[2..=3].copy_from_slice(dest_port.to_be_bytes().as_ref());
    }

    pub fn set_seq_number(&mut self, seq_number: u32) {
        self.buffer.as_mut()[4..=7].copy_from_slice(seq_number.to_be_bytes().as_ref());
    }

    pub fn set_ack_number(&mut self, ack_number: u32) {
        self.buffer.as_mut()[8..=11].copy_from_slice(ack_number.to_be_bytes().as_ref());
    }

    pub fn set_data_offset(&mut self, data_offset: u8) {
        self.buffer.as_mut()[12] = (self.buffer.as_mut()[12] & 0x0f) | (data_offset << 4)
    }

    pub fn set_reserved(&mut self, reserved: u8) {
        self.buffer.as_mut()[12] = (self.buffer.as_mut()[12] & 0xf0) | (reserved >> 2);
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0x3f) | (reserved << 6);
    }

    pub fn set_urg(&mut self, urg: bool) {
        let bit = if urg { 1 } else { 0 };
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0xdf) | (bit << 5);
    }

    pub fn set_ack(&mut self, ack: bool) {
        let bit = if ack { 1 } else { 0 };
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0xef) | (bit << 4);
    }

    pub fn set_psh(&mut self, psh: bool) {
        let bit = if psh { 1 } else { 0 };
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0xf7) | (bit << 3);
    }

    pub fn set_rst(&mut self, rst: bool) {
        let bit = if rst { 1 } else { 0 };
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0xfb) | (bit << 2);
    }

    pub fn set_syn(&mut self, syn: bool) {
        let bit = if syn { 1 } else { 0 };
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0xfd) | (bit << 1);
    }

    pub fn set_fin(&mut self, fin: bool) {
        let bit = if fin { 1 } else { 0 };
        self.buffer.as_mut()[13] = (self.buffer.as_mut()[13] & 0xfe) | bit;
    }

    pub fn set_window(&mut self, window: u16) {
        self.buffer.as_mut()[14..=15].copy_from_slice(window.to_be_bytes().as_ref());
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer.as_mut()[16..=17].copy_from_slice(checksum.to_be_bytes().as_ref());
    }

    pub fn set_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.buffer.as_mut()[18..=19].copy_from_slice(urgent_pointer.to_be_bytes().as_ref());
    }

    // TODO: set_option method
}

impl<Buf> Packet<Buf>
where
    Buf: AsMut<[u8]> + AsRef<[u8]>,
{
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_bytes_len: usize = (self.data_offset() * 4) as usize;
        &mut self.buffer.as_mut()[header_bytes_len..]
    }

    pub fn set_payload(&mut self, payload: Buf) {
        self.payload_mut()[..payload.as_ref().len()].copy_from_slice(payload.as_ref());
    }
}

impl<Buf> Debug for Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "source port: {:?}, destination port: {:?}, sequence number: {:#x}, acknowledgment number: {:#x}, data offset: {:?}, reserved: {:#x}, URG: {:?}, ACK: {:?}, PSH: {:?}, RST: {:?}, SYN: {:?}, FIN: {:?}, window: {:#x}, checksum: {:#x}, urgent pointer: {:#x}",
            self.src_port(),
            self.dest_port(),
            self.seq_number(),
            self.ack_number(),
            self.data_offset(),
            self.reserved(),
            self.urg(),
            self.ack(),
            self.psh(),
            self.rst(),
            self.syn(),
            self.fin(),
            self.window(),
            self.checksum(),
            self.urgent_pointer(),
        )
    }
}

impl<Buf> AsRef<[u8]> for Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<Buf> AsMut<[u8]> for Packet<Buf>
where
    Buf: AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new_checked() {
        let mut tcp_header_bytes: Vec<u8> = vec![
            // tcp header
            0xc0, 0x9b, 0x0b, 0xb8, 0x57, 0x16, 0x23, 0x08, 0x60, 0x82, 0x25, 0x90, 0x80, 0x18, 0x18, 0xeb, 0xfe, 0x76,
            0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xf1, 0x51, 0xfb, 0xc9, 0xa8, 0x10, 0x91, 0x0d,
        ];

        let mut tcp_payload_bytes: Vec<u8> = vec![
            // tcp payload
            0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f,
            0x73, 0x74, 0x3a, 0x20, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x33, 0x30, 0x30, 0x30,
            0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c,
            0x2f, 0x37, 0x2e, 0x36, 0x34, 0x2e, 0x31, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a,
            0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a,
        ];

        let mut bytes: Vec<u8> = vec![];
        bytes.append(&mut tcp_header_bytes);
        bytes.append(&mut tcp_payload_bytes);

        // tcp packet generated from "curl 127.0.0.1:3000"
        let packet = super::Packet::new_checked(bytes).expect("a valid tcp packet");

        assert_eq!(packet.src_port(), 49307);
        assert_eq!(packet.dest_port(), 3000);
        assert_eq!(packet.seq_number(), 0x57162308);
        assert_eq!(packet.ack_number(), 0x60822590);
        assert_eq!(packet.data_offset(), 8);
        assert_eq!(packet.urg(), false);
        assert_eq!(packet.ack(), true);
        assert_eq!(packet.psh(), true);
        assert_eq!(packet.rst(), false);
        assert_eq!(packet.syn(), false);
        assert_eq!(packet.fin(), false);
        assert_eq!(packet.window(), 0x18eb);
        assert_eq!(packet.checksum(), 0xfe76);
        assert_eq!(packet.urgent_pointer(), 0x0000);
    }

    #[test]
    fn setter() {
        let data_offset = 5 as usize;
        let payload_len = 8 as usize;
        let total_len = data_offset * 4 + payload_len;

        let buffer: Vec<u8> = vec![0; total_len];
        let mut packet = super::Packet::new_unchecked(buffer);

        packet.set_src_port(4096);
        assert_eq!(packet.src_port(), 4096);

        packet.set_dest_port(80);
        assert_eq!(packet.dest_port(), 80);

        packet.set_seq_number(0x11223344);
        assert_eq!(packet.seq_number(), 0x11223344);

        packet.set_ack_number(0xffeeddcc);
        assert_eq!(packet.ack_number(), 0xffeeddcc);

        packet.set_data_offset(data_offset as u8);
        assert_eq!(packet.data_offset(), data_offset as u8);

        packet.set_reserved(0b111111);
        assert_eq!(packet.reserved(), 0b111111);

        packet.set_urg(true);
        assert_eq!(packet.urg(), true);

        packet.set_ack(true);
        assert_eq!(packet.ack(), true);

        packet.set_psh(true);
        assert_eq!(packet.psh(), true);

        packet.set_rst(true);
        assert_eq!(packet.rst(), true);

        packet.set_syn(true);
        assert_eq!(packet.syn(), true);

        packet.set_fin(true);
        assert_eq!(packet.fin(), true);

        packet.set_window(0x45bd);
        assert_eq!(packet.window(), 0x45bd);

        packet.set_checksum(0x34e8);
        assert_eq!(packet.checksum(), 0x34e8);

        packet.set_urgent_pointer(0xc67f);
        assert_eq!(packet.urgent_pointer(), 0xc67f);

        packet.set_payload(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(packet.payload(), vec![1, 2, 3, 4, 5, 6, 7, 8].as_slice());
    }
}
