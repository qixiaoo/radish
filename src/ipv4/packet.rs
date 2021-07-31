use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;

use crate::c_like_enum;
use crate::error::Result;
use crate::ipv4::error::Error;

pub mod consts {
    pub const VERSION: u8 = 4;
    pub const MIN_HEADER_LEN: u8 = 5;
}

c_like_enum!(
    /// assigned internet protocol numbers defined in RFC 790 and other RFCs
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum Protocol(u8) {
        Icmp = 1,
        Tcp = 6,
        Udp = 17,
    }
);

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
        packet.check_version()?;
        packet.check_len()?;
        Ok(packet)
    }

    pub fn check_version(&self) -> Result<()> {
        if self.version() != consts::VERSION {
            return Err(Error::InvalidVersion.into());
        }
        Ok(())
    }

    pub fn check_len(&self) -> Result<()> {
        let header_len = self.header_len();
        let total_len = self.total_len();

        if header_len < consts::MIN_HEADER_LEN {
            return Err(Error::InvalidHeaderLen.into());
        }
        if total_len as usize != self.buffer.as_ref().len() {
            return Err(Error::InvalidTotalLen.into());
        }

        Ok(())
    }

    pub fn version(&self) -> u8 {
        self.buffer.as_ref()[0] >> 4
    }

    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[0] & 0x0f
    }

    pub fn tos(&self) -> u8 {
        self.buffer.as_ref()[1]
    }

    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[2], self.buffer.as_ref()[3]])
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[4], self.buffer.as_ref()[5]])
    }

    pub fn flags(&self) -> u8 {
        self.buffer.as_ref()[6] >> 5
    }

    pub fn offset(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[6], self.buffer.as_ref()[7]]) & 0x1fff
    }

    pub fn ttl(&self) -> u8 {
        self.buffer.as_ref()[8]
    }

    pub fn protocol(&self) -> Protocol {
        self.buffer.as_ref()[9].into()
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[10], self.buffer.as_ref()[11]])
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([
            self.buffer.as_ref()[12],
            self.buffer.as_ref()[13],
            self.buffer.as_ref()[14],
            self.buffer.as_ref()[15],
        ])
    }

    pub fn dest_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([
            self.buffer.as_ref()[16],
            self.buffer.as_ref()[17],
            self.buffer.as_ref()[18],
            self.buffer.as_ref()[19],
        ])
    }

    pub fn payload(&self) -> &[u8] {
        let header_bytes_len: usize = (self.header_len() * 4) as usize;
        &self.buffer.as_ref()[header_bytes_len..]
    }
}

impl<Buf> Packet<Buf>
where
    Buf: AsMut<[u8]>,
{
    pub fn set_header_len(&mut self, header_len: u8) {
        self.buffer.as_mut()[0] = (self.buffer.as_mut()[0] & 0xf0) | (header_len & 0x0f);
    }

    pub fn set_tos(&mut self, tos: u8) {
        self.buffer.as_mut()[1] = tos;
    }

    pub fn set_total_len(&mut self, total_len: u16) {
        let be_bytes = total_len.to_be_bytes();
        self.buffer.as_mut()[2] = be_bytes[0];
        self.buffer.as_mut()[3] = be_bytes[1];
    }

    pub fn set_identification(&mut self, identification: u16) {
        let be_bytes = identification.to_be_bytes();
        self.buffer.as_mut()[4] = be_bytes[0];
        self.buffer.as_mut()[5] = be_bytes[1];
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.buffer.as_mut()[6] = (self.buffer.as_mut()[6] & 0x1f) | (flags << 5);
    }

    pub fn set_offset(&mut self, offset: u16) {
        let be_bytes = offset.to_be_bytes();
        self.buffer.as_mut()[6] = (self.buffer.as_mut()[6] & 0xe0) | (be_bytes[0] & 0x1f);
        self.buffer.as_mut()[7] = be_bytes[1];
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.buffer.as_mut()[8] = ttl;
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.buffer.as_mut()[9] = protocol.into();
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        let be_bytes = checksum.to_be_bytes();
        self.buffer.as_mut()[10] = be_bytes[0];
        self.buffer.as_mut()[11] = be_bytes[1];
    }

    pub fn set_src_addr(&mut self, src_addr: Ipv4Addr) {
        self.buffer.as_mut()[12..=15].copy_from_slice(src_addr.octets().as_ref());
    }

    pub fn set_dest_addr(&mut self, dest_addr: Ipv4Addr) {
        self.buffer.as_mut()[16..=19].copy_from_slice(dest_addr.octets().as_ref());
    }
}

impl<Buf> Packet<Buf>
where
    Buf: AsMut<[u8]> + AsRef<[u8]>,
{
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_bytes_len: usize = (self.header_len() * 4) as usize;
        &mut self.buffer.as_mut()[header_bytes_len..]
    }
}

impl<Buf> Debug for Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "version: {:?}, header length: {:?}, total length: {:?}, source address: {:?}, destination address: {:?}, type of service: {:#x}, identification: {:#x}, flags: {:#b}, fragment offset: {:#x}, time to live: {:?}, protocol: {:?}, header checksum: {:#x}",
            self.version(),
            self.header_len(),
            self.total_len(),
            self.src_addr(),
            self.dest_addr(),
            self.tos(),
            self.identification(),
            self.flags(),
            self.offset(),
            self.ttl(),
            self.protocol(),
            self.checksum()
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
