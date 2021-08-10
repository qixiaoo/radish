use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::option::Option as StdOption;

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

    pub fn options(&self) -> OptionIterator {
        let header_bytes_len: usize = (self.header_len() * 4) as usize;
        OptionIterator::new(&self.buffer.as_ref()[20..header_bytes_len])
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

pub struct OptionIterator<'buf> {
    buffer: &'buf [u8],
    cursor: usize,
}

impl<'buf> OptionIterator<'buf> {
    pub fn new(buffer: &'buf [u8]) -> Self {
        OptionIterator { buffer, cursor: 0 }
    }
}

impl<'buf> Iterator for OptionIterator<'buf> {
    type Item = Result<Option<'buf>>;

    fn next(&mut self) -> StdOption<Self::Item> {
        if self.cursor >= self.buffer.len() {
            return None;
        }

        let buffer_to_iterate = &self.buffer[self.cursor..];
        let result = Option::new_checked(buffer_to_iterate);

        match result {
            Ok(option) => {
                self.cursor += option.as_ref().len();
                if option.kind() == OptionKind::End {
                    None
                } else {
                    Some(Ok(option))
                }
            }
            Err(err) => Some(Err(err)),
        }
    }
}

pub struct Option<'buf> {
    buffer: &'buf [u8],
}

impl<'buf> Option<'buf> {
    pub fn new_unchecked(buffer: &'buf [u8]) -> Self {
        Option { buffer }
    }

    pub fn new_checked(buffer: &'buf [u8]) -> Result<Self> {
        let buf_len = buffer.len();

        if buf_len < 1 {
            return Err(Error::InvalidOptionLen.into());
        }

        let mut option = Self::new_unchecked(buffer);
        let option_kind = option.kind();

        if buf_len == 1 {
            return match option_kind {
                OptionKind::End | OptionKind::NoOperation | OptionKind::Unknown => Ok(option),
                _ => Err(Error::InvalidOptionLen.into()),
            };
        }

        let consumed_len = match option_kind {
            OptionKind::End | OptionKind::NoOperation | OptionKind::Unknown => 1,
            OptionKind::Security => 11,
            OptionKind::LooseSourceRouting
            | OptionKind::StrictSourceRouting
            | OptionKind::RecordRoute
            | OptionKind::Timestamp => buffer[1],
            OptionKind::StreamId => 4,
        };

        if buf_len < consumed_len as usize {
            return Err(Error::InvalidOptionLen.into());
        }

        option = Self::new_unchecked(&buffer[0..consumed_len as usize]);

        Ok(option)
    }

    pub fn r#type(&self) -> OptionType {
        self.buffer[0].into()
    }

    pub fn length(&self) -> StdOption<u8> {
        let buf_len = self.buffer.len();

        if buf_len > 1 {
            Some(self.buffer[1])
        } else {
            None
        }
    }

    pub fn data(&self) -> StdOption<&[u8]> {
        self.length().map(|length| &(self.buffer[2..=(length as usize)]))
    }

    pub fn kind(&self) -> OptionKind {
        let option_type = self.r#type();
        let option_class = option_type.class();
        let option_number = option_type.number();

        match (option_class, option_number) {
            (OptionClass::Control, 0) => OptionKind::End,
            (OptionClass::Control, 1) => OptionKind::NoOperation,
            (OptionClass::Control, 2) => OptionKind::Security,
            (OptionClass::Control, 3) => OptionKind::LooseSourceRouting,
            (OptionClass::Control, 7) => OptionKind::RecordRoute,
            (OptionClass::Control, 8) => OptionKind::StreamId,
            (OptionClass::Control, 9) => OptionKind::StrictSourceRouting,
            (OptionClass::DebuggingAndMeasurement, 4) => OptionKind::Timestamp,
            _ => OptionKind::Unknown,
        }
    }
}

impl<'buf> AsRef<[u8]> for Option<'buf> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

pub struct OptionType(u8);

impl OptionType {
    /// whether the option is copied into all fragments
    pub fn copied(&self) -> bool {
        ((self.0 & 0b10000000) >> 7) == 1
    }

    pub fn class(&self) -> OptionClass {
        ((self.0 & 0b01100000) >> 5).into()
    }

    pub fn number(&self) -> u8 {
        self.0 & 0b00011111
    }
}

impl From<u8> for OptionType {
    fn from(value: u8) -> Self {
        OptionType(value)
    }
}

impl From<OptionType> for u8 {
    fn from(value: OptionType) -> Self {
        value.0
    }
}

c_like_enum!(
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum OptionClass(u8) {
        Control = 0,
        DebuggingAndMeasurement = 2,
    }
);

/// internet option kind predefined in RFC 791
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OptionKind {
    End,
    NoOperation,
    Security,
    LooseSourceRouting,
    StrictSourceRouting,
    RecordRoute,
    StreamId,
    Timestamp,
    Unknown,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    #[test]
    fn new_checked() {
        let mut ip_header_bytes: Vec<u8> = vec![
            // ip header
            0x4e, 0x00, 0x00, 0x78, 0x10, 0x2c, 0x00, 0x00, 0x40, 0x01, 0xdd, 0xaa, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
            0x00, 0x01, 0x44, 0x24, 0x1d, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x13, 0x37, 0xc3, 0x7f, 0x00, 0x00, 0x01,
            0x00, 0x13, 0x37, 0xc3, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x13, 0x37, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut ip_payload_bytes: Vec<u8> = vec![
            // ip payload (icmp echo reply)
            0x00, 0x00, 0x87, 0xa5, 0x00, 0x06, 0x00, 0x06, 0xeb, 0x17, 0x13, 0x61, 0x00, 0x00, 0x00, 0x00, 0xb4, 0x02,
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];

        let mut bytes: Vec<u8> = vec![];
        bytes.append(&mut ip_header_bytes);
        bytes.append(&mut ip_payload_bytes);

        // ip packet generated from "ping 127.0.0.1 -T tsandaddr"
        let packet = super::Packet::new_checked(bytes).expect("a valid ipv4 packet");

        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 14);
        assert_eq!(packet.tos(), 0);
        assert_eq!(packet.total_len(), 120);
        assert_eq!(packet.identification(), 0x102c);
        assert_eq!(packet.flags(), 0b000);
        assert_eq!(packet.offset(), 0);
        assert_eq!(packet.ttl(), 64);
        assert_eq!(packet.protocol(), super::Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xddaa);
        assert_eq!(packet.src_addr(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(packet.dest_addr(), Ipv4Addr::new(127, 0, 0, 1));

        let mut option_iterator = packet.options();

        let timestamp_option = option_iterator
            .next()
            .expect("some result")
            .expect("a valid ipv4 option");

        assert_eq!(timestamp_option.r#type().copied(), false);
        assert_eq!(
            timestamp_option.r#type().class(),
            super::OptionClass::DebuggingAndMeasurement
        );
        assert_eq!(timestamp_option.r#type().number(), 0b00000100);
        assert_eq!(timestamp_option.length(), Some(36));
        assert_eq!(option_iterator.next().is_none(), true);
    }
}
