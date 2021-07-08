use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

use crate::c_like_enum;
use crate::error::Result;
use crate::icmpv4::error::Error;

c_like_enum!(
    /// ICMP message types defined in RFC 792
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum MessageType(u8) {
        EchoReply = 0,
        DestinationUnreachable = 3,
        SourceQuench = 4,
        Redirect = 5,
        Echo = 8,
        TimeExceeded = 11,
        ParameterProblem = 12,
        Timestamp = 13,
        TimestampReply = 14,
        InformationRequest = 15,
        InformationReply = 16,
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

    pub fn r#type(&self) -> MessageType {
        self.buffer.as_ref()[0].into()
    }

    pub fn code(&self) -> u8 {
        self.buffer.as_ref()[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer.as_ref()[2], self.buffer.as_ref()[3]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[4..]
    }
}

impl<Buf> Packet<Buf>
where
    Buf: AsMut<[u8]>,
{
    pub fn set_type(&mut self, r#type: MessageType) {
        self.buffer.as_mut()[0] = r#type.into();
    }

    pub fn set_code(&mut self, code: u8) {
        self.buffer.as_mut()[1] = code;
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer.as_mut()[2..=3].copy_from_slice(checksum.to_be_bytes().as_ref());
    }
}

impl<Buf> Debug for Packet<Buf>
where
    Buf: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "type: {:?}, code: {:?}, checksum: {:#x}",
            self.r#type(),
            self.code(),
            self.checksum(),
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

c_like_enum!(
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum DestinationUnreachablePacketCode(u8) {
        NetUnreachable = 0,
        HostUnreachable = 1,
        ProtocolUnreachable = 2,
        PortUnreachable = 3,
        FragmentationNeededAndDfSet = 4,
        SourceRouteFailed = 5,
    }
);

pub struct DestinationUnreachablePacket<Buf> {
    packet: Packet<Buf>,
}

impl<Buf> DestinationUnreachablePacket<Buf>
where
    Buf: AsRef<[u8]>,
{
    pub fn new_unchecked(buffer: Buf) -> Self {
        DestinationUnreachablePacket {
            packet: Packet { buffer },
        }
    }

    pub fn new_checked(buffer: Buf) -> Result<Self> {
        let unchecked = Self::new_unchecked(buffer);

        match unchecked.packet.try_into() {
            Ok(packet) => Ok(packet),
            Err(err) => Err(err.into()),
        }
    }

    pub fn code(&self) -> DestinationUnreachablePacketCode {
        self.packet.buffer.as_ref()[1].into()
    }

    pub fn payload(&self) -> &[u8] {
        &self.packet.buffer.as_ref()[8..]
    }
}

impl<Buf> Deref for DestinationUnreachablePacket<Buf>
where
    Buf: AsRef<[u8]>,
{
    type Target = Packet<Buf>;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl<Buf> TryFrom<Packet<Buf>> for DestinationUnreachablePacket<Buf>
where
    Buf: AsRef<[u8]>,
{
    type Error = Error;

    fn try_from(value: Packet<Buf>) -> std::result::Result<Self, Self::Error> {
        let packet = Self::new_unchecked(value.buffer);

        if packet.r#type() != MessageType::DestinationUnreachable {
            return Err(Error::InvalidMessageType);
        }

        Ok(packet)
    }
}

// TODO: support other ICMP message types

pub struct EchoAndEchoReplyPacket<Buf> {
    packet: Packet<Buf>,
}

impl<Buf> EchoAndEchoReplyPacket<Buf>
where
    Buf: AsRef<[u8]>,
{
    pub fn new_unchecked(buffer: Buf) -> Self {
        EchoAndEchoReplyPacket {
            packet: Packet { buffer },
        }
    }

    pub fn new_checked(buffer: Buf) -> Result<Self> {
        let unchecked = Self::new_unchecked(buffer);

        match unchecked.packet.try_into() {
            Ok(packet) => Ok(packet),
            Err(err) => Err(err.into()),
        }
    }

    pub fn is_reply(&self) -> bool {
        self.r#type() == MessageType::EchoReply
    }

    pub fn is_request(&self) -> bool {
        self.r#type() == MessageType::Echo
    }

    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.packet.buffer.as_ref()[4], self.packet.buffer.as_ref()[5]])
    }

    pub fn sequence_number(&self) -> u16 {
        u16::from_be_bytes([self.packet.buffer.as_ref()[6], self.packet.buffer.as_ref()[7]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.packet.buffer.as_ref()[8..]
    }
}

impl<Buf> EchoAndEchoReplyPacket<Buf>
where
    Buf: AsMut<[u8]>,
{
    pub fn set_identifier(&mut self, identifier: u16) {
        self.packet.buffer.as_mut()[4..=5].copy_from_slice(identifier.to_be_bytes().as_ref());
    }

    pub fn set_sequence_number(&mut self, sequence_number: u16) {
        self.packet.buffer.as_mut()[6..=7].copy_from_slice(sequence_number.to_be_bytes().as_ref());
    }
}

impl<Buf> Deref for EchoAndEchoReplyPacket<Buf>
where
    Buf: AsRef<[u8]>,
{
    type Target = Packet<Buf>;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl<Buf> TryFrom<Packet<Buf>> for EchoAndEchoReplyPacket<Buf>
where
    Buf: AsRef<[u8]>,
{
    type Error = Error;

    fn try_from(value: Packet<Buf>) -> std::result::Result<Self, Self::Error> {
        let packet = Self::new_unchecked(value.buffer);

        if packet.r#type() != MessageType::Echo && packet.r#type() != MessageType::EchoReply {
            return Err(Error::InvalidMessageType);
        }

        Ok(packet)
    }
}
