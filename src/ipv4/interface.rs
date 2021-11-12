use std::error::Error as StdError;
use std::io::{Error as IOError, Read, Write};

use log::error;

use crate::checksum::checksum;
use crate::error::Result;
use crate::ipv4::error::Error as Ipv4Error;
use crate::ipv4::packet::Packet;
use crate::ipv4::reassembly::Reassembler;
use crate::net_device::tun::TunDevice;

pub mod consts {
    pub const DEFAULT_MTU: usize = 1500; // Default Maximum Transmission Unit
}

/// The interface provided by the ipv4 module to the upper layers.
/// Since we build the ipv4 module based on TUN device,
/// we do not consider the scenario when it is used as a gateway currently.
pub struct Interface {
    device: TunDevice,
    reassembler: Reassembler,
}

impl Interface {
    pub fn new(device: TunDevice, reassembler: Reassembler) -> Self {
        Self { device, reassembler }
    }

    pub fn send(&mut self, packet: Packet<&[u8]>) -> Result<usize> {
        let octets = packet.as_ref();

        if octets.len() > consts::DEFAULT_MTU {
            if packet.dont_fragment() {
                Err(Ipv4Error::NonFragmentablePacket.into())
            } else {
                for fragment in packet.fragments(consts::DEFAULT_MTU) {
                    let map_err_fn = |e: IOError| -> Box<dyn StdError> { e.into() };
                    self.device.write(fragment.as_ref()).map_err(map_err_fn)?;
                }
                Ok(octets.len())
            }
        } else {
            self.device.write(octets).map_err(|e| e.into())
        }
    }

    pub fn receive(&mut self) -> Result<Packet<Vec<u8>>> {
        let mut buf: Vec<u8> = vec![0; consts::DEFAULT_MTU];
        let read_byte_number = self.device.read(buf.as_mut_slice())?;
        buf.resize(read_byte_number, 0);

        let packet = Packet::new_checked(buf)?;
        let checksum_value = checksum(&packet.as_ref()[..(packet.header_len() * 4) as usize]);

        if packet.checksum() != checksum_value {
            error!("Invalid checksum, ip packet dropped.");
            return Err(Ipv4Error::InvalidChecksum.into());
        }

        // If the packet is a whole datagram, return it directly.
        if packet.offset() == 0 && !packet.more_fragments() {
            self.reassembler.release(packet.datagram_id());
            return Ok(packet);
        }

        self.reassembler
            .reassemble(packet)
            .ok_or_else(|| Ipv4Error::TryAgainLater.into())
    }
}
