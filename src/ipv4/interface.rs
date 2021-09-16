use std::error::Error as StdError;
use std::io::Error as IOError;
use std::io::Write;

use crate::error::Result;
use crate::ipv4::error::Error as Ipv4Error;
use crate::ipv4::packet::Packet;
use crate::net_device::tun::TunDevice;

pub mod consts {
    pub const DEFAULT_MTU: usize = 1500; // Default Maximum Transmission Unit
    pub const DEFAULT_TLB: u8 = 15; // Default Timer Lower Bound
}

pub struct Interface {
    device: TunDevice,
}

impl Interface {
    pub fn new(device: TunDevice) -> Self {
        Self { device }
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

    pub fn receive() {
        todo!();
    }
}
