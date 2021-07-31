use std::io::{Read, Write};

use radish::checksum::checksum;
use radish::error::Result;
use radish::icmpv4::packet::{EchoAndEchoReplyPacket, MessageType};
use radish::ipv4::packet::{Packet as Ipv4Packet, Protocol};
use radish::net_device::tun::TunDevice;

///  usage:
/// 1. follow `./examples/tun-device` to create tun interface "tun-radish"
/// 2. build and run this example to start a ping server
/// 3. run `ping 192.168.233.234` in a new terminal
/// 4. the received icmp echo reply packet will be printed

fn main() {
    let mtu = 1500;
    let name = String::from("tun-radish");
    let mut device = TunDevice::new(&name).expect("connect to an existed tun device");

    let mut counter: u16 = 1;

    loop {
        let mut buf: Vec<u8> = vec![0; mtu];
        let read_byte_number = device.read(buf.as_mut()).expect("read bytes from tun device");
        buf.resize(read_byte_number, 0);

        if read_byte_number > 0 {
            let result = reply(buf, counter).and_then(|packet| {
                println!("send echo replay {}: {:?}", counter, packet);

                device.write_all(packet.as_ref()).map_err(|err| err.into())
            });

            match result {
                Ok(_ok) => {
                    counter += 1;
                }
                Err(_err) => println!("{}", _err),
            }
        }
    }
}

fn reply(buf: Vec<u8>, identification: u16) -> Result<Ipv4Packet<Vec<u8>>> {
    let mut ipv4_packet = Ipv4Packet::new_checked(buf)?;
    let mut echo_packet = EchoAndEchoReplyPacket::new_checked(ipv4_packet.payload_mut())?;

    if !echo_packet.is_request() {
        return Err("not an icmp echo request packet".into());
    }

    echo_packet.set_type(MessageType::EchoReply);
    echo_packet.set_checksum(0);

    let checksum_value = checksum(echo_packet.as_ref()); // check the entire icmp message
    echo_packet.set_checksum(checksum_value);

    let reply_buf: Vec<u8> = ipv4_packet.as_ref().into();

    let mut ipv4_packet = Ipv4Packet::new_unchecked(reply_buf);
    let src_addr = ipv4_packet.src_addr();
    ipv4_packet.set_src_addr(ipv4_packet.dest_addr());
    ipv4_packet.set_dest_addr(src_addr);

    ipv4_packet.set_tos(0);
    ipv4_packet.set_identification(identification);
    ipv4_packet.set_flags(2); // don't fragment and last fragment
    ipv4_packet.set_offset(0);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_protocol(Protocol::Icmp);
    ipv4_packet.set_checksum(0);

    let checksum_value = checksum(&ipv4_packet.as_ref()[..(ipv4_packet.header_len() * 4) as usize]); // check ip header
    ipv4_packet.set_checksum(checksum_value);

    Ok(ipv4_packet)
}
