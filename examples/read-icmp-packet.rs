use std::io::Read;

use radish::icmpv4::packet::Packet as Icmpv4Packet;
use radish::ipv4::packet::Packet as Ipv4Packet;
use radish::net_device::tun::TunDevice;

fn main() {
    let mtu = 1500;
    let name = String::from("tun-radish");
    let mut device = TunDevice::new(&name).expect("connect to an existed tun device");

    loop {
        let mut buf: Vec<u8> = vec![0; mtu];
        let read_byte_number = device.read(buf.as_mut()).expect("read bytes from tun device");
        buf.resize(read_byte_number, 0);

        if read_byte_number > 0 {
            let ipv4_packet_result = Ipv4Packet::new_checked(buf);

            match ipv4_packet_result {
                Ok(ipv4_packet) => {
                    let ipv4_payload = ipv4_packet.payload();
                    let icmpv4_packet = Icmpv4Packet::new_unchecked(ipv4_payload);
                    println!("{:?}", icmpv4_packet);
                }
                Err(err) => println!("{:?}", err),
            }
        }
    }
}
