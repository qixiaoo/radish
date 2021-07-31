use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use radish::net_device::tun::TunDevice;

/// usage:
/// 1. run `cargo build --example tun-device` to build
/// 2. find executable file in `target/debug/examples`
/// 3. run `sudo ./tun-device` to create a tun interface

fn main() {
    let name = String::from("tun-radish");
    let device = TunDevice::new(&name).expect("create a new tun device");

    device
        .persist()
        .expect("persist current tun device")
        .address(IpAddr::from(Ipv4Addr::new(192, 168, 233, 233)))
        .expect("set ipv4 address")
        .netmask(IpAddr::from(Ipv4Addr::new(255, 255, 255, 0)))
        .expect("set ipv4 netmask")
        .flags(libc::IFF_UP as i16)
        .expect("set flags");

    let command = format!("ip link | grep {}", name);
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("tun device information");

    println!("{:?}", String::from_utf8(output.stdout));
}
