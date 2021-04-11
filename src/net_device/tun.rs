use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

use libc::{
    c_short, close, in_addr, ioctl, open, read, sockaddr_in, socket, write, AF_INET, IFF_NO_PI, IFF_TUN, O_RDWR,
    SIOCSIFADDR, SIOCSIFFLAGS, SIOCSIFNETMASK, SOCK_DGRAM,
};
use log::error;

use crate::error::Result;
use crate::net_device::r#if::{consts, InterfaceRequest};

#[derive(Debug)]
pub struct TunDevice {
    fd: RawFd,
    name: String,
    socket_fd: RawFd,
}

impl TunDevice {
    /// Create a new tun device, or connect to a tun device that already exists
    pub fn new(name: &str) -> Result<Self> {
        let mut request = InterfaceRequest::new(name)?;
        request.union.flags = (IFF_TUN | IFF_NO_PI) as i16;

        let fd = unsafe { open(CString::new("/dev/net/tun")?.as_ptr(), O_RDWR) };
        if fd < 0 {
            error!("Failed to open '/dev/net/tun'.");
            return Err(std::io::Error::last_os_error().into());
        }

        let result = unsafe { ioctl(fd, consts::TUNSETIFF, &request) };
        if result < 0 {
            if unsafe { close(fd) } < 0 {
                error!("Failed to close TunDevice file descriptor.");
            }
            return Err(std::io::Error::last_os_error().into());
        }

        let socket_fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if socket_fd < 0 {
            error!("Failed to create a socket.");
            let err = Err(std::io::Error::last_os_error().into());
            if unsafe { close(fd) } < 0 {
                error!("Failed to close TunDevice file descriptor.");
            }
            return err;
        }

        Ok(Self {
            fd,
            name: unsafe { CStr::from_ptr(request.name.name.as_ptr().cast()) }
                .to_string_lossy()
                .into_owned(),
            socket_fd,
        })
    }

    /// Set the active flag word of current tun device
    pub fn flags(&self, flags: c_short) -> Result<&Self> {
        let mut request = InterfaceRequest::new(&self.name)?;
        request.union.flags = flags;

        let result = unsafe { ioctl(self.socket_fd, SIOCSIFFLAGS, &request) };
        if result < 0 {
            error!("Failed to set flags: {}.", flags);
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(self)
    }

    /// Persist current tun device
    pub fn persist(&self) -> Result<&Self> {
        let result = unsafe { ioctl(self.fd, consts::TUNSETPERSIST, 1) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(self)
    }

    /// Delete current tun device
    pub fn delete(&self) -> Result<&Self> {
        let result = unsafe { ioctl(self.fd, consts::TUNSETPERSIST, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(self)
    }

    /// Set ip address
    pub fn address(&self, ip_addr: IpAddr) -> Result<&Self> {
        match ip_addr {
            IpAddr::V4(v4) => self.ipv4_address(v4),
            IpAddr::V6(v6) => self.ipv6_address(v6),
        }
    }

    /// Set ipv4 address
    fn ipv4_address(&self, ipv4_addr: Ipv4Addr) -> Result<&Self> {
        let mut request = InterfaceRequest::new(&self.name)?;
        request.union.addr = unsafe {
            transmute(sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: u32::from(ipv4_addr).to_be(),
                },
                sin_zero: [0; 8],
            })
        };

        let result = unsafe { ioctl(self.socket_fd, SIOCSIFADDR, &request) };
        if result < 0 {
            error!("Failed to set ipv4 address: {}.", ipv4_addr);
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(self)
    }

    /// Set ipv6 address
    fn ipv6_address(&self, _ipv6_addr: Ipv6Addr) -> Result<&Self> {
        todo!()
    }

    /// Set netmask
    pub fn netmask(&self, netmask: IpAddr) -> Result<&Self> {
        match netmask {
            IpAddr::V4(v4) => self.ipv4_netmask(v4),
            IpAddr::V6(v6) => self.ipv6_netmask(v6),
        }
    }

    /// Set ipv4 netmask
    fn ipv4_netmask(&self, netmask: Ipv4Addr) -> Result<&Self> {
        let mut request = InterfaceRequest::new(&self.name)?;
        request.union.netmask = unsafe {
            transmute(sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: u32::from(netmask).to_be(),
                },
                sin_zero: [0; 8],
            })
        };

        let result = unsafe { ioctl(self.socket_fd, SIOCSIFNETMASK, &request) };
        if result < 0 {
            error!("Failed to set ipv4 netmask: {}.", netmask);
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(self)
    }

    /// Set ipv6 netmask
    fn ipv6_netmask(&self, _ipv6_addr: Ipv6Addr) -> Result<&Self> {
        todo!()
    }
}

impl Read for TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Write for TunDevice {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { write(self.fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if unsafe { close(self.fd) } < 0 {
            error!("Failed to close TunDevice file descriptor.");
        }
        if unsafe { close(self.socket_fd) } < 0 {
            error!("Failed to close TunDevice socket file descriptor.");
        }
    }
}
