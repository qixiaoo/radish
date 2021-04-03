use std::ffi::CString;
use std::mem::zeroed;

use libc::{c_int, c_short, c_uchar, c_ulong, c_ushort, sockaddr, IFNAMSIZ};

use crate::net_device::error::{Error, Result};

/// Data structure defined in <net/if.h>

#[repr(C)]
pub struct InterfaceRequest {
    pub name: InterfaceName,
    pub union: InterfaceRequestUnion,
}

#[repr(C)]
pub union InterfaceName {
    pub name: [c_uchar; IFNAMSIZ],
}

#[repr(C)]
pub union InterfaceRequestUnion {
    pub addr: sockaddr,
    pub dst_addr: sockaddr,
    pub broadcast_addr: sockaddr,
    pub netmask: sockaddr,
    pub mac_addr: sockaddr,
    pub flags: c_short,
    pub value: c_int,
    pub mtu: c_int,
    pub map: InterfaceMap,
    pub slave: [c_uchar; IFNAMSIZ],
    pub new_name: [c_uchar; IFNAMSIZ],
    pub data: *mut c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct InterfaceMap {
    pub mem_start: c_ulong,
    pub mem_end: c_ulong,
    pub base_addr: c_ushort,
    pub irq: c_uchar,
    pub dma: c_uchar,
    pub port: c_uchar,
}

impl InterfaceRequest {
    pub fn new(name: &str) -> Result<Self> {
        let name = CString::new(name)?;
        let name = name.as_bytes_with_nul();
        if name.len() > IFNAMSIZ {
            return Err(Error::NameTooLong.into());
        }

        let mut device_name: [c_uchar; IFNAMSIZ] = [0; IFNAMSIZ];
        device_name[..name.len()].copy_from_slice(name);

        Ok(Self {
            name: InterfaceName { name: device_name },
            ..Default::default()
        })
    }
}

impl Default for InterfaceRequest {
    fn default() -> Self {
        unsafe { zeroed() }
    }
}

pub mod consts {
    use libc::c_ulong;

    pub const TUNSETIFF: c_ulong = 0x400454ca;
    pub const TUNSETPERSIST: c_ulong = 0x400454cb;
    pub const TUNSETOWNER: c_ulong = 0x400454cc;
    pub const TUNSETGROUP: c_ulong = 0x400454ce;
}
