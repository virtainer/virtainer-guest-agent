// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Public viosock ABI facts: Windows sockaddr_vm has no Linux trailing padding.
//! https://github.com/virtio-win/kvm-guest-drivers-windows/blob/master/viosock/inc/vio_sockets.h

pub const AF_VSOCK: u16 = 40;
#[repr(C)]
#[derive(Default)]
pub struct Address {
    pub family: u16,
    pub reserved: u16,
    pub port: u32,
    pub cid: u32,
}
pub fn host_peer(address: &Address, length: i32) -> bool {
    length == std::mem::size_of::<Address>() as i32
        && address.family == AF_VSOCK
        && address.cid == 2
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_address_layout_and_host_guard_follow_the_provider() {
        assert_eq!(std::mem::size_of::<Address>(), 12);
        assert_eq!(std::mem::align_of::<Address>(), 4);
        assert_eq!(std::mem::offset_of!(Address, port), 4);
        assert_eq!(std::mem::offset_of!(Address, cid), 8);
        let mut address = Address {
            family: AF_VSOCK,
            cid: 2,
            port: 100,
            ..Default::default()
        };
        assert!(host_peer(&address, 12));
        for len in [0, 11, 16, 128] {
            assert!(!host_peer(&address, len));
        }
        for cid in [0, 1, 3, u32::MAX] {
            address.cid = cid;
            assert!(!host_peer(&address, 12));
        }
        address.cid = 2;
        address.family = 2;
        assert!(!host_peer(&address, 12));
    }
}
