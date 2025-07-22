#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnlinkEvent {
    pub-buf: [u8; 256],
}
