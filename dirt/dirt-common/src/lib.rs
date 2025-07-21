#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnlinkEvent {
    pub inode: u64,
}
