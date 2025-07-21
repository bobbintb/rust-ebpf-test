#![no_std]

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UnlinkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub inode: u64,
}
