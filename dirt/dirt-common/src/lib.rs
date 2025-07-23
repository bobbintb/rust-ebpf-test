#![no_std]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct UnlinkEvent {
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ret_val: i32,
}
