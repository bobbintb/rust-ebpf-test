#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlinkEvent {
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ret_val: i32,
}
