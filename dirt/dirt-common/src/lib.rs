#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlinkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub inode: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnlinkEvent {}
