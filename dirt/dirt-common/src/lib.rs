#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlinkEvent {
    pub tgid: u32,
    pub pid: u32,
    pub inode: u64,
}

// Ensure the event structure is aligned to a 4-byte boundary
#[cfg(feature = "user")]
unsafe impl aya::Pod for UnlinkEvent {}
