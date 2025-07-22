#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileDeleteEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; 256],
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileDeleteEvent {}
