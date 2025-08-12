#![no_std]

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    FEntry,
    FExit,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UnlinkEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub target_dev: u32,
    pub ret_val: i32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}
