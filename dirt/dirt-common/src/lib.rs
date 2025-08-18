#![no_std]

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    FEntry,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UnlinkEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub filename: [u8; 256],
}
