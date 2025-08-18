#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

#[cfg_attr(feature = "user", derive(Serialize))]
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
