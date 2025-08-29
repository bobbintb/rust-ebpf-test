#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

#[cfg_attr(feature = "user", derive(Serialize))]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    FEntry,
    FExit,
}

#[derive(Debug, Clone, Copy)]
pub struct UnlinkEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub target_dev: u32,
    pub ret_val: i32,
    pub pathname: [u8; 4096],
    pub filename: [u8; 256],
}
