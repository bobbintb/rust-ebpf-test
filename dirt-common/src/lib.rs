#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

#[cfg_attr(feature = "user", derive(Serialize))]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Unlink,
    Create,
}

#[derive(Debug, Clone, Copy)]
pub struct FileEvent {
    pub event_type: EventType,
    pub target_dev: u32,
    pub ret_val: i32,
    pub pathname: [u8; 4096],
    pub filename: [u8; 256],
}
