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
    pub src_path: [u8; 4096],
    pub src_file: [u8; 256],
    pub trgt_path: [u8; 4096],
    pub trgt_file: [u8; 256],
}
