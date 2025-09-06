#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

#[cfg_attr(feature = "user", derive(Serialize))]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Unlink,
    Create,
    Rename,
}

pub const MAX_FILENAME_LEN: usize = 256;
pub const MAX_PATH_LEN: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct FileEvent {
    pub event_type: EventType,
    pub target_dev: u32,
    pub ret_val: i32,
    pub src_path: [u8; MAX_PATH_LEN + 1], // the +1s are because helper functions will still null terminate if files are the maximum size imposed by Linux.
    pub src_file: [u8; MAX_FILENAME_LEN + 1],
    pub trgt_path: [u8; MAX_PATH_LEN +1],
    pub trgt_file: [u8; MAX_FILENAME_LEN +1],
}
