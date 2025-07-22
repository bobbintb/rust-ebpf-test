#![no_std]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub struct FileDeleteEvent {
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ret: i32,
}
