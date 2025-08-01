#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

#[cfg_attr(feature = "user", derive(Serialize))]
#[derive(Debug, Clone, Copy)]
pub struct UnlinkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub target_dev: u32,
}
