#![no_std]

pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;
pub const FS_EVENT_MAX: usize = 15;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub type_: u32,
    pub ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RecordFs {
    pub rc: Record,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX],
    pub ino: u32,
    pub imode: u32,
    pub inlink: u32,
    pub isize: u64,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX],
    pub filename: [u8; FILENAME_LEN_MAX],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RecordFs {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}
