#![no_std]

use core::ffi::c_char;
use crate::vmlinux::dentry;

const FS_EVENT_MAX: usize = FSEVT.len();
const FILEPATH_LEN_MAX: usize = 96;
const FILENAME_LEN_MAX: usize = 32;

// File system event values from dirt.h
pub const FS_ACCESS: i16 = 0x00000001;
pub const FS_MODIFY: i16 = 0x00000002;
pub const FS_ATTRIB: i16 = 0x00000004;
pub const FS_CLOSE_WRITE: i16 = 0x00000008;
pub const FS_CLOSE_NOWRITE: i16 = 0x00000010;
pub const FS_OPEN: i16 = 0x00000020;
pub const FS_MOVED_FROM: i16 = 0x00000040;
pub const FS_MOVED_TO: i16 = 0x00000080;
pub const FS_CREATE: i16 = 0x00000100;
pub const FS_DELETE: i16 = 0x00000200;
pub const FS_DELETE_SELF: i16 = 0x00000400;
pub const FS_MOVE_SELF: i16 = 0x00000800;
pub const FS_OPEN_EXEC: i16 = 0x00001000;
pub const FS_UNMOUNT: i16 = 0x00002000;
pub const FS_Q_OVERFLOW: i16 = 0x00004000;

#[repr(u32)]
pub enum IndexFsEvent {
    Create,
    Open,
    OpenExec,
    Access,
    Attrib,
    Modify,
    CloseWrite,
    CloseNowrite,
    MovedFrom,
    MovedTo,
    Delete,
    DeleteSelf,
    MoveSelf,
    Unmount,
    QOverflow,
}

#[repr(C)]
pub struct FsEventInfo {
    pub index: i32,
    pub dentry: *mut dentry,
    pub dentry_old: *mut dentry,
    pub func: *const c_char,
}

#[repr(C)]
pub struct FsEvent {
    index: i16,
    value: i16,
    name: [u8; 16],
    shortname: [u8; 4],
    shortname2: [u8; 4],
}

pub static FSEVT: [FsEvent; 15] = [
    FsEvent { index: IndexFsEvent::Create as i16, value: FS_CREATE, name: *b"CREATE\0\0\0\0\0\0\0\0\0\0", shortname: *b"CRE\0", shortname2: *b"CR\0\0" },
    FsEvent { index: IndexFsEvent::Open as i16, value: FS_OPEN, name: *b"OPEN\0\0\0\0\0\0\0\0\0\0\0\0", shortname: *b"OPN\0", shortname2: *b"OP\0\0" },
    FsEvent { index: IndexFsEvent::OpenExec as i16, value: FS_OPEN_EXEC, name: *b"OPEN_EXEC\0\0\0\0\0\0\0", shortname: *b"OPX\0", shortname2: *b"OX\0\0" },
    FsEvent { index: IndexFsEvent::Access as i16, value: FS_ACCESS, name: *b"ACCESS\0\0\0\0\0\0\0\0\0\0", shortname: *b"ACC\0", shortname2: *b"AC\0\0" },
    FsEvent { index: IndexFsEvent::Attrib as i16, value: FS_ATTRIB, name: *b"ATTRIB\0\0\0\0\0\0\0\0\0\0", shortname: *b"ATT\0", shortname2: *b"AT\0\0" },
    FsEvent { index: IndexFsEvent::Modify as i16, value: FS_MODIFY, name: *b"MODIFY\0\0\0\0\0\0\0\0\0\0", shortname: *b"MOD\0", shortname2: *b"MO\0\0" },
    FsEvent { index: IndexFsEvent::CloseWrite as i16, value: FS_CLOSE_WRITE, name: *b"CLOSE_WRITE\0\0\0\0\0", shortname: *b"CLW\0", shortname2: *b"CW\0\0" },
    FsEvent { index: IndexFsEvent::CloseNowrite as i16, value: FS_CLOSE_NOWRITE, name: *b"CLOSE_NOWRITE\0\0\0", shortname: *b"CLN\0", shortname2: *b"CN\0\0" },
    FsEvent { index: IndexFsEvent::MovedFrom as i16, value: FS_MOVED_FROM, name: *b"MOVED_FROM\0\0\0\0\0\0", shortname: *b"MVF\0", shortname2: *b"MF\0\0" },
    FsEvent { index: IndexFsEvent::MovedTo as i16, value: FS_MOVED_TO, name: *b"MOVED_TO\0\0\0\0\0\0\0\0", shortname: *b"MVT\0", shortname2: *b"MT\0\0" },
    FsEvent { index: IndexFsEvent::Delete as i16, value: FS_DELETE, name: *b"DELETE\0\0\0\0\0\0\0\0\0\0", shortname: *b"DEL\0", shortname2: *b"DE\0\0" },
    FsEvent { index: IndexFsEvent::DeleteSelf as i16, value: FS_DELETE_SELF, name: *b"DELETE_SELF\0\0\0\0\0", shortname: *b"DSF\0", shortname2: *b"DS\0\0" },
    FsEvent { index: IndexFsEvent::MoveSelf as i16, value: FS_MOVE_SELF, name: *b"MOVE_SELF\0\0\0\0\0\0\0", shortname: *b"MSF\0", shortname2: *b"MS\0\0" },
    FsEvent { index: IndexFsEvent::Unmount as i16, value: FS_UNMOUNT, name: *b"UNMOUNT\0\0\0\0\0\0\0\0\0", shortname: *b"UNM\0", shortname2: *b"UM\0\0" },
    FsEvent { index: IndexFsEvent::QOverflow as i16, value: FS_Q_OVERFLOW, name: *b"Q_OVERFLOW\0\0\0\0\0\0", shortname: *b"QOF\0", shortname2: *b"QO\0\0" },
];

#[repr(C)]
pub struct Record {
    pub type_: u32,
    pub ts: u64,
}

#[repr(C)]
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
    pub filename_union: FilenameUnion,
}

#[repr(C)]
pub union FilenameUnion {
    pub filenames: FilenameStruct,
    pub filename: [u8; FILENAME_LEN_MAX],
}

#[repr(C)]
pub struct FilenameStruct {
    pub filename_from: [u8; FILENAME_LEN_MAX / 2],
    pub filename_to: [u8; FILENAME_LEN_MAX / 2],
}

#[repr(C)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}
