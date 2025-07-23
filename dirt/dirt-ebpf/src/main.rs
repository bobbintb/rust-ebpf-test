#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use core::mem;
use dirt_common::{RecordFs, Stats, FILENAME_LEN_MAX, FILEPATH_LEN_MAX};
use vmlinux::{dentry, file, iattr, inode};

const I_CREATE: usize = 0;
const I_DELETE: usize = 10;
const I_MOVED_FROM: usize = 8;
const I_MOVED_TO: usize = 9;
const I_CLOSE_WRITE: usize = 6;

#[map]
static mut RECORD_FS_HEAP: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut HASH_RECORDS: HashMap<u64, RecordFs> = HashMap::with_max_entries(1024, 0);

#[map]
static mut STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_max_entries(16384, 0);

#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    match try_do_filp_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_filp_open(ctx: RetProbeContext) -> Result<u32, u32> {
    let file = ctx.ret().unwrap() as *mut file;
    let dentry = unsafe { (*file).f_path.dentry };
    handle_fs_event(ctx.get_mut(), I_CREATE, dentry, None, "do_filp_open");
    Ok(0)
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    let dentry = ctx.arg::<*mut dentry>(1).unwrap();
    handle_fs_event(ctx.get_mut(), I_DELETE, dentry, None, "security_inode_unlink");
    Ok(0)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    match try_security_inode_rename(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_security_inode_rename(ctx: ProbeContext) -> Result<u32, u32> {
    let old_dentry = ctx.arg::<*mut dentry>(1).unwrap();
    let new_dentry = ctx.arg::<*mut dentry>(3).unwrap();
    handle_fs_event(
        ctx.get_mut(),
        I_MOVED_FROM,
        old_dentry,
        None,
        "security_inode_rename",
    );
    handle_fs_event(
        ctx.get_mut(),
        I_MOVED_TO,
        new_dentry,
        Some(old_dentry),
        "security_inode_rename",
    );
    Ok(0)
}

#[kprobe]
pub fn vfs_close(ctx: ProbeContext) -> u32 {
    match try_vfs_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_close(ctx: ProbeContext) -> Result<u32, u32> {
    let file = ctx.arg::<*mut file>(0).unwrap();
    let dentry = unsafe { (*file).f_path.dentry };
    handle_fs_event(ctx.get_mut(), I_CLOSE_WRITE, dentry, None, "vfs_close");
    Ok(0)
}

fn handle_fs_event(
    ctx: &mut ProbeContext,
    event_index: usize,
    dentry: *mut dentry,
    dentry_old: Option<*mut dentry>,
    function_name: &str,
) {
    let pid = bpf_get_current_pid_tgid() >> 32;
    let ts_event = bpf_ktime_get_ns();

    let d_inode = unsafe { (*dentry).d_inode };
    if d_inode.is_null() {
        return;
    }

    let ino = unsafe { (*d_inode).i_ino as u32 };
    let imode = unsafe { (*d_inode).i_mode };
    let key = (pid as u64) << 32 | ino as u64;

    let mut r = match unsafe { HASH_RECORDS.get_mut(&key) } {
        Some(record) => record,
        None => {
            let zero: u32 = 0;
            let record = match unsafe { RECORD_FS_HEAP.get_mut(zero) } {
                Some(record) => record,
                None => return,
            };
            record.rc.ts = ts_event;
            record.ino = ino;
            let _ = unsafe {
                core::ptr::copy_nonoverlapping(
                    (*dentry).d_name.name.as_ptr(),
                    record.filename.as_mut_ptr(),
                    FILENAME_LEN_MAX,
                )
            };
            record.isize_first = unsafe { (*d_inode).i_size as u64 };
            unsafe { HASH_RECORDS.insert(&key, record, 0).unwrap() };
            unsafe { HASH_RECORDS.get_mut(&key).unwrap() }
        }
    };

    r.imode = imode;
    r.isize = unsafe { (*d_inode).i_size as u64 };
    r.inlink = unsafe { (*d_inode).i_nlink as u32 };
    r.atime_nsec = unsafe { (*d_inode).i_atime.tv_sec as u64 * 1_000_000_000
        + (*d_inode).i_atime.tv_nsec as u64 };
    r.mtime_nsec = unsafe { (*d_inode).i_mtime.tv_sec as u64 * 1_000_000_000
        + (*d_inode).i_mtime.tv_nsec as u64 };
    r.ctime_nsec = unsafe { (*d_inode).i_ctime.tv_sec as u64 * 1_000_000_000
        + (*d_inode).i_ctime.tv_nsec as u64 };
    r.events += 1;
    r.event[event_index] += 1;

    let agg_end = event_index == I_CLOSE_WRITE
        || event_index == I_DELETE
        || event_index == I_MOVED_TO;

    if agg_end {
        r.rc.type_ = 1; // RECORD_TYPE_FILE
        unsafe {
            RINGBUF_RECORDS.output(r, 0);
            HASH_RECORDS.remove(&key).unwrap();
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
