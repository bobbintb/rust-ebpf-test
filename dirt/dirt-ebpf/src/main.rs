#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{macros::{kprobe, kretprobe, map}, programs::{ProbeContext, RetProbeContext}, helpers::{bpf_ktime_get_ns, bpf_get_current_pid_tgid}, maps::{RingBuf, LruHashMap, PerCpuArray, Array}};
use aya_log_ebpf::info;
use dirt_common::{RecordFs, Stats, AllowedPrefix, Record};
use vmlinux::{dentry, inode};

#[map]
static mut ringbuf_records: RingBuf = RingBuf::with_max_entries(256 * 1024, 0);

#[map]
static mut hash_records: LruHashMap<u64, RecordFs> = LruHashMap::with_max_entries(65536, 0);

#[map]
static mut heap_record_fs: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut stats: Array<Stats> = Array::with_max_entries(1, 0);

#[map]
static mut allowed_prefixes: Array<AllowedPrefix> = Array::with_max_entries(8, 0);

use vmlinux::iattr;

const I_CREATE: usize = 0;
const I_MODIFY: usize = 5;
const I_CLOSE_WRITE: usize = 6;
const I_CLOSE_NOWRITE: usize = 7;
const I_DELETE: usize = 10;
const I_MOVED_FROM: usize = 8;
const I_MOVED_TO: usize = 9;
const I_ACCESS: usize = 3;
const I_ATTRIB: usize = 4;

struct FsEventInfo {
    index: usize,
    dentry: *const dentry,
    dentry_old: *const dentry,
}

fn is_path_allowed(filepath: &[u8]) -> bool {
    // TODO: implement this
    true
}

fn handle_fs_event(ctx: ProbeContext, event: &FsEventInfo) -> Result<u32, u32> {
    if event.index == I_ACCESS || event.index == I_ATTRIB {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() >> 32;

    // TODO: add pid_self check

    let dentry = unsafe { event.dentry.as_ref() }.ok_or(0u32)?;
    let inode = unsafe { dentry.d_inode.as_ref() }.ok_or(0u32)?;

    let filename = unsafe {
        let mut name = [0u8; dirt_common::FILENAME_LEN_MAX];
        let name_ptr = dentry.d_name.name.as_ptr();
        core::ptr::copy_nonoverlapping(name_ptr, name.as_mut_ptr() as *mut u8, name.len());
        name
    };

    if unsafe{ (*inode).i_ino } == 0 || filename[0] == 0 {
        return Ok(0);
    }

    let imode = unsafe { (*inode).i_mode };
    if (imode & 0o170000) != 0o100000 && (imode & 0o170000) != 0o120000 {
        return Ok(0);
    }

    let ino = unsafe { (*inode).i_ino } as u32;
    let key = (pid as u64) << 32 | ino as u64;

    let ts_event = unsafe { bpf_ktime_get_ns() };

    if let Some(r) = r.as_mut() {
        if event.index == FS_MOVED_TO {
            let filename_to = unsafe {
                let mut name = [0u8; dirt_common::FILENAME_LEN_MAX];
                let name_ptr = dentry.d_name.name.as_ptr();
                core::ptr::copy_nonoverlapping(name_ptr, name.as_mut_ptr() as *mut u8, name.len());
                name
            };
            r.filename = filename_to;
        }
        r.rc.ts = ts_event;
    } else {
        let zero = 0;
        let mut r = unsafe { heap_record_fs.get_mut(zero) }.ok_or(0u32)?;

        r.rc.ts = ts_event;
        r.ino = ino;
        r.filename = filename;
        r.isize_first = unsafe { (*inode).i_size };

        let mut current_dentry = dentry;
        let mut path_nodes: [*const [u8]; 16] = [core::ptr::null(); 16];
        let mut num_nodes = 0;

        for i in 0..16 {
            let d_name = unsafe { &(*current_dentry).d_name };
            let name_ptr = d_name.name.as_ptr();
            path_nodes[i] = unsafe { core.slice.from_raw_parts(name_ptr, d_name.len as usize) };
            num_nodes += 1;

            let d_parent = unsafe { (*current_dentry).d_parent };
            if d_parent == current_dentry {
                break;
            }
            current_dentry = d_parent;
        }

        let mut offset = 0;
        for i in (0..num_nodes).rev() {
            let node = path_nodes[i];
            let len = unsafe{ (*node).len() };
            if offset + len < dirt_common::FILEPATH_LEN_MAX {
                unsafe {
                    core::ptr::copy_nonoverlapping((*node).as_ptr(), r.filepath.as_mut_ptr().add(offset), len);
                }
                offset += len;
                if i != 0 && offset < dirt_common::FILEPATH_LEN_MAX {
                    r.filepath[offset] = b'/';
                    offset += 1;
                }
            }
        }

        r.events = 0;
        for i in 0..dirt_common::FS_EVENT_MAX {
            r.event[i] = 0;
        }
        r.inlink = 0;

        let zero: u32 = 0;
        if let Some(s) = unsafe { stats.get_mut(&zero) } {
            s.fs_records += 1;
        }
    }

    if !is_path_allowed(&r.filepath) {
        return Ok(0);
    }

    let zero: u32 = 0;
    if let Some(s) = unsafe { stats.get_mut(&zero) } {
        s.fs_events += 1;
    }

    r.imode = imode;
    r.isize = unsafe { (*inode).i_size };
    r.inlink = unsafe { (*inode).i_nlink };
    if event.index == I_CREATE && !event.dentry_old.is_null() {
        r.inlink += 1;
    }
    r.atime_nsec = unsafe { (*inode).i_atime.tv_sec as u64 * 1_000_000_000 + (*inode).i_atime.tv_nsec as u64 };
    r.mtime_nsec = unsafe { (*inode).i_mtime.tv_sec as u64 * 1_000_000_000 + (*inode).i_mtime.tv_nsec as u64 };
    r.ctime_nsec = unsafe { (*inode).i_ctime.tv_sec as u64 * 1_000_000_000 + (*inode).i_ctime.tv_nsec as u64 };
    r.events += 1;
    r.event[event.index] += 1;

    unsafe { hash_records.insert(&key, &*r, 0) }.map_err(|e| e as u32)?;

    let mut agg_end = false;
    if event.index == I_CLOSE_WRITE || event.index == I_CLOSE_NOWRITE || event.index == I_DELETE || event.index == I_MOVED_TO ||
        (event.index == I_CREATE && ((imode & 0o170000) == 0o120000 || r.inlink > 1)) {
        agg_end = true;
    }
    // TODO: add agg_events_max check

    if agg_end {
        r.rc.record_type = 1; // RECORD_TYPE_FILE
        unsafe { ringbuf_records.output(&*r, 0) };
        unsafe { hash_records.remove(&key) };

        let zero: u32 = 0;
        if let Some(s) = unsafe { stats.get_mut(&zero) } {
            s.fs_records_deleted += 1;
        }
    }

    let zero: u32 = 0;
    if let Some(s) = unsafe { stats.get_mut(&zero) } {
        if s.fs_records == 1 {
            // TODO: query ring buffer size
        }
    }

    Ok(0)
}

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    // Get return value - handle the Option type
    let ret_val = match ctx.ret() {
        Some(val) => val,
        None => 0, // Default to 0 if no return value
    };
    
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log return information in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"return\":{}}}", current_pid, tgid, ret_val);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - {\"pid\": %d, \"tgid\": %d, \"return\": %d}", current_pid, tgid, ret_val);
    }
    Ok(0)
}

#[kprobe]
pub fn vfs_unlink_probe(ctx: ProbeContext) -> u32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log entry information with process details in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{}}}", current_pid, tgid);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - {\"pid\": %d, \"tgid\": %d}", current_pid, tgid);
    }
    
    Ok(0)
}

use vmlinux::file;

#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    let filp = unsafe { ctx.ret().unwrap() as *const file };
    if (unsafe { (*filp).f_mode } & 0x100000) != 0 { // FMODE_CREATED
        let event = FsEventInfo {
            index: I_CREATE,
            dentry: unsafe { (*filp).f_path.dentry },
            dentry_old: core::ptr::null(),
        };
        handle_fs_event(ctx.into(), &event);
    }
    Ok(0)
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    let old_dentry = unsafe { ctx.arg::<*const dentry>(0).unwrap() };
    let new_dentry = unsafe { ctx.arg::<*const dentry>(2).unwrap() };
    let event = FsEventInfo {
        index: I_CREATE,
        dentry: new_dentry,
        dentry_old: old_dentry,
    };
    handle_fs_event(ctx, &event);
    Ok(0)
}

#[map]
static mut dentry_symlink: PerCpuArray<*const dentry> = PerCpuArray::with_max_entries(1, 0);

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    let dentry = unsafe { ctx.arg::<*const dentry>(1).unwrap() };
    let zero = 0;
    unsafe { dentry_symlink.set(zero, &dentry) };
    Ok(0)
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    let dentry = unsafe { ctx.arg::<*const dentry>(0).unwrap() };
    let zero = 0;
    let symlink_dentry = unsafe { dentry_symlink.get(zero) };
    if let Some(symlink_dentry) = symlink_dentry {
        if *symlink_dentry == dentry {
            let inode = unsafe { (*dentry).d_inode };
            if (unsafe { (*inode).i_mode } & 0o170000) == 0o120000 && unsafe { (*inode).i_ino } != 0 {
                let event = FsEventInfo {
                    index: I_CREATE,
                    dentry: dentry,
                    dentry_old: core::ptr::null(),
                };
                handle_fs_event(ctx, &event);
            }
            unsafe { dentry_symlink.set(zero, &core::ptr::null()) };
        }
    }
    Ok(0)
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    let dentry = unsafe { ctx.arg::<*const dentry>(0).unwrap() };
    let attr = unsafe { ctx.arg::<*const iattr>(1).unwrap() };

    let ia_valid = unsafe { (*attr).ia_valid };
    if (ia_valid & 0x1) != 0 { // ATTR_MODE
        let event = FsEventInfo { index: I_ATTRIB, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }
    if (ia_valid & 0x8) != 0 { // ATTR_SIZE
        let event = FsEventInfo { index: I_MODIFY, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }
    if (ia_valid & 0x10) != 0 { // ATTR_ATIME
        let event = FsEventInfo { index: I_ACCESS, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }
    if (ia_valid & 0x20) != 0 { // ATTR_MTIME
        let event = FsEventInfo { index: I_MODIFY, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }
    if (ia_valid & 0x2) != 0 || (ia_valid & 0x4) != 0 { // ATTR_UID | ATTR_GID
        let event = FsEventInfo { index: I_ATTRIB, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }

    Ok(0)
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    let dentry = unsafe { ctx.arg::<*const dentry>(0).unwrap() };
    let mask = unsafe { ctx.arg::<u32>(1).unwrap() };

    if (mask & 0x4) != 0 { // FS_ATTRIB
        let event = FsEventInfo { index: I_ATTRIB, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }
    if (mask & 0x2) != 0 { // FS_MODIFY
        let event = FsEventInfo { index: I_MODIFY, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }
    if (mask & 0x1) != 0 { // FS_ACCESS
        let event = FsEventInfo { index: I_ACCESS, dentry: dentry, dentry_old: core::ptr::null() };
        handle_fs_event(ctx.clone(), &event);
    }

    Ok(0)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    let old_dentry = unsafe { ctx.arg::<*const dentry>(1).unwrap() };
    let new_dentry = unsafe { ctx.arg::<*const dentry>(3).unwrap() };

    if (unsafe { (*old_dentry).d_flags } & 0x00700000) == 0x00200000 || (unsafe { (*old_dentry).d_flags } & 0x00700000) == 0x00300000 {
        return Ok(0);
    }

    let event_from = FsEventInfo { index: I_MOVED_FROM, dentry: old_dentry, dentry_old: core::ptr::null() };
    handle_fs_event(ctx.clone(), &event_from);

    let event_to = FsEventInfo { index: I_MOVED_TO, dentry: new_dentry, dentry_old: old_dentry };
    handle_fs_event(ctx, &event_to);

    Ok(0)
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    let dentry = unsafe { ctx.arg::<*const dentry>(1).unwrap() };
    let event = FsEventInfo {
        index: I_DELETE,
        dentry: dentry,
        dentry_old: core::ptr::null(),
    };
    handle_fs_event(ctx, &event);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
