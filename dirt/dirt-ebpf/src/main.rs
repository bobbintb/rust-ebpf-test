#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    maps::{Array, HashMap, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
};
use dirt_common::{EventType, UnlinkEvent};

const MAX_FILENAME_LEN: usize = 256;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static FILENAMES: HashMap<u32, [u8; MAX_FILENAME_LEN]> = HashMap::with_max_entries(1024, 0);

use aya_ebpf::helpers::bpf_probe_read_kernel;
// Kernel helpers (not wrapped by this aya-ebpf version)
#[link(name = "bpf_path_d_path")]
extern "C" {
    fn bpf_path_d_path(path: *mut core::ffi::c_void, buf: *mut u8, sz: u32) -> i64;
}

#[repr(C)]
struct Path {
    mnt: *mut core::ffi::c_void,
    dentry: *mut core::ffi::c_void,
}

// Resolve full path at unlink time using bpf_path_d_path
#[kprobe]
pub fn security_path_unlink(ctx: ProbeContext) -> u32 {
    match try_security_path_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_path_unlink(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // int security_path_unlink(struct path *dir, struct dentry *dentry)
    let dir_ptr: *const Path = match ctx.arg::<*const Path>(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let dentry_ptr: *mut core::ffi::c_void = match ctx.arg::<*mut core::ffi::c_void>(1) {
        Some(p) => p,
        None => return Ok(0),
    };

    if dir_ptr.is_null() || dentry_ptr.is_null() {
        return Ok(0);
    }

    // Construct a struct path with dir->mnt and target dentry
    let mut p = Path {
        mnt: core::ptr::null_mut(),
        dentry: dentry_ptr,
    };

    // Read mnt from dir->mnt (first field of struct path)
    p.mnt = unsafe { bpf_probe_read_kernel(dir_ptr as *const *mut core::ffi::c_void)? };

    let mut filename = [0u8; MAX_FILENAME_LEN];
    let rc = unsafe {
        bpf_path_d_path(
            &mut p as *mut _ as *mut core::ffi::c_void,
            filename.as_mut_ptr(),
            MAX_FILENAME_LEN as u32,
        )
    };

    if rc >= 0 {
        FILENAMES.insert(&tgid, &filename, 0)?;
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_unlink(_ctx: TracePointContext) -> Result<u32, i64> {
    // Path resolution handled in kprobe via bpf_path_d_path
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_unlinkat(_ctx: TracePointContext) -> Result<u32, i64> {
    // Path resolution handled in kprobe via bpf_path_d_path
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_exit_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_unlink(ctx: TracePointContext) -> Result<u32, u32> {
    let ret_val = unsafe { ctx.read_at::<i64>(16).map(|val| val as i32).unwrap_or(-1) };
    if ret_val != 0 {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if let Some(filename) = unsafe { FILENAMES.get(&tgid) } {
        let target_dev = match TARGET_DEV.get(0) {
            Some(val) => *val,
            None => return Err(1),
        };

        let pid = pid_tgid as u32;
        let event = UnlinkEvent {
            event_type: EventType::FExit,
            pid,
            tgid,
            target_dev,
            ret_val,
            filename: *filename,
        };
        EVENTS.output(&ctx, &event, 0);
        FILENAMES.remove(&tgid).ok();
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_exit_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_exit_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_unlinkat(ctx: TracePointContext) -> Result<u32, u32> {
    let ret_val = unsafe { ctx.read_at::<i64>(16).map(|val| val as i32).unwrap_or(-1) };
    if ret_val != 0 {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if let Some(filename) = unsafe { FILENAMES.get(&tgid) } {
        let target_dev = match TARGET_DEV.get(0) {
            Some(val) => *val,
            None => return Err(1),
        };

        let pid = pid_tgid as u32;
        let event = UnlinkEvent {
            event_type: EventType::FExit,
            pid,
            tgid,
            target_dev,
            ret_val,
            filename: *filename,
        };
        EVENTS.output(&ctx, &event, 0);
        FILENAMES.remove(&tgid).ok();
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
