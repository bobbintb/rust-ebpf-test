#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerfEventArray},
    programs::TracePointContext,
};
use dirt_common::{EventType, UnlinkEvent};

const MAX_FILENAME_LEN: usize = 256;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static FILENAMES: HashMap<u32, [u8; MAX_FILENAME_LEN]> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_unlink(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let pathname_ptr: u64 = unsafe { ctx.read_at(16)? };
    let mut filename = [0u8; MAX_FILENAME_LEN];
    let res =
        unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut filename) };

    if res.is_ok() {
        FILENAMES.insert(&tgid, &filename, 0)?;
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let pathname_ptr: u64 = unsafe { ctx.read_at(24)? };
    let mut filename = [0u8; MAX_FILENAME_LEN];
    let res =
        unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut filename) };

    if res.is_ok() {
        FILENAMES.insert(&tgid, &filename, 0)?;
    }

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
