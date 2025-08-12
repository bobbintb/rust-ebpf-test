#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerfEventArray, PerCpuArray},
    programs::TracePointContext,
};
use dirt_common::{EventType, UnlinkEvent};

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static UNLINK_ARGS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENT_SCRATCH: PerCpuArray<UnlinkEvent> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_unlink(ctx: TracePointContext) -> Result<u32, u32> {
    let path_ptr: *const u8 = unsafe { ctx.read_at(16) }.map_err(|_| 1u32)?;
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let path_ptr_u64 = path_ptr as u64;
    UNLINK_ARGS.insert(&pid_tgid, &path_ptr_u64, 0).map_err(|_| 1u32)?;
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<u32, u32> {
    let path_ptr: *const u8 = unsafe { ctx.read_at(24) }.map_err(|_| 1u32)?;
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let path_ptr_u64 = path_ptr as u64;
    UNLINK_ARGS.insert(&pid_tgid, &path_ptr_u64, 0).map_err(|_| 1u32)?;
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
    // Only process successful unlinks (ret == 0)
    let ret_val = unsafe {
        match ctx.read_at::<i64>(16) {
            Ok(val) => val as i32,
            Err(_) => return Err(1),
        }
    };

    if ret_val != 0 {
        return Ok(0); // Skip failed unlinks
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let path_ptr_u64 = unsafe { UNLINK_ARGS.get(&pid_tgid) };
    if path_ptr_u64.is_none() {
        return Ok(0);
    }
    let path_ptr = *path_ptr_u64.unwrap() as *const u8;
    UNLINK_ARGS.remove(&pid_tgid).map_err(|_| 1u32)?;

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    // Use a scratch buffer to avoid stack overflow
    let zero: u32 = 0;
    let event = match EVENT_SCRATCH.get_ptr_mut(zero) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(1),
    };

    event.event_type = EventType::FExit;
    event.pid = pid;
    event.tgid = tgid;
    event.target_dev = target_dev;
    event.ret_val = ret_val;
    event.comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap();
    unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(path_ptr, &mut event.filename) }.map_err(|_| 1u32)?;

    EVENTS.output(&ctx, event, 0);

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
    // Only process successful unlinks (ret == 0)
    let ret_val = unsafe {
        match ctx.read_at::<i64>(16) {
            Ok(val) => val as i32,
            Err(_) => return Err(1),
        }
    };

    if ret_val != 0 {
        return Ok(0); // Skip failed unlinks
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let path_ptr_u64 = unsafe { UNLINK_ARGS.get(&pid_tgid) };
    if path_ptr_u64.is_none() {
        return Ok(0);
    }
    let path_ptr = *path_ptr_u64.unwrap() as *const u8;
    UNLINK_ARGS.remove(&pid_tgid).map_err(|_| 1u32)?;

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    // Use a scratch buffer to avoid stack overflow
    let zero: u32 = 0;
    let event = match EVENT_SCRATCH.get_ptr_mut(zero) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(1),
    };

    event.event_type = EventType::FExit;
    event.pid = pid;
    event.tgid = tgid;
    event.target_dev = target_dev;
    event.ret_val = ret_val;
    event.comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap();
    unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(path_ptr, &mut event.filename) }.map_err(|_| 1u32)?;

    EVENTS.output(&ctx, event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
