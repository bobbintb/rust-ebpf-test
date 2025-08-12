#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerfEventArray},
    programs::TracePointContext,
};
use dirt_common::{EventType, UnlinkEvent};

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static UNLINK_ARGS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

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
pub fn sys_exit_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_exit_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_unlink(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let path_ptr_u64 = unsafe { UNLINK_ARGS.get(&pid_tgid) };
    if path_ptr_u64.is_none() {
        return Ok(0);
    }
    UNLINK_ARGS.remove(&pid_tgid).map_err(|_| 1u32)?;
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
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
