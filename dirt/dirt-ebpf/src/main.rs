#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, PerfEventArray},
    programs::TracePointContext,
};
use dirt_common::{EventType, UnlinkEvent};

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

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

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let event = UnlinkEvent {
        event_type: EventType::FExit,
        pid,
        tgid,
        target_dev,
        ret_val,
    };
    EVENTS.output(&ctx, &event, 0);

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

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let event = UnlinkEvent {
        event_type: EventType::FExit,
        pid,
        tgid,
        target_dev,
        ret_val,
    };
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
