#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{fentry, fexit, map},
    maps::{Array, PerfEventArray},
    programs::{FEntryContext, FExitContext},
};
use dirt_common::{EventType, UnlinkEvent};

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[fentry]
pub fn do_unlinkat_entry(ctx: FEntryContext) -> u32 {
    match try_do_unlinkat_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat_entry(ctx: FEntryContext) -> Result<u32, u32> {
    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let event = UnlinkEvent {
        event_type: EventType::FEntry,
        pid,
        tgid,
        target_dev,
        ret_val: 0,
    };
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[fexit]
pub fn do_unlinkat_exit(ctx: FExitContext) -> u32 {
    match try_do_unlinkat_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat_exit(ctx: FExitContext) -> Result<u32, u32> {
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
        ret_val: 0,
    };
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
