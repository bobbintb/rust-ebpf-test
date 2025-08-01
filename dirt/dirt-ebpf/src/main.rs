#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{fentry, map},
    maps::{Array, PerfEventArray},
    programs::FEntryContext,
};
use dirt_common::UnlinkEvent;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[fentry]
pub fn do_unlinkat(ctx: FEntryContext) -> u32 {
    match try_do_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat(ctx: FEntryContext) -> Result<u32, u32> {
    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let event = UnlinkEvent {
        pid,
        tgid,
        target_dev,
    };
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
