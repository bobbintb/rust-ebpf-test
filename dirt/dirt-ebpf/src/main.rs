#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{macros::{fentry, fexit, map}, programs::{FExitContext, FEntryContext}, helpers::bpf_printk, maps::Array};
use aya_log_ebpf::info;

// Map to store the target dev_t from userspace
#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[fentry]
pub fn do_unlinkat_entry(ctx: FEntryContext) -> u32 {
    match try_do_unlinkat_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat_entry(ctx: FEntryContext) -> Result<u32, u32> {
    // Get the target dev_t from userspace
    let target_dev = TARGET_DEV.get(0).ok_or(1u32)?;

    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log entry information with process details in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"do_unlinkat_entry\",\"pid\":{},\"tgid\":{},\"target_dev\":{}}}", current_pid, tgid, *target_dev);
    
    unsafe {
        bpf_printk!(b"DIRT: do_unlinkat ENTRY - {\"pid\": %d, \"tgid\": %d, \"target_dev\": %u}", current_pid, tgid, *target_dev);
    }
    
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
    // Get the target dev_t from userspace
    let target_dev = TARGET_DEV.get(0).ok_or(1u32)?;

    // Get return value - fexit context does not have a return value so we set to 0.
    let ret_val = 0;
    
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log return information in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"do_unlinkat_return\",\"pid\":{},\"tgid\":{},\"return\":{},\"target_dev\":{}}}", current_pid, tgid, ret_val, *target_dev);
    
    unsafe {
        bpf_printk!(b"DIRT: do_unlinkat RETURN - {\"pid\": %d, \"tgid\": %d, \"return\": %d, \"target_dev\": %u}", current_pid, tgid, ret_val, *target_dev);
    }
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
