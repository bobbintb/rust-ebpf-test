#![no_std]
#![no_main]

mod vmlinux;
// Commenting this out for now until it is done so it won't cause errors.
// mod types;

use aya_ebpf::{macros::{fentry, fexit}, programs::{FEntryContext, FExitContext}, helpers::bpf_printk};
use aya_log_ebpf::info;

#[fexit]
pub fn do_unlinkat(ctx: FExitContext) -> u32 {
    match try_do_unlinkat_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat_exit(ctx: FExitContext) -> Result<u32, u32> {
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log return information in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"do_unlinkat_exit\",\"pid\":{},\"tgid\":{}}}", current_pid, tgid);
    
    unsafe {
        bpf_printk!(b"DIRT: do_unlinkat EXIT - {\"pid\": %d, \"tgid\": %d}", current_pid, tgid);
    }
    Ok(0)
}

#[fentry]
pub fn do_unlinkat_entry(ctx: FEntryContext) -> u32 {
    match try_do_unlinkat_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat_entry(ctx: FEntryContext) -> Result<u32, u32> {
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log entry information with process details in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"do_unlinkat_entry\",\"pid\":{},\"tgid\":{}}}", current_pid, tgid);
    
    unsafe {
        bpf_printk!(b"DIRT: do_unlinkat ENTRY - {\"pid\": %d, \"tgid\": %d}", current_pid, tgid);
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
