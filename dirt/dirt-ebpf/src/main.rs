#![no_std]
#![no_main]

mod vmlinux;
// mod types;

use aya_ebpf::{macros::{fentry, fexit}, programs::FExitContext, helpers::bpf_printk};
use aya_log_ebpf::info;

#[fexit]
pub fn do_unlinkat_exit(ctx: FExitContext) -> u32 {
    match try_do_unlinkat_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_unlinkat_exit(ctx: FExitContext) -> Result<u32, u32> {
    // Get return value - fexit context does not have a return value so we set to 0.
    let ret_val = 0;
    
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Log return information in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"do_unlinkat_return\",\"pid\":{},\"tgid\":{},\"return\":{}}}", current_pid, tgid, ret_val);
    
    unsafe {
        bpf_printk!(b"DIRT: do_unlinkat RETURN - {\"pid\": %d, \"tgid\": %d, \"return\": %d}", current_pid, tgid, ret_val);
    }
    Ok(0)
}

use aya_ebpf::programs::FEntryContext;

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
