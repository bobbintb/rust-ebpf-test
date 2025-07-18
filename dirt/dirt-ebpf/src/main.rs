#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}, helpers::bpf_printk};
use aya_log_ebpf::info;

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    // Get return value - handle the Option type
    let ret_val = match ctx.ret() {
        Some(val) => val,
        None => 0, // Default to 0 if no return value
    };
    
    // Get current task info for process details
    let task = unsafe { aya_ebpf::helpers::bpf_get_current_task() };
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid_num = (pid >> 32) as u32;
    let tgid_num = (pid & 0xFFFFFFFF) as u32;
    
    // Log detailed return information with process details
    info!(&ctx, "DIRT: vfs_unlink RETURN - PID: {}, TGID: {}, Task: {}, Return: {}", 
          pid_num, tgid_num, task, ret_val);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - PID: %u, TGID: %u, Return: %d", 
                    pid_num, tgid_num, ret_val);
    }
    Ok(0)
}

#[kprobe]
pub fn vfs_unlink_probe(ctx: ProbeContext) -> u32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    // Get current task info for process details
    let task = unsafe { aya_ebpf::helpers::bpf_get_current_task() };
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid_num = (pid >> 32) as u32;
    let tgid_num = (pid & 0xFFFFFFFF) as u32;
    
    // Log detailed entry information with process details
    info!(&ctx, "DIRT: vfs_unlink ENTRY - PID: {}, TGID: {}, Task: {}", 
          pid_num, tgid_num, task);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - PID: %u, TGID: %u", 
                    pid_num, tgid_num);
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
