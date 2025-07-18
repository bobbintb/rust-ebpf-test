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
    // Get process information using BPF helpers
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tgid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get return value - handle the Option type
    let ret_val = match ctx.ret() {
        Some(val) => val,
        None => 0, // Default to 0 if no return value
    };
    
    // Log detailed return information
    info!(&ctx, "DIRT: vfs_unlink RETURN - PID: {}, TGID: {}, Return: {}", 
          pid, tgid, ret_val);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - PID: %u, TGID: %u, Return: %d", 
                    pid, tgid, ret_val);
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
    // Get process information using BPF helpers
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tgid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    // Get process name
    let mut comm: [u8; 16] = [0; 16];
    let comm_result = unsafe { bpf_get_current_comm(comm.as_mut_ptr()) };
    
    // Convert comm array to string for logging
    let comm_str = if comm_result == 0 {
        // Find the first null byte to get the string length
        let mut len = 0;
        for (i, &byte) in comm.iter().enumerate() {
            if byte == 0 {
                len = i;
                break;
            }
        }
        core::str::from_utf8(&comm[..len]).unwrap_or("unknown")
    } else {
        "unknown"
    };
    
    // Log detailed entry information
    info!(&ctx, "DIRT: vfs_unlink ENTRY - PID: {}, TGID: {}, Comm: {}", 
          pid, tgid, comm_str);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - PID: %u, TGID: %u, Comm: %s", 
                    pid, tgid, comm.as_ptr());
    }
    Ok(0)
}

// BPF helper function declarations
unsafe extern "C" {
    fn bpf_get_current_pid_tgid() -> u64;
    fn bpf_get_current_comm(buf: *mut u8) -> i32;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
