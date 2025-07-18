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
    // Get process information
    let pid = bpf_get_current_pid_tgid() >> 32;
    let tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Log detailed return information
    info!(&ctx, "DIRT: vfs_unlink RETURN - PID: {}, TGID: {}, Return Code: {}", 
          pid, tgid, ctx.ret());
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - PID: %d, TGID: %d, Return: %d", 
                    pid, tgid, ctx.ret());
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
    // Get process information
    let pid = bpf_get_current_pid_tgid() >> 32;
    let tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Get current task info
    let task = bpf_get_current_task();
    let comm = bpf_get_current_comm();
    
    // Log detailed entry information
    info!(&ctx, "DIRT: vfs_unlink ENTRY - PID: {}, TGID: {}, Comm: {}, Task: {}", 
          pid, tgid, comm, task);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - PID: %d, TGID: %d, Comm: %s", 
                    pid, tgid, &comm);
    }
    Ok(0)
}

// Helper functions to get process information
#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    unsafe {
        let mut pid_tgid: u64 = 0;
        bpf_get_current_pid_tgid(&mut pid_tgid as *mut u64 as *mut core::ffi::c_void);
        pid_tgid
    }
}

#[inline(always)]
fn bpf_get_current_task() -> u64 {
    unsafe {
        let mut task: u64 = 0;
        bpf_get_current_task(&mut task as *mut u64 as *mut core::ffi::c_void);
        task
    }
}

#[inline(always)]
fn bpf_get_current_comm() -> [u8; 16] {
    unsafe {
        let mut comm: [u8; 16] = [0; 16];
        bpf_get_current_comm(&mut comm as *mut u8 as *mut core::ffi::c_void, 16);
        comm
    }
}

// BPF helper function declarations
extern "C" {
    fn bpf_get_current_pid_tgid(pid_tgid: *mut core::ffi::c_void) -> u64;
    fn bpf_get_current_task(task: *mut core::ffi::c_void) -> u64;
    fn bpf_get_current_comm(buf: *mut core::ffi::c_void, size: u32) -> i32;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
