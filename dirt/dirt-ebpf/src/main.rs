#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}, helpers::bpf_printk};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{dentry, inode};

mod maps;
use maps::UNLINK_EVENTS;

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

use dirt_common::UnlinkEvent;

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    // Get return value - handle the Option type
    let ret_val = match ctx.ret() {
        Some(val) => val,
        None => 0, // Default to 0 if no return value
    };
    
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
    
    // Try to get the event from the map
    let event = match unsafe { UNLINK_EVENTS.get(&pid) } {
        Some(event) => event,
        None => return Ok(0),
    };

    // Log return information in JSON format
    let filename = unsafe { core::str::from_utf8_unchecked(&event.buf) };
    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"return\":{},\"filename\":\"{}\"}}", pid, ret_val, filename);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - {\"pid\": %d, \"return\": %d, \"filename\": \"%s\"}", pid, ret_val, filename.as_ptr());
    }

    // Remove the event from the map
    unsafe {
        UNLINK_EVENTS.remove(&pid).map_err(|e| e as u32)?;
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
