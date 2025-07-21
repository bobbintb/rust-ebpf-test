#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe, map}, programs::{ProbeContext, RetProbeContext}, helpers::bpf_printk, maps::HashMap};
use aya_log_ebpf::info;
use dirt_common::UnlinkEvent;

#[map]
static mut UNLINK_EVENTS: HashMap<u32, UnlinkEvent> = HashMap::with_max_entries(1024, 0);

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
    let event = unsafe { UNLINK_EVENTS.get(&pid) };
    match event {
        Some(event) => {
            let ret_val = match ctx.ret() {
                Some(val) => val,
                None => 0,
            };
            info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"inode\":{},\"return\":{}}}", event.pid, event.tgid, event.inode, ret_val);
            unsafe {
                bpf_printk!(b"DIRT: vfs_unlink RETURN - {\"pid\": %d, \"tgid\": %d, \"inode\": %d, \"return\": %d}", event.pid, event.tgid, event.inode, ret_val);
            }
        }
        None => {
            info!(&ctx, "DIRT: vfs_unlink return probe: no event found for pid {}", pid);
        }
    }
    unsafe {
        UNLINK_EVENTS.remove(&pid).unwrap();
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
    let dentry: *const self::vmlinux::dentry = unsafe { ctx.arg(1) }.ok_or(1u32)?;
    let inode = unsafe { (*dentry).d_inode };
    let i_ino = unsafe { (*inode).i_ino };

    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    let event = UnlinkEvent {
        pid: current_pid,
        tgid,
        inode: i_ino,
    };

    unsafe {
        UNLINK_EVENTS.insert(&current_pid, &event, 0).unwrap();
    }

    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{},\"inode\":{}}}", current_pid, tgid, i_ino);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - {\"pid\": %d, \"tgid\": %d, \"inode\": %d}", current_pid, tgid, i_ino);
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

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;
