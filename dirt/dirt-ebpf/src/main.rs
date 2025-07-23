#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{macros::{kprobe, kretprobe, map}, programs::{ProbeContext, RetProbeContext}, helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel}, maps::HashMap};
use aya_log_ebpf::info;
use dirt_common::UnlinkEvent;
use vmlinux::dentry;

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
    let ret_val = ctx.ret().unwrap_or(0) as i32;
    let pid = bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;

    if let Some(event) = unsafe { UNLINK_EVENTS.get_mut(&current_pid) } {
        event.ret_val = ret_val;
        info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"inode\":{},\"return\":{}}}", event.pid, event.tgid, event.inode, event.ret_val);
    }

    unsafe {
        UNLINK_EVENTS.remove(&current_pid).unwrap();
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
    let pid = bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;

    let dentry: *const dentry = unsafe { ctx.arg(1).unwrap() };
    let inode = unsafe { bpf_probe_read_kernel(&(*dentry).d_inode).unwrap() };
    let inode_no = unsafe { bpf_probe_read_kernel(&inode.i_ino).unwrap() };

    let event = UnlinkEvent {
        inode: inode_no,
        pid: current_pid,
        tgid,
        ret_val: 0,
    };

    unsafe {
        UNLINK_EVENTS.insert(&current_pid, &event).unwrap();
    }

    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{},\"inode\":{}}}", current_pid, tgid, inode_no);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
