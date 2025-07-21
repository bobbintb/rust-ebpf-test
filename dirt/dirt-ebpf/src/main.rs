#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}, macros::map, maps::PerCpuArray, helpers::bpf_get_current_pid_tgid};
use aya_log_ebpf::info;
use dirt_common::UnlinkEvent;

#[map]
static mut EVENTS: PerCpuArray<UnlinkEvent> = PerCpuArray::with_max_entries(1024, 0);

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    let ret_val = match ctx.ret() {
        Some(val) => val,
        None => 0,
    };

    let pid = bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;

    // TODO: Get inode from EVENTS map
    // let mut inode = 0;
    // unsafe {
    //     if let Some(event) = EVENTS.get(0) {
    //         inode = event.inode;
    //     }
    // }

    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"return\":{}}}", current_pid, tgid, ret_val);

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
    // TODO: Get inode from dentry
    // let dentry: *const dentry = unsafe { ctx.arg(1) }.ok_or(1u32)?;
    // let d_inode: *const inode = unsafe { (*dentry).d_inode };
    // let i_ino = unsafe { (*d_inode).i_ino };

    // let event = UnlinkEvent { inode: i_ino };

    let pid = bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;

    // unsafe {
    //     if let Some(val_ptr) = EVENTS.get_ptr_mut(0) {
    //         *val_ptr = event;
    //     }
    // }

    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{}}}", current_pid, tgid);

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
