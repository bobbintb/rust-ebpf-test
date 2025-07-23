#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}, helpers::bpf_printk, macros::map, maps::HashMap};
use aya_log_ebpf::info;

use dirt_common::UnlinkEvent;

#[map]
static mut DENTRY_MAP: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

use crate::vmlinux::dentry;
use crate::vmlinux::inode;

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    let ret_val = match ctx.ret() {
        Some(val) => val as i32,
        None => 0,
    };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let dentry_ptr = unsafe { DENTRY_MAP.get(&pid) };
    if dentry_ptr.is_none() {
        return Ok(0);
    }
    let dentry_ptr = dentry_ptr.unwrap();

    let dentry: dentry = unsafe { core::ptr::read_volatile(dentry_ptr as *const dentry) };
    let inode: inode = unsafe { core::ptr::read_volatile(dentry.d_inode as *const inode) };

    let event = UnlinkEvent {
        inode: inode.i_ino,
        pid,
        tgid,
        ret_val,
    };

    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"inode\":{},\"return\":{}}}", event.pid, event.tgid, event.inode, event.ret_val);

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
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
    let dentry: u64 = ctx.arg(1).ok_or(1u32)?;
    unsafe {
        DENTRY_MAP.insert(&pid, &dentry, 0).map_err(|e| e as u32)?;
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
