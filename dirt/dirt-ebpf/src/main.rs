#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
    helpers::bpf_get_current_pid_tgid,
    maps::{PerCpuArray, PerfMap},
    bindings::vmlinux::d_inode,
};
use core::mem;
use dirt_common::FileDeleteEvent;

#[repr(C)]
pub struct Dentry {
    pub d_inode: *const d_inode,
}

#[repr(C)]
pub struct Path {
    pub dentry: *const Dentry,
}

#[map]
static mut EVENTS: PerfMap<FileDeleteEvent> = PerfMap::with_max_entries(1024, 0);

#[map]
static mut INODE_MAP: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[kprobe]
pub fn vfs_unlink_probe(ctx: ProbeContext) -> u32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    let path: *const Path = ctx.arg(1).ok_or(1u32)?;
    let dentry = unsafe { (*path).dentry };
    let inode = unsafe { (*dentry).d_inode };
    let inode_num = unsafe { (*inode).i_ino };

    let zero: u32 = 0;
    INODE_MAP.set(&zero, &inode_num);

    Ok(0)
}

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    let zero: u32 = 0;
    let inode_num = INODE_MAP.get(&zero).copied().unwrap_or(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let ret = ctx.ret().unwrap_or(0) as i32;

    let event = FileDeleteEvent {
        inode: inode_num,
        pid,
        tgid,
        ret,
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
