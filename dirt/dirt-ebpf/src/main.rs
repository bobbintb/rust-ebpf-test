#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
    helpers::bpf_get_current_pid_tgid,
};
use core::mem;
use dirt_common::UnlinkEvent;

// Define a struct that represents the arguments to the vfs_unlink function
#[repr(C)]
struct VfsUnlinkArgs {
    dentry: *const dentry,
}

// Define the vmlinux structs that we need
#[repr(C)]
struct dentry {
    d_inode: *const inode,
}

#[repr(C)]
struct inode {
    i_ino: u64,
}


#[map]
static mut EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe]
pub fn dirt(ctx: ProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;

    // The first argument to vfs_unlink is a pointer to the dentry
    let dentry_ptr: *const dentry = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => return Err(1),
    };

    let dentry: dentry = match unsafe { dentry_ptr.read_volatile() } {
        Ok(d) => d,
        Err(_) => return Err(2),
    };

    let inode_ptr = dentry.d_inode;
    let inode_val: inode = match unsafe { inode_ptr.read_volatile() } {
        Ok(i) => i,
        Err(_) => return Err(3),
    };
    
    let inode = inode_val.i_ino;

    let event = UnlinkEvent {
        tgid,
        pid: current_pid,
        inode,
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
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
