#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{fentry, map},
    maps::PerfEventArray,
    programs::FEntryContext,
    helpers::bpf_get_current_pid_tgid,
};
use vmlinux::{dentry, path};

const MAX_PATH_LEN: u32 = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub filename: [u8; 256],
}


#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[fentry]
pub fn vfs_unlink(ctx: FEntryContext) -> i32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_unlink(ctx: FEntryContext) -> Result<i32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let dentry: *const dentry = unsafe { ctx.arg(2) };

    let mut event: UnlinkEvent = unsafe { core::mem::zeroed() };
    event.pid = pid;
    event.tgid = tgid;

    let path_struct = path {
        dentry: dentry as *mut dentry,
        mnt: core::ptr::null_mut(),
    };

    let ret = unsafe { bpf_path_d_path(&path_struct, event.filename.as_mut_ptr(), MAX_PATH_LEN) };

    if ret < 0 {
        return Err(ret as i32);
    }

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

extern "C" {
    fn bpf_path_d_path(path: *const path, buf: *mut u8, sz: u32) -> i64;
}
