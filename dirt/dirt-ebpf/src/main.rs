#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{kprobe, map},
    maps::{Array, PerfEventArray},
    programs::ProbeContext,
    helpers::bpf_get_current_pid_tgid,
    BpfContext,
};
use dirt_common::{EventType, UnlinkEvent};

const MAX_FILENAME_LEN: usize = 256;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

unsafe extern "C" {
    fn bpf_path_d_path(path: *mut vmlinux::path, buf: *mut u8, sz: u32) -> i64;
}

#[kprobe]
pub fn security_path_unlink(ctx: ProbeContext) -> u32 {
    match try_security_path_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_path_unlink(ctx: ProbeContext) -> Result<u32, i64> {
    let dir_path_ptr: *const vmlinux::path = ctx.arg(0).ok_or(1i64)?;
    let dentry_ptr: *mut vmlinux::dentry = ctx.arg(1).ok_or(1i64)?;

    let mnt = unsafe { (*dir_path_ptr).mnt };
    let mut file_path = vmlinux::path {
        mnt,
        dentry: dentry_ptr,
    };

    let mut event = UnlinkEvent {
        event_type: EventType::FExit,
        pid: 0,
        tgid: 0,
        target_dev: 0,
        ret_val: 0,
        filename: [0u8; MAX_FILENAME_LEN],
    };

    let len = unsafe {
        bpf_path_d_path(
            &mut file_path,
            event.filename.as_mut_ptr(),
            MAX_FILENAME_LEN as u32,
        )
    };
    if len < 0 {
        return Err(len);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };
    event.target_dev = target_dev;

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
