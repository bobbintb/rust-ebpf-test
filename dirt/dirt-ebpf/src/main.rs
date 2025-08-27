#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{map, kprobe},
    maps::{Array, PerfEventArray, PerCpuArray},
    programs::ProbeContext,
};
use aya_ebpf_cty::{c_char, c_long};
use dirt_common::{EventType, UnlinkEvent};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use vmlinux::path;

unsafe extern "C" {
    fn bpf_path_d_path(path: *mut path, buf: *mut c_char, sz: u32) -> c_long;
}

const MAX_FILENAME_LEN: usize = 256;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static FILENAME_BUF: PerCpuArray<[u8; MAX_FILENAME_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, i64> {
    let path: *mut path = unsafe { ctx.arg(1) }.ok_or(1i64)?;

    let filename_buf_ptr = FILENAME_BUF.get_ptr_mut(0).ok_or(1i64)?;
    let filename_buf = unsafe { &mut *filename_buf_ptr };
    let ret = unsafe { bpf_path_d_path(path, filename_buf.as_mut_ptr() as *mut c_char, MAX_FILENAME_LEN as u32) };

    if ret < 0 {
        return Err(ret as i64);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(1),
    };

    let event = UnlinkEvent {
        event_type: EventType::FExit,
        pid,
        tgid,
        target_dev,
        ret_val: 0,
        filename: *filename_buf,
    };
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
