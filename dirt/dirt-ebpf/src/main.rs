#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, PerfEventArray, PerCpuArray},
    programs::LsmContext,
    helpers::bpf_d_path,
};
use dirt_common::{EventType, UnlinkEvent};
use vmlinux::path;

const MAX_FILENAME_LEN: usize = 256;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static FILENAME_BUF: PerCpuArray<[u8; MAX_FILENAME_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "path_unlink")]
pub fn lsm_path_unlink(ctx: LsmContext) -> i32 {
    match try_lsm_path_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_lsm_path_unlink(ctx: LsmContext) -> Result<i32, i32> {
    let path_ptr: *const path = unsafe { ctx.arg(0) };
    if path_ptr.is_null() {
        return Ok(0);
    }
    let path = unsafe { &*path_ptr };

    let filename_buf = unsafe {
        let buf_ptr = FILENAME_BUF.get_ptr_mut(0).ok_or(-1)?;
        &mut *buf_ptr
    };

    let path_str_len = unsafe {
        bpf_d_path(
            path as *const _ as *mut _,
            filename_buf.as_mut_ptr() as *mut i8,
            MAX_FILENAME_LEN as u32,
        )
    };

    if path_str_len > 0 {
        let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
        let tgid = (pid_tgid >> 32) as u32;

        let target_dev = match TARGET_DEV.get(0) {
            Some(val) => *val,
            None => return Err(-1),
        };

        let pid = pid_tgid as u32;
        let event = UnlinkEvent {
            event_type: EventType::FEntry,
            pid,
            tgid,
            target_dev,
            ret_val: 0,
            filename: *filename_buf,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
