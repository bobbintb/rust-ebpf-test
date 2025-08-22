#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{lsm, map},
    maps::{Array, PerCpuArray, PerfEventArray},
    programs::LsmContext,
};
use dirt_common::{EventType, UnlinkEvent};

unsafe extern "C" {
    fn bpf_path_d_path(path: *mut vmlinux::path, buf: *mut u8, sz: u32) -> i32;
}

const MAX_FILENAME_LEN: usize = 256;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static FILENAME_BUF: PerCpuArray<[u8; MAX_FILENAME_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "file_free")]
pub fn file_free(ctx: LsmContext) -> i32 {
    match unsafe { try_file_free(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_file_free(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    if file.is_null() {
        return Ok(0);
    }
    let path = unsafe { &(*file).f_path };

    let buf_ptr = match FILENAME_BUF.get_ptr_mut(0) {
        Some(buf_ptr) => buf_ptr,
        None => return Ok(0),
    };

    let len = unsafe {
        bpf_path_d_path(
            path as *const _ as *mut _,
            buf_ptr as *mut u8,
            MAX_FILENAME_LEN as u32,
        )
    };

    if len > 0 {
        let pid_tgid = bpf_get_current_pid_tgid();
        let tgid = (pid_tgid >> 32) as u32;
        let pid = pid_tgid as u32;

        let target_dev = match TARGET_DEV.get(0) {
            Some(val) => *val,
            None => return Err(1),
        };

        let event = UnlinkEvent {
            event_type: EventType::FEntry,
            pid,
            tgid,
            target_dev,
            ret_val: 0,
            filename: unsafe { *buf_ptr },
        };
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
