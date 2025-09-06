#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, RingBuf, PerCpuArray},
    programs::LsmContext,
    helpers::{bpf_d_path, bpf_probe_read_kernel_str_bytes},
};
use dirt_common::*;
use core::cmp;
use vmlinux::path;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

#[map]
static EVENT_BUF: PerCpuArray<FileEvent> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "path_unlink")]
pub fn lsm_path_unlink(ctx: LsmContext) -> i32 {
    match try_lsm_path_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn get_path(ctx: &LsmContext, event_buf: &mut FileEvent) -> Result<i64, i32> {
    let path_ptr: *const path = unsafe { ctx.arg(0) };
    if path_ptr.is_null() {
        return Err(0);
    }
    let path = unsafe { &*path_ptr };

    let path_len = unsafe {
        bpf_d_path(
            path as *const _ as *mut _,
            event_buf.src_path.as_mut_ptr() as *mut i8,
            (MAX_PATH_LEN as u32) + 1,
        )
    };
    if path_len <= 0 {
        return Err(0);
    }

    Ok(path_len)
}

fn get_filename(dentry_ptr: *const vmlinux::dentry, event_buf: &mut FileEvent) {
    if !dentry_ptr.is_null() {
        let dentry = unsafe { &*dentry_ptr };
        let copy_len = cmp::min(
            unsafe { dentry.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize + 1 },
            MAX_FILENAME_LEN,
        );
        let ptr = event_buf.src_file.as_mut_ptr();
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(
                dentry.d_name.name as *const u8,
                core::slice::from_raw_parts_mut(ptr, copy_len),
            )
        };
    } else {
        event_buf.src_file[0] = 0;
    }
}

fn try_lsm_path_unlink(ctx: LsmContext) -> Result<i32, i32> {
    // --- early filter by device ID ---
    let target_dev = TARGET_DEV.get(0).ok_or(-1)?;
    let dentry_ptr: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    if unsafe {
        dentry_ptr.as_ref()
            .and_then(|d| d.d_inode.as_ref())
            .and_then(|i| i.i_sb.as_ref())
            .map(|sb| sb.s_dev != *target_dev)
            .unwrap_or(false)
    } {
        return Ok(0);
    }

    let event_buf_ptr = EVENT_BUF.get_ptr_mut(0).ok_or(-1)?;
    let event_buf = unsafe { &mut *event_buf_ptr };

    if get_path(&ctx, event_buf).is_err() {
        return Ok(0);
    }

    get_filename(dentry_ptr, event_buf);

    // --- fill remaining fields ---
    event_buf.event_type = EventType::Unlink;
    event_buf.target_dev = *target_dev;
    event_buf.ret_val = 0;

    EVENTS.output(event_buf, 0).map_err(|_| -1)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
