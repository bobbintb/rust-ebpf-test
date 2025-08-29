#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, PerfEventArray, PerCpuArray},
    programs::LsmContext,
    helpers::{bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
};
use dirt_common::{EventType, UnlinkEvent};
use core::cmp;
use vmlinux::path;

const MAX_FILENAME_LEN: usize = 256;
const MAX_PATH_LEN: usize = 4096;

#[map]
static TARGET_DEV: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static PATH_NAME_BUF: PerCpuArray<[u8; MAX_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILE_NAME_BUF: PerCpuArray<[u8; MAX_FILENAME_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENT_BUF: PerCpuArray<UnlinkEvent> = PerCpuArray::with_max_entries(1, 0);

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

    let pathname_buf = PATH_NAME_BUF.get_ptr_mut(0).ok_or(-1)?;
    let filename_buf = FILE_NAME_BUF.get_ptr_mut(0).ok_or(-1)?;
    let event_buf = EVENT_BUF.get_ptr_mut(0).ok_or(-1)?;

    let path_len = unsafe {
        bpf_d_path(
            path as *const _ as *mut _,
            (&mut *pathname_buf)[..].as_mut_ptr() as *mut i8,
            MAX_PATH_LEN as u32,
        )
    };
    if path_len <= 0 {
        return Ok(0);
    }

    let dentry_ptr: *const vmlinux::dentry = unsafe { ctx.arg(1) };
    if !dentry_ptr.is_null() {
        let dentry = unsafe { &*dentry_ptr };
        let dentry_len = unsafe { dentry.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize };
        let copy_len = cmp::min(dentry_len + 1, MAX_FILENAME_LEN); // include null
        unsafe {
            let buf_ptr = (*filename_buf).as_mut_ptr();
            let _ = bpf_probe_read_kernel_str_bytes(
                dentry.d_name.name as *const u8,
                core::slice::from_raw_parts_mut(buf_ptr, copy_len),
            );
        }
    } else {
        unsafe { (*filename_buf)[0] = 0; }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let target_dev = match TARGET_DEV.get(0) {
        Some(val) => *val,
        None => return Err(-1),
    };

    unsafe {
        (*event_buf).event_type = EventType::FEntry;
        (*event_buf).pid = pid;
        (*event_buf).tgid = tgid;
        (*event_buf).target_dev = target_dev;
        (*event_buf).ret_val = 0i32;

        // Copy path safely
        let path_copy_len = cmp::min(path_len as usize, MAX_PATH_LEN - 1);
        core::ptr::copy_nonoverlapping(
            (&*pathname_buf)[..path_copy_len].as_ptr(),
            (&mut (*event_buf).pathname)[..path_copy_len].as_mut_ptr(),
            path_copy_len,
        );
        (*event_buf).pathname[path_copy_len] = 0;

        // Copy filename safely
        let mut i = 0usize;
        while i < MAX_FILENAME_LEN && (*filename_buf)[i] != 0 {
            i += 1;
        }
        let fn_copy = cmp::min(i, MAX_FILENAME_LEN - 1);
        core::ptr::copy_nonoverlapping(
            (&*filename_buf)[..fn_copy].as_ptr(),
            (&mut (*event_buf).filename)[..fn_copy].as_mut_ptr(),
            fn_copy,
        );
        (*event_buf).filename[fn_copy] = 0;

        EVENTS.output(&ctx, &*event_buf, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
