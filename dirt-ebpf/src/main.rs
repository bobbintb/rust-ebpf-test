#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_d_path, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use core::cmp;
use dirt_common::{EventType, FileEvent, MAX_FILENAME_LEN, MAX_PATH_LEN};
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

    // --- get path ---
    let path_ptr: *const path = unsafe { ctx.arg(0) };
    if path_ptr.is_null() { return Ok(0); }
    let path = unsafe { &*path_ptr };

    let event_buf = EVENT_BUF.get_ptr_mut(0).ok_or(-1)?;

    // --- read full path directly into event_buf.src_path ---
    let path_len = unsafe {
        bpf_d_path(path as *const _ as *mut _, (*event_buf).src_path.as_mut_ptr() as *mut i8, (MAX_PATH_LEN as u32) + 1)
    };
    if path_len <= 0 { return Ok(0); }

    // --- read filename directly into event_buf.src_file ---
    if !dentry_ptr.is_null() {
        let dentry = unsafe { &*dentry_ptr };
        let copy_len = cmp::min(
            unsafe { dentry.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize + 1 },
            MAX_FILENAME_LEN,
        );
        let ptr = unsafe { (*event_buf).src_file.as_mut_ptr() };
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(
                dentry.d_name.name as *const u8,
                core::slice::from_raw_parts_mut(ptr, copy_len),
            )
        };
    } else {
        unsafe { (*event_buf).src_file[0] = 0; }
    }

    // --- fill remaining fields ---
    unsafe {
        (*event_buf).event_type = EventType::Unlink;
        (*event_buf).target_dev = *target_dev;
        (*event_buf).ret_val = 0;

        EVENTS.output(&*event_buf, 0).map_err(|_| -1)?;
    }

    Ok(0)
}

#[lsm(hook = "path_rename")]
pub fn lsm_path_rename(ctx: LsmContext) -> i32 {
    match try_lsm_path_rename(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_lsm_path_rename(ctx: LsmContext) -> Result<i32, i32> {
    // --- early filter by device ID ---
    let target_dev = TARGET_DEV.get(0).ok_or(-1)?;
    let old_dentry_ptr: *const vmlinux::dentry = unsafe { ctx.arg(1) };

    if unsafe {
        old_dentry_ptr.as_ref()
            .and_then(|d| d.d_inode.as_ref())
            .and_then(|i| i.i_sb.as_ref())
            .map(|sb| sb.s_dev != *target_dev)
            .unwrap_or(false)
    } {
        return Ok(0);
    }

    let event_buf = EVENT_BUF.get_ptr_mut(0).ok_or(-1)?;

    // --- get old path ---
    let old_path_ptr: *const path = unsafe { ctx.arg(0) };
    if old_path_ptr.is_null() { return Ok(0); }
    let old_path = unsafe { &*old_path_ptr };

    // --- read full old path directly into event_buf.src_path ---
    let old_path_len = unsafe {
        bpf_d_path(old_path as *const _ as *mut _, (*event_buf).src_path.as_mut_ptr() as *mut i8, (MAX_PATH_LEN as u32) + 1)
    };
    if old_path_len <= 0 { return Ok(0); }

    // --- get new path ---
    let new_path_ptr: *const path = unsafe { ctx.arg(2) };
    if new_path_ptr.is_null() { return Ok(0); }
    let new_path = unsafe { &*new_path_ptr };

    // --- read full new path directly into event_buf.trgt_path ---
    let new_path_len = unsafe {
        bpf_d_path(new_path as *const _ as *mut _, (*event_buf).trgt_path.as_mut_ptr() as *mut i8, (MAX_PATH_LEN as u32) + 1)
    };
    if new_path_len <= 0 { return Ok(0); }

    // --- read old filename directly into event_buf.src_file ---
    if !old_dentry_ptr.is_null() {
        let old_dentry = unsafe { &*old_dentry_ptr };
        let copy_len = cmp::min(
            unsafe { old_dentry.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize + 1 },
            MAX_FILENAME_LEN,
        );
        let ptr = unsafe { (*event_buf).src_file.as_mut_ptr() };
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(
                old_dentry.d_name.name as *const u8,
                core::slice::from_raw_parts_mut(ptr, copy_len),
            )
        };
    } else {
        unsafe { (*event_buf).src_file[0] = 0; }
    }

    // --- read new filename directly into event_buf.trgt_file ---
    let new_dentry_ptr: *const vmlinux::dentry = unsafe { ctx.arg(3) };
    if !new_dentry_ptr.is_null() {
        let new_dentry = unsafe { &*new_dentry_ptr };
        let copy_len = cmp::min(
            unsafe { new_dentry.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize + 1 },
            MAX_FILENAME_LEN,
        );
        let ptr = unsafe { (*event_buf).trgt_file.as_mut_ptr() };
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(
                new_dentry.d_name.name as *const u8,
                core::slice::from_raw_parts_mut(ptr, copy_len),
            )
        };
    } else {
        unsafe { (*event_buf).trgt_file[0] = 0; }
    }

    // --- fill remaining fields ---
    unsafe {
        (*event_buf).event_type = EventType::Rename;
        (*event_buf).target_dev = *target_dev;
        (*event_buf).ret_val = 0;

        EVENTS.output(&*event_buf, 0).map_err(|_| -1)?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
