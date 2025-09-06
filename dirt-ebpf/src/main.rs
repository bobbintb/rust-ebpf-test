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

#[inline(always)]
fn process_event_generic(
    event_type: EventType,
    path_args: &[(*const path, fn(&mut FileEvent) -> &mut [u8])],
    dentry_args: &[(*const vmlinux::dentry, fn(&mut FileEvent) -> &mut [u8])],
) -> i32 {
    let target_dev = match TARGET_DEV.get(0) {
        Some(dev) => *dev,
        None => return 0,
    };

    let event_buf = match EVENT_BUF.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return 0,
    };

    // Simple device check for the first dentry
    let (first_dentry_ptr, _) = dentry_args[0];

if unsafe {
    first_dentry_ptr
        .as_ref()
        .and_then(|d| d.d_inode.as_ref())
        .and_then(|i| i.i_sb.as_ref())
        .map(|sb| sb.s_dev != target_dev)
        .unwrap_or(false)
} {
    return 0;
}


    // Read paths
    for (path_ptr, field_fn) in path_args {
        if path_ptr.is_null() { continue; }
        let path_ref = unsafe { &**path_ptr };
        let buf = field_fn(event_buf);
        let _ = unsafe {
            bpf_d_path(path_ref as *const _ as *mut _, buf.as_mut_ptr() as *mut i8, (MAX_PATH_LEN as u32) + 1)
        };
    }

    // Read dentries
    for (dentry_ptr, field_fn) in dentry_args {
        let buf = field_fn(event_buf);
        if dentry_ptr.is_null() {
            if !buf.is_empty() { buf[0] = 0; }
            continue;
        }
        let dentry = unsafe { &**dentry_ptr };
        let copy_len = cmp::min(
            unsafe { dentry.d_name.__bindgen_anon_1.__bindgen_anon_1.len as usize + 1 },
            MAX_FILENAME_LEN,
        );
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(
                dentry.d_name.name as *const u8,
                core::slice::from_raw_parts_mut(buf.as_mut_ptr(), copy_len),
            )
        };
    }

    // Fill remaining fields
        event_buf.event_type = event_type;
        event_buf.target_dev = target_dev;
        event_buf.ret_val = 0;

        let _ = EVENTS.output(event_buf, 0);
    0
}

// LSM hooks
#[lsm(hook = "path_unlink")]
pub fn lsm_path_unlink(ctx: LsmContext) -> i32 {
    process_event_generic(
        EventType::Unlink,
        &[ (unsafe { ctx.arg(0) }, |ev| &mut ev.src_path) ],
        &[ (unsafe { ctx.arg(1) }, |ev| &mut ev.src_file) ],
    )
}

#[lsm(hook = "path_rename")]
pub fn lsm_path_rename(ctx: LsmContext) -> i32 {
    process_event_generic(
        EventType::Rename,
        &[
            (unsafe { ctx.arg(0) }, |ev| &mut ev.src_path),
            (unsafe { ctx.arg(2) }, |ev| &mut ev.trgt_path),
        ],
        &[
            (unsafe { ctx.arg(1) }, |ev| &mut ev.src_file),
            (unsafe { ctx.arg(3) }, |ev| &mut ev.trgt_file),
        ],
    )
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
