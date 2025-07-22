#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm},
};
use dirt_common::FileDeleteEvent;

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256KB

#[kprobe]
pub fn dirt(ctx: ProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;

    let mut comm = [0u8; 16];
    bpf_get_current_comm(&mut comm).map_err(|e| e as u32)?;

    let filename_ptr: *const u8 = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => return Err(1),
    };

    let mut filename = [0u8; 256];
    unsafe {
        ctx.read_user_str_bytes(filename_ptr, &mut filename)
            .map_err(|e| e as u32)?;
    }

    let event = FileDeleteEvent {
        pid,
        uid,
        filename,
        comm,
    };

    unsafe {
        if let Some(mut buf) = EVENTS.reserve(core::mem::size_of::<FileDeleteEvent>() as u32, 0) {
            let event_ptr = buf.as_mut_ptr() as *mut FileDeleteEvent;
            event_ptr.write(event);
            buf.submit(0);
        }
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
