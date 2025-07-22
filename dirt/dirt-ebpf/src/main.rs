#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe, map}, programs::{ProbeContext, RetProbeContext}, helpers::bpf_printk, maps::HashMap};
use aya_log_ebpf::info;
use dirt_ebpf::vmlinux::dentry;

#[map]
static INODE_MAP: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[kretprobe]
pub fn dirt(ctx: RetProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: RetProbeContext) -> Result<u32, u32> {
    // Get return value - handle the Option type
    let ret_val = match ctx.ret() {
        Some(val) => val,
        None => 0, // Default to 0 if no return value
    };
    
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Read the inode from the map
    let inode = INODE_MAP.get(&current_pid).copied().unwrap_or(0);

    // Log return information in JSON format
    info!(&ctx, "DIRT_JSON: {{"event":"vfs_unlink_return","pid":{},"tgid":{},"return":{},"inode":{}}}", current_pid, tgid, ret_val, inode);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - {"pid": %d, "tgid": %d, "return": %d, "inode": %d}", current_pid, tgid, ret_val, inode);
    }

    // Remove the entry from the map
    INODE_MAP.remove(&current_pid);

    Ok(0)
}

#[kprobe]
pub fn vfs_unlink_probe(ctx: ProbeContext) -> u32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    // Get process information
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;

    // Get the dentry from the context
    let dentry: *const dentry = unsafe { ctx.arg(1) }.ok_or(1u32)?;
    let d_inode = unsafe { (*dentry).d_inode };
    let i_ino = unsafe { (*d_inode).i_ino };

    // Store the inode in the map
    INODE_MAP.insert(&current_pid, &i_ino, 0).map_err(|e| e as u32)?;
    
    // Log entry information with process details in JSON format
    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{}}}", current_pid, tgid);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - {\"pid\": %d, \"tgid\": %d}", current_pid, tgid);
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
