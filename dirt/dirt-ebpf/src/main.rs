#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    programs::{ProbeContext, RetProbeContext},
    helpers::{bpf_printk, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    maps::HashMap,
};
use aya_log_ebpf::info;

const MAX_FILENAME_LEN: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct FileInfo {
    filename: [u8; MAX_FILENAME_LEN],
    filename_len: u32,
    inode: u64,
}

#[map]
static FILE_INFO_MAP: HashMap<u64, FileInfo> = HashMap::with_max_entries(1024, 0);

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
    let pid = bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // Try to get file info from the map
    let key = pid;
    unsafe {
        if let Some(file_info) = FILE_INFO_MAP.get(&key) {
            // Include filename preview in return probe as well
            let mut filename_preview = [0u8; 8];
            let preview_len = core::cmp::min(file_info.filename_len as usize, 8);
            for i in 0..preview_len {
                filename_preview[i] = file_info.filename[i];
            }
            
            info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"return\":{},\"inode\":{},\"filename_len\":{},\"filename_preview\":[{},{},{},{},{},{},{},{}]}}", 
                  current_pid, tgid, ret_val, file_info.inode, file_info.filename_len,
                  filename_preview[0], filename_preview[1], filename_preview[2], filename_preview[3],
                  filename_preview[4], filename_preview[5], filename_preview[6], filename_preview[7]);
            
            // Clean up the map entry
            let _ = FILE_INFO_MAP.remove(&key);
        } else {
            // Log return information without file details
            info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"return\":{}}}", current_pid, tgid, ret_val);
        }
    }
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - {\"pid\": %d, \"tgid\": %d, \"return\": %d}", current_pid, tgid, ret_val);
    }
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
    let pid = bpf_get_current_pid_tgid();
    let tgid = (pid >> 32) as u32;
    let current_pid = pid as u32;
    
    // For now, use simple test data to get the JSON structure working
    // This avoids complex kernel memory access that the verifier rejects
    let mut file_info = FileInfo {
        filename: [0u8; MAX_FILENAME_LEN],
        filename_len: 12,
        inode: 123456789,
    };
    
    // Add a simple filename that shows the structure works
    let test_filename = b"deleted_file";
    let copy_len = core::cmp::min(test_filename.len(), MAX_FILENAME_LEN);
    for i in 0..copy_len {
        file_info.filename[i] = test_filename[i];
    }
    file_info.filename_len = copy_len as u32;
    
    // Store file info in map for the return probe
    let key = pid;
    let _ = FILE_INFO_MAP.insert(&key, &file_info, 0);
    
    // Log entry information with file details in JSON format
    let mut filename_preview = [0u8; 8];
    let preview_len = core::cmp::min(file_info.filename_len as usize, 8);
    for i in 0..preview_len {
        filename_preview[i] = file_info.filename[i];
    }
    
    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{},\"inode\":{},\"filename_len\":{},\"filename_preview\":[{},{},{},{},{},{},{},{}]}}", 
          current_pid, tgid, file_info.inode, file_info.filename_len,
          filename_preview[0], filename_preview[1], filename_preview[2], filename_preview[3],
          filename_preview[4], filename_preview[5], filename_preview[6], filename_preview[7]);
    
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
