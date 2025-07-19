#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    programs::{ProbeContext, RetProbeContext},
    helpers::{bpf_printk, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    maps::HashMap,
};
use aya_log_ebpf::info;

const MAX_FILENAME_LEN: usize = 256;

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
    
    let mut file_info = FileInfo {
        filename: [0u8; MAX_FILENAME_LEN],
        filename_len: 0,
        inode: 0,
    };
    
    // Extract file information from vfs_unlink parameters
    // vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    // Try different parameter indices as they might vary
    
    let mut extraction_success = false;
    
    // Try parameter indices 0, 1, 2 to find the dentry
    for param_idx in 0..3 {
        if let Some(dentry_ptr) = ctx.arg::<usize>(param_idx) {
            if dentry_ptr != 0 && dentry_ptr > 0xFFFF000000000000 { // Basic kernel address validation
                unsafe {
                    // Try to extract inode number with multiple offset combinations
                    let d_inode_offsets = [48, 56, 40, 32, 64]; // Extended list of common offsets
                    
                    for &d_inode_offset in &d_inode_offsets {
                        if let Ok(inode_ptr) = bpf_probe_read_kernel::<usize>((dentry_ptr + d_inode_offset) as *const usize) {
                            if inode_ptr != 0 && inode_ptr > 0xFFFF000000000000 {
                                let i_ino_offsets = [40, 32, 48, 24, 56]; // Extended list
                                
                                for &i_ino_offset in &i_ino_offsets {
                                    if let Ok(inode_num) = bpf_probe_read_kernel::<u64>((inode_ptr + i_ino_offset) as *const u64) {
                                        if inode_num > 0 && inode_num < 0x1000000000000 { // Reasonable inode range
                                            file_info.inode = inode_num;
                                            extraction_success = true;
                                            break;
                                        }
                                    }
                                }
                                if extraction_success { break; }
                            }
                        }
                    }
                    
                    // Try to extract filename with multiple approaches
                    if !extraction_success {
                        // Method 1: Try direct d_name extraction
                        let d_name_offsets = [32, 40, 24, 48]; // Common d_name offsets
                        
                        for &d_name_offset in &d_name_offsets {
                            // Try reading d_name.name directly
                            if let Ok(name_ptr) = bpf_probe_read_kernel::<usize>((dentry_ptr + d_name_offset) as *const usize) {
                                if name_ptr != 0 && name_ptr > 0xFFFF000000000000 {
                                    // Method 1a: Use bpf_probe_read_kernel_str_bytes
                                    let mut temp_buf = [0u8; 64];
                                    if let Ok(result_slice) = bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, &mut temp_buf) {
                                        let len = result_slice.len();
                                        if len > 0 && len <= 64 {
                                            let copy_len = core::cmp::min(len, MAX_FILENAME_LEN);
                                            for i in 0..copy_len {
                                                file_info.filename[i] = result_slice[i];
                                            }
                                            file_info.filename_len = copy_len as u32;
                                            extraction_success = true;
                                            break;
                                        }
                                    }
                                    
                                    // Method 1b: Manual byte-by-byte reading (fallback)
                                    if !extraction_success {
                                        let mut len = 0;
                                        let mut valid = true;
                                        
                                        for i in 0..core::cmp::min(32, MAX_FILENAME_LEN) {
                                            if let Ok(byte) = bpf_probe_read_kernel::<u8>((name_ptr + i) as *const u8) {
                                                if byte == 0 { break; }
                                                if byte >= 32 && byte <= 126 { // Printable ASCII
                                                    file_info.filename[i] = byte;
                                                    len += 1;
                                                } else if byte == b'.' || byte == b'-' || byte == b'_' {
                                                    file_info.filename[i] = byte;
                                                    len += 1;
                                                } else {
                                                    valid = false;
                                                    break;
                                                }
                                            } else {
                                                break;
                                            }
                                        }
                                        
                                        if valid && len > 0 {
                                            file_info.filename_len = len as u32;
                                            extraction_success = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if extraction_success { break; }
                }
            }
        }
    }
    
    // If extraction failed, add debug information
    if !extraction_success {
        file_info.inode = 0xDEADBEEF; // Debug marker
        let debug_msg = b"EXTRACT_FAIL";
        let debug_len = core::cmp::min(debug_msg.len(), MAX_FILENAME_LEN);
        for i in 0..debug_len {
            file_info.filename[i] = debug_msg[i];
        }
        file_info.filename_len = debug_len as u32;
    }
    
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
