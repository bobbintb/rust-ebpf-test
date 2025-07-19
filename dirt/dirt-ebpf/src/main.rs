#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    programs::{ProbeContext, RetProbeContext},
    helpers::{bpf_printk, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
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
    // dentry is the second parameter (index 1)
    if let Some(dentry_ptr) = ctx.arg::<usize>(1) {
        unsafe {
            // Try to extract inode number from dentry->d_inode->i_ino
            // Note: These offsets may vary by kernel version, trying common offsets
            
            // Try different common offsets for d_inode in struct dentry
            let d_inode_offsets = [48, 56, 40]; // Common offsets across kernel versions
            
            for &d_inode_offset in &d_inode_offsets {
                let inode_ptr_addr = dentry_ptr + d_inode_offset;
                
                if let Ok(inode_ptr) = bpf_probe_read_kernel::<usize>(inode_ptr_addr as *const usize) {
                    if inode_ptr != 0 {
                        // Try different common offsets for i_ino in struct inode
                        let i_ino_offsets = [40, 32, 48]; // Common offsets across kernel versions
                        
                        for &i_ino_offset in &i_ino_offsets {
                            let ino_addr = inode_ptr + i_ino_offset;
                            
                            if let Ok(inode_num) = bpf_probe_read_kernel::<u64>(ino_addr as *const u64) {
                                if inode_num != 0 && inode_num < 0xFFFFFFFFFFFF { // Sanity check
                                    file_info.inode = inode_num;
                                    break;
                                }
                            }
                        }
                        if file_info.inode != 0 {
                            break;
                        }
                    }
                }
            }
            
            // Try to extract filename from dentry->d_name.name
            // d_name offset may vary, trying common offsets
            let d_name_offsets = [32, 40, 24]; // Common offsets for d_name in struct dentry
            
            for &d_name_offset in &d_name_offsets {
                let name_ptr_addr = dentry_ptr + d_name_offset;
                
                if let Ok(name_ptr) = bpf_probe_read_kernel::<usize>(name_ptr_addr as *const usize) {
                    if name_ptr != 0 {
                        // Read filename characters one by one
                        let mut len = 0;
                        let mut valid_filename = true;
                        
                        for i in 0..core::cmp::min(MAX_FILENAME_LEN, 64) { // Limit to reasonable size
                            let char_addr = name_ptr + i;
                            if let Ok(byte) = bpf_probe_read_kernel::<u8>(char_addr as *const u8) {
                                if byte == 0 {
                                    break;
                                }
                                // Basic validation - printable ASCII characters
                                if byte < 32 || byte > 126 {
                                    if byte != b'.' && byte != b'-' && byte != b'_' {
                                        valid_filename = false;
                                        break;
                                    }
                                }
                                file_info.filename[i] = byte;
                                len += 1;
                            } else {
                                break;
                            }
                        }
                        
                        if valid_filename && len > 0 {
                            file_info.filename_len = len as u32;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    // Store file info in map for the return probe
    let key = pid;
    let _ = FILE_INFO_MAP.insert(&key, &file_info, 0);
    
    // Log entry information with file details in JSON format
    // Include first 8 characters of filename for debugging (as hex values)
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
