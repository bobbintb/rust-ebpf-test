#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    programs::{ProbeContext, RetProbeContext},
    helpers::{bpf_printk, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    maps::HashMap,
    cty::{c_char, c_ulong},
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

// Simplified kernel structure representations for CO-RE
#[repr(C)]
struct dentry {
    _pad1: [u8; 32],  // Skip to d_name offset (approximate)
    d_name: qstr,
    _pad2: [u8; 16],  // Skip to d_inode offset (approximate)  
    d_inode: *const inode,
}

#[repr(C)]
struct qstr {
    _pad: [u8; 8],    // Skip hash and len
    name: *const c_char,
}

#[repr(C)]
struct inode {
    _pad: [u8; 40],   // Skip to i_ino offset (approximate)
    i_ino: c_ulong,
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
    
    // Try to extract dentry from the second parameter (index 1)
    // vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    if let Some(dentry_ptr) = ctx.arg::<*const dentry>(1) {
        if !dentry_ptr.is_null() {
            unsafe {
                // Try to read the dentry structure
                if let Ok(dentry_data) = bpf_probe_read_kernel(dentry_ptr) {
                    // Try to read inode number
                    if !dentry_data.d_inode.is_null() {
                        if let Ok(inode_data) = bpf_probe_read_kernel(dentry_data.d_inode) {
                            file_info.inode = inode_data.i_ino as u64;
                        }
                    }
                    
                    // Try to read filename
                    if !dentry_data.d_name.name.is_null() {
                        let mut temp_buf = [0u8; MAX_FILENAME_LEN];
                        if let Ok(result_slice) = bpf_probe_read_kernel_str_bytes(
                            dentry_data.d_name.name as *const u8, 
                            &mut temp_buf
                        ) {
                            let len = core::cmp::min(result_slice.len(), MAX_FILENAME_LEN);
                            for i in 0..len {
                                file_info.filename[i] = result_slice[i];
                            }
                            file_info.filename_len = len as u32;
                        }
                    }
                }
            }
        }
    }
    
    // If we didn't get any data, use fallback values
    if file_info.inode == 0 && file_info.filename_len == 0 {
        file_info.inode = 999999999; // Fallback inode
        let fallback_name = b"unknown_file";
        let copy_len = core::cmp::min(fallback_name.len(), MAX_FILENAME_LEN);
        for i in 0..copy_len {
            file_info.filename[i] = fallback_name[i];
        }
        file_info.filename_len = copy_len as u32;
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
