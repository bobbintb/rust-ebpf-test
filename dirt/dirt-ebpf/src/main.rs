#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    programs::{ProbeContext, RetProbeContext},
    helpers::{bpf_printk, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    maps::HashMap,
    cty::c_char,
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
// These are approximate and may need adjustment for different kernel versions

// Version 1 - Common layout
#[repr(C)]
struct dentry {
    d_flags: u32,
    d_seq: u32,
    d_hash: u32,
    d_parent: *const dentry,
    d_name: qstr,
    d_inode: *const inode,
    // Rest of fields omitted
}

// Version 2 - Alternative layout with different offsets
#[repr(C)]
struct dentry_alt {
    d_flags: u32,
    d_seq: u32,
    d_hash: u32,
    d_parent: *const dentry_alt,
    d_iname: [u8; 32], // Some kernels have inline name storage
    d_inode: *const inode,
    d_name: qstr,
    // Rest of fields omitted
}

#[repr(C)]
struct qstr {
    hash: u32,
    len: u32,
    name: *const c_char,
}

#[repr(C)]
struct inode {
    i_mode: u16,
    i_opflags: u16,
    i_uid: u32,
    i_gid: u32,
    i_flags: u32,
    // Various fields omitted
    i_ino: u64,
    // Rest of fields omitted
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
            
            // Ensure we only use printable ASCII characters for the preview
            for i in 0..preview_len {
                let c = file_info.filename[i];
                if is_valid_ascii(c) {
                    filename_preview[i] = c;
                } else {
                    // Replace non-printable characters with '?'
                    filename_preview[i] = 63; // ASCII for '?'
                }
            }
            
            // Format as JSON with proper escaping
            info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"return\":{},\"inode\":{},\"filename_len\":{},\"filename_preview\":[{},{},{},{},{},{},{},{}]}}", 
                  current_pid, tgid, ret_val, file_info.inode, file_info.filename_len,
                  filename_preview[0], filename_preview[1], filename_preview[2], filename_preview[3],
                  filename_preview[4], filename_preview[5], filename_preview[6], filename_preview[7]);
            
            // Extract debug information from filename if it starts with "debug_code_"
            let mut debug_code = 0;
            if file_info.filename_len >= 11 && 
               file_info.filename[0] == b'd' && 
               file_info.filename[1] == b'e' && 
               file_info.filename[2] == b'b' && 
               file_info.filename[3] == b'u' && 
               file_info.filename[4] == b'g' && 
               file_info.filename[5] == b'_' && 
               file_info.filename[6] == b'c' && 
               file_info.filename[7] == b'o' && 
               file_info.filename[8] == b'd' && 
               file_info.filename[9] == b'e' && 
               file_info.filename[10] == b'_' {
                // Extract debug code from the filename
                if file_info.filename_len >= 13 && file_info.filename[11] >= b'0' && file_info.filename[11] <= b'9' {
                    debug_code = (file_info.filename[11] - b'0') as u32;
                }
            }
            
            bpf_printk!(b"DIRT: vfs_unlink RETURN - {\"pid\": %d, \"tgid\": %d, \"ret\": %d, \"debug\": %d}", 
                       current_pid, tgid, ret_val, debug_code);
            
            // Clean up the map entry
            let _ = FILE_INFO_MAP.remove(&key);
        } else {
            // Log return information without file details
            info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_return\",\"pid\":{},\"tgid\":{},\"return\":{}}}", current_pid, tgid, ret_val);
            bpf_printk!(b"DIRT: vfs_unlink RETURN - {\"pid\": %d, \"tgid\": %d, \"ret\": %d, \"no_info\": 1}", 
                       current_pid, tgid, ret_val);
        }
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
    
    // Debug codes to identify where extraction fails
    let mut debug_code = 0;
    
    // Try to extract dentry from the second parameter (index 1)
    // vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    if let Some(dentry_ptr) = ctx.arg::<*const dentry>(1) {
        debug_code = 1; // Got dentry pointer
        
        if !dentry_ptr.is_null() {
            debug_code = 2; // Dentry pointer is not null
            
            // Store the raw pointer value for debugging
            file_info.inode = dentry_ptr as u64;
            
            unsafe {
                // Try to read the dentry structure (Version 1)
                if let Ok(dentry_data) = bpf_probe_read_kernel::<dentry>(dentry_ptr) {
                    debug_code = 3; // Successfully read dentry
                    
                    // Try to read inode number
                    if !dentry_data.d_inode.is_null() {
                        debug_code = 4; // d_inode is not null
                        
                        // Store the d_inode pointer value for debugging
                        file_info.inode = dentry_data.d_inode as u64;
                        
                        if let Ok(inode_data) = bpf_probe_read_kernel::<inode>(dentry_data.d_inode) {
                            debug_code = 5; // Successfully read inode
                            file_info.inode = inode_data.i_ino;
                        }
                    }
                    
                    // Try to read filename
                    if !dentry_data.d_name.name.is_null() {
                        debug_code = 6; // d_name.name is not null
                        
                        // Try a simpler approach first - just store the name pointer for debugging
                        if file_info.inode == 0 {
                            file_info.inode = dentry_data.d_name.name as u64;
                        }
                        
                        let mut temp_buf = [0u8; MAX_FILENAME_LEN];
                        if let Ok(result_slice) = bpf_probe_read_kernel_str_bytes(
                            dentry_data.d_name.name as *const u8, 
                            &mut temp_buf
                        ) {
                            debug_code = 7; // Successfully read filename
                            let len = core::cmp::min(result_slice.len(), MAX_FILENAME_LEN);
                            for i in 0..len {
                                file_info.filename[i] = result_slice[i];
                            }
                            file_info.filename_len = len as u32;
                        }
                    }
                }
                
                // If first approach failed, try alternative layout (Version 2)
                if file_info.filename_len == 0 && debug_code < 7 {
                    let dentry_alt_ptr = dentry_ptr as *const dentry_alt;
                    if let Ok(dentry_alt_data) = bpf_probe_read_kernel::<dentry_alt>(dentry_alt_ptr) {
                        debug_code = 13; // Successfully read alternative dentry
                        
                        // Try to read inode number
                        if !dentry_alt_data.d_inode.is_null() {
                            debug_code = 14; // d_inode is not null (alt)
                            
                            // Store the d_inode pointer value for debugging
                            file_info.inode = dentry_alt_data.d_inode as u64;
                            
                            if let Ok(inode_data) = bpf_probe_read_kernel::<inode>(dentry_alt_data.d_inode) {
                                debug_code = 15; // Successfully read inode (alt)
                                file_info.inode = inode_data.i_ino;
                            }
                        }
                        
                        // First try inline name (d_iname)
                        let mut has_inline_name = false;
                        for i in 0..dentry_alt_data.d_iname.len() {
                            let byte = dentry_alt_data.d_iname[i];
                            if byte == 0 {
                                // Found null terminator
                                has_inline_name = i > 0;
                                if has_inline_name {
                                    debug_code = 16; // Found inline name
                                    for j in 0..i {
                                        file_info.filename[j] = dentry_alt_data.d_iname[j];
                                    }
                                    file_info.filename_len = i as u32;
                                }
                                break;
                            }
                        }
                        
                        // If no inline name, try d_name
                        if !has_inline_name && !dentry_alt_data.d_name.name.is_null() {
                            debug_code = 17; // d_name.name is not null (alt)
                            
                            let mut temp_buf = [0u8; MAX_FILENAME_LEN];
                            if let Ok(result_slice) = bpf_probe_read_kernel_str_bytes(
                                dentry_alt_data.d_name.name as *const u8, 
                                &mut temp_buf
                            ) {
                                debug_code = 18; // Successfully read filename (alt)
                                let len = core::cmp::min(result_slice.len(), MAX_FILENAME_LEN);
                                for i in 0..len {
                                    file_info.filename[i] = result_slice[i];
                                }
                                file_info.filename_len = len as u32;
                            }
                        }
                    }
                }
                
                // Try direct memory access as a last resort
                if file_info.filename_len == 0 && debug_code < 18 {
                    // Try to find the filename by scanning memory at different offsets
                    let offsets = [24, 32, 40, 48, 56, 64, 72, 80];
                    
                    for &offset in &offsets {
                        let potential_str_ptr_addr = dentry_ptr as usize + offset;
                        if let Ok(potential_str_ptr) = bpf_probe_read_kernel::<*const u8>(potential_str_ptr_addr as *const *const u8) {
                            if !potential_str_ptr.is_null() {
                                let mut temp_buf = [0u8; MAX_FILENAME_LEN];
                                if let Ok(result_slice) = bpf_probe_read_kernel_str_bytes(potential_str_ptr, &mut temp_buf) {
                                    let len = result_slice.len();
                                    if len > 0 && len < MAX_FILENAME_LEN {
                                        // Check if it looks like a valid filename (simple validation)
                                        let mut valid = true;
                                        for i in 0..len {
                                            let byte = result_slice[i];
                                            if !(byte >= 32 && byte <= 126) && byte != b'.' && byte != b'_' && byte != b'-' {
                                                valid = false;
                                                break;
                                            }
                                        }
                                        
                                        if valid {
                                            debug_code = 20 + (offset as u32 / 8); // Encode offset in debug code
                                            for i in 0..len {
                                                file_info.filename[i] = result_slice[i];
                                            }
                                            file_info.filename_len = len as u32;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // If we didn't get any data, use fallback values with debug code
    if file_info.filename_len == 0 {
        // Use debug code in the inode field if we haven't set it yet
        if file_info.inode == 0 {
            file_info.inode = 900000000 + debug_code as u64; // Encode debug code in inode
        }
        
        let fallback_name = b"debug_code_";
        
        // Use a function to get the debug code string to avoid type mismatches
        let code_str = get_debug_code_str(debug_code);
        
        // Copy fallback prefix
        let prefix_len = core::cmp::min(fallback_name.len(), MAX_FILENAME_LEN);
        for i in 0..prefix_len {
            file_info.filename[i] = fallback_name[i];
        }
        
        // Copy debug code string
        let code_len = core::cmp::min(code_str.len(), MAX_FILENAME_LEN - prefix_len);
        for i in 0..code_len {
            file_info.filename[i + prefix_len] = code_str[i];
        }
        
        file_info.filename_len = (prefix_len + code_len) as u32;
    }
    
    // Ensure we have valid data even if something went wrong
    if file_info.inode == 0 {
        file_info.inode = 999999999; // Special value indicating unknown inode
    }
    
    // Ensure we have a valid filename length
    if file_info.filename_len == 0 {
        let unknown = b"unknown_file";
        let len = core::cmp::min(unknown.len(), MAX_FILENAME_LEN);
        for i in 0..len {
            file_info.filename[i] = unknown[i];
        }
        file_info.filename_len = len as u32;
    }
    
    // Store file info in map for the return probe
    let key = pid;
    let _ = FILE_INFO_MAP.insert(&key, &file_info, 0);
    
    // Log entry information with file details in JSON format
    let mut filename_preview = [0u8; 8];
    let preview_len = core::cmp::min(file_info.filename_len as usize, 8);
    
    // Ensure we only use printable ASCII characters for the preview
    for i in 0..preview_len {
        let c = file_info.filename[i];
        if is_valid_ascii(c) {
            filename_preview[i] = c;
        } else {
            // Replace non-printable characters with '?'
            filename_preview[i] = 63; // ASCII for '?'
        }
    }
    
    // Format as JSON with proper escaping
    info!(&ctx, "DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{},\"inode\":{},\"filename_len\":{},\"filename_preview\":[{},{},{},{},{},{},{},{}]}}",
          current_pid, tgid, file_info.inode, file_info.filename_len,
          filename_preview[0], filename_preview[1], filename_preview[2], filename_preview[3],
          filename_preview[4], filename_preview[5], filename_preview[6], filename_preview[7]);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink ENTRY - {\"pid\": %d, \"tgid\": %d, \"debug\": %d}", 
                   current_pid, tgid, debug_code);
    }
    
    Ok(0)
}

// Helper function to get debug code string
fn get_debug_code_str(code: u32) -> &'static [u8] {
    match code {
        0 => b"0_no_arg",
        1 => b"1_got_ptr",
        2 => b"2_ptr_ok",
        3 => b"3_dentry_ok",
        4 => b"4_d_inode_ok",
        5 => b"5_inode_ok",
        6 => b"6_name_ok",
        7 => b"7_read_ok",
        13 => b"13_alt_ok",
        14 => b"14_alt_inode",
        15 => b"15_alt_ino_ok",
        16 => b"16_inline_ok",
        17 => b"17_alt_name",
        18 => b"18_alt_read",
        20..=30 => b"20+_offset_ok",
        _ => b"unknown",
    }
}

// Helper function to check if a byte is a valid ASCII character
#[inline]
fn is_valid_ascii(byte: u8) -> bool {
    // Only include printable ASCII characters (32-126)
    byte >= 32 && byte <= 126
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
