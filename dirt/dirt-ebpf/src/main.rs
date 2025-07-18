#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}, helpers::bpf_printk};
use aya_log_ebpf::info;

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
    
    // Log return information
    info!(&ctx, "DIRT: vfs_unlink RETURN - Return: {}", ret_val);
    
    unsafe {
        bpf_printk!(b"DIRT: vfs_unlink RETURN - Return: %d", ret_val);
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
    // Get the dentry parameter (second parameter of vfs_unlink)
    // vfs_unlink(struct inode *dir, struct dentry *dentry)
    let dentry = ctx.arg::<u64>(1);
    
    // Get the filename from the dentry
    if let Some(dentry_ptr) = dentry {
        let mut filename: [u8; 64] = [0; 64];
        let filename_result = unsafe { 
            aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes((dentry_ptr + 32) as *const u8, &mut filename) 
        };
        
        match filename_result {
            Ok(len) if len > 0 => {
                // Convert to string for logging
                let name_str = core::str::from_utf8(&filename[..len]).unwrap_or("unknown");
                info!(&ctx, "DIRT: vfs_unlink ENTRY - File: {}", name_str);
                
                unsafe {
                    bpf_printk!(b"DIRT: vfs_unlink ENTRY - File: %s", filename.as_ptr());
                }
            }
            _ => {
                info!(&ctx, "DIRT: vfs_unlink ENTRY - File: (could not read filename)");
                unsafe {
                    bpf_printk!(b"DIRT: vfs_unlink ENTRY - File: (could not read filename)");
                }
            }
        }
    } else {
        info!(&ctx, "DIRT: vfs_unlink ENTRY - File: (no dentry)");
        unsafe {
            bpf_printk!(b"DIRT: vfs_unlink ENTRY - File: (no dentry)");
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
