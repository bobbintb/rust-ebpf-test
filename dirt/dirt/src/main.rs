use aya::programs::{FEntry, FExit};
use aya::maps::Array;
use aya::Btf;
use std::os::unix::fs::MetadataExt;
use std::fs;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set default log level to Info if RUST_LOG is not set
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .format_module_path(false)
        .format_target(false)
        .init();

    info!("=== DIRT eBPF File Deletion Monitor Starting ===");
    info!("Monitoring file deletions via do_unlinkat system calls");
    info!("Target filesystem: /mnt/user/");

    // Get the dev_t from /mnt/user/
    let target_path = "/mnt/user/";
    let metadata = fs::metadata(target_path).map_err(|e| {
        anyhow::anyhow!("Failed to get metadata for {}: {}. Make sure the path exists and is accessible.", target_path, e)
    })?;
    
    let target_dev = metadata.dev() as u32;
    info!("DIRT: Target device ID: {} (0x{:x})", target_dev, target_dev);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("DIRT: Failed to remove limit on locked memory, ret: {ret}");
    } else {
        debug!("DIRT: Successfully set memlock limit to infinity");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    info!("DIRT: Loading eBPF program...");
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;
    
    info!("DIRT: Initializing eBPF logger...");
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("DIRT: Failed to initialize eBPF logger: {e}");
    } else {
        info!("DIRT: eBPF logger initialized successfully");
    }
    
    // Get the TARGET_DEV map and set the target device ID
    info!("DIRT: Setting target device ID in eBPF map...");
    let mut target_dev_map: Array<_, u32> = Array::try_from(ebpf.map_mut("TARGET_DEV").unwrap())?;
    target_dev_map.set(0, target_dev, 0)?;
    info!("DIRT: Target device ID {} set in eBPF map successfully", target_dev);
    
    let btf = Btf::from_sys_fs()?;
    // Attach the fexit probe
    info!("DIRT: Loading and attaching fexit 'do_unlinkat_exit'...");
    let do_unlinkat_exit_program: &mut FExit = ebpf.program_mut("do_unlinkat_exit").unwrap().try_into()?;
    do_unlinkat_exit_program.load("do_unlinkat", &btf)?;
    do_unlinkat_exit_program.attach()?;
    info!("DIRT: fexit 'do_unlinkat_exit' attached successfully to do_unlinkat");
    
    // Attach the fentry probe
    info!("DIRT: Loading and attaching fentry 'do_unlinkat_entry'...");
    let do_unlinkat_entry_program: &mut FEntry = ebpf.program_mut("do_unlinkat_entry").unwrap().try_into()?;
    do_unlinkat_entry_program.load("do_unlinkat", &btf)?;
    do_unlinkat_entry_program.attach()?;
    info!("DIRT: fentry 'do_unlinkat_entry' attached successfully to do_unlinkat");

    info!("DIRT: === Monitoring Active ===");
    info!("DIRT: Both probes are now active and monitoring file deletions");
    info!("DIRT: Target device filter: {} ({})", target_dev, target_path);
    info!("DIRT: Each deletion will show structured JSON output with event type, timestamp, process info, and return values");
    info!("DIRT: Try deleting a file in {} to see detailed output!", target_path);
    info!("DIRT: Example: 'touch /mnt/user/test && rm /mnt/user/test' in another terminal");
    info!("DIRT: You can use 'ps -p <PID>' to see which process is deleting files");
    
    let ctrl_c = signal::ctrl_c();
    println!("DIRT: Waiting for Ctrl-C to stop monitoring...");
    ctrl_c.await?;
    println!("DIRT: Shutting down file deletion monitor...");

    Ok(())
}
