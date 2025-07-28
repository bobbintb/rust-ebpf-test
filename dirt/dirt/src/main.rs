use aya::programs::{FEntry, FExit};
use aya::Btf;
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
    info!("You'll see detailed process information for each deletion");

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
    info!("DIRT: Each deletion will show structured JSON output with event type, timestamp, process info, and return values");
    info!("DIRT: Try deleting a file to see detailed output!");
    info!("DIRT: Example: 'touch /tmp/test && rm /tmp/test' in another terminal");
    info!("DIRT: You can use 'ps -p <PID>' to see which process is deleting files");
    
    let ctrl_c = signal::ctrl_c();
    println!("DIRT: Waiting for Ctrl-C to stop monitoring...");
    ctrl_c.await?;
    println!("DIRT: Shutting down file deletion monitor...");

    Ok(())
}
