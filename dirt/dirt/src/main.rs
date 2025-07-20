use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::KProbe,
    util::online_cpus,
    Ebpf,
};
use bytes::Bytes;
use dirt_common::UnlinkEvent;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::{signal, task};

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
    info!("Monitoring file deletions via vfs_unlink system calls");
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
    
    // Attach the existing kretprobe
    info!("DIRT: Loading and attaching kretprobe 'dirt'...");
    let dirt_program: &mut KProbe = ebpf.program_mut("dirt").unwrap().try_into()?;
    dirt_program.load()?;
    dirt_program.attach("vfs_unlink", 0)?;
    info!("DIRT: kretprobe 'dirt' attached successfully to vfs_unlink");
    
    // Attach the new kprobe for vfs_unlink
    info!("DIRT: Loading and attaching kprobe 'vfs_unlink_probe'...");
    let vfs_unlink_program: &mut KProbe = ebpf.program_mut("vfs_unlink_probe").unwrap().try_into()?;
    vfs_unlink_program.load()?;
    vfs_unlink_program.attach("vfs_unlink", 0)?;
    info!("DIRT: kprobe 'vfs_unlink_probe' attached successfully to vfs_unlink");

    let mut events =
        AsyncPerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = events.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| Bytes::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const UnlinkEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    info!("DIRT_JSON: {{\"event\":\"vfs_unlink_entry\",\"pid\":{},\"tgid\":{},\"inode\":{}}}", event.pid, event.tgid, event.inode);
                }
            }
        });
    }


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
