use anyhow::Context;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::KProbe,
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use dirt_common::FileDeleteEvent;
use std::mem;
use tokio::{signal, task};
use log::{info, warn};

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
        warn!("Failed to remove limit on locked memory, ret: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/dirt"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/dirt"
    ))?;

    let program: &mut KProbe = bpf.program_mut("dirt").unwrap().try_into()?;
    program.load()?;
    program.attach("vfs_unlink", 0)?;

    let mut events =
        aya::maps::RingBuf::try_from(bpf.map_mut("EVENTS")?)?;

    task::spawn(async move {
        loop {
            let mut buf = [0u8; mem::size_of::<FileDeleteEvent>()];
            events.read(&mut buf).await.unwrap();
            let event = unsafe { &*(buf.as_ptr() as *const FileDeleteEvent) };
            let filename = String::from_utf8_lossy(&event.filename);
            let comm = String::from_utf8_lossy(&event.comm);
            println!(
                "{{\"pid\":{},\"uid\":{},\"filename\":\"{}\",\"comm\":\"{}\"}}",
                event.pid, event.uid, filename.trim_end_matches(char::from(0)), comm.trim_end_matches(char::from(0))
            );
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await.expect("failed to listen for event");
    info!("Exiting...");

    Ok(())
}
