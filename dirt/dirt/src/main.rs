use anyhow::Context;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::KProbe,
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use dirt_common::UnlinkEvent;
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
        AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = events.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(mem::size_of::<UnlinkEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const UnlinkEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    println!(
                        "{{\"pid\":{},\"tgid\":{},\"inode\":{}}}",
                        event.pid, event.tgid, event.inode
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await.expect("failed to listen for event");
    info!("Exiting...");

    Ok(())
}
