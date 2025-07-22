use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::KProbe,
    util::online_cpus,
    Bpf,
};
use bytes::Bytes;
use dirt_common::FileDeleteEvent;
use log::{info, warn};
use std::mem;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting DIRT eBPF File Deletion Monitor");

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        warn!("Failed to remove limit on locked memory");
    }

    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;

    let program: &mut KProbe = bpf.program_mut("dirt").unwrap().try_into()?;
    program.load()?;
    program.attach("vfs_unlink", 0)?;

    let vfs_unlink_program: &mut KProbe = bpf.program_mut("vfs_unlink_probe").unwrap().try_into()?;
    vfs_unlink_program.load()?;
    vfs_unlink_program.attach("vfs_unlink", 0)?;

    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = events.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| Bytes::with_capacity(mem::size_of::<FileDeleteEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let event = unsafe { mem::transmute::<_, FileDeleteEvent>(*buffers[i]) };
                    let json = serde_json::to_string(&event).unwrap();
                    println!("{}", json);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
