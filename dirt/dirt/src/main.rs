use aya::programs::KProbe;
use log::{info, warn, debug};
use tokio::signal;
use aya_log::EbpfLogger;
use futures::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .format_timestamp_millis()
        .format_module_path(false)
        .format_target(false)
        .init();

    info!("=== DIRT eBPF File Deletion Monitor Starting ===");

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        debug!("Failed to remove limit on locked memory");
    }

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;

    let mut logger = EbpfLogger::init(&mut bpf)?;

    let dirt_program: &mut KProbe = bpf.program_mut("dirt").unwrap().try_into()?;
    dirt_program.load()?;
    dirt_program.attach("vfs_unlink", 0)?;

    let vfs_unlink_program: &mut KProbe = bpf.program_mut("vfs_unlink_probe").unwrap().try_into()?;
    vfs_unlink_program.load()?;
    vfs_unlink_program.attach("vfs_unlink", 0)?;

    info!("Monitoring file deletions...");

    let mut tasks = Vec::new();
    for i in 0..logger.len() {
        let log = logger.next().await.unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match log.read(&mut buf).await {
                    Ok(len) => {
                        let msg = String::from_utf8_lossy(&buf[..len]);
                        if let Some(json_str) = msg.strip_prefix("DIRT_JSON: ") {
                            println!("{}", json_str);
                        }
                    }
                    Err(e) => {
                        warn!("Error reading from eBPF log: {}", e);
                    }
                }
            }
        });
        tasks.push(task);
    }


    signal::ctrl_c().await?;
    info!("Shutting down...");

    for task in tasks {
        task.abort();
    }

    Ok(())
}
