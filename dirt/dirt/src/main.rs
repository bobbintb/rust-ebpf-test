use aya::programs::KProbe;
use log::{info, warn, debug};
use tokio::signal;
use aya_log::EbpfLogger;
use std::os::unix::fs::MetadataExt;
use serde::Serialize;
use serde_json;

#[derive(Serialize)]
struct FileDeleteEvent {
    event: String,
    pid: u32,
    tgid: u32,
    inode: u64,
    ret: i64,
}

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

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    let dirt_program: &mut KProbe = bpf.program_mut("dirt").unwrap().try_into()?;
    dirt_program.load()?;
    dirt_program.attach("vfs_unlink", 0)?;

    let vfs_unlink_program: &mut KProbe = bpf.program_mut("vfs_unlink_probe").unwrap().try_into()?;
    vfs_unlink_program.load()?;
    vfs_unlink_program.attach("vfs_unlink", 0)?;

    info!("Monitoring file deletions...");

    let mut logs = EbpfLogger::logs(&bpf)?;
    let mut tasks = Vec::new();
    for i in 0..logs.len() {
        let log = logs.remove(0);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match log.read(&mut buf).await {
                    Ok(len) => {
                        let msg = String::from_utf8_lossy(&buf[..len]);
                        if let Some(json_str) = msg.strip_prefix("DIRT_JSON: ") {
                            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(json_str) {
                                if let Some(path_bytes) = json.get("path_bytes").and_then(|p| p.as_array()) {
                                    let path_bytes: Vec<u8> = path_bytes.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
                                    if let Ok(path_str) = String::from_utf8(path_bytes) {
                                        if let Ok(metadata) = std::fs::metadata(&path_str) {
                                            json["inode"] = serde_json::Value::from(metadata.ino());
                                        }
                                        json["path"] = serde_json::Value::from(path_str);
                                    }
                                }
                                json.remove("path_bytes");
                                if let Ok(pretty_json) = serde_json::to_string_pretty(&json) {
                                    println!("{}", pretty_json);
                                }
                            }
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
