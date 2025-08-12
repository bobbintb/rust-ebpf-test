use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, Array},
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use dirt_common::{EventType, UnlinkEvent};
use serde::Serialize;
use std::{fs, os::unix::fs::MetadataExt, ptr};

#[derive(Serialize)]
struct UnlinkEventJson {
    event_type: EventType,
    pid: u32,
    tgid: u32,
    target_dev: u32,
    ret_val: i32,
    filename: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bpf = Box::leak(Box::new(Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?));

    let target_path = "/tmp/";
    let metadata = fs::metadata(target_path)?;
    let target_dev = metadata.dev() as u32;

    let mut target_dev_map: Array<_, u32> =
        Array::try_from(bpf.map_mut("TARGET_DEV").ok_or(anyhow::anyhow!("TARGET_DEV map not found"))?)?;
    target_dev_map.set(0, target_dev, 0)?;

    // Load and attach enter tracepoints
    let unlink_enter_program: &mut TracePoint =
        bpf.program_mut("sys_enter_unlink").unwrap().try_into()?;
    unlink_enter_program.load()?;
    unlink_enter_program.attach("syscalls", "sys_enter_unlink")?;

    let unlinkat_enter_program: &mut TracePoint =
        bpf.program_mut("sys_enter_unlinkat").unwrap().try_into()?;
    unlinkat_enter_program.load()?;
    unlinkat_enter_program.attach("syscalls", "sys_enter_unlinkat")?;

    // Load and attach exit tracepoints
    let unlink_exit_program: &mut TracePoint =
        bpf.program_mut("sys_exit_unlink").unwrap().try_into()?;
    unlink_exit_program.load()?;
    unlink_exit_program.attach("syscalls", "sys_exit_unlink")?;

    let unlinkat_exit_program: &mut TracePoint =
        bpf.program_mut("sys_exit_unlinkat").unwrap().try_into()?;
    unlinkat_exit_program.load()?;
    unlinkat_exit_program.attach("syscalls", "sys_exit_unlinkat")?;

    let mut events =
        AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").ok_or(anyhow::anyhow!("EVENTS map not found"))?)?;

    for cpu_id in online_cpus().map_err(|(msg, err)| anyhow::anyhow!("{}: {}", msg, err))? {
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let ptr = buffers[i].as_ptr() as *const UnlinkEvent;
                    let data = unsafe { ptr::read_unaligned(ptr) };

                    let first_null = data
                        .filename
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(data.filename.len());
                    let filename = String::from_utf8_lossy(&data.filename[..first_null]).to_string();

                    let event_json = UnlinkEventJson {
                        event_type: data.event_type,
                        pid: data.pid,
                        tgid: data.tgid,
                        target_dev: data.target_dev,
                        ret_val: data.ret_val,
                        filename,
                    };

                    println!("{}", serde_json::to_string(&event_json).unwrap());
                }
            }
        });
    }

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
