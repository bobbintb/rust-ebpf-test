use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, Array},
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use dirt_common::UnlinkEvent;
use std::{fs, os::unix::fs::MetadataExt, ptr};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bpf = Box::leak(Box::new(Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?));

    let target_path = "/tmp/";  // Change this to a path that exists on your system
    let metadata = fs::metadata(target_path)?;
    let target_dev = metadata.dev() as u32;

    let mut target_dev_map: Array<_, u32> =
        Array::try_from(bpf.map_mut("TARGET_DEV").ok_or(anyhow::anyhow!("TARGET_DEV map not found"))?)?;
    target_dev_map.set(0, target_dev, 0)?;

    let unlink_program: &mut TracePoint = bpf.program_mut("sys_exit_unlink").unwrap().try_into()?;
    unlink_program.load()?;
    unlink_program.attach("syscalls", "sys_exit_unlink")?;

    let unlinkat_program: &mut TracePoint = bpf.program_mut("sys_exit_unlinkat").unwrap().try_into()?;
    unlinkat_program.load()?;
    unlinkat_program.attach("syscalls", "sys_exit_unlinkat")?;

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
                    println!("{}", serde_json::to_string(&data).unwrap());
                }
            }
        });
    }

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
