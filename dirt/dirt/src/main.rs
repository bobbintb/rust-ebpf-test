use aya::{
    include_bytes_aligned,
    maps::perf::PerfEventArray,
    programs::FEntry,
    util::online_cpus,
    Ebpf, Btf,
};
use bytes::BytesMut;
use dirt_common::{UnlinkEvent};
use serde::Serialize;
use std::{ptr};

#[derive(Serialize)]
struct UnlinkEventJson {
    event_type: String,
    pid: u32,
    tgid: u32,
    filename: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;

    let program: &mut FEntry =
        bpf.program_mut("vfs_unlink").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
    program.load("vfs_unlink", &btf)?;
    program.attach()?;

    let mut events =
        PerfEventArray::try_from(bpf.map_mut("EVENTS").ok_or(anyhow::anyhow!("EVENTS map not found"))?)?;

    for cpu_id in online_cpus().map_err(|(msg, err)| anyhow::anyhow!("{}: {}", msg, err))? {
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).unwrap();
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
                        event_type: format!("{:?}", data.event_type),
                        pid: data.pid,
                        tgid: data.tgid,
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
