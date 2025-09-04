use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, Array},
    programs::Lsm,
    util::online_cpus,
    Btf, Ebpf,
};
use bytes::BytesMut;
use dirt_common::{EventType, FileEvent};
use serde::Serialize;
use std::{fs, os::unix::fs::MetadataExt, ptr};

#[derive(Serialize)]
struct FileEventJson {
    event_type: EventType,
    target_dev: u32,
    ret_val: i32,
    pathname: String,
    filename: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bpf = Box::leak(Box::new(Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?));

    let target_path = "/mnt/user/";
    let metadata = fs::metadata(target_path)?;
    let target_dev = metadata.dev() as u32;

    let mut target_dev_map: Array<_, u32> =
        Array::try_from(bpf.map_mut("TARGET_DEV").ok_or(anyhow::anyhow!("TARGET_DEV map not found"))?)?;
    target_dev_map.set(0, target_dev, 0)?;

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("lsm_path_unlink").unwrap().try_into()?;
    program.load("path_unlink", &btf)?;
    program.attach()?;

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
                    let ptr = buffers[i].as_ptr() as *const FileEvent;
                    let data = unsafe { ptr::read_unaligned(ptr) };

                    let first_null_filename = data
                        .pathname
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(data.filename.len());
                    let pathname = String::from_utf8_lossy(&data.pathname[..first_null_filename]).to_string();

                    let first_null_dentry = data
                        .filename
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(data.filename.len());
                    let filename = String::from_utf8_lossy(&data.filename[..first_null_dentry]).to_string();

                    let event_json = FileEventJson {
                        event_type: data.event_type,
                        target_dev: data.target_dev,
                        ret_val: data.ret_val,
                        pathname,
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
