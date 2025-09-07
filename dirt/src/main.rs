use aya::{
    include_bytes_aligned,
    maps::{Array, RingBuf},
    programs::{FEntry, Lsm},
    Btf, Ebpf,
};
use dirt_common::*;
use serde::Serialize;
use std::{fs, os::unix::fs::MetadataExt, ptr};

#[derive(Serialize)]
struct FileEventJson {
    event_type: EventType,
    target_dev: u32,
    ret_val: i32,
    src_path: String,
    src_file: String,
    trgt_path: String,
    trgt_file: String,
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

    let program: &mut Lsm = bpf.program_mut("lsm_path_rename").unwrap().try_into()?;
    program.load("path_rename", &btf)?;
    program.attach()?;

    let program: &mut FEntry = bpf
        .program_mut("fentry_file_update_time")
        .unwrap()
        .try_into()?;
    program.load("file_update_time", &btf)?;
    program.attach()?;

    let mut ring_buf =
        RingBuf::try_from(bpf.map_mut("EVENTS").ok_or(anyhow::anyhow!("EVENTS map not found"))?)?;

    tokio::spawn(async move {
        loop {
            while let Some(data) = ring_buf.next() {
                let ptr = data.as_ptr() as *const FileEvent;
                let data = unsafe { ptr::read_unaligned(ptr) };

                let first_null_src_path = data
                    .src_path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.src_path.len());
                let src_path =
                    String::from_utf8_lossy(&data.src_path[..first_null_src_path]).to_string();

                let first_null_src_file = data
                    .src_file
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.src_file.len());
                let src_file =
                    String::from_utf8_lossy(&data.src_file[..first_null_src_file]).to_string();

                let first_null_trgt_path = data
                    .trgt_path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.trgt_path.len());
                let trgt_path =
                    String::from_utf8_lossy(&data.trgt_path[..first_null_trgt_path]).to_string();

                let first_null_trgt_file = data
                    .trgt_file
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.trgt_file.len());
                let trgt_file =
                    String::from_utf8_lossy(&data.trgt_file[..first_null_trgt_file]).to_string();

                let event_json = FileEventJson {
                    event_type: data.event_type,
                    target_dev: data.target_dev,
                    ret_val: data.ret_val,
                    src_path,
                    src_file,
                    trgt_path,
                    trgt_file,
                };

                if let Ok(json_str) = serde_json::to_string(&event_json) {
                    println!("{}", json_str);
                } else {
                    eprintln!("Error serializing event to JSON");
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
