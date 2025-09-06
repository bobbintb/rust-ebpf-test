use aya::{
    include_bytes_aligned,
    maps::{Array, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use dirt_common::*;
use std::{fs, os::unix::fs::MetadataExt, ptr};

fn bytes_to_string(bytes: &[u8]) -> String {
    let first_null = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..first_null]).to_string()
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

    let mut ring_buf =
        RingBuf::try_from(bpf.map_mut("EVENTS").ok_or(anyhow::anyhow!("EVENTS map not found"))?)?;

    tokio::spawn(async move {
        loop {
            while let Some(data) = ring_buf.next() {
                let ptr = data.as_ptr() as *const FileEvent;
                let data = unsafe { ptr::read_unaligned(ptr) };

                let src_path = bytes_to_string(&data.src_path);
                let src_file = bytes_to_string(&data.src_file);

                match data.event_type {
                    EventType::Unlink => {
                        println!("unlink {},{}", src_path, src_file);
                    }
                    EventType::Create => {
                        println!("create {},{}", src_path, src_file);
                    }
                    EventType::Rename => {
                        let trgt_path = bytes_to_string(&data.trgt_path);
                        let trgt_file = bytes_to_string(&data.trgt_file);
                        println!(
                            "rename {},{},{},{}",
                            src_path, src_file, trgt_path, trgt_file
                        );
                    }
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
