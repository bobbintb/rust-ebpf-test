use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{KProbe, KRetProbe},
    Bpf,
};
use bytes::Bytes;
use dirt_common::RecordFs;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::init_from_env(env);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase rlimit, eBPF loading may fail. Try running as root.");
    }

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/dirt"
    ))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    let do_filp_open: &mut KRetProbe = bpf.program_mut("do_filp_open").unwrap().try_into()?;
    do_filp_open.load()?;
    do_filp_open.attach("do_filp_open", 0)?;

    let security_inode_unlink: &mut KProbe = bpf
        .program_mut("security_inode_unlink")
        .unwrap()
        .try_into()?;
    security_inode_unlink.load()?;
    security_inode_unlink.attach("security_inode_unlink", 0)?;

    let security_inode_rename: &mut KProbe = bpf
        .program_mut("security_inode_rename")
        .unwrap()
        .try_into()?;
    security_inode_rename.load()?;
    security_inode_rename.attach("security_inode_rename", 0)?;

    let vfs_close: &mut KProbe = bpf.program_mut("vfs_close").unwrap().try_into()?;
    vfs_close.load()?;
    vfs_close.attach("vfs_close", 0)?;

    let mut ringbuf = RingBuf::from(bpf.map_mut("RINGBUF_RECORDS")?)?;

    info!("Waiting for events...");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                break;
            }
            Some(event) = ringbuf.next() => {
                let mut buf = Bytes::copy_from_slice(&event);
                let record: RecordFs = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const RecordFs) };
                info!("Received event: {:?}", record.filename);
            }
        }
    }

    Ok(())
}
