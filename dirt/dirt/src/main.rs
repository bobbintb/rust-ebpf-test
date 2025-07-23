use aya::programs::KProbe;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;
    
    // Attach the existing kretprobe
    let dirt_program: &mut KProbe = ebpf.program_mut("dirt").unwrap().try_into()?;
    dirt_program.load()?;
    dirt_program.attach("vfs_unlink", 0)?;
    
    // Attach the new kprobe for vfs_unlink
    let vfs_unlink_program: &mut KProbe = ebpf.program_mut("vfs_unlink_probe").unwrap().try_into()?;
    vfs_unlink_program.load()?;
    vfs_unlink_program.attach("vfs_unlink", 0)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
