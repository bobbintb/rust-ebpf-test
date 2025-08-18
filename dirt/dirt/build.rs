use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{Context as _, anyhow};

fn main() -> anyhow::Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let target_dir = {
        let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("MetadataCommand::exec")?;
        let package = packages
            .iter()
            .find(|p| p.name == "dirt")
            .ok_or_else(|| anyhow!("package `dirt` not found"))?;
        let mut path = PathBuf::from(package.manifest_path.as_path());
        path.pop();
        path.join("target")
    };
    let target_dir = target_dir.to_str().unwrap();

    let args = [
        "+nightly",
        "build",
        "--release",
        "-Z",
        "build-std=core,alloc",
        "--package",
        "dirt-ebpf",
        "--target",
        "bpfel-unknown-none",
        "--target-dir",
        target_dir,
    ];

    let mut command = Command::new(cargo);
    command.env("RUSTFLAGS", "-C panic=abort");
    let status = command
        .args(args)
        .status()
        .expect("failed to build eBPF program");
    assert!(status.success());

    let out_dir = env::var("OUT_DIR").unwrap();
    let src = format!("{}/bpfel-unknown-none/release/dirt-ebpf", target_dir);
    let dst = format!("{}/dirt-ebpf", out_dir);
    fs::copy(&src, &dst).with_context(|| format!("failed to copy {src:?} to {dst:?}"))?;

    println!("cargo:rerun-if-changed={}", src);
    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
