use std::process::Command;

use aya_builder::aya_ebpf::generate::vmlinux::generate_vmlinux;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    // See https://github.com/aya-rs/aya-template/blob/a775f28684784918e0a24f2b1d3abdcc801533bcb/xtask/src/build_ebpf.rs#L41
    let mut vmlinux_path = None;
    if let Ok(path) = std::env::var("VMLINUX_PATH") {
        vmlinux_path = Some(path.into());
    } else if let Ok(output) = Command::new("uname").arg("-r").output() {
        let release = String::from_utf8(output.stdout).unwrap();
        let expected_path = format!("/boot/vmlinux-{}", release.trim());
        if std::fs::metadata(&expected_path).is_ok() {
            vmlinux_path = Some(expected_path.into())
        }
    }
    if vmlinux_path.is_none() {
        eprintln!(
            "
VMLINUX_PATH not found.

A `vmlinux.h` file is required to build the eBPF programs.
Try installing `linux-headers` package, and setting `VMLINUX_PATH` to
`/boot/vmlinux-$(uname -r)`.
"
        );
        std::process::exit(1);
    }
    let vmlinux_path = vmlinux_path.unwrap();

    let dest_path = generate_vmlinux(
        vmlinux_path,
        "src/vmlinux.h",
        &[
            "VMLINUX_H_MUST_EXIST",
            "CONFIG_DEBUG_INFO_BTF",
            "CONFIG_BPF",
        ],
    )
    .unwrap();

    println!("cargo:rerun-if-changed=src/vmlinux.h");
    println!("cargo:rerun-if-changed={}", dest_path.to_str().unwrap());
}
