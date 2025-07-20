use std::env;
use std::path::PathBuf;
use std::process::Command;

use which::which;

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
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

    // It's not recommended to ship an eBPF program that uses vmlinux BTF with a package manager.
    // However, it is fine for local development.
    if let Ok(path) = which("bpftool") {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        let output = Command::new(path)
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("failed to execute bpftool");

        let vmlinux_h = String::from_utf8(output.stdout).expect("output was not valid utf-8");

        let bindings = bindgen::Builder::default()
            .header_contents("vmlinux.h", &vmlinux_h)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .derive_default(true)
            .derive_eq(true)
            .derive_ord(true)
            .allowlist_type("dentry")
            .allowlist_type("inode")
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(out_dir.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
