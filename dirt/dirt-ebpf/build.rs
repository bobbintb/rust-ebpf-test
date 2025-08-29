use which::which;
use std::fs;
use std::process::Command;

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
    let out_file = "src/vmlinux.rs";

    // Remove old file if exists
    let _ = fs::remove_file(out_file);

    // Run aya-tool generate
    let output = Command::new("aya-tool")
        .arg("generate")
        .output()
        .expect("failed to run aya-tool generate");

    if !output.status.success() {
        panic!("aya-tool failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Write fresh vmlinux.rs
    fs::write(out_file, output.stdout).expect("failed to write vmlinux.rs");

    // Prepend the #![allow(...)] line
    let mut contents =
        fs::read_to_string(out_file).expect("failed to read vmlinux.rs after generation");
    let allow_line = "#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unnecessary_transmutes, unused_imports)]\n";
    contents = format!("{}{}", allow_line, contents);
    fs::write(out_file, contents).expect("failed to prepend allow line");

    // Apply sed-like fixes with regex replacements
    let mut contents =
        fs::read_to_string(out_file).expect("failed to reload vmlinux.rs for patching");

    contents = contents
        .replace("#[repr(C, packed)]\n#[derive(Copy, Clone)]\npub struct alt_instr {",
                 "#[repr(C)]\n#[derive(Copy, Clone)]\npub struct alt_instr {")
        .replace("#[repr(C, packed)]\n#[derive(Copy, Clone)]\npub struct hyperv_root_ir_data {",
                 "#[repr(C)]\n#[derive(Copy, Clone)]\npub struct hyperv_root_ir_data {")
        .replace("#[repr(C, packed)]\n#[derive(Copy, Clone)]\npub struct saved_context {",
                 "#[repr(C)]\n#[derive(Copy, Clone)]\npub struct saved_context {")
        .replace("::core::slice::from_raw_parts(self.as_ptr(), len)",
                 "unsafe { ::core::slice::from_raw_parts(self.as_ptr(), len) }")
        .replace("::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)",
                 "unsafe { ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len) }")
        .replace("::core::mem::transmute(self)",
                 "unsafe { ::core::mem::transmute(self) }")
        .replace("#[repr(C, packed)]\n#[derive(Copy, Clone)]\npub struct hv_input_unmap_device_interrupt {",
                 "#[repr(C)]\n#[derive(Copy, Clone)]\npub struct hv_input_unmap_device_interrupt {")
        .replace("#[repr(C)]\n#[derive(Debug)]\npub struct ec_response_get_next_data_v3__bindgen_ty_1 {",
                 "#[repr(C)]\npub struct ec_response_get_next_data_v3__bindgen_ty_1 {");

    fs::write(out_file, contents).expect("failed to apply sed replacements");

    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
