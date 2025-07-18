# eBPF Program Enhancement: Added vfs_unlink kprobe

## Summary
Successfully added a `kprobe` for `vfs_unlink` to the existing eBPF program that previously only had one `kretprobe`. Now the program monitors file unlinking operations at both entry and return points.

## Changes Made

### 1. eBPF Kernel Code (`dirt/dirt-ebpf/src/main.rs`)
- **Added imports**: Updated to include both `kprobe` and `ProbeContext` alongside existing imports
- **Added kprobe function**: Created `vfs_unlink_probe` function with `#[kprobe]` attribute
- **Added helper function**: Created `try_vfs_unlink` to handle the probe logic
- **Console output**: The new probe outputs "vfs_unlink kprobe triggered - file being unlinked" when files are unlinked

### 2. Userspace Code (`dirt/dirt/src/main.rs`)
- **Fixed imports**: Corrected import to use only `KProbe` (since `KRetProbe` doesn't exist in this Aya version)
- **Added probe attachment**: Added code to load and attach the new `vfs_unlink_probe` to the `vfs_unlink` kernel function
- **Maintained existing functionality**: The original `dirt` kretprobe continues to work alongside the new kprobe

### 3. Development Environment Setup
- Installed Rust nightly toolchain (required for eBPF compilation)
- Installed `bpf-linker` tool (required for linking eBPF programs)
- Added `rust-src` component for cross-compilation support

## Program Behavior
The enhanced eBPF program now:

1. **Triggers on vfs_unlink entry** (kprobe): Logs when a file unlink operation begins
2. **Triggers on vfs_unlink return** (kretprobe): Logs when a file unlink operation completes

Both probes output to the console via the eBPF logging infrastructure, providing comprehensive monitoring of file deletion events in the Linux kernel.

## Technical Details
- Uses Aya eBPF framework v0.13.1
- Compiled with Rust nightly for eBPF target `bpfel-unknown-none`
- Both probes attach to the same kernel function (`vfs_unlink`) but at different points in execution
- Console output uses `aya_log_ebpf::info!` macro for kernel-to-userspace logging

## Build Status
✅ **Successfully compiles and builds** - All components build without errors or warnings.