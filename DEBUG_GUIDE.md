# eBPF Program Debugging Guide

## Current Issue: No Output Visible

The eBPF program compiles and runs without errors, but no probe output is visible. Here are the steps to debug and verify the program is working.

## Step 1: Run the Program with Detailed Logging

**IMPORTANT: eBPF programs require root privileges to attach to kernel functions.**

```bash
# Run with sudo and detailed logging
sudo RUST_LOG=debug ./target/debug/dirt
```

You should see output like:
```
[INFO] Starting eBPF program...
[INFO] Loading eBPF program...
[INFO] Initializing eBPF logger...
[INFO] eBPF logger initialized successfully
[INFO] Loading and attaching kretprobe 'dirt'...
[INFO] kretprobe 'dirt' attached successfully to vfs_unlink
[INFO] Loading and attaching kprobe 'vfs_unlink_probe'...
[INFO] kprobe 'vfs_unlink_probe' attached successfully to vfs_unlink
[INFO] Both probes are active. Try deleting a file to see output!
```

## Step 2: Test File Operations

**In a separate terminal**, run the test script:

```bash
# Make sure you have the test script
chmod +x /workspace/test_file_operations.sh

# Run the test
/workspace/test_file_operations.sh
```

Or manually test:
```bash
# Simple test
touch /tmp/test_file.txt
rm /tmp/test_file.txt
```

## Step 3: Troubleshooting Common Issues

### Issue 1: Permission Denied
**Solution**: Run with `sudo`
```bash
sudo ./target/debug/dirt
```

### Issue 2: No Kernel Symbols
Check if the `vfs_unlink` function exists:
```bash
# Check if vfs_unlink is available
sudo grep vfs_unlink /proc/kallsyms
```

### Issue 3: eBPF Logger Not Working
Try alternative approaches:

#### Option A: Check dmesg for kernel logs
```bash
# In another terminal, monitor kernel logs
sudo dmesg -w | grep -i "dirt\|vfs_unlink"
```

#### Option B: Use printk instead of aya_log
Modify the eBPF code to use `bpf_printk`:

```rust
// In dirt-ebpf/src/main.rs, replace info! calls with:
// bpf_printk!(b"kretprobe called");
// bpf_printk!(b"vfs_unlink kprobe triggered");
```

### Issue 4: Function Attachment Problems
Check what functions are actually available:
```bash
# List available kprobe attachment points
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep unlink
```

## Step 4: Alternative Testing Methods

### Method 1: Check if probes are attached
```bash
# Check if probes are attached
sudo cat /sys/kernel/debug/tracing/kprobe_events
sudo ls /sys/kernel/debug/tracing/events/kprobes/
```

### Method 2: Use strace to verify file operations
```bash
# In another terminal, trace file operations
sudo strace -e trace=unlink,unlinkat rm /tmp/test_file.txt 2>&1 | grep unlink
```

### Method 3: Manual probe verification
```bash
# Enable kprobe tracing manually
echo 1 | sudo tee /sys/kernel/debug/tracing/events/kprobes/enable
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on

# Watch trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Step 5: Expected Behavior

When working correctly, you should see:
1. **Startup messages** showing successful probe attachment
2. **eBPF log output** when files are deleted:
   - `"vfs_unlink kprobe triggered - file being unlinked"` (on entry)
   - `"kretprobe called"` (on return)

## Common Root Causes

1. **Insufficient Privileges**: eBPF requires root
2. **Kernel Version**: Ensure kernel supports eBPF and kprobes
3. **Function Availability**: `vfs_unlink` might not be available as a kprobe target
4. **Logging Configuration**: eBPF logs might not reach userspace properly

## Verification Commands

Run these to verify your environment:

```bash
# Check kernel eBPF support
ls /sys/fs/bpf/

# Check if running as root
id

# Verify kernel version (needs 4.1+ for basic eBPF, 4.4+ for kprobes)
uname -r

# Check if debugfs is mounted (needed for tracing)
mount | grep debugfs
```

## Next Steps

1. Try running with `sudo` first
2. Run the test script in a separate terminal
3. Check `dmesg` output
4. If still no output, try the alternative methods above

The enhanced logging should help identify exactly where the issue occurs.