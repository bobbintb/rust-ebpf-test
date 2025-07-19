# Fix for All-Zeros filename_preview in vfs_unlink Probes

## Problem Summary
The vfs_unlink probes were outputting all zeros for:
- `filename_preview` array
- `inode` value  
- `filename_len` value

## Root Cause Analysis

### Primary Issues:
1. **eBPF Verifier Rejection**: Complex kernel memory access patterns were rejected by the eBPF verifier
2. **Context Pointer Constraints**: Attempting to dereference modified context pointers (`ctx.arg()`) was disallowed
3. **Stack Usage**: Large 256-byte filename buffer was consuming too much stack space
4. **Instruction Complexity**: Multiple nested loops for offset probing exceeded verifier limits

### Specific Error:
```
dereference of modified ctx ptr R1 off=112 disallowed
```

## Solution Implemented

### 1. Multiple Approaches for Kernel Structure Access
We've implemented several approaches to extract filename and inode information:

- **Primary Approach**: Direct structure reading with proper CO-RE definitions
- **Alternative Layout**: Try a different kernel structure layout if the first fails
- **Memory Scanning**: Scan memory at different offsets as a last resort
- **Detailed Debug Information**: Capture exactly where extraction fails

### 2. Improved Structure Definitions
- **Added proper kernel structure definitions**: `dentry`, `qstr`, `inode`
- **Multiple structure layouts**: To handle different kernel versions
- **Reduced buffer sizes**: Smaller structures to pass verifier validation

### 3. Enhanced Debugging
- **Debug codes**: Track exactly where extraction fails
- **Fallback values with debug info**: Encode failure point in output
- **Pointer value preservation**: Store pointer values for debugging

## Current Implementation

The current implementation tries multiple approaches:

1. **First attempt**: Read standard kernel structure layout
2. **Second attempt**: Try alternative structure layout with different offsets
3. **Last resort**: Scan memory at different offsets looking for valid strings
4. **Fallback**: If all else fails, provide debug information in the output

## Testing Requirements

To test this implementation, you need:

1. **Kernel with eBPF support**: Linux kernel with eBPF and BTF enabled
2. **Root privileges**: Required to load and run eBPF programs
3. **Proper kernel headers**: Matching your running kernel version

```bash
# Check if your kernel supports eBPF
ls /sys/kernel/btf/vmlinux

# Check for eBPF-related kernel symbols
cat /proc/kallsyms | grep bpf

# Build the program
cd dirt && cargo build

# Run with root privileges
sudo ./target/debug/dirt
```

## Debugging Information

If extraction fails, the output will contain debug information:

```json
{"event":"vfs_unlink_entry","pid":1234,"tgid":1234,"inode":900000002,"filename_len":21,"filename_preview":[100,101,98,117,103,95,99,111]}
```

The debug information encodes:
- **inode**: `900000000 + debug_code` indicates where extraction failed
- **filename**: `debug_code_X_description` provides detailed error information

Debug codes:
- `0_no_arg`: Could not get argument pointer
- `1_got_ptr`: Got pointer but extraction failed
- `2_ptr_ok`: Pointer is valid but structure reading failed
- `3_dentry_ok`: Read dentry but couldn't read inode/filename
- ...and many more detailed codes

## Files Modified

- `dirt/dirt-ebpf/src/main.rs`: Enhanced vfs_unlink probe implementation
- Branch: `json-format-vfs-unlink-probes`
- Commits: 
  - `fb65a63`: Enhanced debugging for kernel structure access
  - `b9f645b`: Proper kernel structure reading with CO-RE
  - `5137ee8`: Simplified version that passes verifier
  - `b2140ad`: Initial complex version (verifier rejected)

## Future Work

1. **Environment-specific tuning**: Adjust structure definitions for specific kernels
2. **Simplified extraction**: Focus on minimal data extraction that passes verifier
3. **Alternative approaches**: Consider tracepoints or userspace processing
4. **Kernel version detection**: Automatically select appropriate structure layout

## Key Learnings

1. **eBPF Verifier is Strict**: Complex memory access patterns are often rejected
2. **Context Access is Limited**: Direct argument extraction has constraints
3. **Stack Space Matters**: Large structures can cause verification failures
4. **Simplicity First**: Start with simple working code, then add complexity gradually
5. **Multiple Approaches**: Try different structure layouts for different kernels
6. **Detailed Debugging**: Encode failure points in the output for easier debugging