#!/bin/bash

echo "=== eBPF Environment Check ==="

echo "1. Checking kernel version..."
uname -r

echo -e "\n2. Checking if running as root..."
if [ "$EUID" -ne 0 ]; then
    echo "❌ NOT running as root. eBPF programs require root privileges."
    echo "   Please run with: sudo $0"
    exit 1
else
    echo "✅ Running as root"
fi

echo -e "\n3. Checking eBPF filesystem support..."
if [ -d "/sys/fs/bpf" ]; then
    echo "✅ eBPF filesystem available"
else
    echo "❌ eBPF filesystem not available"
fi

echo -e "\n4. Checking debugfs (needed for tracing)..."
if mount | grep -q debugfs; then
    echo "✅ debugfs mounted"
    if [ -d "/sys/kernel/debug/tracing" ]; then
        echo "✅ Tracing directory available"
    else
        echo "❌ Tracing directory not available"
    fi
else
    echo "❌ debugfs not mounted"
    echo "   Try: mount -t debugfs none /sys/kernel/debug"
fi

echo -e "\n5. Checking if vfs_unlink function is available..."
if grep -q vfs_unlink /proc/kallsyms 2>/dev/null; then
    echo "✅ vfs_unlink function found in kernel symbols"
    echo "   Available symbols:"
    grep vfs_unlink /proc/kallsyms | head -5
else
    echo "❌ vfs_unlink function not found in kernel symbols"
    echo "   This could be why the probe isn't working"
fi

echo -e "\n6. Checking available kprobe functions..."
if [ -r "/sys/kernel/debug/tracing/available_filter_functions" ]; then
    UNLINK_FUNCS=$(grep unlink /sys/kernel/debug/tracing/available_filter_functions | head -10)
    if [ -n "$UNLINK_FUNCS" ]; then
        echo "✅ Unlink-related functions available for kprobes:"
        echo "$UNLINK_FUNCS"
    else
        echo "❌ No unlink-related functions found for kprobes"
    fi
else
    echo "❌ Cannot read available_filter_functions (permission issue?)"
fi

echo -e "\n7. Checking current kprobe events..."
if [ -r "/sys/kernel/debug/tracing/kprobe_events" ]; then
    EVENTS=$(cat /sys/kernel/debug/tracing/kprobe_events)
    if [ -n "$EVENTS" ]; then
        echo "Current kprobe events:"
        echo "$EVENTS"
    else
        echo "No current kprobe events"
    fi
else
    echo "❌ Cannot read kprobe_events"
fi

echo -e "\n=== Recommendations ==="
echo "If you see any ❌ above, those could be the cause of missing output."
echo "Most importantly:"
echo "1. Run the program with sudo"
echo "2. Make sure vfs_unlink is available (check item 5)"
echo "3. If vfs_unlink is not available, try a different function from item 6"