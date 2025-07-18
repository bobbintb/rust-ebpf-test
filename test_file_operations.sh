#!/bin/bash

echo "Testing eBPF vfs_unlink probes..."
echo "Creating and deleting test files to trigger the probes"

# Create a unique test directory
TEST_DIR="/tmp/ebpf_test_$$"
mkdir -p "$TEST_DIR"

echo "Test directory: $TEST_DIR"

# Create and delete multiple files to trigger vfs_unlink
for i in {1..5}; do
    echo "Test $i: Creating and deleting file"
    touch "$TEST_DIR/test_file_$i.txt"
    echo "some content" > "$TEST_DIR/test_file_$i.txt"
    
    # Small delay to make sure operations are distinct
    sleep 0.1
    
    # Delete the file (this should trigger both probes)
    rm "$TEST_DIR/test_file_$i.txt"
    
    sleep 0.1
done

# Also test with different file operations
echo "Testing with different operations..."

# Create and remove a directory
mkdir "$TEST_DIR/subdir"
touch "$TEST_DIR/subdir/file.txt"
rm "$TEST_DIR/subdir/file.txt"
rmdir "$TEST_DIR/subdir"

# Clean up
rmdir "$TEST_DIR"

echo "File operations complete. Check your eBPF program output."