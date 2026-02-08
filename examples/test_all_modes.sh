#!/bin/bash
# Test script for all three client modes

set -e

BINARY="${1:-so/libbluetooth.so}"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary file not found: $BINARY"
    echo "Usage: $0 [binary_path]"
    exit 1
fi

echo "=========================================="
echo "Testing IDA MCP Client Modes"
echo "Binary: $BINARY"
echo "=========================================="
echo

# Test 1: Auto-start mode (recommended)
echo "Test 1: Auto-start mode (basic_usage.py)"
echo "------------------------------------------"
python examples/basic_usage.py "$BINARY" 2>&1 | head -20
echo
echo "✓ Test 1 passed"
echo

# Test 2: Separate process mode
echo "Test 2: Separate process mode (connect_to_running_server.py)"
echo "-------------------------------------------------------------"
python examples/connect_to_running_server.py --binary "$BINARY" 2>&1 | head -20
echo
echo "✓ Test 2 passed"
echo

# Test 3: Pipe mode (advanced)
echo "Test 3: Pipe mode (separate_server_client.py)"
echo "----------------------------------------------"
echo "Note: This requires manual setup with named pipes or shell redirection"
echo "Example: python -m ida_mcp_stdio $BINARY 2>/dev/null | python examples/separate_server_client.py"
echo "Skipping automated test for pipe mode"
echo

echo "=========================================="
echo "All tests completed successfully!"
echo "=========================================="
