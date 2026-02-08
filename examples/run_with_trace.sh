#!/bin/bash
# Run IDA MCP with TRACE logging enabled for both server and client

set -e

BINARY="${1}"

if [ -z "$BINARY" ]; then
    echo "Usage: $0 <binary_path>"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary file not found: $BINARY"
    exit 1
fi

# Create logs directory
mkdir -p logs

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "=========================================="
echo "IDA MCP with TRACE Logging"
echo "=========================================="
echo "Binary: $BINARY"
echo "Timestamp: $TIMESTAMP"
echo ""

# Run with TRACE logging
# Server will log to logs/ida-mcp-$TIMESTAMP.log
# Client will log to logs/ida-mcp-client-$TIMESTAMP.log
echo "Starting server with TRACE logging..."
echo "Server log: logs/ida-mcp-$TIMESTAMP.log"
echo ""

# Use Python to run with TRACE logging
python3 -c "
import sys
import logging
from pathlib import Path
from datetime import datetime

# Setup TRACE level
TRACE = 5
logging.addLevelName(TRACE, 'TRACE')

def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)

logging.Logger.trace = trace

# Setup logging
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)

timestamp = '$TIMESTAMP'
log_file = log_dir / f'ida-mcp-client-{timestamp}.log'

log_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
date_format = '%Y-%m-%d %H:%M:%S'

root_logger = logging.getLogger()
root_logger.setLevel(TRACE)

# Console handler
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(log_format, date_format))
root_logger.addHandler(console_handler)

# File handler
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(TRACE)
file_handler.setFormatter(logging.Formatter(log_format, date_format))
root_logger.addHandler(file_handler)

print(f'Client log: {log_file}', file=sys.stderr)
print('', file=sys.stderr)

# Import and run client
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient('$BINARY', verbose=False) as client:
    # Initialize
    info = client.initialize()
    print(f\"Connected to: {info['serverInfo']['name']} v{info['serverInfo']['version']}\")
    
    # List tools
    tools = client.list_tools()
    print(f\"Available tools: {len(tools)}\")
    
    # List functions
    funcs = client.list_funcs(count=5)
    print(f\"Functions: {len(funcs['data'])} of {funcs['total']}\")
    for func in funcs['data']:
        print(f\"  {func['addr']} {func['name']}\")
    
    # Decompile first function
    if funcs['data']:
        first_func = funcs['data'][0]
        result = client.decompile(first_func['addr'])
        if result.get('code'):
            print(f\"\\nDecompiled {first_func['name']} ({len(result['code'])} chars)\")
    
    # Disassemble
    if funcs['data']:
        first_func = funcs['data'][0]
        disasm = client.disasm(first_func['addr'], max_instructions=5)
        print(f\"Disassembled {first_func['name']} ({len(disasm['lines'])} instructions)\")

print('', file=sys.stderr)
print('='*60, file=sys.stderr)
print('TRACE logging complete!', file=sys.stderr)
print('Check the log files for detailed request/response data:', file=sys.stderr)
print(f'  Server: logs/ida-mcp-{timestamp}.log', file=sys.stderr)
print(f'  Client: {log_file}', file=sys.stderr)
print('='*60, file=sys.stderr)
"

echo ""
echo "Done!"
