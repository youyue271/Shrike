#!/usr/bin/env python3
"""Patch sample to bypass DynamoRIO detection"""
import sys
import struct

def patch_sample(input_path, output_path):
    """Patch anti-debug checks in the sample"""
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    patches_applied = 0

    # Pattern 1: CreateToolhelp32Snapshot call
    # Look for: push 0 / push <pid> / call CreateToolhelp32Snapshot
    # Replace call with: xor eax, eax / nop nop nop nop (return 0 = fail)

    # Pattern 2: Module32First/Module32Next calls
    # Replace with: xor eax, eax / ret (return FALSE)

    # Pattern 3: EnumProcessModules call
    # Replace with: xor eax, eax / ret (return FALSE)

    # Simple approach: NOP out common detection patterns
    # Search for call instructions to these APIs and replace with safe returns

    # For now, just patch known detection function at specific offset
    # This requires static analysis to find the exact location

    print(f"Original size: {len(data)} bytes")
    print(f"Patches applied: {patches_applied}")

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"Patched sample written to: {output_path}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.exe> <output.exe>")
        sys.exit(1)

    patch_sample(sys.argv[1], sys.argv[2])
