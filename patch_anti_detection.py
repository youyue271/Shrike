#!/usr/bin/env python3
import sys
import struct

def find_and_patch(data, pattern, replacement, description):
    """查找并patch所有匹配的模式"""
    count = 0
    offset = 0
    while True:
        offset = data.find(pattern, offset)
        if offset == -1:
            break
        data[offset:offset+len(replacement)] = replacement
        print(f"  [+] {description} at offset {offset:#x}")
        offset += len(replacement)
        count += 1
    return count

def patch_sample(input_file, output_file):
    print(f"[*] Loading {input_file}")
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    total_patches = 0

    # 1. Patch字符串检测
    print("\n[1] Patching DLL name strings...")
    strings_to_patch = [
        (b'dynamorio.dll', b'xxxxxxxxx.xxx'),
        (b'dynamorio', b'xxxxxxxxx'),
        (b'drrun.exe', b'xxxxx.xxx'),
        (b'drrun', b'xxxxx'),
        (b'drwrap', b'xxxxxx'),
        (b'drmgr', b'xxxxx'),
        (b'pin.exe', b'xxx.xxx'),
        (b'frida', b'xxxxx'),
    ]

    for pattern, replacement in strings_to_patch:
        count = find_and_patch(data, pattern, replacement, f"String '{pattern.decode()}'")
        total_patches += count

    # 2. Patch IsDebuggerPresent调用
    print("\n[2] Patching IsDebuggerPresent calls...")
    # call dword ptr [IsDebuggerPresent] -> xor eax,eax; nop*4
    patterns = [
        (b'\xFF\x15', b'\x31\xC0\x90\x90\x90\x90'),  # call [addr]
    ]
    # 注意：这个会patch所有的call [addr]，可能过于激进

    # 3. Patch PEB.BeingDebugged检查
    print("\n[3] Patching PEB.BeingDebugged checks...")
    peb_patterns = [
        # mov eax, fs:[30h]; mov al, [eax+2]; test al, al
        (b'\x64\xA1\x30\x00\x00\x00\x8A\x40\x02\x84\xC0',
         b'\x31\xC0' + b'\x90' * 9),
        # mov eax, fs:[30h]; cmp byte ptr [eax+2], 0
        (b'\x64\xA1\x30\x00\x00\x00\x80\x78\x02\x00',
         b'\x31\xC0' + b'\x90' * 8),
        # mov eax, fs:[30h]; mov al, [eax+2]
        (b'\x64\xA1\x30\x00\x00\x00\x8A\x40\x02',
         b'\x31\xC0' + b'\x90' * 7),
    ]

    for pattern, replacement in peb_patterns:
        count = find_and_patch(data, pattern, replacement, "PEB.BeingDebugged check")
        total_patches += count

    # 4. Patch GetModuleHandle检查
    print("\n[4] Patching GetModuleHandle checks...")
    # 这个比较难，因为需要找到具体的调用位置

    # 5. Patch RDTSC时间检测（如果有）
    print("\n[5] Patching RDTSC instructions...")
    # rdtsc -> xor eax,eax; xor edx,edx; nop
    count = find_and_patch(data, b'\x0F\x31', b'\x31\xC0\x31\xD2\x90', "RDTSC")
    total_patches += count

    print(f"\n[*] Total patches applied: {total_patches}")

    if total_patches == 0:
        print("[!] Warning: No patches applied. Sample may not have obvious anti-detection.")

    print(f"[*] Saving patched sample to {output_file}")
    with open(output_file, 'wb') as f:
        f.write(data)

    print("[+] Done!")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python patch_anti_detection.py <input.exe> <output.exe>")
        sys.exit(1)

    patch_sample(sys.argv[1], sys.argv[2])
