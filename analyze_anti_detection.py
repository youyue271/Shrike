#!/usr/bin/env python3
import requests
import json

IDA_MCP_URL = "http://localhost:5000"

def call_ida_tool(tool_name, arguments):
    response = requests.post(f"{IDA_MCP_URL}/call_tool", json={
        "name": tool_name,
        "arguments": arguments
    })
    return response.json()

def analyze_anti_detection(sample_path):
    print(f"[*] Analyzing anti-detection in: {sample_path}")

    # 1. 查找IsDebuggerPresent等反调试API
    print("\n[1] Checking for anti-debug API calls...")
    anti_debug_apis = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "GetTickCount", "QueryPerformanceCounter",
        "ZwQueryInformationProcess", "NtSetInformationThread"
    ]

    for api in anti_debug_apis:
        result = call_ida_tool("find_xrefs_to_name", {"name": api})
        if result.get("content"):
            xrefs = json.loads(result["content"][0]["text"])
            if xrefs:
                print(f"  [!] Found {len(xrefs)} xrefs to {api}")
                for xref in xrefs[:3]:
                    print(f"      {xref['from_ea']:#x} -> {xref['to_ea']:#x}")

    # 2. 查找PEB访问（检查BeingDebugged标志）
    print("\n[2] Checking for PEB access patterns...")
    result = call_ida_tool("search_binary", {"pattern": "64 A1 30 00 00 00"})  # mov eax, fs:[30h]
    if result.get("content"):
        matches = json.loads(result["content"][0]["text"])
        if matches:
            print(f"  [!] Found {len(matches)} PEB access patterns")
            for match in matches[:5]:
                print(f"      {match:#x}")

    # 3. 查找时间检测
    print("\n[3] Checking for timing checks...")
    timing_apis = ["GetTickCount", "QueryPerformanceCounter", "timeGetTime"]
    for api in timing_apis:
        result = call_ida_tool("find_xrefs_to_name", {"name": api})
        if result.get("content"):
            xrefs = json.loads(result["content"][0]["text"])
            if xrefs:
                print(f"  [!] Found {len(xrefs)} xrefs to {api}")

    # 4. 查找DLL名称检测
    print("\n[4] Checking for DLL name checks...")
    suspicious_strings = ["dynamorio", "drrun", "pin", "frida", "dbghelp"]
    for s in suspicious_strings:
        result = call_ida_tool("search_text", {"text": s, "case_sensitive": False})
        if result.get("content"):
            matches = json.loads(result["content"][0]["text"])
            if matches:
                print(f"  [!] Found string '{s}' at {len(matches)} locations")

    # 5. 查找异常处理
    print("\n[5] Checking for exception handlers...")
    result = call_ida_tool("find_xrefs_to_name", {"name": "RtlAddVectoredExceptionHandler"})
    if result.get("content"):
        xrefs = json.loads(result["content"][0]["text"])
        if xrefs:
            print(f"  [!] Found {len(xrefs)} vectored exception handlers")

    print("\n[*] Analysis complete")

if __name__ == "__main__":
    sample = "samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2"
    analyze_anti_detection(sample)
