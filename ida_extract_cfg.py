#!/usr/bin/env python3
"""Extract static CFG from IDA database"""
import idaapi
import idautils
import idc
import json
import sys

def extract_static_cfg(output_path="static_cfg.json"):
    """Extract complete CFG from IDA database"""

    print("[*] Starting static CFG extraction...")

    cfg = {
        "metadata": {
            "sample": idc.get_input_file_path(),
            "image_base": hex(idaapi.get_imagebase()),
            "entry_point": hex(idc.get_inf_attr(idc.INF_START_IP)),
        },
        "functions": [],
        "basic_blocks": [],
        "edges": []
    }

    func_count = 0
    bb_count = 0
    edge_count = 0

    # Extract all functions
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue

        func_name = idc.get_func_name(func_ea)
        func_info = {
            "address": hex(func_ea),
            "name": func_name,
            "size": func.size(),
            "basic_blocks": []
        }

        # Extract basic blocks in this function
        flowchart = idaapi.FlowChart(func)
        for bb in flowchart:
            bb_id = f"bb_{bb.start_ea:08x}"

            # Get instructions in this basic block
            instructions = []
            ea = bb.start_ea
            while ea < bb.end_ea:
                disasm = idc.GetDisasm(ea)
                instructions.append({
                    "address": hex(ea),
                    "disasm": disasm,
                    "bytes": idc.get_bytes(ea, idc.get_item_size(ea)).hex()
                })
                ea = idc.next_head(ea, bb.end_ea)

            bb_info = {
                "id": bb_id,
                "start": hex(bb.start_ea),
                "end": hex(bb.end_ea),
                "size": bb.end_ea - bb.start_ea,
                "function": func_name,
                "instructions": instructions
            }

            cfg["basic_blocks"].append(bb_info)
            func_info["basic_blocks"].append(bb_id)
            bb_count += 1

            # Extract edges
            for succ in bb.succs():
                edge = {
                    "from": bb_id,
                    "to": f"bb_{succ.start_ea:08x}",
                    "from_addr": hex(bb.start_ea),
                    "to_addr": hex(succ.start_ea),
                    "type": "flow"
                }
                cfg["edges"].append(edge)
                edge_count += 1

        cfg["functions"].append(func_info)
        func_count += 1

        if func_count % 100 == 0:
            print(f"[*] Processed {func_count} functions...")

    # Save to file
    with open(output_path, "w") as f:
        json.dump(cfg, f, indent=2)

    print(f"\n[+] CFG extraction complete!")
    print(f"    Functions: {func_count}")
    print(f"    Basic blocks: {bb_count}")
    print(f"    Edges: {edge_count}")
    print(f"    Output: {output_path}")

    return cfg

if __name__ == "__main__":
    if not idaapi.get_root_filename():
        print("Error: This script must be run from IDA Pro")
        sys.exit(1)

    extract_static_cfg()
