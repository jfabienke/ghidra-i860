#!/usr/bin/env python3
"""
Comprehensive cross-reference extraction for NDserver analysis.

Extracts:
1. Global variables with full context
2. Hardware registers with access patterns
3. Data structure field mappings
4. Library/OS function calls
5. String constants
6. Call graphs and chains
"""

import json
import re
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

def extract_section(content, section_name):
    """Extract content of a markdown section."""
    # Try various heading levels
    for level in ['###', '##', '#']:
        pattern = rf'^{level}\s+{re.escape(section_name)}.*?(?=^#{level.replace("#", "")}\s|\Z)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        if match:
            return match.group(0)

    # Try with partial matching
    for level in ['###', '##', '#']:
        pattern = rf'^{level}\s+.*{re.escape(section_name)}.*?(?=^#{level.replace("#", "")}\s|\Z)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(0)

    return None

def parse_global_vars(content, func_info):
    """Parse global variables from Hardware Access section."""
    globals_found = []

    # Find "Global Data" subsection
    section = extract_section(content, "Hardware Access")
    if not section:
        section = extract_section(content, "Memory Regions")

    if section:
        # Look for address: description patterns
        for match in re.finditer(r'(0x[0-9A-Fa-f]{8})\s*:\s*([^\n]+)', section):
            addr = match.group(1).lower()
            desc = match.group(2).strip()

            globals_found.append({
                "address": addr,
                "description": desc,
                "function": func_info["address"],
                "function_name": func_info["name"]
            })

    # Also check for code-formatted addresses in markdown
    for match in re.finditer(r'```.*?0x([0-9A-Fa-f]{8}).*?```', content, re.DOTALL):
        addr = "0x" + match.group(1).lower()
        # Check if in known hardware or runtime ranges
        addr_int = int(addr, 16)
        if addr_int >= 0x04000000 or (0x8000 <= addr_int <= 0x9000):
            globals_found.append({
                "address": addr,
                "description": "accessed in code",
                "function": func_info["address"],
                "function_name": func_info["name"]
            })

    return globals_found

def parse_library_calls(content, func_info):
    """Parse library and OS function calls."""
    calls = []

    section = extract_section(content, "OS Functions")
    if not section:
        section = extract_section(content, "Library Calls")

    if section:
        # Pattern: **1. FunctionName** or **FunctionName**
        for match in re.finditer(r'\*\*(?:\d+\.\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\*\*', section):
            func_name = match.group(1)

            # Get surrounding context
            start = max(0, match.start() - 50)
            end = min(len(section), match.end() + 500)
            context = section[start:end]

            # Look for address
            addr_match = re.search(r'0x([0-9A-Fa-f]{8})', context)
            addr = "0x" + addr_match.group(1).lower() if addr_match else None

            # Check for error handling keywords
            has_error_handling = bool(re.search(
                r'error|check|validate|NULL|fail|return',
                context,
                re.IGNORECASE
            ))

            calls.append({
                "function_name": func_name,
                "address": addr,
                "called_from": func_info["address"],
                "called_from_name": func_info["name"],
                "error_handling": has_error_handling,
                "context": context[:200]
            })

    return calls

def parse_data_structures(content, func_info):
    """Parse data structure allocations and accesses."""
    structs = []

    # Find malloc/allocate calls
    for match in re.finditer(r'(?:malloc|vm_allocate|allocate)\s*\(\s*(\d+)\s*\)', content):
        size = int(match.group(1))

        # Try to find struct name nearby
        context_start = max(0, match.start() - 300)
        context_end = min(len(content), match.end() + 100)
        context = content[context_start:context_end]

        struct_name = None
        # Look for patterns like "board_info" or "descriptor"
        name_match = re.search(r'(\w+(?:_(?:info|struct|data|descriptor|table|entry|t))?)', context)
        if name_match:
            struct_name = name_match.group(1)
        else:
            struct_name = f"struct_{size}bytes"

        structs.append({
            "name": struct_name,
            "size": size,
            "allocation_in": func_info["address"],
            "allocation_in_name": func_info["name"]
        })

    # Find field accesses like (0x4,A2) or +0x08
    field_accesses = []
    for match in re.finditer(r'\((?:0x)?([0-9a-fA-F]+),\s*A([0-9])\)', content):
        offset = int(match.group(1), 16)
        register = "A" + match.group(2)

        field_accesses.append({
            "offset": offset,
            "register": register,
            "function": func_info["address"]
        })

    return structs, field_accesses

def parse_hardware_registers(content, func_info):
    """Parse hardware register accesses."""
    registers = []

    section = extract_section(content, "Hardware")
    if section:
        # Look for hardware addresses (0x0200xxxx range typically)
        for match in re.finditer(r'(0x02[0-9A-Fa-f]{6})\s*[:\-]\s*([^\n]+)', section):
            addr = match.group(1).lower()
            desc = match.group(2).strip()

            registers.append({
                "address": addr,
                "description": desc,
                "accessed_by": func_info["address"],
                "accessed_by_name": func_info["name"]
            })

    return registers

def parse_call_graph(content, func_info):
    """Parse call graph information."""
    calls_to = []
    called_by = []

    section = extract_section(content, "Call Graph")
    if section:
        # Calls TO (callees)
        for match in re.finditer(r'(?:call|bsr|jsr)\s+(?:0x)?([0-9a-fA-F]{8})', section, re.IGNORECASE):
            callee_addr = "0x" + match.group(1).lower()
            calls_to.append(callee_addr)

        # Called BY (callers) - look for "Called by:" section
        if "called by" in section.lower():
            for match in re.finditer(r'0x([0-9a-fA-F]{8})', section):
                caller_addr = "0x" + match.group(1).lower()
                called_by.append(caller_addr)

    return calls_to, called_by

def process_function_file(md_file):
    """Process a single function markdown file."""
    with open(md_file, 'r') as f:
        content = f.read()

    # Extract function metadata from filename
    filename = md_file.name
    match = re.match(r'([0-9a-fA-F]{8})_(.+)\.md', filename)
    if not match:
        return None

    func_addr = "0x" + match.group(1).lower()
    func_name = match.group(2)

    func_info = {
        "address": func_addr,
        "name": func_name,
        "file": str(md_file)
    }

    # Extract size from content if available
    size_match = re.search(r'\*\*Size\*\*:\s*(\d+)\s*bytes', content)
    if size_match:
        func_info["size"] = int(size_match.group(1))

    # Extract all cross-reference data
    global_vars = parse_global_vars(content, func_info)
    lib_calls = parse_library_calls(content, func_info)
    structs, field_accesses = parse_data_structures(content, func_info)
    hw_regs = parse_hardware_registers(content, func_info)
    calls_to, called_by = parse_call_graph(content, func_info)

    return {
        "function": func_info,
        "global_vars": global_vars,
        "library_calls": lib_calls,
        "data_structures": structs,
        "field_accesses": field_accesses,
        "hardware_registers": hw_regs,
        "calls_to": calls_to,
        "called_by": called_by
    }

def aggregate_results(all_results):
    """Aggregate results from all functions into cross-reference database."""

    # Aggregate global variables
    globals_db = defaultdict(lambda: {
        "name": None,
        "addresses": set(),
        "accessed_by": [],
        "purpose": None,
        "size": None
    })

    for result in all_results:
        for gvar in result["global_vars"]:
            addr = gvar["address"]
            globals_db[addr]["addresses"].add(addr)
            globals_db[addr]["accessed_by"].append({
                "function": gvar["function"],
                "name": gvar["function_name"],
                "context": gvar["description"]
            })
            if not globals_db[addr]["purpose"]:
                globals_db[addr]["purpose"] = gvar["description"]

    # Aggregate library calls
    lib_db = defaultdict(lambda: {
        "callers": [],
        "total_calls": 0,
        "error_handling_count": 0,
        "addresses": set()
    })

    for result in all_results:
        for call in result["library_calls"]:
            func_name = call["function_name"]
            lib_db[func_name]["callers"].append({
                "function": call["called_from"],
                "name": call["called_from_name"],
                "context": call["context"]
            })
            lib_db[func_name]["total_calls"] += 1
            if call["error_handling"]:
                lib_db[func_name]["error_handling_count"] += 1
            if call["address"]:
                lib_db[func_name]["addresses"].add(call["address"])

    # Aggregate data structures
    struct_db = defaultdict(lambda: {
        "size": None,
        "allocated_in": [],
        "field_accesses": defaultdict(list)
    })

    for result in all_results:
        for struct in result["data_structures"]:
            name = struct["name"]
            if not struct_db[name]["size"]:
                struct_db[name]["size"] = struct["size"]
            struct_db[name]["allocated_in"].append({
                "function": struct["allocation_in"],
                "name": struct["allocation_in_name"]
            })

        # Aggregate field accesses (would need better struct identification)
        for field in result["field_accesses"]:
            # For now, just store them generically
            offset = field["offset"]
            struct_db["_unknown_"]["field_accesses"][offset].append({
                "function": field["function"],
                "register": field["register"]
            })

    # Aggregate hardware registers
    hw_db = defaultdict(lambda: {
        "accessed_by": [],
        "purpose": None,
        "name": None
    })

    for result in all_results:
        for hw_reg in result["hardware_registers"]:
            addr = hw_reg["address"]
            hw_db[addr]["accessed_by"].append({
                "function": hw_reg["accessed_by"],
                "name": hw_reg["accessed_by_name"]
            })
            if not hw_db[addr]["purpose"]:
                hw_db[addr]["purpose"] = hw_reg["description"]

    # Build call graph
    call_graph = {}
    for result in all_results:
        func_addr = result["function"]["address"]
        call_graph[func_addr] = {
            "name": result["function"]["name"],
            "calls_to": result["calls_to"],
            "called_by": result["called_by"]
        }

    # Convert sets to lists for JSON serialization
    for addr in globals_db:
        globals_db[addr]["addresses"] = sorted(list(globals_db[addr]["addresses"]))

    for func in lib_db:
        lib_db[func]["addresses"] = sorted(list(lib_db[func]["addresses"]))

    return {
        "global_variables": dict(globals_db),
        "library_functions": dict(lib_db),
        "data_structures": dict(struct_db),
        "hardware_registers": dict(hw_db),
        "call_graph": call_graph
    }

def generate_statistics(database, analyzed_count):
    """Generate summary statistics."""
    stats = {
        "analyzed_functions": analyzed_count,
        "total_global_vars": len(database["global_variables"]),
        "total_hardware_regs": len(database["hardware_registers"]),
        "total_data_structures": len([s for s in database["data_structures"] if s != "_unknown_"]),
        "total_library_functions": len(database["library_functions"]),
    }

    # Top globals by access count
    globals_by_access = sorted(
        [(addr, len(data["accessed_by"])) for addr, data in database["global_variables"].items()],
        key=lambda x: x[1],
        reverse=True
    )
    stats["hottest_globals"] = [
        {"address": addr, "access_count": count, "purpose": database["global_variables"][addr].get("purpose", "unknown")}
        for addr, count in globals_by_access[:5]
    ]

    # Top library functions
    libs_by_usage = sorted(
        [(name, data["total_calls"]) for name, data in database["library_functions"].items()],
        key=lambda x: x[1],
        reverse=True
    )
    stats["most_used_libraries"] = [
        {
            "name": name,
            "call_count": count,
            "error_handling_pct": round(100 * database["library_functions"][name]["error_handling_count"] / count)
            if count > 0 else 0
        }
        for name, count in libs_by_usage[:10]
    ]

    return stats

def main():
    repo_root = Path(__file__).parent.parent
    docs_dir = repo_root / "docs" / "functions"
    database_dir = repo_root / "database"

    print("=" * 70)
    print("COMPREHENSIVE NDSERVER CROSS-REFERENCE EXTRACTION")
    print("=" * 70)
    print()

    # Get all analyzed function files
    all_md_files = sorted(docs_dir.glob('*.md'))
    md_files = [f for f in all_md_files if not f.name.startswith('0x') and f.name != 'INDEX.md']

    print(f"Found {len(md_files)} analyzed function documentation files\n")

    # Process each function
    all_results = []
    for i, md_file in enumerate(md_files, 1):
        print(f"[{i:2d}/{len(md_files)}] Processing: {md_file.name}")
        result = process_function_file(md_file)
        if result:
            all_results.append(result)

    print()
    print("=" * 70)
    print("AGGREGATING CROSS-REFERENCES...")
    print("=" * 70)
    print()

    # Aggregate all results
    database = aggregate_results(all_results)

    # Add metadata
    database["metadata"] = {
        "generated": datetime.now().isoformat(),
        "analyzed_functions": len(all_results),
        "tool_version": "1.0",
        "confidence": "high for analyzed functions, inferred for relationships"
    }

    # Generate statistics
    stats = generate_statistics(database, len(all_results))
    database["statistics"] = stats

    # Save to JSON
    output_file = database_dir / "cross_references.json"
    with open(output_file, 'w') as f:
        json.dump(database, f, indent=2)

    print(f"✓ Generated: {output_file}")
    print(f"  Size: {output_file.stat().st_size:,} bytes\n")

    # Print statistics
    print("=" * 70)
    print("EXTRACTION STATISTICS")
    print("=" * 70)
    print(f"Analyzed Functions:    {stats['analyzed_functions']}")
    print(f"Global Variables:      {stats['total_global_vars']}")
    print(f"Hardware Registers:    {stats['total_hardware_regs']}")
    print(f"Data Structures:       {stats['total_data_structures']}")
    print(f"Library Functions:     {stats['total_library_functions']}")
    print()

    if stats.get("hottest_globals"):
        print("Top 5 Hottest Global Variables:")
        for item in stats["hottest_globals"]:
            print(f"  {item['address']:12s} ({item['access_count']} accesses) - {item['purpose'][:50]}")
        print()

    if stats.get("most_used_libraries"):
        print("Top Library Functions:")
        for item in stats["most_used_libraries"][:5]:
            print(f"  {item['name']:20s} - {item['call_count']} calls ({item['error_handling_pct']}% error-checked)")
        print()

    print("=" * 70)
    print("✓ CROSS-REFERENCE EXTRACTION COMPLETE")
    print("=" * 70)

    return database

if __name__ == "__main__":
    main()
