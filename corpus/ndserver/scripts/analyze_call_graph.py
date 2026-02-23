#!/usr/bin/env python3
"""
Call Graph Analyzer - Bottom-Up Strategy
Builds layered call graph and identifies leaf functions for analysis order.
"""

import json
import sys
from collections import defaultdict

def load_call_graph(filepath):
    """Load Ghidra call graph JSON"""
    with open(filepath, 'r') as f:
        return json.load(f)

def load_functions(filepath):
    """Load Ghidra functions JSON"""
    with open(filepath, 'r') as f:
        return json.load(f)

def filter_internal_calls(call_graph):
    """
    Separate internal function calls from library calls.
    Library calls are to addresses >= 0x05000000 (shared library)
    """
    internal_graph = []

    for entry in call_graph:
        func_addr = entry['function']['address']
        internal_calls = []
        library_calls = []

        for callee in entry.get('calls', []):
            callee_addr = callee['address']

            # Library calls are in 0x05000000+ range
            if callee_addr >= 0x05000000:
                library_calls.append(callee)
            else:
                internal_calls.append(callee)

        internal_graph.append({
            'function': entry['function'],
            'internal_calls': internal_calls,
            'library_calls': library_calls
        })

    return internal_graph

def build_reverse_index(call_graph):
    """Build index of which functions call each function"""
    called_by = defaultdict(list)

    for entry in call_graph:
        func_addr = entry['function']['address']
        for callee in entry['internal_calls']:
            callee_addr = callee['address']
            called_by[callee_addr].append(func_addr)

    return called_by

def calculate_depths(call_graph):
    """
    Calculate call graph depth for each function.
    Depth 0 = leaf (calls no internal functions, may call libraries)
    Depth N = calls functions with max depth N-1
    """
    addr_to_entry = {entry['function']['address']: entry for entry in call_graph}
    memo = {}

    def get_depth(addr):
        if addr in memo:
            return memo[addr]

        # Get this function's entry
        if addr not in addr_to_entry:
            # External/library function
            memo[addr] = -1
            return -1

        entry = addr_to_entry[addr]
        internal_calls = entry['internal_calls']

        # If no internal calls, it's a leaf (depth 0)
        if not internal_calls:
            memo[addr] = 0
            return 0

        # Depth = 1 + max(callee depths)
        max_callee_depth = -1
        for callee in internal_calls:
            callee_addr = callee['address']
            callee_depth = get_depth(callee_addr)
            if callee_depth > max_callee_depth:
                max_callee_depth = callee_depth

        depth = max_callee_depth + 1
        memo[addr] = depth
        return depth

    # Calculate depth for all functions
    for entry in call_graph:
        addr = entry['function']['address']
        depth = get_depth(addr)
        entry['depth'] = depth

    return call_graph

def analyze_call_graph(call_graph_path, functions_path):
    """Main analysis function"""

    print("=" * 80)
    print("Call Graph Analysis - Bottom-Up Strategy")
    print("=" * 80)

    # Load data
    print("\n[1] Loading data...")
    call_graph = load_call_graph(call_graph_path)
    functions = load_functions(functions_path)

    print(f"  Loaded {len(call_graph)} call graph entries")
    print(f"  Loaded {len(functions)} functions")

    # Filter internal vs library calls
    print("\n[2] Separating internal and library calls...")
    internal_graph = filter_internal_calls(call_graph)

    total_internal = sum(len(e['internal_calls']) for e in internal_graph)
    total_library = sum(len(e['library_calls']) for e in internal_graph)

    print(f"  Internal calls: {total_internal}")
    print(f"  Library calls:  {total_library}")

    # Build reverse index
    print("\n[3] Building reverse call index...")
    called_by = build_reverse_index(internal_graph)

    # Add called_by info to graph
    for entry in internal_graph:
        addr = entry['function']['address']
        entry['called_by'] = called_by.get(addr, [])

    # Calculate depths
    print("\n[4] Calculating call graph depths...")
    layered_graph = calculate_depths(internal_graph)

    # Group by depth
    by_depth = defaultdict(list)
    for entry in layered_graph:
        depth = entry['depth']
        by_depth[depth].append(entry)

    # Print layer statistics
    print("\n[5] Call graph layers:")
    print("  " + "-" * 76)
    print(f"  {'Layer':<8} {'Count':<8} {'Description'}")
    print("  " + "-" * 76)

    for depth in sorted(by_depth.keys()):
        count = len(by_depth[depth])
        if depth == 0:
            desc = "Leaf functions (call no internal functions)"
        elif depth == 1:
            desc = "Call only leaves"
        elif depth == 2:
            desc = "Call Layer 0-1 functions"
        else:
            desc = f"Call Layer 0-{depth-1} functions"

        print(f"  {depth:<8} {count:<8} {desc}")

    print("  " + "-" * 76)
    print(f"  {'TOTAL':<8} {len(layered_graph):<8} functions")
    print("  " + "-" * 76)

    # Identify critical leaf functions
    print("\n[6] Analyzing Layer 0 (leaf functions):")
    leaves = by_depth[0]

    # Categorize leaves
    critical_leaves = []
    utility_leaves = []

    for entry in leaves:
        func_addr = entry['function']['address']
        func_name = entry['function']['name']
        lib_calls = len(entry['library_calls'])
        callers = len(entry['called_by'])

        # Critical if called by multiple functions or has many library calls
        if callers >= 3 or lib_calls >= 5:
            critical_leaves.append(entry)
        else:
            utility_leaves.append(entry)

    print(f"\n  Critical leaves (priority analysis): {len(critical_leaves)}")
    for entry in sorted(critical_leaves, key=lambda e: len(e['called_by']), reverse=True)[:10]:
        addr_hex = entry['function']['address_hex']
        name = entry['function']['name']
        callers = len(entry['called_by'])
        libs = len(entry['library_calls'])
        print(f"    {addr_hex}  {name:<30}  (called by {callers}, lib calls: {libs})")

    if len(critical_leaves) > 10:
        print(f"    ... and {len(critical_leaves) - 10} more")

    print(f"\n  Utility leaves (lower priority): {len(utility_leaves)}")
    if utility_leaves:
        for entry in utility_leaves[:5]:
            addr_hex = entry['function']['address_hex']
            name = entry['function']['name']
            print(f"    {addr_hex}  {name}")
        if len(utility_leaves) > 5:
            print(f"    ... and {len(utility_leaves) - 5} more")

    # Find root functions (highest depth, few callers)
    print("\n[7] Root functions (entry points):")
    max_depth = max(by_depth.keys())
    roots = [e for e in by_depth[max_depth] if len(e['called_by']) == 0]

    if roots:
        for entry in roots:
            addr_hex = entry['function']['address_hex']
            name = entry['function']['name']
            calls = len(entry['internal_calls'])
            print(f"  {addr_hex}  {name:<30}  (depth {max_depth}, calls {calls} functions)")
    else:
        print("  No isolated roots found (all functions are called)")

    # Save enriched data
    print("\n[8] Saving enriched call graph...")
    output_path = 'database/call_graph_layered.json'
    with open(output_path, 'w') as f:
        json.dump(layered_graph, f, indent=2)
    print(f"  Saved to: {output_path}")

    # Generate analysis order file
    print("\n[9] Generating analysis order...")
    analysis_order = []

    for depth in sorted(by_depth.keys()):
        layer_functions = sorted(by_depth[depth],
                                 key=lambda e: (len(e['called_by']), e['function']['address']),
                                 reverse=True)

        for entry in layer_functions:
            analysis_order.append({
                'address': entry['function']['address'],
                'address_hex': entry['function']['address_hex'],
                'name': entry['function']['name'],
                'depth': entry['depth'],
                'priority': 'critical' if entry in critical_leaves else 'normal',
                'callers': len(entry['called_by']),
                'internal_calls': len(entry['internal_calls']),
                'library_calls': len(entry['library_calls'])
            })

    order_path = 'database/analysis_order.json'
    with open(order_path, 'w') as f:
        json.dump(analysis_order, f, indent=2)
    print(f"  Saved to: {order_path}")

    # Generate Markdown summary
    print("\n[10] Generating analysis plan Markdown...")

    md_content = f"""# Analysis Order - Bottom-Up Strategy

**Generated**: Automatic from call graph analysis
**Strategy**: Leaf nodes first, work up the call graph

---

## Layer Statistics

| Layer | Count | Description |
|-------|-------|-------------|
"""

    for depth in sorted(by_depth.keys()):
        count = len(by_depth[depth])
        if depth == 0:
            desc = "Leaf functions (no internal calls)"
        else:
            desc = f"Calls Layer 0-{depth-1} functions"
        md_content += f"| {depth} | {count} | {desc} |\n"

    md_content += f"\n**Total**: {len(layered_graph)} functions\n\n"

    md_content += """---

## Analysis Plan

### Phase 1: Layer 0 (Leaf Functions)

**Count**: {leaf_count} functions
**Time Estimate**: 15-30 min each = {leaf_time_low}-{leaf_time_high} hours total

#### Priority 1: Critical Leaves ({critical_count})

These are called by multiple functions or have significant library usage:

""".format(
        leaf_count=len(leaves),
        leaf_time_low=len(leaves) * 15 // 60,
        leaf_time_high=len(leaves) * 30 // 60,
        critical_count=len(critical_leaves)
    )

    for i, entry in enumerate(critical_leaves[:20], 1):
        addr_hex = entry['function']['address_hex']
        name = entry['function']['name']
        callers = len(entry['called_by'])
        libs = len(entry['library_calls'])
        md_content += f"{i}. `{addr_hex}` - **{name}** (called by {callers}, lib calls: {libs})\n"

    if len(critical_leaves) > 20:
        md_content += f"\n... and {len(critical_leaves) - 20} more\n"

    md_content += f"""

#### Priority 2: Utility Leaves ({len(utility_leaves)})

Simpler helper functions, analyze after critical leaves.

"""

    # Add higher layers
    for depth in sorted(by_depth.keys())[1:]:
        layer_funcs = by_depth[depth]
        md_content += f"""
### Phase {depth + 1}: Layer {depth}

**Count**: {len(layer_funcs)} functions
**Prerequisite**: All Layer 0-{depth-1} functions analyzed

"""
        for entry in layer_funcs[:10]:
            addr_hex = entry['function']['address_hex']
            name = entry['function']['name']
            calls = len(entry['internal_calls'])
            md_content += f"- `{addr_hex}` - **{name}** (calls {calls} internal functions)\n"

        if len(layer_funcs) > 10:
            md_content += f"\n... and {len(layer_funcs) - 10} more\n"

    md_path = 'docs/ANALYSIS_ORDER.md'
    with open(md_path, 'w') as f:
        f.write(md_content)
    print(f"  Saved to: {md_path}")

    print("\n" + "=" * 80)
    print("Analysis complete!")
    print(f"  Start with {len(critical_leaves)} critical leaf functions")
    print(f"  Then proceed layer by layer up to depth {max_depth}")
    print("=" * 80)

    return analysis_order

if __name__ == '__main__':
    call_graph_path = 'ghidra_export/call_graph.json'
    functions_path = 'ghidra_export/functions.json'

    try:
        analysis_order = analyze_call_graph(call_graph_path, functions_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Make sure you run this from the ndserver_re directory")
        sys.exit(1)
