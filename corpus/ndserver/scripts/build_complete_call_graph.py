#!/usr/bin/env python3
"""
Build Complete Call Graph from Disassembly

This script parses the Ghidra disassembly to extract ALL function calls
(BSR.L and JSR instructions) and builds a complete call graph.

The Ghidra call_graph.json only contains 29 of 88 functions, so we rebuild
the complete graph by parsing the disassembly directly.

Output: database/call_graph_complete.json
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# Memory ranges
CODE_START = 0x00002000
CODE_END = 0x00008000
LIBRARY_START = 0x05000000

def parse_address(addr_str: str) -> int:
    """Parse hex address string to integer"""
    addr_str = addr_str.strip()
    if addr_str.startswith('0x'):
        return int(addr_str, 16)
    elif addr_str.startswith('(') and addr_str.endswith(').l'):
        # Extract address from (0x1234).l format
        return int(addr_str[1:-3], 16)
    else:
        try:
            return int(addr_str, 16)
        except ValueError:
            return 0

def is_call_instruction(line: str) -> Tuple[bool, str, str]:
    """
    Check if line is a call instruction (BSR or JSR)
    Returns: (is_call, instruction, target_address)
    """
    line = line.strip()

    # Match BSR.L or JSR instructions
    # Format: "  0x00002df2:  bsr.l      0x05003008"
    # Format: "  0x00002e16:  bsr.l      0x0000305c     ; -> FUN_0000305c"
    match = re.match(r'\s*0x[0-9a-fA-F]+:\s+(bsr\.l|jsr)\s+(.+?)(?:\s+;.*)?$', line)

    if not match:
        return False, '', ''

    instruction = match.group(1)
    target = match.group(2).strip()

    return True, instruction, target

def load_functions(functions_json: Path) -> Dict[int, dict]:
    """Load function metadata from functions.json"""
    with open(functions_json) as f:
        functions = json.load(f)

    func_map = {}
    for func in functions:
        addr = func['address']
        func_map[addr] = {
            'address': addr,
            'address_hex': func['address_hex'],
            'name': func['name'],
            'size': func['size'],
            'external': func.get('external', False),
            'thunk': func.get('thunk', False)
        }

    return func_map

def find_function_containing(address: int, func_map: Dict[int, dict]) -> dict:
    """Find which function contains this address"""
    for addr, func in sorted(func_map.items()):
        if addr <= address < addr + func['size']:
            return func
    return None

def classify_call(target_addr: int) -> str:
    """Classify call target as internal, library, or external"""
    if CODE_START <= target_addr < CODE_END:
        return 'internal'
    elif target_addr >= LIBRARY_START:
        return 'library'
    else:
        return 'external'

def parse_disassembly(disasm_file: Path, func_map: Dict[int, dict]) -> Dict[int, List[dict]]:
    """
    Parse disassembly to extract all function calls
    Returns: dict mapping function_address -> list of calls
    """
    calls_by_function = defaultdict(list)
    current_function = None
    current_function_addr = None

    with open(disasm_file) as f:
        for line in f:
            # Track current function
            if line.startswith('; Function:'):
                # Extract function name
                parts = line.split(':', 1)
                if len(parts) > 1:
                    func_name = parts[1].strip()
                    # Find corresponding function in func_map
                    for addr, func in func_map.items():
                        if func['name'] == func_name:
                            current_function = func
                            current_function_addr = addr
                            break
                continue

            # Check for function address marker
            if line.startswith('; Address:'):
                addr_str = line.split(':', 1)[1].strip()
                addr = parse_address(addr_str)
                if addr in func_map:
                    current_function = func_map[addr]
                    current_function_addr = addr
                continue

            # Parse instruction lines
            is_call, instr, target = is_call_instruction(line)
            if is_call and current_function_addr:
                target_addr = parse_address(target)
                if target_addr > 0:
                    call_type = classify_call(target_addr)

                    # Extract source address from line
                    addr_match = re.match(r'\s*0x([0-9a-fA-F]+):', line)
                    source_addr = int(addr_match.group(1), 16) if addr_match else 0

                    # Find target function name if internal
                    target_name = None
                    if call_type == 'internal' and target_addr in func_map:
                        target_name = func_map[target_addr]['name']

                    call_info = {
                        'source_address': source_addr,
                        'source_address_hex': f'0x{source_addr:08x}',
                        'target_address': target_addr,
                        'target_address_hex': f'0x{target_addr:08x}',
                        'instruction': instr,
                        'type': call_type,
                        'target_name': target_name
                    }

                    calls_by_function[current_function_addr].append(call_info)

    return dict(calls_by_function)

def calculate_depths(func_map: Dict[int, dict], call_graph: Dict[int, List[dict]]) -> Dict[int, int]:
    """
    Calculate call depth for each function using topological sort
    Depth = longest path from entry point (main) to function
    """
    depths = {}
    visited = set()

    def calculate_depth(func_addr: int, visiting: Set[int]) -> int:
        """Recursively calculate depth, detecting cycles"""
        if func_addr in depths:
            return depths[func_addr]

        if func_addr in visiting:
            # Cycle detected - return large depth
            return 999

        # Get all callees of this function
        calls = call_graph.get(func_addr, [])
        internal_callees = [c['target_address'] for c in calls if c['type'] == 'internal']

        if not internal_callees:
            # Leaf function
            depths[func_addr] = 0
            return 0

        # Calculate depth as 1 + max(callee depths)
        visiting.add(func_addr)
        max_callee_depth = 0
        for callee_addr in internal_callees:
            if callee_addr in func_map:
                callee_depth = calculate_depth(callee_addr, visiting)
                max_callee_depth = max(max_callee_depth, callee_depth)
        visiting.remove(func_addr)

        depths[func_addr] = max_callee_depth + 1
        return depths[func_addr]

    # Calculate depths for all functions
    for func_addr in func_map:
        if func_addr not in depths:
            calculate_depth(func_addr, set())

    return depths

def build_reverse_call_graph(call_graph: Dict[int, List[dict]], func_map: Dict[int, dict]) -> Dict[int, List[dict]]:
    """Build reverse call graph: function -> list of callers"""
    called_by = defaultdict(list)

    for caller_addr, calls in call_graph.items():
        caller_info = func_map.get(caller_addr)
        if not caller_info:
            continue

        for call in calls:
            if call['type'] == 'internal':
                target_addr = call['target_address']
                called_by[target_addr].append({
                    'caller_address': caller_addr,
                    'caller_address_hex': f'0x{caller_addr:08x}',
                    'caller_name': caller_info['name'],
                    'call_site': call['source_address'],
                    'call_site_hex': call['source_address_hex']
                })

    return dict(called_by)

def main():
    """Main execution"""
    # Paths
    project_root = Path(__file__).parent.parent
    ghidra_dir = project_root / 'ghidra_export'
    db_dir = project_root / 'database'
    db_dir.mkdir(exist_ok=True)

    functions_json = ghidra_dir / 'functions.json'
    disasm_file = ghidra_dir / 'disassembly_full.asm'
    output_file = db_dir / 'call_graph_complete.json'

    print('Building Complete Call Graph from Disassembly')
    print('=' * 60)

    # Load functions
    print(f'Loading functions from {functions_json}...')
    func_map = load_functions(functions_json)
    print(f'  Found {len(func_map)} functions')

    # Parse disassembly
    print(f'Parsing disassembly from {disasm_file}...')
    call_graph = parse_disassembly(disasm_file, func_map)
    print(f'  Found {len(call_graph)} functions with calls')

    # Count call types
    total_calls = 0
    internal_calls = 0
    library_calls = 0
    external_calls = 0

    for calls in call_graph.values():
        for call in calls:
            total_calls += 1
            if call['type'] == 'internal':
                internal_calls += 1
            elif call['type'] == 'library':
                library_calls += 1
            else:
                external_calls += 1

    print(f'  Total calls: {total_calls}')
    print(f'    Internal: {internal_calls}')
    print(f'    Library:  {library_calls}')
    print(f'    External: {external_calls}')

    # Calculate depths
    print('Calculating call depths...')
    depths = calculate_depths(func_map, call_graph)
    max_depth = max(depths.values()) if depths else 0
    print(f'  Maximum depth: {max_depth}')

    # Build reverse call graph
    print('Building reverse call graph (called_by)...')
    called_by = build_reverse_call_graph(call_graph, func_map)
    print(f'  Found {len(called_by)} functions that are called')

    # Build complete output
    output = {
        'metadata': {
            'total_functions': len(func_map),
            'functions_with_calls': len(call_graph),
            'total_calls': total_calls,
            'internal_calls': internal_calls,
            'library_calls': library_calls,
            'external_calls': external_calls,
            'max_depth': max_depth,
            'code_range': {
                'start': f'0x{CODE_START:08x}',
                'end': f'0x{CODE_END:08x}'
            }
        },
        'functions': []
    }

    # Add function entries
    for func_addr in sorted(func_map.keys()):
        func = func_map[func_addr]
        calls = call_graph.get(func_addr, [])
        callers = called_by.get(func_addr, [])
        depth = depths.get(func_addr, 0)

        # Count call types for this function
        func_internal = sum(1 for c in calls if c['type'] == 'internal')
        func_library = sum(1 for c in calls if c['type'] == 'library')
        func_external = sum(1 for c in calls if c['type'] == 'external')

        func_entry = {
            'address': func_addr,
            'address_hex': func['address_hex'],
            'name': func['name'],
            'size': func['size'],
            'external': func['external'],
            'thunk': func['thunk'],
            'depth': depth,
            'calls': calls,
            'called_by': callers,
            'call_counts': {
                'total': len(calls),
                'internal': func_internal,
                'library': func_library,
                'external': func_external
            },
            'caller_count': len(callers)
        }

        output['functions'].append(func_entry)

    # Save output
    print(f'Saving complete call graph to {output_file}...')
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print('Done!')
    print()
    print('Summary:')
    print(f'  Functions analyzed: {len(func_map)}')
    print(f'  Functions with calls: {len(call_graph)}')
    print(f'  Leaf functions: {len(func_map) - len(call_graph)}')
    print(f'  Maximum call depth: {max_depth}')
    print(f'  Average calls per function: {total_calls / len(func_map):.1f}')

    # Find entry points (functions not called by anyone)
    entry_points = [f for f in func_map.keys() if f not in called_by]
    print(f'  Entry points (not called): {len(entry_points)}')
    if entry_points:
        for addr in sorted(entry_points)[:5]:
            print(f'    - {func_map[addr]["name"]} @ {func_map[addr]["address_hex"]}')
        if len(entry_points) > 5:
            print(f'    ... and {len(entry_points) - 5} more')

if __name__ == '__main__':
    main()
