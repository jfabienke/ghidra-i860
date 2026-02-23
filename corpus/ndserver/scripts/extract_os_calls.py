#!/usr/bin/env python3
"""
Extract OS Library Calls

Catalog all library calls (addresses >= 0x05000000) and group by target.
Provides frequency analysis and identifies commonly used system functions.

Output: database/os_library_calls.json
"""

import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

# Known library function names (from common NeXTSTEP/Mach libraries)
KNOWN_LIBRARY_FUNCTIONS = {
    0x05000000: 'libsys_s_entry',
    0x050024b0: 'exit',
    0x0500219e: 'atoi',
    0x05002a14: 'device_port_lookup',
    0x050028c4: 'printf',
    0x05002ce4: 'fprintf / puts',
    0x05003008: 'strcmp',
    0x05002d98: 'strcpy / strdup',
    0x05002efc: 'strlen',
    0x05003240: 'memcpy',
    0x050032a0: 'memset',
    0x05003384: 'malloc',
    0x050033e4: 'free',
    0x05003444: 'calloc',
    0x050034a4: 'realloc',
    # Add more as discovered
}

def load_call_graph(call_graph_file: Path) -> Dict:
    """Load complete call graph"""
    with open(call_graph_file) as f:
        return json.load(f)

def extract_library_calls(call_graph: Dict) -> Dict[int, List[dict]]:
    """
    Extract all library calls grouped by target address
    Returns: dict mapping library_address -> list of call sites
    """
    library_calls = defaultdict(list)

    for func in call_graph['functions']:
        func_addr = func['address']
        func_name = func['name']

        for call in func['calls']:
            if call['type'] == 'library':
                target_addr = call['target_address']
                call_info = {
                    'caller_function': func_name,
                    'caller_address': func_addr,
                    'caller_address_hex': func['address_hex'],
                    'call_site': call['source_address'],
                    'call_site_hex': call['source_address_hex'],
                    'instruction': call['instruction']
                }
                library_calls[target_addr].append(call_info)

    return dict(library_calls)

def analyze_library_usage(library_calls: Dict[int, List[dict]]) -> List[dict]:
    """Analyze library call patterns and create sorted summary"""
    library_summary = []

    for lib_addr, call_sites in library_calls.items():
        # Get known name or mark as unknown
        lib_name = KNOWN_LIBRARY_FUNCTIONS.get(lib_addr, 'UNKNOWN')

        # Group by caller function
        callers = defaultdict(int)
        for site in call_sites:
            callers[site['caller_function']] += 1

        entry = {
            'address': lib_addr,
            'address_hex': f'0x{lib_addr:08x}',
            'name': lib_name,
            'total_calls': len(call_sites),
            'caller_count': len(callers),
            'call_sites': call_sites,
            'callers': [
                {
                    'function': func,
                    'call_count': count
                }
                for func, count in sorted(callers.items(), key=lambda x: -x[1])
            ]
        }

        library_summary.append(entry)

    # Sort by total calls (most frequently used first)
    library_summary.sort(key=lambda x: -x['total_calls'])

    return library_summary

def categorize_library_functions(library_summary: List[dict]) -> Dict[str, List[dict]]:
    """Categorize library functions by type"""
    categories = {
        'Memory Management': [],
        'String Operations': [],
        'I/O and Formatting': [],
        'Process Control': [],
        'Device/Driver Interface': [],
        'Unknown': []
    }

    # Simple categorization based on known functions
    memory_funcs = {'malloc', 'free', 'calloc', 'realloc', 'memcpy', 'memset'}
    string_funcs = {'strcmp', 'strcpy', 'strdup', 'strlen', 'strcat', 'strchr'}
    io_funcs = {'printf', 'fprintf', 'sprintf', 'puts', 'scanf', 'fopen', 'fclose', 'read', 'write'}
    process_funcs = {'exit', 'fork', 'exec', 'wait', 'signal'}
    device_funcs = {'device_port_lookup', 'IOKit', 'driver', 'port_allocate', 'vm_allocate'}

    for entry in library_summary:
        name = entry['name'].lower()
        categorized = False

        if any(func in name for func in memory_funcs):
            categories['Memory Management'].append(entry)
            categorized = True
        elif any(func in name for func in string_funcs):
            categories['String Operations'].append(entry)
            categorized = True
        elif any(func in name for func in io_funcs):
            categories['I/O and Formatting'].append(entry)
            categorized = True
        elif any(func in name for func in process_funcs):
            categories['Process Control'].append(entry)
            categorized = True
        elif any(func in name for func in device_funcs):
            categories['Device/Driver Interface'].append(entry)
            categorized = True

        if not categorized:
            categories['Unknown'].append(entry)

    return categories

def main():
    """Main execution"""
    # Paths
    project_root = Path(__file__).parent.parent
    db_dir = project_root / 'database'
    call_graph_file = db_dir / 'call_graph_complete.json'
    output_file = db_dir / 'os_library_calls.json'

    print('Extracting OS Library Calls')
    print('=' * 60)

    # Load call graph
    print(f'Loading call graph from {call_graph_file}...')
    call_graph = load_call_graph(call_graph_file)
    total_funcs = call_graph['metadata']['total_functions']
    print(f'  {total_funcs} functions in call graph')

    # Extract library calls
    print('Extracting library calls...')
    library_calls = extract_library_calls(call_graph)
    print(f'  Found {len(library_calls)} unique library functions')
    total_lib_calls = sum(len(sites) for sites in library_calls.values())
    print(f'  Total library call sites: {total_lib_calls}')

    # Analyze usage
    print('Analyzing library usage patterns...')
    library_summary = analyze_library_usage(library_calls)

    # Categorize
    print('Categorizing library functions...')
    categories = categorize_library_functions(library_summary)

    # Print category summary
    print()
    print('Library Function Categories:')
    for category, funcs in categories.items():
        if funcs:
            total_calls = sum(f['total_calls'] for f in funcs)
            print(f'  {category}: {len(funcs)} functions, {total_calls} calls')

    # Build output
    output = {
        'metadata': {
            'total_library_functions': len(library_calls),
            'total_call_sites': total_lib_calls,
            'known_functions': sum(1 for f in library_summary if f['name'] != 'UNKNOWN'),
            'unknown_functions': sum(1 for f in library_summary if f['name'] == 'UNKNOWN')
        },
        'library_functions': library_summary,
        'by_category': categories,
        'top_10_most_called': library_summary[:10]
    }

    # Save output
    print(f'\nSaving library calls to {output_file}...')
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print('Done!')
    print()
    print('Top 10 Most Called Library Functions:')
    for i, func in enumerate(library_summary[:10], 1):
        name = func['name'] if func['name'] != 'UNKNOWN' else f'UNKNOWN_{func["address_hex"]}'
        print(f'  {i:2d}. {name:30s} - {func["total_calls"]:3d} calls from {func["caller_count"]:2d} functions')

    # List unknown functions
    unknown = [f for f in library_summary if f['name'] == 'UNKNOWN']
    if unknown:
        print(f'\nUnknown Library Functions ({len(unknown)}):')
        for func in unknown[:10]:
            print(f'  - {func["address_hex"]} - {func["total_calls"]} calls')
        if len(unknown) > 10:
            print(f'  ... and {len(unknown) - 10} more')

if __name__ == '__main__':
    main()
