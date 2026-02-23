#!/usr/bin/env python3
"""
Generate Complete Function Documentation

Master script that generates Markdown documentation for all functions
using the template from docs/FUNCTION_ANALYSIS_EXAMPLE.md.

Combines data from:
- ghidra_export/disassembly_full.asm (disassembly)
- ghidra_export/functions.json (function metadata)
- database/call_graph_complete.json (call relationships)
- database/os_library_calls.json (library usage)
- database/hardware_accesses.json (MMIO accesses)

Output: docs/functions/{address}_{name}.md
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

def load_json(file_path: Path) -> Dict:
    """Load JSON file"""
    with open(file_path) as f:
        return json.load(f)

def extract_function_disassembly(disasm_file: Path, function_name: str, func_addr: int, func_size: int) -> str:
    """Extract disassembly for a specific function"""
    lines = []
    in_function = False
    found_function = False

    with open(disasm_file) as f:
        for line in f:
            # Check for function start
            if f'; Function: {function_name}' in line:
                in_function = True
                found_function = True
                continue

            # Check for function end (next function marker or size exceeded)
            if in_function:
                if line.startswith('; Function:') and found_function:
                    # Hit next function
                    break

                # Check if we've exceeded the function size
                addr_match = re.match(r'\s*0x([0-9a-fA-F]+):', line)
                if addr_match:
                    current_addr = int(addr_match.group(1), 16)
                    if current_addr >= func_addr + func_size:
                        break

                # Add line to output
                if line.strip():
                    lines.append(line.rstrip())

    return '\n'.join(lines)

def format_calls_made(calls: List[dict], max_display: int = 20) -> str:
    """Format the calls made section"""
    if not calls:
        return "**None** - This is a **leaf function** with no BSR/JSR instructions.\n"

    # Group by type
    internal = [c for c in calls if c['type'] == 'internal']
    library = [c for c in calls if c['type'] == 'library']
    external = [c for c in calls if c['type'] == 'external']

    output = []

    if internal:
        output.append("### Internal Function Calls\n")
        for call in internal[:max_display]:
            target_name = call.get('target_name', 'UNKNOWN')
            output.append(f"- `{target_name}` at `{call['target_address_hex']}` (called from `{call['source_address_hex']}`)")

        if len(internal) > max_display:
            output.append(f"- ... and {len(internal) - max_display} more internal calls\n")
        else:
            output.append("")

    if library:
        output.append("### Library/System Calls\n")
        for call in library[:max_display]:
            output.append(f"- `{call['target_address_hex']}` (called from `{call['source_address_hex']}`)")

        if len(library) > max_display:
            output.append(f"- ... and {len(library) - max_display} more library calls\n")
        else:
            output.append("")

    if external:
        output.append("### External Calls\n")
        for call in external[:max_display]:
            output.append(f"- `{call['target_address_hex']}` (called from `{call['source_address_hex']}`)")

        if len(external) > max_display:
            output.append(f"- ... and {len(external) - max_display} more external calls\n")

    return '\n'.join(output)

def format_called_by(callers: List[dict], max_display: int = 20) -> str:
    """Format the called by section"""
    if not callers:
        return "**None** - This function is not called by any other internal function (may be an entry point or unused)\n"

    output = []
    for caller in callers[:max_display]:
        output.append(f"- `{caller['caller_name']}` at `{caller['call_site_hex']}`")

    if len(callers) > max_display:
        output.append(f"- ... and {len(callers) - max_display} more callers")

    return '\n'.join(output)

def format_hardware_access(hw_accesses: List[dict]) -> str:
    """Format hardware access section"""
    if not hw_accesses:
        return """### Hardware Registers Accessed

**None** - This function does not directly access any hardware registers.

**Rationale**:
- No memory-mapped I/O addresses in range `0x02000000-0x02FFFFFF` (NeXT hardware registers)
- No NeXTdimension MMIO in range `0xF8000000-0xFFFFFFFF` (ND RAM/VRAM/registers)
- Pure software function operating on RAM-based data structures
"""

    output = ["### Hardware Registers Accessed\n"]

    # Group by region
    by_region = {}
    for access in hw_accesses:
        region = access.get('region', 'UNKNOWN')
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(access)

    for region, accesses in sorted(by_region.items()):
        output.append(f"**{region}**:")
        for access in accesses[:10]:  # Limit to 10 per region
            reg_name = access.get('register_name', 'UNKNOWN')
            hw_addr = access.get('hardware_address_hex', '???')
            access_type = access.get('access_type', 'read')
            instr = access.get('instruction', '???')
            output.append(f"- `{hw_addr}` ({reg_name}) - {access_type.upper()} via `{instr}`")

        if len(accesses) > 10:
            output.append(f"- ... and {len(accesses) - 10} more accesses\n")
        else:
            output.append("")

    return '\n'.join(output)

def format_library_calls_detail(calls: List[dict], lib_calls_db: Dict) -> str:
    """Format library calls with details from database"""
    library_calls = [c for c in calls if c['type'] == 'library']

    if not library_calls:
        return "**None** - This function does not make any library/system calls.\n"

    output = ["### Library Functions Called\n"]

    # Get library info for each call
    lib_funcs = lib_calls_db.get('library_functions', [])
    lib_lookup = {f['address']: f for f in lib_funcs}

    for call in library_calls:
        target_addr = call['target_address']
        lib_info = lib_lookup.get(target_addr)

        if lib_info:
            name = lib_info['name']
            total_uses = lib_info['total_calls']
            output.append(f"- `{name}` at `{call['target_address_hex']}` (used {total_uses}x across codebase)")
        else:
            output.append(f"- `UNKNOWN` at `{call['target_address_hex']}`")

    return '\n'.join(output)

def generate_function_doc(
    func: dict,
    disasm: str,
    call_graph: Dict,
    lib_calls_db: Dict,
    hw_access_db: Dict
) -> str:
    """Generate complete Markdown documentation for a function"""

    func_addr = func['address']
    func_name = func['name']
    func_size = func['size']
    func_hex = func['address_hex']

    # Find function data in databases
    func_data = None
    for f in call_graph['functions']:
        if f['address'] == func_addr:
            func_data = f
            break

    if not func_data:
        func_data = {
            'calls': [],
            'called_by': [],
            'depth': 0,
            'call_counts': {'total': 0, 'internal': 0, 'library': 0, 'external': 0}
        }

    # Find hardware accesses
    hw_accesses = []
    for f in hw_access_db.get('functions', []):
        if f['address'] == func_addr:
            hw_accesses = f.get('hardware_accesses', [])
            break

    # Build document
    doc = f"""# Function Analysis: {func_name}

**Analysis Date**: {datetime.now().strftime('%B %d, %Y')}
**Tool**: Ghidra 11.2.1 (m68k disassembly)
**Binary**: NDserver (Mach-O m68k executable)

---

## Function Overview

**Address**: `{func_hex}`
**Size**: {func_size} bytes
**Call Depth**: {func_data['depth']}
**Calls Made**: {func_data['call_counts']['total']} total ({func_data['call_counts']['internal']} internal, {func_data['call_counts']['library']} library, {func_data['call_counts']['external']} external)
**Called By**: {len(func_data['called_by'])} functions

---

## Called By

{format_called_by(func_data['called_by'])}

---

## Complete Disassembly

```asm
{disasm}
```

---

## Hardware Access Analysis

{format_hardware_access(hw_accesses)}

---

## Calls Made

{format_calls_made(func_data['calls'])}

---

## Library/System Functions

{format_library_calls_detail(func_data['calls'], lib_calls_db)}

---

## Function Classification

**Type**: {'Entry Point' if not func_data['called_by'] else 'Internal Function'}
**Complexity**: {'Leaf Function' if func_data['call_counts']['total'] == 0 else f"Calls {func_data['call_counts']['total']} functions"}
**Hardware Interaction**: {'Yes' if hw_accesses else 'No'}

---

## Notes

- This documentation was automatically generated from disassembly analysis
- Function purpose and detailed behavior require manual reverse engineering
- See `FUNCTION_ANALYSIS_EXAMPLE.md` for an example of deep manual analysis

---

## Related Functions

### Calls

{format_calls_made(func_data['calls'], max_display=10)}

### Called By

{format_called_by(func_data['called_by'], max_display=10)}

---

*Generated by generate_all_function_docs.py*
"""

    return doc

def main():
    """Main execution"""
    # Paths
    project_root = Path(__file__).parent.parent
    ghidra_dir = project_root / 'ghidra_export'
    db_dir = project_root / 'database'
    docs_dir = project_root / 'docs' / 'functions'
    docs_dir.mkdir(parents=True, exist_ok=True)

    functions_json = ghidra_dir / 'functions.json'
    disasm_file = ghidra_dir / 'disassembly_full.asm'
    call_graph_file = db_dir / 'call_graph_complete.json'
    lib_calls_file = db_dir / 'os_library_calls.json'
    hw_access_file = db_dir / 'hardware_accesses.json'

    print('Generating Complete Function Documentation')
    print('=' * 60)

    # Load all data
    print('Loading data files...')
    functions = load_json(functions_json)
    call_graph = load_json(call_graph_file)
    lib_calls_db = load_json(lib_calls_file)
    hw_access_db = load_json(hw_access_file)

    print(f'  Functions: {len(functions)}')
    print(f'  Call graph entries: {len(call_graph["functions"])}')
    print(f'  Library functions: {lib_calls_db["metadata"]["total_library_functions"]}')
    print(f'  Functions with HW access: {hw_access_db["metadata"]["functions_with_hw_access"]}')

    # Generate documentation for each function
    print()
    print('Generating function documentation...')

    generated = 0
    errors = 0

    for func in functions:
        func_name = func['name']
        func_addr = func['address']
        func_hex = func['address_hex']

        try:
            # Extract disassembly
            disasm = extract_function_disassembly(
                disasm_file,
                func_name,
                func_addr,
                func['size']
            )

            if not disasm:
                print(f'  WARNING: No disassembly found for {func_name}')
                disasm = '; [No disassembly available]'

            # Generate documentation
            doc = generate_function_doc(
                func,
                disasm,
                call_graph,
                lib_calls_db,
                hw_access_db
            )

            # Save to file
            output_file = docs_dir / f'{func_hex}_{func_name}.md'
            with open(output_file, 'w') as f:
                f.write(doc)

            generated += 1

            if generated % 10 == 0:
                print(f'  Generated {generated}/{len(functions)} docs...')

        except Exception as e:
            print(f'  ERROR generating {func_name}: {e}')
            errors += 1

    print()
    print('Done!')
    print(f'  Successfully generated: {generated} docs')
    print(f'  Errors: {errors}')
    print(f'  Output directory: {docs_dir}')

    # Generate index
    print()
    print('Generating function index...')
    index_file = docs_dir / 'INDEX.md'

    with open(index_file, 'w') as f:
        f.write('# NDserver Function Documentation Index\n\n')
        f.write(f'**Generated**: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}\n')
        f.write(f'**Total Functions**: {len(functions)}\n\n')
        f.write('---\n\n')

        # Group by address range
        f.write('## Functions by Address\n\n')
        for func in sorted(functions, key=lambda x: x['address']):
            func_name = func['name']
            func_hex = func['address_hex']
            func_size = func['size']

            # Get call info
            func_data = None
            for fd in call_graph['functions']:
                if fd['address'] == func['address']:
                    func_data = fd
                    break

            if func_data:
                depth = func_data['depth']
                calls = func_data['call_counts']['total']
                called_by = len(func_data['called_by'])
                f.write(f'- [{func_name}]({func_hex}_{func_name}.md) - `{func_hex}` ({func_size} bytes, depth={depth}, calls={calls}, called_by={called_by})\n')
            else:
                f.write(f'- [{func_name}]({func_hex}_{func_name}.md) - `{func_hex}` ({func_size} bytes)\n')

    print(f'  Index saved to {index_file}')

if __name__ == '__main__':
    main()
