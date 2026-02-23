# NDserver Analysis Scripts

Automated analysis tools for reverse engineering the NDserver binary.

---

## Scripts Overview

### 1. build_complete_call_graph.py
**Builds complete call graph from Ghidra disassembly**

**Input**:
- `ghidra_export/disassembly_full.asm`
- `ghidra_export/functions.json`

**Output**:
- `database/call_graph_complete.json`

**What it does**:
- Parses all BSR.L and JSR instructions
- Classifies calls as internal/library/external
- Calculates call depths
- Builds bidirectional call graph (calls + called_by)

**Why needed**: Ghidra's call_graph.json only had 29/88 functions

**Run**: `python3 build_complete_call_graph.py`

---

### 2. extract_os_calls.py
**Catalogs all OS/library function calls**

**Input**:
- `database/call_graph_complete.json`

**Output**:
- `database/os_library_calls.json`

**What it does**:
- Extracts calls to library addresses (0x05000000+)
- Groups by target address
- Calculates usage frequency
- Categorizes by function type

**Run**: `python3 extract_os_calls.py`

---

### 3. extract_hardware_access.py
**Finds all hardware register accesses**

**Input**:
- `ghidra_export/disassembly_full.asm`
- `ghidra_export/functions.json`

**Output**:
- `database/hardware_accesses.json`

**What it does**:
- Parses disassembly for absolute memory accesses
- Classifies by memory region (NeXT HW, System Data, ND RAM/VRAM)
- Identifies read vs write operations
- Maps to known register names

**Run**: `python3 extract_hardware_access.py`

---

### 4. generate_all_function_docs.py
**Master documentation generator**

**Input**:
- `ghidra_export/disassembly_full.asm`
- `ghidra_export/functions.json`
- `database/call_graph_complete.json`
- `database/os_library_calls.json`
- `database/hardware_accesses.json`

**Output**:
- `docs/functions/{address}_{name}.md` (88 files)
- `docs/functions/INDEX.md`

**What it does**:
- Extracts per-function disassembly
- Combines all analysis data
- Generates comprehensive Markdown documentation
- Creates searchable function index

**Run**: `python3 generate_all_function_docs.py`

---

## Complete Workflow

Run scripts in order (each depends on previous outputs):

```bash
cd /Users/jvindahl/Development/nextdimension/ndserver_re/scripts

# Step 1: Build complete call graph
python3 build_complete_call_graph.py

# Step 2: Extract library calls (depends on call graph)
python3 extract_os_calls.py

# Step 3: Extract hardware accesses (independent)
python3 extract_hardware_access.py

# Step 4: Generate all documentation (depends on all above)
python3 generate_all_function_docs.py
```

**Total runtime**: ~5-10 seconds

---

## Dependencies

**Python**: 3.6+ (tested with 3.9)

**Standard Libraries**:
- json
- re
- pathlib
- collections
- datetime
- typing

**No external packages required** - uses only Python standard library

---

## Output Files

### Database Files (database/)
- `call_graph_complete.json` (~250 KB) - Complete call graph with metadata
- `os_library_calls.json` (~180 KB) - Library usage analysis
- `hardware_accesses.json` (~45 KB) - Hardware register access patterns

### Documentation (docs/functions/)
- 88 function documentation files
- INDEX.md with summary and links
- Total size: ~1.2 MB

---

## Customization

### Adding Known Library Functions
Edit `extract_os_calls.py`:

```python
KNOWN_LIBRARY_FUNCTIONS = {
    0x05000000: 'libsys_s_entry',
    0x050024b0: 'exit',
    # Add more here
}
```

### Adding Hardware Registers
Edit `extract_hardware_access.py`:

```python
NEXT_REGISTERS = {
    0x02000000: 'DMA_CSR',
    # Add more here
}
```

### Modifying Documentation Template
Edit `generate_all_function_docs.py`, function `generate_function_doc()`

---

## Troubleshooting

### "File not found" errors
- Ensure you run scripts from the `scripts/` directory
- Or use absolute paths in script arguments

### "No disassembly found" warnings
- Check that `ghidra_export/disassembly_full.asm` exists
- Verify function names match between `functions.json` and disassembly

### Empty call graph
- Verify BSR/JSR instructions are present in disassembly
- Check address ranges (CODE_START, CODE_END) match your binary

---

## Extending the Scripts

### Adding New Analysis
Create a new script following this pattern:

```python
#!/usr/bin/env python3
import json
from pathlib import Path

def main():
    project_root = Path(__file__).parent.parent

    # Load input data
    with open(project_root / 'database/call_graph_complete.json') as f:
        data = json.load(f)

    # Do analysis
    results = analyze(data)

    # Save output
    output_file = project_root / 'database/my_analysis.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    main()
```

---

## Examples

### Query Call Graph
```python
import json

with open('../database/call_graph_complete.json') as f:
    cg = json.load(f)

# Find entry points
entry_points = [f for f in cg['functions']
                if len(f['called_by']) == 0]
print(f"Entry points: {len(entry_points)}")

# Find most-called function
most_called = max(cg['functions'],
                  key=lambda f: len(f['called_by']))
print(f"Most called: {most_called['name']} "
      f"({len(most_called['called_by'])} callers)")
```

### Find Library Usage
```python
import json

with open('../database/os_library_calls.json') as f:
    lib_calls = json.load(f)

# Top 5 library functions
top_5 = lib_calls['top_10_most_called'][:5]
for func in top_5:
    print(f"{func['name']:30s} - {func['total_calls']} calls")
```

### Find Hardware Access
```python
import json

with open('../database/hardware_accesses.json') as f:
    hw = json.load(f)

# Functions that access hardware
hw_funcs = hw['functions']
print(f"Functions with HW access: {len(hw_funcs)}")

for func in hw_funcs:
    print(f"{func['name']:20s} - "
          f"{func['access_count']} accesses")
```

---

## Performance

**Benchmarks** (M1 Mac, Python 3.9):
- `build_complete_call_graph.py`: ~2 seconds
- `extract_os_calls.py`: ~1 second
- `extract_hardware_access.py`: ~2 seconds
- `generate_all_function_docs.py`: ~5 seconds

**Total**: ~10 seconds for complete analysis of 88 functions

**Memory usage**: ~50 MB peak (loading all JSON data)

---

## License

These scripts are part of the NDserver reverse engineering project for the Previous emulator.

---

*For more information, see AUTOMATION_SUMMARY.md in the project root*
