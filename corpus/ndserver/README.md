# NDserver Reverse Engineering

**Target**: NeXTdimension host driver (NDserver)
**Binary**: `NDserver` (m68k Mach-O, 816KB)
**Source**: NeXTSTEP 3.3
**Goal**: Discover host→NeXTdimension high-level protocol

## Directory Structure

```
ndserver_re/
├── README.md                    # This file
├── NDserver                     # Target binary
├── analysis/                    # Analysis output
│   ├── binary_info.txt
│   ├── functions.txt
│   ├── strings.txt
│   ├── imports.txt
│   └── callgraph.dot
├── disassembly/                 # Disassembly output
│   ├── main.asm
│   ├── full_disasm.asm
│   └── annotated/
├── extracted/                   # Extracted data
│   ├── i860_kernel.bin
│   └── data_sections/
├── scripts/                     # Analysis scripts
│   ├── extract_csr_accesses.py
│   ├── find_protocol_structs.py
│   └── correlate_hardware_log.py
└── docs/                        # Documentation
    ├── PROTOCOL_DISCOVERED.md
    ├── FUNCTION_MAP.md
    └── FINDINGS.md
```

## Quick Start

### 1. Basic Info

```bash
# Get binary info
file NDserver
otool -hv NDserver
otool -lv NDserver

# Or with radare2
r2 -A NDserver -c 'iI; iS; ie'
```

### 2. String Analysis

```bash
strings -n 8 NDserver > analysis/strings.txt
grep -iE "csr|dimension|vram|kernel|error" analysis/strings.txt
```

### 3. Disassembly

```bash
r2 -A NDserver <<EOF
aaa
afl > analysis/functions.txt
pdf @ main > disassembly/main.asm
EOF
```

### 4. Function Analysis

```bash
r2 -A NDserver <<EOF
aaa
agC > analysis/callgraph.dot
EOF

dot -Tpng analysis/callgraph.dot -o analysis/callgraph.png
```

## Key Addresses

From hardware capture correlation:

- **CSR0**: `0xFF800000` - Control/Status Register
- **CSR1**: `0xFF800010` - i860→Host Interrupt
- **ND RAM Window**: `0xF8000000-0xFBFFFFFF` (64MB)
- **ND VRAM Window**: `0xFE000000-0xFE3FFFFF` (4MB)

## Research Questions

1. **How does NDserver detect the board?**
   - NeXTBus slot scanning?
   - Board ID verification?

2. **What triggers CSR0/CSR1 writes?**
   - From our logs: 85% CSR0 reads, 15% writes
   - What operations cause writes?

3. **How is shared memory used?**
   - Command structure?
   - Data buffers?

4. **How is the i860 kernel loaded?**
   - Where's the embedded kernel?
   - Loading mechanism?

5. **What graphics operations are sent?**
   - Operation codes?
   - Parameter format?

## Tools

- **radare2**: Primary disassembly/analysis
- **r2pipe**: Python automation
- **Ghidra**: Optional GUI analysis
- **Python**: Protocol reconstruction scripts

## Progress Tracking

- [ ] Phase 1: Binary structure (Week 1)
- [ ] Phase 2: Control flow (Week 2)
- [ ] Phase 3: Protocol discovery (Week 3)
- [ ] Phase 4: Dynamic analysis (Week 4)
- [ ] Phase 5: Documentation (Week 5)

## References

- `../NDSERVER_RE_PLAN.md` - Complete methodology
- `../NEXTDIMENSION_PROTOCOL_COMPLETE.md` - Hardware protocol spec
- `/tmp/previous_mailbox.log` - 583K captured operations
- `/Users/jvindahl/Development/previous/src/ROM_ANALYSIS.md` - System ROM
