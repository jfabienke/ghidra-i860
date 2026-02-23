# NDserver Comprehensive Analysis Project Plan

**Goal**: Complete reverse engineering of NeXTSTEP NDserver driver
**Scope**: Protocol documentation + Complete function database + OS/Hardware analysis
**Timeline**: 3-4 weeks
**Date Started**: November 8, 2025

---

## Deliverables

### 1. **Protocol Specification Document** 📋
- Host ↔ NeXTDimension communication protocol
- Message formats (Mach IPC structure)
- Command opcodes (kern_loader interface)
- Shared memory layout
- Initialization sequence
- Error handling and recovery

### 2. **Individual Function Documentation** 📝
- **88-92 Markdown files** (one per function)
- Format: Like `FUNCTION_ANALYSIS_EXAMPLE.md`
- Sections per function:
  - Complete disassembly
  - Hardware access analysis
  - OS functions and library calls
  - Reverse-engineered C pseudocode
  - Data structures
  - Call graph integration
  - Purpose and classification

### 3. **OS/Library Call Reference** 📚
- Complete catalog of all library functions used
- Mach IPC calls (port_allocate, msg_send, etc.)
- kern_loader facility usage
- IOKit device operations
- C library functions (malloc, printf, etc.)
- Usage frequency and context

### 4. **Hardware Access Documentation** 🔧
- All MMIO register accesses
- Memory-mapped addresses (0x02000000+, 0xF8000000+)
- Read vs write operations
- Initialization sequences
- Register functions and bit definitions

### 5. **Fully Annotated Disassembly** 📄
- Complete m68k disassembly with comments
- Function purposes inline
- Data structure references
- Cross-references to protocol spec
- Library call annotations
- Hardware access annotations

### 6. **Interactive Call Graph** 🕸️
- Visual call graph (Graphviz/Mermaid)
- Function relationships
- Library call dependencies
- Color-coded by category
- Clickable links to function docs

### 7. **Searchable Function Database** 🗄️
- JSON database with all function metadata
- Searchable by: address, name, purpose, calls made, hardware accessed
- Integration with call graph
- Cross-referenced with protocol spec

---

## Project Structure

```
ndserver_re/
├── docs/
│   ├── PROTOCOL_SPECIFICATION.md          # Main protocol doc
│   ├── OS_LIBRARY_CALLS.md                # Complete OS call reference
│   ├── HARDWARE_REGISTERS.md              # MMIO register map
│   ├── FUNCTION_ANALYSIS_EXAMPLE.md       # Template (✓ done)
│   ├── PROJECT_PLAN_COMPREHENSIVE.md      # This file
│   └── functions/                         # Individual function docs
│       ├── 00002dc6_ND_GetBoardList.md
│       ├── 00003820_ND_LookupBoardBySlot.md
│       └── ... (88-92 total)
│
├── disassembly/
│   ├── annotated_full.asm                 # Complete annotated disassembly
│   ├── functions/                         # Individual function disassemblies
│   │   ├── 00002dc6_ND_GetBoardList.asm
│   │   └── ... (88-92 total)
│   └── call_graph.dot                     # Graphviz call graph
│
├── database/
│   ├── functions.json                     # Complete function database
│   ├── os_calls.json                      # OS/library call catalog
│   ├── hardware_access.json               # MMIO register access log
│   └── protocol_messages.json             # Protocol message definitions
│
├── analysis/
│   ├── function_map.txt                   # Phase 2 ground truth
│   ├── annotated_functions.json           # Phase 2 metadata
│   └── strings_categorized.txt            # String analysis
│
└── ghidra_export/
    ├── functions.json                     # Ghidra function list
    ├── call_graph.json                    # Ghidra call graph
    └── disassembly_full.asm               # Ghidra raw disassembly
```

---

## Phase 3 - Comprehensive Analysis

### Phase 3.1: Foundation (Week 1) ✅ STARTED

**Tasks**:
- [x] Export Ghidra disassembly
- [x] Verify export quality
- [x] Create function analysis template
- [ ] Reconcile Ghidra (88) vs Phase 2 (92) function count
- [ ] Generate initial function classification
- [ ] Set up documentation structure

**Deliverables**:
- Clean Ghidra export
- Function analysis template
- Initial function database

---

### Phase 3.2: OS/Library Analysis (Week 1-2)

**Tasks**:
1. **Identify all library calls**:
   - Extract all BSR.L calls to 0x05000000+ addresses
   - Identify unique library functions
   - Map addresses to function names (cross-ref with libsys_s headers)

2. **Categorize OS calls**:
   - Mach IPC: port_allocate, msg_send, msg_receive, etc.
   - kern_loader: server_load, server_getinfo, etc.
   - IOKit: IOServiceGetMatchingServices, IODeviceMatching, etc.
   - VM: vm_allocate, vm_deallocate, vm_read, vm_write
   - C library: printf, malloc, free, strcmp, memcpy, etc.

3. **Document usage patterns**:
   - Which functions call which OS functions
   - Parameter passing patterns
   - Return value handling
   - Error checking

4. **Create OS call reference**:
   - Function signatures
   - Purpose and behavior
   - Usage frequency
   - Critical vs optional calls

**Deliverables**:
- `OS_LIBRARY_CALLS.md` (comprehensive reference)
- `database/os_calls.json` (structured data)
- Annotated call sites in disassembly

**Estimated Time**: 3-4 days

---

### Phase 3.3: Hardware Access Analysis (Week 2)

**Tasks**:
1. **Identify MMIO accesses**:
   - Search for addresses in range 0x02000000-0x02FFFFFF (NeXT hardware)
   - Search for addresses in range 0xF8000000-0xFFFFFFFF (NeXTdimension)
   - Extract all memory access instructions

2. **Classify registers**:
   - Mailbox registers
   - DMA control registers
   - Video/RAMDAC registers
   - Interrupt control
   - System control
   - Status registers

3. **Document access patterns**:
   - Initialization sequences
   - Read vs write operations
   - Register dependencies
   - Timing-critical operations

4. **Map to hardware**:
   - Cross-reference with `nextdimension_hardware.h`
   - Verify against emulator code
   - Compare with hardware capture logs

**Deliverables**:
- `HARDWARE_REGISTERS.md` (complete register map)
- `database/hardware_access.json` (access patterns)
- Hardware annotations in disassembly

**Estimated Time**: 3-4 days

---

### Phase 3.4: Protocol Discovery (Week 2-3)

**Tasks**:
1. **Find kern_loader usage**:
   - Locate all kern_loader calls
   - Analyze message construction
   - Document command types

2. **Analyze Mach IPC**:
   - Message format structures
   - Port allocation and management
   - Send/receive patterns
   - Timeout and error handling

3. **Map shared memory**:
   - Identify shared memory windows
   - Buffer allocation patterns
   - Synchronization mechanisms

4. **Document initialization**:
   - Board detection sequence
   - Firmware loading process
   - Configuration setup
   - Ready state detection

5. **Trace graphics commands**:
   - Display PostScript → ND command translation
   - Command queuing
   - Synchronization points

**Deliverables**:
- `PROTOCOL_SPECIFICATION.md` (complete protocol doc)
- `database/protocol_messages.json` (message definitions)
- Sequence diagrams for key operations

**Estimated Time**: 5-6 days

---

### Phase 3.5: Function-by-Function Analysis (Week 3-4)

**Tasks**:
1. **Classify all functions**:
   - Initialization (board detection, setup)
   - Communication (kern_loader, IPC)
   - Graphics (command construction, submission)
   - Utility (memory management, string handling)
   - Error handling

2. **Deep-dive critical functions** (20-25 functions):
   - ND_GetBoardList (board enumeration)
   - ND_LoadKernel (firmware loading)
   - ND_SendCommand (command dispatch)
   - ND_InitMailbox (mailbox setup)
   - ND_WaitReady (synchronization)
   - Graphics command builders
   - Memory management functions
   - Error handlers

3. **Quick-analyze remaining functions** (60-70 functions):
   - Extract basic metadata
   - Identify calls made
   - Classify purpose
   - Document key behaviors

4. **Generate Markdown docs**:
   - Use template from FUNCTION_ANALYSIS_EXAMPLE.md
   - Include all sections:
     - Overview
     - Complete disassembly
     - Hardware access
     - OS function calls
     - C pseudocode
     - Data structures
     - Call graph integration
     - Purpose analysis

**Deliverables**:
- 88-92 individual function Markdown docs
- `database/functions.json` (complete function database)
- Function classification matrix

**Estimated Time**: 8-10 days

---

### Phase 3.6: Annotated Disassembly (Week 4)

**Tasks**:
1. **Merge all analysis**:
   - Combine Ghidra disassembly with annotations
   - Add function purpose headers
   - Add OS call annotations
   - Add hardware access annotations
   - Add data structure references

2. **Add inline comments**:
   - Explain complex operations
   - Document register usage
   - Note protocol-relevant code
   - Cross-reference to docs

3. **Generate individual function disassemblies**:
   - Split full disassembly by function
   - Include function-specific annotations

**Deliverables**:
- `annotated_full.asm` (complete annotated disassembly)
- 88-92 individual annotated .asm files

**Estimated Time**: 2-3 days

---

### Phase 3.7: Call Graph & Database (Week 4)

**Tasks**:
1. **Generate call graph**:
   - Convert Ghidra call_graph.json to Graphviz DOT format
   - Add function names (from analysis)
   - Color-code by category
   - Add library call nodes
   - Add hardware access indicators

2. **Create interactive version**:
   - Generate SVG with clickable links
   - Link to function Markdown docs
   - Add hover tooltips with function purpose

3. **Build searchable database**:
   - Merge all JSON data
   - Add search indices
   - Create query interface (optional: simple web page)

**Deliverables**:
- `call_graph.dot` (Graphviz source)
- `call_graph.svg` (interactive graph)
- `database/functions.json` (complete searchable database)

**Estimated Time**: 2 days

---

## Automation Strategy

### Scripts to Create

**1. `generate_function_docs.py`**:
```python
# For each function:
#   1. Extract disassembly from Ghidra output
#   2. Find OS calls from call graph
#   3. Find hardware accesses (grep for MMIO addresses)
#   4. Apply analysis template
#   5. Generate Markdown file
```

**2. `annotate_disassembly.py`**:
```python
# Process full disassembly:
#   1. Add function purpose headers
#   2. Annotate BSR.L calls with function names
#   3. Annotate MMIO accesses with register names
#   4. Add data structure references
#   5. Insert cross-references to docs
```

**3. `generate_call_graph.py`**:
```python
# Convert call_graph.json to DOT:
#   1. Create nodes for each function
#   2. Add edges for calls
#   3. Color-code by category
#   4. Add library function nodes
#   5. Generate SVG with hyperlinks
```

**4. `build_database.py`**:
```python
# Merge all analysis data:
#   1. Combine Ghidra + Phase 2 metadata
#   2. Add OS call information
#   3. Add hardware access data
#   4. Add protocol relevance
#   5. Export unified JSON
```

---

## Quality Standards

### For Each Function Doc:
- [ ] Complete disassembly included
- [ ] All OS calls identified and documented
- [ ] All hardware accesses identified and documented
- [ ] C pseudocode reverse-engineered
- [ ] Data structures documented
- [ ] Purpose clearly stated
- [ ] Confidence level assigned
- [ ] Cross-references to protocol spec

### For Protocol Spec:
- [ ] All message formats documented
- [ ] Initialization sequence complete
- [ ] Error handling documented
- [ ] Timing requirements noted
- [ ] Validated against hardware logs
- [ ] Validated against emulator code

### For OS Call Reference:
- [ ] All calls identified
- [ ] Function signatures documented
- [ ] Usage patterns explained
- [ ] Frequency statistics included
- [ ] Critical calls highlighted

### For Hardware Register Map:
- [ ] All MMIO addresses identified
- [ ] Register functions documented
- [ ] Bit definitions included (where discoverable)
- [ ] Access patterns documented
- [ ] Initialization sequences captured

---

## Success Criteria

### Phase 3 Complete When:
1. ✅ All 88-92 functions have Markdown documentation
2. ✅ Protocol specification is complete and validated
3. ✅ All OS/library calls are catalogued
4. ✅ All hardware registers are mapped
5. ✅ Fully annotated disassembly generated
6. ✅ Interactive call graph created
7. ✅ Searchable function database built
8. ✅ Documentation cross-referenced and consistent

### Validation Checks:
- Protocol spec matches hardware capture logs
- Emulator behavior aligns with documented protocol
- No unexplained functions remain
- No unexplained hardware accesses remain
- All OS calls have known purposes

---

## Timeline Summary

**Week 1**:
- Foundation setup ✓
- OS/Library analysis (3-4 days)
- Start hardware analysis

**Week 2**:
- Complete hardware analysis (3-4 days)
- Protocol discovery (5-6 days start)

**Week 3**:
- Complete protocol discovery
- Function-by-function analysis (8-10 days start)

**Week 4**:
- Complete function analysis
- Annotated disassembly (2-3 days)
- Call graph & database (2 days)

**Total**: 3-4 weeks for complete analysis

---

## Current Status

**Completed**:
- ✅ Ghidra export (functions.json, call_graph.json, disassembly_full.asm)
- ✅ Export quality verified (BSR.L properly disassembled)
- ✅ Function analysis template created (FUNCTION_ANALYSIS_EXAMPLE.md)
- ✅ Deep-dive example: FUN_00003820 (ND_LookupBoardBySlot)

**In Progress**:
- ⏳ Function count reconciliation (88 vs 92)

**Next Steps**:
1. Set up documentation structure (docs/functions/ directory)
2. Create automation scripts
3. Start OS/library call analysis
4. Begin systematic function documentation

---

## Notes

- Use Phase 2 function boundaries as ground truth
- Merge Phase 2 metadata with Ghidra analysis
- Cross-validate everything against hardware logs
- Focus on actionable results (protocol understanding)
- Document unknowns (don't fabricate details)
- Maintain consistent terminology across docs
