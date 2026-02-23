# NeXTdimension Firmware Annotation Project - Status Report

## Overview

We have successfully begun the systematic annotation of the 64 KB NeXTdimension i860 firmware using the "Seed, Grow, and Conquer" methodology.

---

## What We've Accomplished

### Phase 1: Landmark Functions (✅ COMPLETE)

**1. Automated Analysis Tools Created**

| Tool | Purpose | Status |
|------|---------|--------|
| `verify_clean_firmware.py` | Static pattern analysis | ✅ Complete |
| `trace_entry_point.sh` | Disassembly and control flow | ✅ Complete |
| `analyze_callgraph.py` | Call graph extraction | ✅ Complete |

**2. Call Graph Analysis Complete**

```
Functions identified:      77
Call relationships:        77
Function prologues:        28
Function epilogues:        20
Exception handlers:        8
```

**3. Hardware Access Patterns Mapped**

```
Mailbox accesses:          7 total
  Hot spot: 0xFFF07000 (3 accesses)

VRAM accesses:             146 total
  Hot spot: 0xFFF07000 (20 accesses)
  Hot spot: 0xFFF09000 (19 accesses)
  Hot spot: 0xFFF0B000 (18 accesses)
```

**4. PostScript String Table Located**

- Address: `0xF800F93C`
- Total strings: 24 operators
- Examples: `"2 copy curveto"`, `"/y load def"`, `"pl moveto"`

**5. Annotated Disassembly Framework Created**

File: `ND_i860_CLEAN_ANNOTATED.asm`

Structure:
- Table of contents
- Binary structure documentation
- Exception handler identification
- Control register operations cataloged
- Hardware access regions mapped
- PostScript interface documented
- Call graph summary
- Next steps outlined

---

## Key Findings from Analysis

### 1. Binary Structure

```
Offset 0x000000-0x000347 (840 bytes):     Mach-O header + load commands
Offset 0x000348-0x001347 (4,096 bytes):  Padding / Exception vector data
Offset 0x001348-0x00FFFF (59,640 bytes): Actual i860 executable code
─────────────────────────────────────────────────────────────────────────
Total: 65,536 bytes (64 KB)
```

### 2. Exception Vectors

All 8 i860 exception vectors identified at standard addresses:
- Reset Handler: 0xFFF00000
- Alignment Fault: 0xFFF00008
- Page Fault: 0xFFF00010
- Data Fault: 0xFFF00018
- Instruction Fault: 0xFFF00020
- **Trap (System Calls)**: 0xFFF00028 ← Key entry point
- External Interrupt: 0xFFF00030
- Reserved: 0xFFF00038

### 3. Control Register Operations

Found **20+ instances** of control register access:

**Read Operations:**
- `ld.c %fir,%rX` - Fault Instruction Register
- `ld.c %epsr,%rX` - Extended Processor Status
- `ld.c %dirbase,%rX` - Page Directory Base
- `ld.c %fsr,%rX` - Floating-Point Status

**Write Operations:**
- `st.c %rX,%dirbase` - Set page table
- `st.c %rX,%fir` - Clear fault
- `st.c %rX,%db` - Set data breakpoint

### 4. Function Hot Spots

**Most-Called Function:**
- `0xFDB17B40`: called by 2 functions

**Entry Points (Never Called):**
- `0xFFF00158`, `0xFFF0015C` - Early initialization
- `0xFFF01480` - Main initialization (likely)
- `0xFFF03474` through `0xFFF0BAE8` - Various handlers

**Heavy VRAM Users (Graphics Primitives):**
- `0xFFF07000` - 20 VRAM accesses + 3 mailbox reads
- `0xFFF09000` - 19 VRAM accesses + 2 mailbox reads
- `0xFFF0B000` - 18 VRAM accesses

---

## Phase 2: In Progress

### Current Task: Function Extraction

**Functions with Clear Prologues Identified:**

| Address | Prologue Pattern | Status |
|---------|------------------|--------|
| 0xFFF06728 | `subs 4324,%r1,%r24` | 🔍 Extracted |
| 0xFFF06750 | `subs 4324,%r1,%r24` | 🔍 Extracted |
| 0xFFF0687C | `subs 4324,%r17,%r24` | 🔍 Extracted |
| 0xFFF07A10 | `subs 4324,%r1,%r24` | ⏳ Pending |
| 0xFFF07C14 | `subs 1508,%r1,%r24` | ⏳ Pending |

**Next Steps:**
1. Complete extraction of all 28 functions with prologues
2. Map function boundaries (find epilogues)
3. Analyze call targets and build caller/callee relationships
4. Identify function purposes based on hardware access patterns

---

## Phase 3: Planned

### Thematic Analysis Tasks

**1. Graphics Primitive Identification**

Strategy:
- Search for VRAM write patterns
- Identify loops with FPU operations
- Categorize by operation type:
  - Fill operations (constant writes)
  - Blit operations (copy patterns)
  - Rasterizers (complex math)

**2. MMIO Driver Classification**

Strategy:
- Group functions by MMIO region accessed
- Mailbox access → Command dispatch
- RAMDAC access → Video configuration
- Clock access → Timing setup

**3. System Call Handler Mapping**

Strategy:
- Trace from trap handler (0xFFF00028)
- Find system call dispatch table
- Map syscall numbers to handlers
- Document parameter conventions

**4. IPC Message Flow**

Strategy:
- Find message send/receive primitives
- Map port allocation functions
- Trace message passing infrastructure
- Document IPC data structures

---

## Tools Usage Guide

### 1. Call Graph Analyzer

```bash
./analyze_callgraph.py ND_i860_CLEAN.bin.asm
```

**Outputs:**
- `CALLGRAPH_ANALYSIS.md` - Comprehensive analysis report

**What it finds:**
- Function boundaries
- Call relationships
- Hardware access patterns
- Entry points and hot spots

### 2. Pattern Search Scripts

```bash
# Find all function prologues
grep -n "adds.*-.*%r2,%r2\|subs.*%r2" ND_i860_CLEAN.bin.asm

# Find all control register operations
grep "ld.c\|st.c" ND_i860_CLEAN.bin.asm

# Find all cache flushes
grep "flush" ND_i860_CLEAN.bin.asm

# Find all MMIO address formation
grep -E "orh.*0xff|andnoth.*0xff" ND_i860_CLEAN.bin.asm

# Find all returns
grep "bri.*%r1" ND_i860_CLEAN.bin.asm
```

### 3. Function Extraction

```bash
# Extract function at line N, length M
sed -n 'N,$((N+M))p' ND_i860_CLEAN.bin.asm > function_addr.asm

# Example: Extract function at line 6608, 100 instructions
sed -n '6608,6708p' ND_i860_CLEAN.bin.asm > func_0xFFF06728.asm
```

---

## Annotation Workflow

### For Each Function:

**1. Extract the function**
```bash
sed -n 'START_LINE,END_LINE p' ND_i860_CLEAN.bin.asm > temp_function.asm
```

**2. Provide to Claude for analysis**
```
I've extracted a function at 0xFFF06728. Here's the disassembly:
[paste disassembly]

Based on the patterns you see (hardware access, loop structure, etc.),
please analyze and annotate this function.
```

**3. Claude provides annotated version**
```asm
; ============================================================================
; Function:      handle_fill_rect
; Address:       0xFFF06728
; Purpose:       Handler for CMD_FILL_RECT mailbox command
; Inputs:        r16 (x), r17 (y), r18 (width), r19 (height), r20 (color)
; Outputs:       r16 (status code)
; Analysis:      Parses rectangle parameters and calls optimized blitter
; ============================================================================
[annotated instructions]
```

**4. Add to master annotated file**
Append to `ND_i860_CLEAN_ANNOTATED.asm`

**5. Update call graph**
Note caller/callee relationships

---

## Progress Tracking

### Phase 1: Landmark Functions
- [✅] Static analysis tools
- [✅] Call graph extraction
- [✅] Hardware access mapping
- [✅] PostScript string table
- [✅] Exception vector identification
- [✅] Annotated framework created

### Phase 2: Call Graph Growth
- [⏳] Function prologue/epilogue extraction (28/28 identified)
- [⏳] Function boundary mapping (0/28 complete)
- [  ] Caller/callee relationships (0/77 complete)
- [  ] Parameter passing analysis
- [  ] Complete function annotations

### Phase 3: Thematic Analysis
- [  ] Graphics primitives (0 identified)
- [  ] MMIO drivers (0 categorized)
- [  ] System call handlers (0 mapped)
- [  ] IPC message flow (0 traced)

### Overall Completion: ~15%

**Estimated work remaining:**
- Phase 2: ~40 hours (function-by-function annotation)
- Phase 3: ~20 hours (thematic grouping and documentation)
- **Total**: ~60 hours of focused analysis

---

## Immediate Next Steps

### Priority 1: High-Value Functions

**1. Main Command Dispatcher (CRITICAL)**
   - Location: Near 0xFFF07000 (heavy mailbox + VRAM access)
   - Why: Understanding command dispatch unlocks all handlers
   - Action: Extract and analyze this function first

**2. System Call Entry (CRITICAL)**
   - Location: Trap handler at 0xFFF00028
   - Why: Entry point for all OS services
   - Action: Trace from exception vector to dispatcher

**3. Top Graphics Primitives (HIGH VALUE)**
   - Locations: 0xFFF07000, 0xFFF09000, 0xFFF0B000
   - Why: Most frequently used, show optimization patterns
   - Action: Extract and categorize by operation type

### Priority 2: Infrastructure Functions

**4. Control Register Init**
   - Locations: 0xFFF013A4, 0xFFF014B4
   - Why: Shows hardware setup sequence
   - Action: Document initialization flow

**5. PostScript Operator Dispatch**
   - Location: Near 0xF800F93C (string table)
   - Why: Shows DPS interface implementation
   - Action: Find code that references strings

---

## Files Generated

| File | Size | Purpose |
|------|------|---------|
| `verify_clean_firmware.py` | 550 lines | Static pattern analyzer |
| `trace_entry_point.sh` | 300 lines | Entry point tracer |
| `analyze_callgraph.py` | 400 lines | Call graph extractor |
| `CALLGRAPH_ANALYSIS.md` | 111 lines | Analysis report |
| `ND_i860_CLEAN_ANNOTATED.asm` | 600+ lines | Annotated disassembly (growing) |
| `ND_i860_CLEAN.bin.asm` | 16,391 lines | Full disassembly (reference) |

---

## Collaboration Model

### Human (You) Tasks:
1. Run analysis scripts
2. Extract functions using sed/grep
3. Provide context (memory maps, hardware docs)
4. Validate annotations

### LLM (Claude) Tasks:
1. Pattern recognition
2. Architectural analysis
3. Function annotation
4. Cross-referencing

### Iterative Process:
```
You: "Here's a function with VRAM writes"
  ↓
Claude: "This is a fill primitive, here's the annotation"
  ↓
You: "Extract the function it calls"
  ↓
Claude: "That's the FPU blitter, here's the annotation"
  ↓
[Repeat until complete]
```

---

## Success Criteria

### Phase 2 Complete When:
- [  ] All 77 call graph functions annotated
- [  ] Complete caller/callee map
- [  ] Function purposes identified
- [  ] Parameter conventions documented

### Phase 3 Complete When:
- [  ] All graphics primitives categorized
- [  ] All hardware drivers documented
- [  ] System call interface mapped
- [  ] IPC infrastructure traced

### Project Complete When:
- [  ] Every function annotated
- [  ] Complete call graph visualized
- [  ] Hardware interaction documented
- [  ] GaCKliNG can use as reference

---

## For GaCKliNG Development

### What You Can Use Now:

**1. Hardware Initialization Sequences**
- Control register setup patterns
- Cache configuration
- MMIO addressing idioms

**2. Calling Conventions**
- Register usage (r1, r2, r3)
- Stack frame layout
- Parameter passing

**3. Optimization Patterns**
- FPU for integer data movement
- Cache flush placement
- Dual-pipeline usage

### What's Coming:

**1. Complete Graphics Primitives**
- Reference implementations for blitting
- Optimized loops
- VRAM access patterns

**2. IPC Infrastructure**
- Message passing implementation
- Port management
- Mailbox protocol

**3. Command Dispatch**
- How host commands are processed
- Parameter extraction
- Result return

---

## Conclusion

We have successfully:
✅ Created automated analysis tools
✅ Extracted call graph (77 functions)
✅ Mapped hardware access patterns
✅ Located PostScript interface
✅ Identified exception handlers
✅ Set up annotation framework

**Next:** Begin systematic function-by-function annotation, starting with high-value command dispatchers and graphics primitives.

The foundation is solid. The methodology is proven. The tools are ready.

**Time to annotate! 🎯**

---

**Status**: Phase 1 Complete, Phase 2 In Progress
**Last Updated**: November 5, 2025
**Completion**: ~15%
**Next Milestone**: Annotate top 10 hot spot functions
