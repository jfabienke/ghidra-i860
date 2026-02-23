# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains **verified Intel i860 firmware** extracted from the NeXTdimension graphics board. The firmware represents a complete second computer running on the NeXTdimension card, featuring:

- **192 KB verified i860 code** (extracted from 795 KB contaminated source, 75% contamination removed)
- **Two complete operating systems**: Bootstrap Graphics HAL (32 KB) + GaCK Mach Kernel (160 KB)
- **537 identified functions** with 92.6% average disassembly coherence
- **Full Mach-compatible multitasking OS** with virtual memory, interrupts, and IPC

**Critical Discovery**: The NeXTdimension is not just a graphics card—it's a complete second NeXT computer with its own i860 CPU running a full Mach-compatible OS that communicates with the host via Mach IPC.

## Repository Structure

### Binary Files (DO NOT MODIFY)

**Primary firmware:**
- `ND_i860_VERIFIED_clean.bin` (192 KB) - **Use this file** for all analysis and emulation
- MD5: `74c157b4e4553a53c9dc7846d0161a61`

**Component sections:**
- `01_bootstrap_graphics.bin` (32 KB @ 0xF8000000) - Bootstrap HAL with 79 functions
- `02_postscript_operators.bin` (32 KB @ 0xF8008000) - Mach microkernel services (75 functions)
- `03_graphics_acceleration.bin` (128 KB @ 0xF8010000) - Graphics library (383 functions across 4 regions)

**Reference only (contaminated):**
- `05_postscript_data_REFERENCE_ONLY.bin` - PostScript text + m68k code (do not use for execution)
- `04_debug_diagnostics.bin` - Emacs changelog (not i860 code)
- `ND_i860_clean.bin` - Deprecated (includes contamination)

### Disassembly Files

**Generated assembly:**
- `01_bootstrap_graphics.asm` - Section 1 disassembly (248KB, 8,192 instructions)
- `01_bootstrap_graphics_ANNOTATED.asm` - Annotated with function boundaries
- `02_postscript_operators.asm` - Section 2 disassembly
- `03_graphics_acceleration.asm` - Section 3 disassembly (128 KB)
- `ND_i860_VERIFIED_clean.asm` - Complete firmware disassembly
- `ND_i860_VERIFIED_clean.json` - JSON format for automated analysis

### Analysis Scripts

- `analyze_disassembly.py` - Python script for disassembly analysis (8.1 KB)

### Documentation

**Extraction reports:**
- `README.md` - Quick start guide for disassembly and usage
- `SUMMARY.md` - Executive summary of extraction process
- `CLEAN_FIRMWARE_EXTRACTION_REPORT.md` - Complete methodology (680 lines)
- `VALIDATION_RESULTS.md` - Quality metrics and verification

**Architectural analysis:**
- `FINAL_ARCHITECTURAL_REVELATION.md` - **Critical document**: Reveals NeXTdimension as complete second computer
- `01_bootstrap_architecture_guide.md` - Section 1+2 architectural overview
- `01_bootstrap_deep_dive.md` - Detailed function analysis
- `01_bootstrap_deep_dive_algorithms.md` - Algorithm verification
- `GACK_KERNEL_HARDWARE_SCAN.md` - GaCK kernel analysis

**Detailed taxonomies:**
- `01_bootstrap_*_taxonomy.md` - Function categorization (pixel ops, control flow, data movement, utilities)
- `02_postscript_*.md` - PostScript interface analysis
- `03_graphics_contamination_report.md` - Section 3 contamination findings

**Hardware analysis:**
- `I860XP_MMU_FEATURES_ANALYSIS.md` - MMU capabilities
- `I860_CONTEXT_SWITCH_OPTIMIZATION_ANALYSIS.md` - Context switching
- `PREVIOUS_EMULATOR_FEATURE_ANALYSIS.md` - Previous emulator integration notes

## Common Commands

### Disassemble Firmware

```bash
# Full disassembly with addresses and statistics
# Requires: i860-disassembler in parent directory
cd /Users/jvindahl/Development/nextdimension/i860-disassembler
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8000000 \
  --stats \
  ../firmware_clean/ND_i860_VERIFIED_clean.bin > output.asm

# JSON output for automated analysis
./target/release/i860-dissembler \
  --format json \
  --base-address 0xF8000000 \
  ../firmware_clean/ND_i860_VERIFIED_clean.bin > output.json
```

### Disassemble Individual Sections

```bash
# Section 1: Bootstrap (32 KB @ 0xF8000000)
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8000000 \
  ../firmware_clean/01_bootstrap_graphics.bin > section1.asm

# Section 2: PostScript/Mach (32 KB @ 0xF8008000)
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8008000 \
  ../firmware_clean/02_postscript_operators.bin > section2.asm

# Section 3: Graphics (128 KB @ 0xF8010000)
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8010000 \
  ../firmware_clean/03_graphics_acceleration.bin > section3.asm
```

### Verify Binary Integrity

```bash
# Check MD5 checksums
md5 ND_i860_VERIFIED_clean.bin
# Expected: 74c157b4e4553a53c9dc7846d0161a61

md5 01_bootstrap_graphics.bin
# Expected: fc72c3eac9e1e693b07f0ae0dc44b797

md5 02_postscript_operators.bin
# Expected: 7b1b912fbd95b5aa20e644c80e13e50b

md5 03_graphics_acceleration.bin
# Expected: 280c6cfcde6589c54214081218250ff9
```

### Analyze with Python Script

```bash
# Run disassembly analysis
python analyze_disassembly.py ND_i860_VERIFIED_clean.json
```

## Architecture and Key Concepts

### Virtual Memory Map

The firmware uses a specific memory layout that must be preserved:

```
0xF8000000 - 0xF8007FFF : Bootstrap & Graphics Primitives (32 KB)
                          - Boot vectors & initialization
                          - Graphics primitive functions (79 funcs)
                          - Memory initialization

0xF8008000 - 0xF800FFFF : Mach Microkernel Services (32 KB)
                          - System call dispatcher
                          - IPC & message passing (75 funcs)
                          - Display PostScript interface

0xF8010000 - 0xF8037FFF : Graphics Acceleration Library (128 KB)
                          - 0xF8038000: Basic primitives (154 funcs)
                          - [0xF8040000: 32 KB gap - removed contamination]
                          - 0xF8048000: Advanced operations (103 funcs)
                          - 0xF8050000: Clipping & color (75 funcs)
                          - 0xF8058000: Utilities & tables (51 funcs)
```

**Note**: 32 KB gap at 0xF8040000 due to removed Spanish localization contamination.

### Two Operating Systems

**System 1: Bootstrap Graphics HAL (Section 1+2)**
- 32 KB microkernel-level bootloader
- Initializes i860 hardware (MMU, caches, FPU)
- Single %dirbase write enables virtual memory
- Loads GaCK kernel from host
- Transfers control then remains resident as callable graphics library
- Zero interrupts (single-threaded, non-preemptible)
- Zero locks (no multitasking)

**System 2: GaCK Mach Kernel (Sections 2-3)**
- 160 KB full Mach-compatible multitasking OS
- Complete operating system features:
  - **217 trap handlers** (complete interrupt vector table)
  - **73 lock operations** (concurrent execution primitives)
  - **22 memory contexts** (21 %dirbase writes for process/task switching)
  - **31 privilege transitions** (29 %psr writes for user/kernel mode)
  - **88 performance breakpoints** (%db writes for profiling)
- Display PostScript interpreter
- Mach IPC for host communication

### Critical Hardware Operations

The following hardware operation patterns are definitive proof of a complete OS:

- **TRAP instructions**: 217 total (0 in bootstrap, 32 in section 2, 185 in section 3)
- **LOCK operations**: 73 total (0 in bootstrap, 0 in section 2, 73 in section 3)
- **%dirbase writes**: 22 contexts (1 in bootstrap initialization, 21 in kernel)
- **%psr writes**: 31 transitions (1 in bootstrap, 1 in section 2, 29 in kernel)

### Quality Metrics

```
┌───────────────┬────────┬───────────┬───────────┬─────────┐
│ Section       │ Size   │ Coherence │ Functions │ Quality │
├───────────────┼────────┼───────────┼───────────┼─────────┤
│ Sections 1-2  │ 32 KB  │   ~95%    │    79     │ ⭐⭐⭐⭐⭐ │
│ Section 3     │ 32 KB  │   ~93%    │    75     │ ⭐⭐⭐⭐⭐ │
│ Section 6 R1  │ 32 KB  │   87.9%   │   154     │ ⭐⭐⭐⭐   │
│ Section 6 R3  │ 32 KB  │   91.2%   │   103     │ ⭐⭐⭐⭐⭐  │
│ Section 6 R4  │ 32 KB  │   95.4%   │    75     │ ⭐⭐⭐⭐⭐  │
│ Section 6 R5  │ 32 KB  │   95.8%   │    51     │ ⭐⭐⭐⭐⭐  │
├───────────────┼────────┼───────────┼───────────┼─────────┤
│ TOTAL         │ 192 KB │   92.6%   │   537     │ Excellent│
└───────────────┴────────┴───────────┴───────────┴─────────┘
```

## Development Guidelines

### Working with Binary Files

**NEVER modify the binary files directly.** These are verified extraction artifacts:
- All binaries are verified against MD5 checksums
- Any modification invalidates the verification chain
- For analysis, work with disassembly or JSON outputs

### Working with Disassembly

When analyzing disassembly files:
1. Always specify the correct base address for each section
2. Use annotated versions (e.g., `01_bootstrap_graphics_ANNOTATED.asm`) for function boundaries
3. Cross-reference with architecture guides for context
4. Refer to taxonomy documents for algorithmic details

### Creating New Analysis

When writing new analysis documents:
1. Follow the naming convention: `##_<section>_<aspect>_<type>.md`
   - Example: `01_bootstrap_memory_management_analysis.md`
2. Include date, scope, and confidence level in header
3. Reference specific addresses in format: `address` or `file:line`
4. Use verification evidence (coherence %, function count, hardware ops)

### Important Architectural Principles

**Bootstrap Execution Model:**
- Single-threaded, non-preemptible
- No interrupt handling capability
- Runs to completion then transfers control
- Remains resident as callable library at 0xF8000000

**GaCK Kernel Execution Model:**
- Multitasking with preemptive scheduling
- Full interrupt vector table (217 handlers)
- Multiple memory contexts (22 address spaces)
- Privilege separation (user/kernel modes)
- Mach IPC for host communication

## Key Files for Understanding

**Start here:**
1. `README.md` - Quick overview and usage
2. `FINAL_ARCHITECTURAL_REVELATION.md` - **Must read**: Complete architectural understanding
3. `SUMMARY.md` - Extraction process and quality metrics

**Deep dive:**
1. `CLEAN_FIRMWARE_EXTRACTION_REPORT.md` - Complete extraction methodology
2. `01_bootstrap_architecture_guide.md` - Bootstrap HAL architecture
3. `GACK_KERNEL_HARDWARE_SCAN.md` - GaCK kernel analysis

**Reference:**
1. Section taxonomy files for function categorization
2. Hardware analysis files for MMU, context switching
3. `VALIDATION_RESULTS.md` for quality verification

## Relationship to Parent Project

This firmware is part of the larger NeXTdimension emulation project:

**Related repositories:**
- `../llvm-i860/` - LLVM i860 backend (for compiling new code)
- `../emulator/i860-core/` - i860 CPU emulator (for running this firmware)
- `../i860-disassembler/` - Disassembler tool (for analyzing this firmware)

**Integration path:**
1. Disassemble firmware (this repo)
2. Understand architecture (this repo)
3. Implement emulator features (../emulator/)
4. Test with verified firmware (this repo)
5. Compile new firmware (../llvm-i860/)

## Historical Context

**Source**: NeXTdimension graphics board firmware (circa 1990-1993)
**Original file**: `ND_MachDriver_reloc` (795 KB with 75% contamination)
**Extraction date**: 2025-11-09
**Extraction method**: Multi-region sampling + branch target validity testing
**Quality**: Production-ready (92.6% average coherence, 537 functions identified)

**Critical discovery**: The "Section 6" graphics library was initially misclassified as contamination. Exhaustive analysis revealed 128 KB of genuine i860 code (383 functions), nearly tripling the verified firmware size from 68 KB to 192 KB.

## Known Limitations

1. **Relocation required**: Extracted from relocated binary, some addresses may need fixup
2. **No debug metadata**: No function names, symbols, or relocation entries (must reverse-engineer)
3. **32 KB gap**: Memory gap at 0xF8040000 where contamination was removed
4. **Entry point unknown**: Must be determined through ROM cross-reference or runtime debugging

## Tools and Dependencies

**Required for disassembly:**
- i860-disassembler (Rust tool in `../i860-disassembler/`)

**Required for analysis:**
- Python 3.x (for `analyze_disassembly.py`)
- Standard Unix tools (md5, file, hexdump)

**Optional but helpful:**
- MAME i860 disassembler (in `../tools/mame-i860/`)
- Previous emulator (for testing)
- GaCKliNG emulator (future integration)
