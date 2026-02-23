# Ghidra i860 Processor Module

This project provides a comprehensive processor module for the Intel i860 (80860) RISC processor in [Ghidra](https://ghidra-sre.org/). It enables high-fidelity disassembly and decompilation of i860 binaries, with a specific focus on NeXTdimension hardware reverse engineering.

## Project Overview

- **Core Technology:** Ghidra SLEIGH language for processor modeling.
- **Architecture:** 32-bit RISC with dual-instruction mode, floating-point and graphics pipelines.
- **Supported Variants:** Little-endian and Big-endian for both XR (1989) and XP (1991) revisions.
- **Main Components:**
    - `data/languages/`: SLEIGH specifications (`.slaspec`, `.sinc`), processor specs (`.pspec`), compiler specs (`.cspec`), and language definitions (`.ldefs`).
    - `re/`: Reverse engineering workspaces for various i860 targets, primarily the NeXTdimension board (kernel, firmware, boot-rom).
    - `scripts/`: Ghidra scripts (Java) and Python tools for automated analysis, statistics, and LLM-assisted reverse engineering.
    - `docs/`: Extensive documentation on i860 architecture, SLEIGH development, and analysis findings.

## Building and Running

### Compiling SLEIGH Specifications
The SLEIGH specifications must be compiled into `.sla` files for Ghidra to use them.

```bash
# Using the Ghidra 'sleigh' compiler
# Replace <ghidra-install> with your actual Ghidra installation path

# Little-endian
<ghidra-install>/Ghidra/Features/Decompiler/os/<platform>/sleigh data/languages/i860_le.slaspec

# Big-endian
<ghidra-install>/Ghidra/Features/Decompiler/os/<platform>/sleigh data/languages/i860_be.slaspec
```

### Running the Analysis Pipeline
A specialized pipeline exists for analyzing the NeXTdimension i860 kernel.

```bash
./re/nextdimension/kernel/scripts/run_analysis.sh [binary] [xrefs_json] [recovery_map_json]
```

### Running the LLM Swarm
The LLM swarm analysis can be used to analyze promoted functions.

```bash
python3 -m scripts.swarm.orchestrate <sharded_dir> --backend api
```

## Development Conventions

### SLEIGH Implementation
- **Shared Definitions:** Common tokens, registers, and sub-constructors are defined in `i860_common.sinc`.
- **Instruction Categories:** ALU, control flow, floating-point, and graphics instructions are modularized into separate `.sinc` files.
- **Register Aliasing:** Floating-point registers are aliased to support single (32-bit), double (64-bit), and quad (128-bit) views at the same offset.
- **Delay Slots:** Modeled using the `delayslot(1)` directive, following patterns from MIPS and SPARC modules.
- **Dual-Instruction Mode (DIM):** Modeled sequentially as parallel execution does not impact static data flow analysis for reverse engineering.

### Testing and Verification
- **Verification Script:** `scripts/DisassembleAll.java` is used for headless linear-sweep disassembly verification.
- **Reference Comparison:** Output is verified against a reference Rust-based i860 disassembler to ensure 100% mnemonic matching.

### Documentation
- All architecture-specific findings and implementation details should be documented in the `docs/` directory.
- Lessons learned and coverage analysis are tracked in `docs/07-lessons-learned.md` and `docs/08-coverage-analysis.md`.
