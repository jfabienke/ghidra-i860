# ghidra-i860

Intel i860 (80860) processor module for [Ghidra](https://ghidra-sre.org/) — disassembly and decompilation of i860 binaries.

## Features

- **~172 unique instructions** across 337 SLEIGH definitions covering the full i860 ISA
- **4 language variants**: little-endian and big-endian for both XR (1989) and XP (1991)
- **2 calling conventions**: GCC/NeXTSTEP ABI and SPEA/APX2 ABI
- **Full p-code semantics** for decompiler output — no `unimpl` instructions
- **Auto-detection** of Mach-O (CPU type 15) and ELF (EM_860 = 7) binaries; ND kernel Mach-O requires scripted import (see below)
- **100% mnemonic match** on 15,432 instructions verified against reference disassembler

## Installation

Copy the contents of `data/languages/` into your Ghidra processor directory:

```
cp -r data/languages/ <ghidra-install>/Ghidra/Processors/i860/data/languages/
```

On macOS with Homebrew:
```
cp -r data/languages/ /opt/homebrew/Cellar/ghidra/<version>/libexec/Ghidra/Processors/i860/data/languages/
```

Restart Ghidra after copying.

## Supported Binary Formats

| Format | Status | Details |
|--------|--------|---------|
| **Mach-O** | Supported | CPU_TYPE_I860 (15) — auto-detected by Ghidra |
| **ELF** | Supported | EM_860 (7) — auto-detected by Ghidra |
| **Raw binary** | Supported | Manual language selection required |
| **COFF** | Planned | Magic `0x014D` (Intel APX2) and `0x0090` (SPEA FGA) |

**Target binaries**: NeXTdimension firmware (64 KB Mach-O), SPEA Fire graphics firmware (COFF), Intel iPSC/Paragon applications (ELF).

## Architecture Overview

The Intel i860 is a 32-bit RISC processor with fixed 32-bit instruction width.

- **Registers**: 32 integer (r0 = zero), 32 floating-point (f0/f1 = zero), 6 control
- **Encoding**: primary opcode in bits [31:26], register fields src2[25:21], dest[20:16], src1[15:11]
- **FP escape**: opcode `0x12` with 7-bit sub-opcode in bits [6:0]
- **Core escape**: opcode `0x13` with 3-bit sub-opcode in bits [2:0]
- **Delay slots**: `bc.t`, `bnc.t`, `bla`, `br`, `call`, `bri`, `calli` (NOT `bc`, `bnc`, `bte`, `btne`)
- **Dual-instruction mode**: core + FP execute simultaneously via `d.` prefix
- **Bi-endian**: configurable at reset, default little-endian

## Language Variants

| ID | Endianness | Variant | Processor Spec |
|----|------------|---------|----------------|
| `i860:LE:32:XR` | Little | XR (1989) | `i860_xr.pspec` |
| `i860:BE:32:XR` | Big | XR (1989) | `i860_xr.pspec` |
| `i860:LE:32:XP` | Little | XP (1991) | `i860_xp.pspec` |
| `i860:BE:32:XP` | Big | XP (1991) | `i860_xp.pspec` |

All variants share the same `.sinc` instruction definitions. XP adds 10 instructions gated by a context register. Endianness is set at SLEIGH compile time via separate `.slaspec` files.

## Calling Conventions

| ABI | Stack Pointer | Frame Pointer | Arg Registers | Return Register |
|-----|---------------|---------------|---------------|-----------------|
| **GCC/NeXTSTEP** (`gcc.cspec`) | r2 | r3 | r16–r27 | r16 |
| **SPEA/APX2** (`spea.cspec`) | r29 | r28 | r4–r11 | r2 |

Both conventions use r1 as the return address register (set by `call`/`calli`).

## Building from Source

Compile the SLEIGH specifications into `.sla` files:

```bash
# Little-endian
sleigh data/languages/i860_le.slaspec

# Big-endian
sleigh data/languages/i860_be.slaspec
```

The SLEIGH compiler is included with Ghidra:
```
<ghidra-install>/Ghidra/Features/Decompiler/os/<platform>/sleigh
```

Pre-compiled `.sla` files are included in the repository.

## Verification

Tested against a Rust-based i860 disassembler (99.93% MAME accuracy) using the NeXTdimension firmware binary:

- **15,432 / 15,432** comparable instructions = **100.0% mnemonic match**
- Ghidra decodes 55 additional instructions that the reference outputs as `.long`

Verification uses the included `scripts/DisassembleAll.java` Ghidra script for headless linear-sweep disassembly.

## Mach-O Kernel Analysis

For Mach-O binaries where Ghidra can't parse the i860 thread command (e.g., NeXTdimension kernel), a two-script pipeline handles import and analysis:

```bash
./re/nextdimension/kernel/scripts/run_analysis.sh [binary] [xrefs_json] [recovery_map_json]
```

This runs `I860Import.java` (entry point + recursive descent with iterative call/branch seeding) as a preScript, followed by `I860Analyze.java` (worklist-based seed discovery, function creation, code/data classification, optional range filtering) as a postScript. With the bundled recovery map (311 seeds, 43 deny ranges), the 784 KB kernel yields 2,536 instructions across 60 functions (1.4% coverage). Phase 2 cross-block BRI resolution and LLM swarm analysis of all 60 promoted functions confirmed a static analysis ceiling: real firmware logic sits behind 616 unresolved `bri rN` dynamic dispatch sites that require emulation to resolve.

Runtime-assisted pass:

```bash
./re/nextdimension/kernel/scripts/run_emu_trace_seed_pass.sh \
  re/nextdimension/kernel/i860_kernel.bin \
  0xF8000000 0xF8000000 200000
```

Then feed the generated trace into `run_analysis.sh` as the optional 5th argument (`dynamic_trace_jsonl`) to auto-merge runtime-discovered targets into the recovery map.

See [`re/nextdimension/kernel/`](re/nextdimension/kernel/) for results, findings, and scripts.

## File Structure

```
ghidra-i860/
├── data/languages/
│   ├── i860.ldefs              # Language definitions (4 variants)
│   ├── i860.opinion            # Loader-to-language mapping
│   ├── i860_xr.pspec          # XR processor spec
│   ├── i860_xp.pspec          # XP processor spec
│   ├── i860_le.slaspec        # LE top-level (compiles to i860_le.sla)
│   ├── i860_be.slaspec        # BE top-level (compiles to i860_be.sla)
│   ├── i860_common.sinc       # Tokens, registers, attach directives
│   ├── i860_integer.sinc      # ALU, shifts, loads/stores
│   ├── i860_control.sinc      # Branches, calls, traps
│   ├── i860_float.sinc        # FP instructions
│   ├── i860_graphics.sinc     # Graphics ops, dual operations
│   ├── i860_xp.sinc           # XP-specific instructions
│   ├── gcc.cspec              # GCC/NeXTSTEP calling convention
│   └── spea.cspec             # SPEA/APX2 calling convention
├── scripts/
│   ├── DisassembleAll.java    # Raw binary linear sweep + export
│   ├── AnalysisStats.java     # Analysis statistics utility
│   └── swarm/                 # LLM multi-agent analysis pipeline
│       ├── orchestrate.py     #   Intent → verify → contrarian → synthesis
│       ├── schemas.py         #   Response schema validation
│       ├── store.py           #   SQLite claim store
│       └── report.py          #   Run summary reporter
├── re/                        # Reverse engineering targets
│   └── nextdimension/
│       ├── kernel/
│       │   ├── i860_kernel.bin        # 784 KB Mach-O binary
│       │   ├── scripts/               # Kernel analysis pipeline
│       │   ├── reports/               # Analysis reports + logs
│       │   └── docs/                  # Findings + memory map
│       ├── firmware/                  # ND firmware binaries
│       └── boot-rom/                  # ND boot ROM
├── docs/                      # Architecture & development reference
│   ├── 01-i860-architecture-reference.md
│   ├── 02-instruction-encoding-reference.md
│   ├── 03-ghidra-sleigh-development-guide.md
│   ├── 04-instruction-set-status.md
│   ├── 05-binary-formats-and-platforms.md
│   ├── 06-local-resources-inventory.md
│   ├── 07-lessons-learned.md
│   ├── 08-coverage-analysis.md
│   └── 09-dynamic-trace-integration.md
└── README.md
```

## Documentation

The `docs/` directory contains detailed reference material:

| Document | Description |
|----------|-------------|
| [01-i860-architecture-reference.md](docs/01-i860-architecture-reference.md) | Registers, addressing modes, pipelines, memory model |
| [02-instruction-encoding-reference.md](docs/02-instruction-encoding-reference.md) | Bit-level opcode maps and instruction formats |
| [03-ghidra-sleigh-development-guide.md](docs/03-ghidra-sleigh-development-guide.md) | SLEIGH patterns, file structure, implementation notes |
| [04-instruction-set-status.md](docs/04-instruction-set-status.md) | Complete instruction inventory (~172 instructions) |
| [05-binary-formats-and-platforms.md](docs/05-binary-formats-and-platforms.md) | Mach-O, COFF, ELF format details and calling conventions |
| [06-local-resources-inventory.md](docs/06-local-resources-inventory.md) | Index of reference material and test binaries |
| [07-lessons-learned.md](docs/07-lessons-learned.md) | Consolidated implementation gotchas and analysis pitfalls |
| [08-coverage-analysis.md](docs/08-coverage-analysis.md) | Byte-accounting and execution-proven coverage status |
| [09-dynamic-trace-integration.md](docs/09-dynamic-trace-integration.md) | Emulator trace schema and trace→seed headless workflow |

## Roadmap

- [x] Phase 2 cross-block BRI resolution (0 new seeds — static ceiling confirmed)
- [x] LLM swarm analysis of 60 promoted functions (30/32 accepted = dead code)
- [ ] Emulation/symbolic execution for runtime `bri rN` dispatch resolution
- [ ] COFF loader extension for i860 magic values (`0x014D`, `0x0090`)
- [ ] Decompiler quality tuning on real-world binaries
- [ ] GUI testing and usability review

## License

This project is not affiliated with Intel Corporation or the Ghidra project.
