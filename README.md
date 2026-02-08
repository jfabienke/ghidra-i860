# ghidra-i860: Intel i860 Processor Module for Ghidra

A Ghidra extension providing disassembly and decompilation support for the Intel i860 (80860) RISC microprocessor.

## Status

**Phase**: Documentation and planning. No SLEIGH code written yet.

## Background

The Intel i860 is not supported by any mainstream open-source reverse engineering tool except IDA Pro. This project adds i860 support to Ghidra via a SLEIGH language module.

### Target Binaries

- **NeXTdimension** firmware (Mach-O / raw binary, little-endian)
- **SPEA Fire** graphics card firmware (COFF, little-endian)
- **Intel iPSC/860 and Paragon** applications (ELF)
- Raw ROM images from various i860 systems

### Architecture Highlights

- 32-bit RISC, fixed 32-bit instruction width
- 32 integer registers (r0 hardwired to zero) + 32 FP registers (f0/f1 hardwired to zero)
- Bi-endian (configurable, default little-endian)
- Dual-instruction VLIW mode (core + FP simultaneously)
- Branch delay slots on `.t` variants and `bla` only
- Pipelined FP with program-accessible pipeline state
- Two variants: XR (1989) and XP (1991), binary compatible

## Documentation

The `docs/` directory contains a comprehensive documentation corpus:

| Document | Description |
|----------|-------------|
| [01-i860-architecture-reference.md](docs/01-i860-architecture-reference.md) | Complete ISA reference: registers, addressing, pipelines, memory model |
| [02-instruction-encoding-reference.md](docs/02-instruction-encoding-reference.md) | Bit-level opcode maps and instruction format layouts |
| [03-ghidra-sleigh-development-guide.md](docs/03-ghidra-sleigh-development-guide.md) | SLEIGH patterns, file structure, XML configs, implementation strategy |
| [04-instruction-set-status.md](docs/04-instruction-set-status.md) | Complete instruction inventory (~172 instructions) |
| [05-binary-formats-and-platforms.md](docs/05-binary-formats-and-platforms.md) | Mach-O, COFF, ELF details; relocations; calling conventions; memory maps |
| [06-local-resources-inventory.md](docs/06-local-resources-inventory.md) | Index of all local i860 artifacts across repositories |

## Implementation Plan

### Phase 1: Minimal Disassembly
- Token and register definitions
- Integer ALU (adds, addu, subs, subu, and, or, xor, shifts)
- Load/store (ld.b, ld.s, ld.l, st.b, st.s, st.l)
- Branches (br, call, bc, bnc, bri, calli, bte, btne)
- `orh`/`or` for 32-bit constants
- Pseudo-ops (nop, mov, ret)

### Phase 2: Control Flow Correctness
- Delay slots (bc.t, bnc.t, bla)
- Split branch offset reconstruction
- Control register access (ld.c, st.c)

### Phase 3: Floating-Point Disassembly
- Basic FP (fadd, fsub, fmul with all precision variants)
- FP load/store (fld, fst with l/d/q sizes)
- FP specials (frcp, frsqr, fix, ftrunc, famov, fxfr, ixfr)
- FP comparisons (pfgt, pfle, pfeq)

### Phase 4: Decompiler Quality
- P-code semantics for all Phase 1-3 instructions
- Calling convention tuning (cspec/pspec)
- Regression testing against Rust disassembler golden output

### Phase 5: Advanced Features
- Pipelined FP, auto-increment addressing
- Graphics operations (faddp, faddz, fzchk, form, pst.d)
- Dual operations (PFAM, PFSM, PFMAM, PFMSM)
- XP-specific instructions
- Mach-O loader patch (CPU_TYPE_I860 mapping)
- COFF loader support (magic 0x0090)

## Development Resources

### Existing i860 Implementations (local)
- **Rust disassembler**: `../nextdimension/i860-disassembler/` — 99.93% MAME match
- **MAME emulator**: `../nextdimension/tools/mame-i860/` — Authoritative decoder
- **LLVM backend**: `../nextdimension/llvm-i860/` — TableGen definitions
- **Rust emulator**: `../nextdimension/emulator/i860-core/` — 73% ISA coverage
- **Intel manual**: `../nextdimension/docs/i860/reference/i860-reference.pdf`

### Test Binaries
- `../previous/reverse-engineering/nextdimension-files/disassembly/i860/ND_i860_CLEAN.bin` (64 KB)
- `../spea-fire/refs/APX2/BOOT.OUT` (13.8 KB COFF)
- `../spea-fire/refs/APX2/BOOT2.OUT` (27.8 KB COFF)

### Closest Ghidra Processor Modules (for patterns)
- **SPARC** — Best match: RISC, delay slots, FP register aliasing, similar instruction width
- **MIPS** — Delay slot handling, r0 hardwired to zero
- **Toy** — Minimal reference implementation for learning SLEIGH structure
