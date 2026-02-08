# Local Resources Inventory

*Index of all i860-related artifacts across local repositories*

## Repository: nextdimension

**Path**: `/Users/jvindahl/Development/nextdimension/`

### Instruction Data
| File | Description |
|------|-------------|
| `data/i860/i860-encodings.json` | Complete JSON instruction encoding database (1100+ lines) |
| `data/i860/i860-opcodes.txt` | Opcode quick reference extracted from Appendix B |

### Disassembler (Rust)
| File | Description |
|------|-------------|
| `i860-disassembler/` | High-performance Rust disassembler |
| `i860-disassembler/src/lib.rs` | Library interface with test suite |
| `i860-disassembler/src/disassembler.rs` | Main decode logic |
| `i860-disassembler/src/opcode_table.rs` | Const-evaluated opcode lookup tables |
| `i860-disassembler/src/register_extractor.rs` | Register field decoding |
| `i860-disassembler/src/instruction_formatter.rs` | Output formatting |
| `i860-disassembler/README.md` | Features: 1.6x faster than MAME, 99.93% match rate |

### MAME Emulator (C++)
| File | Description |
|------|-------------|
| `tools/mame-i860/i860.h` | CPU device class, register enums (308 lines) |
| `tools/mame-i860/i860.cpp` | CPU initialization |
| `tools/mame-i860/i860dis.h` | Disassembler header, decode table structures |
| `tools/mame-i860/i860dis.cpp` | Disassembler implementation |
| `tools/mame-i860/i860dec.hxx` | **Complete decoder** (3500+ lines) — bit extraction macros, instruction handlers |

### LLVM Backend (TableGen)
| File | Description |
|------|-------------|
| `llvm-i860/lib/Target/I860/I860RegisterInfo.td` | Complete register file definition |
| `llvm-i860/lib/Target/I860/I860InstrFormats.td` | Instruction format definitions |
| `llvm-i860/lib/Target/I860/I860InstrInfo.td` | High-level instruction definitions |
| `llvm-i860/lib/Target/I860/I860CallingConv.td` | Calling convention definitions |
| `llvm-i860/lib/Target/I860/I860Schedule.td` | Pipeline scheduling info |
| `llvm-i860/lib/Target/I860/I860PairingRules.td` | Dual-instruction pairing rules |
| `llvm-i860/lib/Target/I860/I860InstrPatterns.td` | Selection patterns |
| `llvm-i860/lib/Target/I860/I860InstrControl.td` | Control flow definitions |
| `llvm-i860/lib/Target/I860/I860InstrSIMD.td` | SIMD/vector definitions |

### Emulator Core (Rust)
| File | Description |
|------|-------------|
| `emulator/i860-core/` | Rust emulator (MAME-compatible decoder) |
| `emulator/i860-core/docs/i860-instruction-status.md` | Implementation tracker (507 lines) — 73% complete |
| `emulator/i860-core/src/mame_decoder.rs` | Rust port of MAME decode table |
| `emulator/i860-core/src/mame_handlers.rs` | All execution implementations |

### Documentation
| File | Description |
|------|-------------|
| `docs/i860/reference/i860-reference.pdf` | **Official Intel manual** (366 pages, 12 MB) |
| `docs/i860/reference/i860-reference.txt` | Full text extraction (833 KB) |
| `docs/i860/reference/i860-reference-toc.md` | Formatted table of contents |
| `docs/i860/i860xp-instruction-summary.md` | XP-specific instruction reference |

### Firmware
| File | Description |
|------|-------------|
| `firmware/` | Firmware binaries and assembly code examples |

---

## Repository: NeXTRust

**Path**: `/Users/jvindahl/Development/NeXTRust/`

### i860 Documentation
| File | Description |
|------|-------------|
| `docs/hardware/i860-gpu-simulations.md` | GPU simulation capabilities (590 lines) |
| `docs/hardware/nextdimension-acceleration.md` | NeXTdimension acceleration project (476 lines) |
| `docs/gpu/nextgpu-webgpu-implementation.md` | WebGPU on i860 design (399+ lines) |
| `docs/hardware/postscript-interpreter-options.md` | PostScript acceleration |

### LLVM Infrastructure
| File | Description |
|------|-------------|
| `llvm-project/llvm/include/llvm/BinaryFormat/ELF.h` | `EM_860 = 7` definition |
| `llvm-project/llvm/tools/llvm-readobj/ELFDumper.cpp` | ELF i860 machine type mapping |
| `llvm-project/llvm/lib/Target/M68k/` | M68k LLVM backend (reference implementation) |

---

## Repository: previous/reverse-engineering

**Path**: `/Users/jvindahl/Development/previous/reverse-engineering/`

### Core i860 Documentation
| File | Description |
|------|-------------|
| `nextdimension-files/emulation/dimension-i860-cpu.md` | Complete ISA reference (1200+ lines) |
| `nextdimension-files/includes/I860_HEADERS_EXTRACTED.h` | **NeXTSTEP headers**: CPU type, thread state, relocations |
| `03-firmware-analysis/code-patterns/I860_CODE_PATTERNS.md` | Code recognition guide |
| `03-firmware-analysis/code-patterns/I860_ARCHITECTURE_COMPARISON.md` | Comparison with Windows NT i860 |

### Disassembly Files
| File | Description |
|------|-------------|
| `nextdimension-files/disassembly/i860/ND_i860_CLEAN.bin` | **64 KB firmware binary** |
| `nextdimension-files/disassembly/i860/ND_i860_CLEAN.bin.asm` | Full disassembly listing |
| `nextdimension-files/disassembly/i860/ND_i860_CLEAN_ANNOTATED.asm` | Annotated disassembly |
| `nextdimension-files/disassembly/i860/ND_i860_CLEAN.bin_mach.asm` | Mach kernel disassembly |
| `nextdimension-files/disassembly/i860/ND_i860_CLEAN.bin_bootstrap.asm` | Bootstrap code |

### Protocol & Hardware
| File | Description |
|------|-------------|
| `04-protocol-specs/HOST_I860_PROTOCOL_SPEC.md` | Host-i860 protocol (2043 lines) |
| `02-hardware-specs/NEXTDIMENSION_MEMORY_MAP_COMPLETE.md` | Complete memory map |
| `02-hardware-specs/FINAL_VERIFIED_MEMORY_MAP.md` | Verified memory layout |

### Firmware Analysis (36 documents)
| Category | Count | Key Files |
|----------|-------|-----------|
| ROM/Boot | 4 | ROM_BOOT_SEQUENCE_DETAILED.md |
| Kernel | 5 | KERNEL_ARCHITECTURE_COMPLETE.md |
| Function mapping | 11 | CALL_GRAPH_COMPLETE.md, PARAMETER_CONVENTIONS.md |
| Disassembly methodology | 9 | REVERSE_ENGINEERING_PLAYBOOK.md |
| Code patterns | 5 | I860_CODE_PATTERNS.md, I860_CODE_INVENTORY.md |

---

## Repository: spea-fire/refs/APX2

**Path**: `/Users/jvindahl/Development/spea-fire/refs/APX2/`

### Intel APX2 Development Tools
| File | Description |
|------|-------------|
| `UNIX_binaries/bin/as860` | **i860 Assembler** (contains all instruction mnemonics) |
| `UNIX_binaries/bin/sim860` | **i860 Simulator/Debugger** (execution error messages) |
| `UNIX_binaries/bin/dump860` | Object file dumper (relocation types) |
| `UNIX_binaries/bin/ld860` | Linker |
| `UNIX_binaries/bin/ar860` | Librarian |
| `UNIX_binaries/bin/nm860` | Symbol utility |
| `UNIX_binaries/bin/mac860` | Macro preprocessor |
| `UNIX_binaries/bin/mas860` | Macro assembler |
| `UNIX_binaries/inc/fmath.h` | Math library (complex numbers, transcendentals) |
| `UNIX_binaries/lib/libfma.a` | Scalar math library |

### Firmware Binaries
| File | Description |
|------|-------------|
| `BOOT.OUT` | 13,786 B, COFF magic 0x0090, entry 0x03fe3fe0 |
| `KERNEL2.0` | 185,723 B, kernel firmware |
| `BENCH/DHRY860` | Dhrystone benchmark for i860 |
| `BENCH/HILBERT` | Hilbert curve benchmark |

### SPEA Fire Analysis
| File | Description |
|------|-------------|
| `/Users/jvindahl/Development/spea-fire/analysis/parse_i860_coff.py` | COFF file parser |
| `/Users/jvindahl/Development/spea-fire/analysis/disasm/boot2_rom_f0000000.asm` | ROM disassembly (134 KB) |
| `/Users/jvindahl/Development/spea-fire/analysis/i860_dispatcher/dispatcher.c` | C dispatcher implementation |
| `/Users/jvindahl/Development/spea-fire/analysis/i860_dispatcher/dispatcher.asm` | Assembly dispatcher |
| `/Users/jvindahl/Development/spea-fire/docs/intel-i860.md` | Architecture overview |

---

## Test Binaries Available

| Binary | Source | Size | Format | Use |
|--------|--------|------|--------|-----|
| `ND_i860_CLEAN.bin` | NeXTdimension | 64 KB | Raw / Mach-O | Primary test corpus |
| `BOOT.OUT` | SPEA Fire | 13.8 KB | COFF (0x0090) | COFF loader testing |
| `BOOT2.OUT` | SPEA Fire | 27.8 KB | COFF (0x0090) | COFF loader testing |
| `KERNEL2.0` | SPEA Fire | 185.7 KB | COFF | Large binary testing |
| `DHRY860` | APX2 benchmark | Small | COFF | Known-good binary |

---

## Key Decoder Sources (Priority Order for SLEIGH)

1. **`nextdimension/tools/mame-i860/i860dec.hxx`** — Authoritative decoder, 3500+ lines
2. **`nextdimension/data/i860/i860-encodings.json`** — Machine-readable encoding database
3. **`nextdimension/llvm-i860/lib/Target/I860/*.td`** — LLVM TableGen (clean, structured)
4. **`nextdimension/i860-disassembler/src/opcode_table.rs`** — Rust opcode tables
5. **`nextdimension/docs/i860/reference/i860-reference.pdf`** — Official Intel manual
