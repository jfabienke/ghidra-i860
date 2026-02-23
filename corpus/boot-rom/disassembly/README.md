# NeXTdimension Disassembly Files

This directory contains verified binary firmware and disassembled code for the NeXTdimension graphics board.

---

## Directory Structure

```
disassembly/
├── i860/          - Intel i860 firmware binaries and disassemblies
├── rom/           - m68k ROM binaries and disassemblies
└── archive/       - Historical ROM versions
```

---

## i860 Firmware (5 files)

### ⭐ Start Here: `i860/ND_i860_CLEAN_ANNOTATED.asm` (19 KB)
**Most valuable file** - Hand-annotated disassembly with:
- Function names and boundaries
- Comments explaining code behavior
- Table of contents showing firmware structure
- Easy to read and understand

**Use this first** when trying to understand how the firmware works!

### Source of Truth: `i860/ND_i860_CLEAN.bin` (64 KB)
The verified i860 firmware binary. This is the actual code that runs on the i860 processor.

- **Size**: 65,536 bytes (64 KB)
- **Base Address**: 0xF8000000
- **Architecture**: Intel i860XP RISC processor
- **Verification**: MD5, disassembly coherence, branch target validity
- **Status**: Clean, verified firmware (no contamination)

### Complete Disassembly: `i860/ND_i860_CLEAN.bin.asm` (992 KB)
Full machine-generated disassembly of the entire firmware. Contains every instruction with addresses.

Use when you need to:
- Find specific instruction addresses
- Analyze complete control flow
- Generate call graphs
- Study instruction patterns

### Section Disassemblies

#### `i860/ND_i860_CLEAN.bin_bootstrap.asm` (496 KB)
Disassembly of the bootstrap section (Sections 1-2):
- Hardware initialization
- Graphics HAL setup
- Exception vectors
- Early boot code

#### `i860/ND_i860_CLEAN.bin_mach.asm` (496 KB)
Disassembly of the Mach kernel section (remainder of firmware):
- Mach IPC services
- Mailbox protocol
- PostScript operator handlers
- Graphics acceleration

---

## m68k ROM (5 files)

### Primary ROMs

#### `rom/Rev_2.5_v66.bin` (128 KB)
**Most commonly used ROM version** (v2.5, revision 66)
- Standard NeXTdimension ROM
- Best compatibility with NeXTSTEP 3.x

#### `rom/Rev_3.3_v74.bin` (128 KB)
**Latest ROM version** (v3.3, revision 74)
- Final production ROM
- Enhanced features and bug fixes

### ROM Disassemblies

#### `rom/ROMV66-0001E-02588.ASM` (849 KB)
Complete m68k disassembly of ROM v2.5 (Rev_2.5_v66.bin)

Contains:
- Boot sequence
- Hardware initialization
- BIOS-like functions
- i860 loading and control

#### `rom/ND_step1_v43_eeprom.bin` (128 KB)
ROM v1.0 binary (revision 43)

#### `rom/ND_step1_v43_eeprom.asm` (1.9 MB)
Complete m68k disassembly of ROM v1.0

---

## Archive (2 files)

Historical ROM versions kept for reference:

- `archive/Rev_0.8_v31.bin` (64 KB) - Very early ROM (v0.8)
- `archive/Rev_1.0_v41.bin` (64 KB) - Intermediate ROM (v1.0)

---

## Usage Guide

### For Understanding the Firmware
1. **Start with**: `i860/ND_i860_CLEAN_ANNOTATED.asm`
2. **Reference**: Related documentation in `/docs/03-firmware-analysis/`
3. **Deep dive**: `i860/ND_i860_CLEAN.bin.asm` for specific details

### For Emulator Development
1. **Binary**: `i860/ND_i860_CLEAN.bin` (what to execute)
2. **ROM**: `rom/Rev_2.5_v66.bin` (boot ROM to emulate)
3. **Reference**: Disassemblies to understand expected behavior

### For Firmware Development
1. **Study**: Annotated disassembly for architecture
2. **Reference**: Complete disassembly for implementation details
3. **Binary**: Original firmware as reference implementation

---

## File Integrity

### i860 Firmware
```
MD5 (ND_i860_CLEAN.bin) = [verified in docs]
Size: 65,536 bytes
```

### ROM Binaries
```
Rev_2.5_v66.bin: 131,072 bytes
Rev_3.3_v74.bin: 131,072 bytes
```

---

## Related Documentation

- **Firmware Analysis**: `/docs/03-firmware-analysis/`
- **Hardware Specs**: `/docs/02-hardware-specs/`
- **Protocol Specs**: `/docs/04-protocol-specs/`
- **ROM Analysis**: `/docs/03-firmware-analysis/rom-boot/`

---

## Tools Used

### Disassemblers
- **Rust i860-disassembler**: Primary tool (1.6× faster than MAME)
- **MAME i860disasm**: Reference disassembler
- **m68k disassembler**: For ROM analysis

### Verification Tools
- `verify_clean_firmware.py`: Binary verification
- Branch target validity analysis
- Disassembly coherence checking

---

## Notes

### Why Three Disassembly Formats?

1. **Annotated** (19 KB): Human-readable with explanations → **Start here**
2. **Complete** (992 KB): Machine-generated with all details → Reference
3. **Section** (496 KB each): Logical sections split out → Specific analysis

### ROM Versions

- **v2.5 (Rev 66)**: Most common, best compatibility
- **v3.3 (Rev 74)**: Latest, most features
- **v1.0 (Rev 43)**: Early version (in archive)
- **v0.8 (Rev 31)**: Initial release (in archive)

Use **v2.5** unless you need specific v3.3 features.

---

**Last Updated**: 2025-11-11
**Total Size**: ~4.4 MB (i860) + 3.1 MB (ROM) = 7.5 MB
