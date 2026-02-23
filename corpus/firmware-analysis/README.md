# NeXTdimension Clean Firmware

This directory contains the **verified i860 code** extracted from the contaminated ND_MachDriver_reloc firmware (795 KB → 196 KB, **74% contamination removed**).

## Quick Reference

| File | Purpose | Load Address |
|------|---------|--------------|
| **ND_i860_clean.bin** | **Concatenated clean firmware** | **0xF8000000** |
| 01_bootstrap_graphics.bin | Bootstrap & Graphics Primitives | 0xF8000000 |
| 02_postscript_operators.bin | PostScript Operators | 0xF8008000 |
| 03_graphics_acceleration.bin | Graphics Acceleration (4 regions) | 0xF8010000 |
| 04_debug_diagnostics.bin | Debug & Diagnostics | 0xF8030000 |

## Usage

### Disassemble Clean Firmware
```bash
cd /Users/jvindahl/Development/nextdimension/i860-disassembler
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8000000 \
  --stats \
  ND_i860_clean.bin > ND_i860_clean.asm
```

### Analyze Individual Sections
```bash
# Section 1: Bootstrap
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8000000 \
  01_bootstrap_graphics.bin > section1.asm

# Section 2: PostScript
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8008000 \
  02_postscript_operators.bin > section2.asm

# Section 3: Graphics (128 KB)
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8010000 \
  03_graphics_acceleration.bin > section3.asm

# Section 4: Debug
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8030000 \
  04_debug_diagnostics.bin > section4.asm
```

### JSON Output for Analysis
```bash
./target/release/i860-dissembler \
  --format json \
  --base-address 0xF8000000 \
  ND_i860_clean.bin > ND_i860_clean.json
```

## Files

- `ND_i860_clean.bin` - **196 KB** concatenated clean firmware
- `01_bootstrap_graphics.bin` - 32 KB bootstrap code
- `02_postscript_operators.bin` - 32 KB PostScript operators
- `03_graphics_acceleration.bin` - 128 KB graphics code (4 regions)
- `04_debug_diagnostics.bin` - 4 KB debug utilities
- `CLEAN_FIRMWARE_EXTRACTION_REPORT.md` - **Full extraction report**
- `README.md` - This file

## Verification

### MD5 Checksums
```
fc72c3eac9e1e693b07f0ae0dc44b797  01_bootstrap_graphics.bin
7b1b912fbd95b5aa20e644c80e13e50b  02_postscript_operators.bin
280c6cfcde6589c54214081218250ff9  03_graphics_acceleration.bin
516f178645dfaa3f8bb94f5fe04137e4  04_debug_diagnostics.bin
cb83a19ac1cb9062e2c935b296c5e645  ND_i860_clean.bin
```

## Source

- **Original Firmware**: `/Users/jvindahl/Development/previous/src/nextdimension_files/ND_MachDriver_reloc`
- **Analysis**: `/Users/jvindahl/Development/previous/src/SECTION_VALIDATION_REPORT.md`
- **Extraction Script**: `/tmp/extract_clean_firmware.sh`
- **Extracted**: 2025-11-09

## Notes

- This firmware is **relocatable** - some addresses may need fixup
- Virtual addresses are **recommended** based on typical i860 layouts
- Compare with NeXTdimension ROM: `/Users/jvindahl/Development/previous/src/ND_step1_v43_eeprom.bin`
- **74% of original firmware was contamination** (PostScript text, m68k code, x86 apps, NIB files, etc.)

## Next Steps

1. Disassemble with Rust i860-dissembler
2. Extract symbols and entry points
3. Validate instruction coherence
4. Test in Previous emulator or GaCKliNG
5. Cross-reference with ND ROM code

See **CLEAN_FIRMWARE_EXTRACTION_REPORT.md** for full details.
