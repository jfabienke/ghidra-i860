# PostScript Data Section - Reference Only

**File**: `05_postscript_data_REFERENCE_ONLY.bin`
**Size**: 64 KB (65,792 bytes)
**MD5**: `8b52a915d9ae209256b50c22c1296613`
**Source Offset**: 66,536 (ND_MachDriver_reloc)
**Virtual Address**: 0xF8010000 (if it were loaded)

---

## ⚠️ IMPORTANT: NOT i860 CODE

**This file is NOT executable i860 code and should NOT be included in the i860 firmware.**

This section contains:
1. **PostScript text** (~27 KB) - Display PostScript operator definitions
2. **m68k code** (~32 KB) - Motorola 68040 host driver utility library

**Both are incompatible with the i860 processor** and included here only for reference/documentation purposes.

---

## Content Breakdown

### Part 1: PostScript Operators (0x0000-0x6800, ~27 KB)

**Type**: ASCII text (Display PostScript Level 1)

**Purpose**: Operator definitions for NeXT's Display PostScript rendering system

**Sample Content**:
```postscript
_doClip 1 eq
  {
    gsave _pf grestore clip newpath /_lp /none ddef _fc
    /_doClip 0 ddef
  }
  {
    _pf
  }ifelse

/f                  % - f -
{
  closepath
  F
} def

/S                  % - S -
{
  _pola 0 eq
    {
      _doClip 1 eq
        {
          gsave _ps grestore clip newpath /_lp /none ddef _sc
          /_doClip 0 ddef
        }
        {
          _ps
        }ifelse
    }
    {
      /CRender {S} ddef
    }ifelse
} def
```

**Operators Defined**:
- Basic graphics: `f`, `s`, `b`, `F`, `S`, `B`
- Clipping: `_doClip`, `_pf`, `_ps`, `_fc`, `_sc`
- Rendering control: `_pola`, `/CRender`
- Path operations: `closepath`, `newpath`, `clip`

**Characteristics**:
- Plain ASCII text (not compiled bytecode)
- Display PostScript Level 1 syntax
- Custom operator definitions (underscore prefix)
- Would require PostScript interpreter to use
- Cannot be executed directly on i860

---

### Part 2: m68k Host Driver Code (0x8000-0x10100, ~32 KB)

**Type**: Motorola 68040 executable code

**Purpose**: Low-level utility library for m68k host driver (runs on NeXTcube, NOT i860)

**Instruction Patterns**:
```
LINK A6,#0      ; Function prologue (stack frame setup)
UNLK A6         ; Function epilogue (restore stack)
RTS             ; Return from subroutine
CLR.L D0        ; Clear data register
MOVE.L ...      ; Move data
BSR.L ...       ; Branch to subroutine
```

**Characteristics**:
- 195 small functions (~170 bytes average)
- Pure utility/wrapper code
- No readable strings (pure binary)
- Part of larger m68k driver (connects to Section 5)
- Cannot execute on i860 (wrong architecture)

**Analysis Evidence**:
```
Offset 0x8000: ff00 4e5e 4e75 4e56 0000 2f2e 0008 61ff
                    ^^^^ ^^^^ ^^^^ ^^^^
                    UNLK RTS  LINK ...

Perfect m68k function boundaries: 195 found
Average function size: ~170 bytes
Typical driver utility library pattern
```

---

## Why This Exists in ND_MachDriver_reloc

**The firmware file is a "Matryoshka doll"** - it contains:
1. i860 executable code (Sections 1-3)
2. m68k host driver that loads the i860 code (Sections 4-5)
3. Various contamination (Sections 6-11)

**Build system issue**: No architecture validation, everything linked into single binary.

**Proper structure would be**:
```
ND_i860_firmware.bin     (192 KB) - i860 code only
ND_m68k_driver.o         (130 KB) - m68k host driver
postscript_prologue.ps   ( 27 KB) - PostScript text
```

Instead we got:
```
ND_MachDriver_reloc      (795 KB) - Everything mixed together!
```

---

## Historical Context: Display PostScript on NeXTdimension

**Original Plan**:
- NeXTdimension i860 would run Display PostScript rendering
- Accelerate graphics operations on dedicated processor
- Offload work from main m68k CPU

**Reality**:
- Display PostScript on i860 was **never completed**
- Feature remained unimplemented in shipping product
- PostScript text in firmware is leftover from incomplete feature
- Graphics acceleration worked, but not via PostScript interpreter

**Evidence**:
- No PostScript interpreter in extracted i860 code
- No references to PostScript operators in i860 disassembly
- Would require ~100KB interpreter + runtime (not present)
- NeXT documentation mentions feature was "planned" but not delivered

---

## Usage Recommendations

### ❌ DO NOT Use For:
- i860 firmware (cannot execute on i860)
- Previous emulator i860 code
- GaCKliNG i860 implementation
- Any i860-based PostScript rendering

### ✅ CAN Use For:
- **Historical reference** - Understanding NeXT's original DPS-on-i860 plans
- **Operator research** - Learning Display PostScript custom operators
- **m68k driver analysis** - Understanding host driver architecture
- **Documentation** - Explaining why DPS-on-i860 didn't ship

### If Implementing PostScript on i860:
1. **Don't use this text** - Requires interpreter (slow, large)
2. **Compile to i860** - Rewrite operators as i860 assembly/C
3. **Use bytecode** - Compile PS to i860 bytecode format
4. **Or skip it** - Original NeXT engineers did!

---

## Connection to Other Sections

**This section connects with**:

**Section 5** (96 KB):
- High-level m68k host driver
- Contains strings: `"NDDriver: ND_Load_MachDriver"`
- Calls Section 4's utility functions
- Together form complete 128 KB m68k driver

**Section 1-3** (192 KB):
- Actual i860 executable code
- What gets loaded by the m68k driver
- Contains graphics acceleration (NOT PostScript-based)
- This is the real NeXTdimension firmware

---

## Analysis Statistics

**PostScript Text Region**:
```
Size:              27,136 bytes
Printable chars:   89.1% (WAY too high for code)
Null bytes:        3.2%
Entropy:           5.1 bits/byte (text-like)
PostScript keywords: 40 found
i860 MMIO refs:    0 (no hardware access)
```

**m68k Code Region**:
```
Size:              32,768 bytes
Function count:    195
Avg function size: ~170 bytes
LINK/UNLK pairs:   195 (perfect match)
RTS instructions:  195
i860 patterns:     0 (different architecture)
```

---

## References

- **SECTION4_VERIFICATION_CARD.md** - Complete analysis with all tests
- **SECTION4_DETAILED_MAP.md** - Detailed memory map
- **SECTION_VALIDATION_REPORT.md** - Multi-section contamination report
- **SECTION5_VERIFICATION_CARD.md** - Connected m68k driver analysis

---

## Conclusion

**Purpose**: Reference/documentation only

**Use Case**: Understanding NeXT's Display PostScript plans and m68k driver architecture

**NOT FOR**: i860 firmware, emulation, or execution

**Status**: ❌ Excluded from `ND_i860_VERIFIED_clean.bin` (correct decision)

---

**Extracted**: 2025-11-09
**Source**: ND_MachDriver_reloc offset 66,536
**Analysis**: Complete (4/4 verification tests confirm non-i860 content)
**Recommendation**: Reference only, do not include in i860 firmware
