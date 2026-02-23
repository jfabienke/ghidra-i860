# Complete i860 Code Inventory
## Definitive List of i860 Code in NeXTdimension Firmware

**Date**: 2025-11-05
**Method**: Manual verification + disassembly coherence + pattern analysis
**Status**: VERIFIED sections only (conservative estimates)

---

## Executive Summary

### Confirmed i860 Code: **68 KB** (9.9% of 686KB total)

```
✓ Section 1-2: 32 KB - Bootstrap + Graphics primitives (79 handlers)
✓ Section 3:   32 KB - PostScript operators (75 operators)
✓ Section 11:   4 KB - Debug/diagnostic routines (13 functions)
═══════════════════════════════════════════════════════════════
TOTAL:         68 KB - Actual i860 executable code
```

### Confirmed NOT i860: **~160 KB** (23% of total)

```
❌ Section 4 (partial):  ~27 KB - PostScript text (ASCII)
❌ Section 4 (partial):  ~32 KB - m68k utility library (195 functions)
❌ Section 5 (partial):  ~8+ KB - m68k high-level driver (strings, IPC)
❌ Section 7 (partial):  ? KB   - x86 NeXTtv.app executable
❌ Section 8 (partial):  ? KB   - NIB UI definitions
❌ Section 9 (partial):  ? KB   - Bitmap graphics
```

### Unknown/Unverified: **~478 KB** (68% of total)

Remaining sections contain mix of:
- Possible i860 code
- Data structures
- Padding/nulls
- Additional contamination

**Conservative conclusion**: Only 68 KB definitively verified as i860 code.

---

## Section-by-Section Analysis

### ✓ Section 1-2 (section1-2_bootstrap.bin) - 32 KB

**Status**: ✅ VERIFIED i860 CODE

**Evidence**:
- Disassembles coherently as i860
- 205 bri (branch indirect) instructions found
- 79 function boundaries identified
- Hardware MMIO access patterns (0x02000000)
- Low printable ratio (18.2%)
- Already mapped in GRAPHICS_PRIMITIVES_MAP.md

**Contents**:
1. Mach-O header (840 bytes)
2. Bootstrap init (205 bytes)
3. Graphics primitive handlers:
   - Dispatch mechanism at 0xFFF014C4
   - 37 substantial handlers (>100 bytes)
   - 28 small handlers/stubs (<100 bytes)
   - Math/utility library (4KB)

**File**: First 32KB of ND_i860_CLEAN.bin (bytes 0x00000-0x07FFF)

---

### ✓ Section 3 (section3_mach.bin) - 32 KB

**Status**: ✅ VERIFIED i860 CODE

**Evidence**:
- Disassembles coherently as i860
- 124 bri instructions
- 75 PostScript operator entry points identified
- Debug trace pattern (`st.b %r8,16412(%r8)`) at each operator
- Hardware access patterns
- Low printable ratio (22.0%)
- Already mapped in POSTSCRIPT_OPERATORS_CORRECTED.md

**Contents**:
- 75 Display PostScript Level 1 operators
- Operator sizes: 48 bytes to 6,232 bytes
- Total code: 30,980 bytes
- Plus PostScript dictionary source (1,768 bytes ASCII at end)

**File**: Second 32KB of ND_i860_CLEAN.bin (bytes 0x08000-0x0FFFF)

---

### ❌ Section 4 (section4_vm.bin) - 65.8 KB

**Status**: ❌ NOT i860 CODE (mixed contamination)

**Verified Contents**:
1. **PostScript operators** (0x0000-0x2000, ~8 KB)
   - ASCII text, operator definitions
   - 89-98% printable characters
   - Disassembles to nonsense

2. **PostScript graphics** (0x2000-0x6800, ~19 KB)
   - ASCII text, vector drawing commands
   - 93-98% printable
   - PDF-style PostScript

3. **Padding** (0x6800-0x8000, ~1.5 KB)
   - Transition/alignment

4. **m68k utility library** (0x8000-0x10100, ~32 KB)
   - 195 m68k functions (UNLK+RTS+LINK pattern)
   - Low-level wrappers
   - Part of host driver (connects to Section 5)

**See**: SECTION4_DETAILED_MAP.md, SECTION4_VERIFICATION_CARD.md

---

### ⚠️ Section 5 (section5_handlers.bin) - 96 KB

**Status**: ⚠️ PARTIALLY VERIFIED (first ~8KB is m68k, rest UNKNOWN)

**Verified m68k portion** (0x0000-~0x2000, first 8+ KB):
- m68k high-level driver code
- 46+ readable strings:
  - "NDDriver: ND_Load_MachDriver"
  - "port_allocate", "msg_send" (Mach IPC)
  - Error messages and paths
- 2 m68k function boundary patterns (UNLK+RTS+LINK)
- 36.6% printable in first 8KB

**Unverified portion** (0x2000-0x17F60, remaining ~88 KB):
- Lower printable ratio (26-38%)
- No obvious strings
- Could be:
  - More m68k code (data/code mixed)
  - i860 code
  - Data structures
  - Padding

**Recommendation**: Needs detailed disassembly of portions beyond first 8KB

**See**: SECTION5_VERIFICATION_CARD.md

---

### ❓ Section 6 (section6_graphics.bin) - 160 KB

**Status**: ❓ UNVERIFIED (conflicting evidence)

**Evidence FOR contamination**:
- Contains Spanish localization strings at offset ~0x8000:
  - "Nuevo grupo" (New group)
  - "Nueva dirección" (New address)
  - "García, Francisco"
- Strings found in previous analysis (SECTION_VALIDATION_REPORT.md)

**Evidence AGAINST (needs investigation)**:
- First 32KB (0x0000-0x7FFF):
  - 37-38% printable (reasonable for code)
  - Low null bytes (2%)
  - Pattern tests show some i860-like patterns
- Second 32KB (0x8000-0xFFFF):
  - 75-85% null bytes (mostly empty/padding)
  - Spanish strings appear here

**Hypothesis**: First ~32KB might be legitimate code with junk appended?

**Recommendation**: Disassemble first 32KB and check coherence

---

### ❓ Section 7 (section7_x86.bin) - 160 KB

**Status**: ❓ PARTIALLY VERIFIED (contains x86, but how much?)

**Known contamination**:
- Contains x86 NeXTtv.app executable (confirmed in SECTION7_X86_CODE_DISCOVERY.md)
- Application strings: "Saturation", "Brightness", "screenlist"
- PostScript font commands

**Unknown**:
- How much of 160KB is actually x86 vs other content?
- Could there be i860 code mixed in?

**Recommendation**: Need systematic scan to separate x86 from potential i860 regions

---

### ❓ Section 8 (section8_video.bin) - 48.9 KB

**Status**: ❓ UNVERIFIED

**Previous analysis** (SECTION_VALIDATION_REPORT.md):
- 75.7% printable (very high)
- Contains "IBOutletConnector" (Interface Builder)
- UI element names: progressTextField, progressLocLabel
- Marked as NIB file data

**Issues with previous analysis**:
- Very high printable ratio suggests text/data
- But pattern matching showed some i860-like patterns

**Recommendation**: Verify if entire section is NIB data or if code exists

---

### ❓ Section 9 (section9_utils.bin) - 33.4 KB

**Status**: ❓ UNVERIFIED

**Previous analysis**:
- 66.8% printable
- Repeating hex patterns (0x5555, 0xAAAA, 0xFFFF)
- Marked as bitmap graphics (cursor/icon data)

**Recommendation**: Likely data, but should verify no code exists

---

### ❓ Section 10 (section10_ipc.bin) - 23.5 KB

**Status**: ❓ UNVERIFIED

**Previous analysis**:
- 27.3% printable (reasonable for code)
- 35.4% null bytes (high)
- Marked as "data structures"

**Pattern test results**:
- Shows some i860-like patterns
- 73% coherence in initial test

**Recommendation**: Could be i860 code OR data structures - needs investigation

---

### ✅ Section 11 (section11_debug.bin) - 4.0 KB

**Status**: ✅ VERIFIED i860 CODE

**Evidence**:
- Disassembles coherently as i860 (90.1% coherence)
- 13 bri (branch indirect) instructions found
- 13 function boundaries identified
- 227 load/store operations
- 19 call instructions
- NO m68k patterns
- NO readable strings
- Low printable ratio (34.3%)
- Already mapped in SECTION11_VERIFICATION_CARD.md

**Contents**:
- 13 debug/diagnostic functions
- Function sizes: 56 bytes to 776 bytes
- Total code: ~3,652 bytes
- Some hardware MMIO access patterns (0x02000000)

**File**: Bytes at offset 0xF809A000 in firmware (4,096 bytes)

---

## Summary Statistics

```
┌────────────────────────┬─────────┬──────────────────────────┐
│ Section                │ Size    │ Status                   │
├────────────────────────┼─────────┼──────────────────────────┤
│ 1-2 Bootstrap+Graphics │  32 KB  │ ✓ Verified i860          │
│ 3   PostScript Ops     │  32 KB  │ ✓ Verified i860          │
│ 4   VM/Memory          │  66 KB  │ ❌ PostScript + m68k     │
│ 5   Handlers           │  96 KB  │ ⚠️ ~8KB m68k, rest ?    │
│ 6   Graphics           │ 160 KB  │ ❓ Spanish strings + ?   │
│ 7   x86/NeXTtv         │ 160 KB  │ ❓ x86 app + ?           │
│ 8   Video              │  49 KB  │ ❓ NIB data + ?          │
│ 9   Utils              │  33 KB  │ ❓ Bitmaps + ?           │
│ 10  IPC                │  24 KB  │ ❓ Data or i860?         │
│ 11  Debug              │   4 KB  │ ✓ Verified i860          │
├────────────────────────┼─────────┼──────────────────────────┤
│ TOTAL                  │ 686 KB  │                          │
└────────────────────────┴─────────┴──────────────────────────┘

Breakdown:
  ✓ Verified i860:      68 KB  (9.9%)
  ❌ Verified NOT i860: ~100 KB (14.6%)
  ❓ Unverified:        ~518 KB (75.5%)
```

---

## Recommendations for Further Analysis

### High Priority (Likely i860 Code)

1. **Section 10 (IPC)** - 24 KB
   - Reasonable printable ratio (27%)
   - Shows i860 patterns
   - Could be IPC/protocol implementation

3. **Section 6 (Graphics) - First 32KB**
   - First half shows code-like characteristics
   - Spanish strings only in second half
   - Could contain graphics acceleration code

### Medium Priority

4. **Section 5 (Handlers) - After first 8KB**
   - First 8KB is definitely m68k
   - Remaining 88KB unverified
   - Could be i860 graphics handlers as originally named

5. **Section 7 (x86/NeXTtv) - Non-x86 portions**
   - Known to contain x86 app
   - But 160KB total - how much is x86?
   - Could have i860 code mixed in

### Low Priority (Likely Data/Contamination)

6. **Section 8 (Video)** - 76% printable suggests NIB data
7. **Section 9 (Utils)** - 67% printable suggests bitmap graphics

---

## Verification Methodology

To properly verify a section as i860 code, ALL of these must pass:

1. ✅ **Disassembly Coherence**
   - >80% valid i860 instructions when disassembled
   - <20% `.long` directives (undecoded bytes)
   - Reasonable branch targets (within file or to known addresses)

2. ✅ **Function Boundaries**
   - Clear bri (branch indirect) instructions for returns
   - Function density: 10-50 functions per 4KB
   - NOT m68k patterns (4E 5E 4E 75 4E 56)

3. ✅ **Register Usage**
   - Valid i860 register names (%r0-%r31, %f0-%f31)
   - Load/store architecture (ld/st instructions)
   - NO direct memory access (no MOVE like m68k)

4. ✅ **Content Analysis**
   - Printable ratio: 20-40% (too high = text, too low = padding)
   - Entropy: 7.0-7.8 bits/byte (high for code)
   - Few readable strings (if many = data/contamination)

5. ✅ **Hardware Access** (for NeXTdimension-specific code)
   - References to 0x02000000 (mailbox/MMIO)
   - References to 0x10000000 (VRAM)
   - May not apply to generic utility code

---

## Conclusion

**Definitively Verified i860 Code**: 68 KB (Sections 1-3 + Section 11)

**Remaining sections**: Need careful manual analysis, not automated pattern matching. Pattern matching gives too many false positives because random data can decode as valid-looking instructions.

**Next Steps**:
1. ✅ ~~Manually disassemble and verify Section 11 (4KB)~~ - COMPLETE (verified as i860 code)
2. Manually check Section 10 (24KB)
3. Disassemble first 32KB of Section 6 to check for code
4. Systematic analysis of Section 5 beyond first 8KB

**Conservative estimate for GaCKliNG**: Only the verified 68KB should be considered actual i860 firmware. Everything else is either proven contamination or unverified.

---

**Document Status**: CONSERVATIVE ANALYSIS
**Last Updated**: 2025-11-06
**Confidence**: HIGH for verified sections (68 KB), LOW for pattern-based guesses
**Recommendation**: Manual verification required for unverified sections
