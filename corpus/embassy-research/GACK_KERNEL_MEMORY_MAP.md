# GaCK Kernel Complete Memory Map
## NeXTdimension i860 Operating System - Detailed Memory Reference

**File**: `ND_i860_CLEAN.bin`
**Size**: 65,536 bytes (64.00 KB exactly)
**Type**: Mach-O preload executable i860g
**Purpose**: Graphics acceleration kernel for NeXTdimension board
**Last Updated**: 2025-11-05

---

## Table of Contents

1. [Overview](#overview)
2. [Address Space Layout](#address-space-layout)
3. [Complete 64KB Memory Map](#complete-64kb-memory-map)
4. [Section 1+2: Bootstrap & Graphics](#section-12-bootstrap--graphics-32kb)
5. [Section 3: Operators & Services](#section-3-operators--services-32kb)
6. [All 75 Operator Entry Points](#all-75-operator-entry-points)
7. [Memory Usage Statistics](#memory-usage-statistics)
8. [Special Memory Regions](#special-memory-regions)
9. [Address Translation Reference](#address-translation-reference)
10. [Quick Reference](#quick-reference)

---

## Overview

The GaCK kernel is a 64KB operating system that runs on the NeXTdimension's Intel i860XR processor. It provides graphics acceleration, Display PostScript rendering, and Mach microkernel services.

### Key Characteristics

- **Total Size**: 65,536 bytes (2^16, exactly 64KB)
- **Architecture**: Intel i860 RISC (big-endian)
- **Load Address**: 0xF8000000 (i860 local DRAM)
- **Structure**: Two 32KB sections
- **Code Density**: 72.33% code, 27.67% padding
- **Entry Points**: 75 identified operators + bootstrap

---

## Address Space Layout

### Three Address Spaces

The GaCK kernel exists in three different address spaces:

```
┌─────────────────────────────────────────────────────────────────┐
│ Space         │ Base Address  │ Purpose                         │
├───────────────┼───────────────┼─────────────────────────────────┤
│ FILE OFFSET   │ 0x00000000    │ Binary file position            │
│ DRAM (Runtime)│ 0xF8000000    │ Where code executes (i860 view) │
│ ROM (Disasm)  │ 0xFFF00000    │ Disassembler default base       │
└─────────────────────────────────────────────────────────────────┘

Conversion:
  DRAM = FILE + 0xF8000000
  ROM  = FILE + 0xFFF00000
  ROM  = DRAM + 0x07F00000
```

### Host vs i860 Memory Views

**i860 Processor View**:
- `0x00000000 - 0x03FFFFFF`: Local DRAM (8-64MB)
- `0xF8000000 - 0xF800FFFF`: **GaCK kernel location** (64KB)
- `0x02000000 - 0x02000FFF`: MMIO registers (4KB)
- `0x10000000 - 0x103FFFFF`: VRAM (4MB)
- `0xFFF00000 - 0xFFFFFFFF`: Boot ROM (1MB)

**68040 Host View**:
- `0xF8000000 - 0xFBFFFFFF`: NeXTdimension RAM window (64MB)
- `0xFE000000 - 0xFE3FFFFF`: NeXTdimension VRAM window (4MB)
- `0xFF800000 - 0xFF803FFF`: NeXTdimension I/O registers

---

## Complete 64KB Memory Map

```
FILE      DRAM          ROM           SIZE    CONTENT
OFFSET    ADDRESS       ADDRESS
─────────────────────────────────────────────────────────────────────
SECTION 1+2: Bootstrap & Graphics Primitives (32 KB)
─────────────────────────────────────────────────────────────────────
0x00000 | 0xF8000000 | 0xFFF00000 |   840 B | Mach-O header & load commands
0x00348 | 0xF8000348 | 0xFFF00348 |   205 B | Bootstrap initialization (entry point)
0x00415 | 0xF8000415 | 0xFFF00415 | 3,891 B | [PADDING - Alignment to 0x1348]
0x01348 | 0xF8001348 | 0xFFF01348 |27,832 B | Main Mach kernel + graphics primitives (~39 cmds)
        |            |            |         | (to 0x07FFF, includes ~6.7KB embedded padding)
─────────────────────────────────────────────────────────────────────
SUBTOTAL: 32,768 bytes (28,037 code + 840 header + 3,891 padding)
  Mach-O header:       840 bytes (file format metadata)
  Bootstrap code:      205 bytes (initialization/entry point)
  Kernel + graphics: 27,832 bytes (kernel + ~39 graphics commands, ~6.7KB embedded padding)
  Explicit padding:  3,891 bytes (alignment to 0x1348)
─────────────────────────────────────────────────────────────────────

─────────────────────────────────────────────────────────────────────
SECTION 3: Operator Implementations & PostScript Dictionary (32 KB)
─────────────────────────────────────────────────────────────────────
0x08000 | 0xF8008000 | 0xFFF08000 |    20 B | Section header (before first operator)
0x08014 | 0xF8008014 | 0xFFF08014 |30,980 B | 75 operator implementations
        |            |            |         | (to 0x0F917, includes embedded padding)
0x0F918 | 0xF800F918 | 0xFFF0F918 | 1,768 B | PostScript dictionary source (ASCII text)
        |            |            |         | (to 0x0FFFF, end of file)
─────────────────────────────────────────────────────────────────────
SUBTOTAL: 32,768 bytes (30,980 operators + 1,768 PS dict + 20 header)
  Operator code:       30,980 bytes (includes embedded padding)
  PostScript source:    1,768 bytes (ASCII text definitions)
  Section header:          20 bytes
─────────────────────────────────────────────────────────────────────

═════════════════════════════════════════════════════════════════════
TOTAL: 65,536 bytes (60,785 code/data + 860 headers + 3,891 padding)
  Code/data:          60,785 bytes (92.8%, includes embedded padding)
  File headers:          860 bytes (1.3%, Mach-O + Section 3 header)
  Explicit padding:    3,891 bytes (5.9%, alignment gap in Section 1+2)

  Section 1+2: 28,037 code + 840 header + 3,891 padding = 32,768 bytes
  Section 3:   32,748 code + 20 header + 0 padding     = 32,768 bytes
═════════════════════════════════════════════════════════════════════
```

---

## Section 1+2: Bootstrap & Graphics (32KB)

### Memory Layout

```
File Offset: 0x00000 - 0x07FFF
DRAM Addr:   0xF8000000 - 0xF8007FFF
ROM Addr:    0xFFF00000 - 0xFFF07FFF
Total Size:  32,768 bytes
```

### Subsections

#### 1. Mach-O Header (0x00000-0x00347, 840 bytes)
- Magic: 0xFEEDFACE (Mach-O preload executable)
- CPU type: i860 big-endian
- Load commands and segment definitions
- Entry point specification

#### 2. Bootstrap Initialization (0x00348-0x00414, 205 bytes)
- Initial entry point (first code executed after ROM hands off)
- Basic CPU/FPU setup
- Early memory initialization

#### 3. Alignment Gap (0x00415-0x01347, 3,891 bytes)
- Padding to align main kernel to 0x1348 boundary

#### 4. Main Mach Kernel + Graphics Primitives (0x01348-0x07FFF, 27,832 bytes)

**Primary Dispatch Mechanism**:
```
Location: 0xFFF014C4 (ROM) / 0xF8001324 (DRAM) / File offset 0x014C4
Type: Computed indirect branch dispatch

Assembly sequence:
  fff01464:  btne  %r8,%r12,0x00000190   ; Compare command with range
  fff01468:  btne  8,%r12,0x00010194     ; Range check
  fff0146c:  bte   %r8,%r12,0xfffe0198   ; Branch if equal
  fff01470:  bte   8,%r12,0xffff019c     ; Additional check
  ...
  fff014c4:  bri   %r8                   ; DISPATCH - branch to handler

Architecture: Command ID → handler address computed → indirect branch
```

**Graphics Command Handlers**:
- **Total handlers**: 79 distinct code regions (identified via `bri` instructions)
- **Substantial handlers**: 37 handlers >100 bytes (matches documented ~39 graphics primitives)
- **Handler boundaries**: Marked by `bri` (branch indirect) instructions serving as function returns

**Handler Size Distribution**:

```
┌──────────────────────────────────────────────────────────────┐
│ Size Range    │ Count │ Percentage │ Typical Operations      │
├───────────────┼───────┼────────────┼─────────────────────────┤
│ <50 bytes     │  28   │   35.4%    │ Stubs/trampolines/NOPs  │
│ 50-200 bytes  │  24   │   30.4%    │ Simple primitives       │
│ 200-1000 bytes│  19   │   24.1%    │ Standard graphics ops   │
│ 1000+ bytes   │   8   │   10.1%    │ Complex operations      │
├───────────────┼───────┼────────────┼─────────────────────────┤
│ TOTAL         │  79   │  100.0%    │                         │
└──────────────────────────────────────────────────────────────┘
```

**Major Graphics Operations** (1K+ bytes, likely complex rendering):

| Address (ROM)  | Size  | Likely Function                              |
|----------------|-------|----------------------------------------------|
| 0xFFF01A7C     | 4172B | **Math/Utility Library** - Shared FP/trig    |
| 0xFFF057A4     | 2536B | **Complex Compositing** - Advanced blending  |
| 0xFFF03B4C     | 2500B | **Bezier/Curve Rendering** - Path ops        |
| 0xFFF030EC     | 1876B | **Text Rendering** - Glyph/font operations   |
| 0xFFF02AC8     | 1464B | **Advanced Blit** - Complex memory transfer  |
| 0xFFF04888     | 1420B | **Image Scaling** - Resize/interpolation     |
| 0xFFF062A0     | 1344B | **Pattern Fill** - Tiled pattern operations  |
| 0xFFF04E74     | 1164B | **Polygon Fill** - Complex shape filling     |

**Standard Graphics Primitives** (200-1000 bytes, core 2D operations):

| Address (ROM)  | Size | Likely Function                              |
|----------------|------|----------------------------------------------|
| 0xFFF0158C     | 864B | **Standard Blit** - Block image transfer     |
| 0xFFF03840     | 780B | **Line Drawing** - Bresenham algorithm       |
| 0xFFF06F74     | 732B | **Rectangle Fill** - Solid color fills       |
| 0xFFF0783C     | 688B | **Alpha Compositing** - Transparency ops     |
| 0xFFF07D24     | 540B | **Color Conversion** - RGB/CMYK transforms   |
| 0xFFF069AC     | 532B | **Mask Operations** - Clipping/masking       |
| 0xFFF07AEC     | 512B | **Pixel Block Ops** - Bulk pixel operations  |
| 0xFFF0560C     | 408B | **Coordinate Transform** - Rotation/scale    |
| 0xFFF04734     | 340B | **Gradient Fill** - Linear/radial gradients  |
| 0xFFF072AC     | 328B | **Texture Mapping** - Simple texturing       |
| 0xFFF053F8     | 324B | **Antialiasing** - Edge smoothing            |
| ...and 8 more medium handlers                                    |

**Simple Operations** (50-200 bytes, fast primitives):

| Address (ROM)  | Size | Likely Function                              |
|----------------|------|----------------------------------------------|
| 0xFFF07F40     | 192B | **Buffer Swap** - Double buffering           |
| 0xFFF018EC     | 188B | **Pixel Read** - Framebuffer read ops        |
| 0xFFF06198     | 188B | **Pixel Write** - Framebuffer write ops      |
| 0xFFF046B8     | 180B | **Simple Fill** - Fast solid fill            |
| 0xFFF045EC     | 176B | **Horizontal Line** - Optimized hline        |
| 0xFFF0738C     | 152B | **Vertical Line** - Optimized vline          |
| ...and 18 more simple handlers                                   |

**Micro Operations** (<50 bytes, stubs/trampolines):
- 28 tiny handlers likely serving as:
  - Unimplemented command placeholders (return immediately)
  - Trampolines to shared utility code
  - Fast paths delegating to larger handlers
  - Reserved command slots (NOPs)

### Padding Distribution

| Location | Size | Purpose |
|----------|------|---------|
| 0x00415-0x01347 | 3,891 bytes | **Major gap** - Mach kernel alignment |
| Scattered in kernel | ~6,700 bytes | Embedded zeros in code/data regions |
| **Total** | **~10,591 bytes (32.3%)** | |

### Architecture Notes

**Design Patterns**:
1. **Shared Library**: 4KB handler at 0xFFF01A7C provides math/FP utilities called by other handlers
2. **Size-Function Correlation**: Larger handlers = more complex operations
3. **Memory-Intensive**: Heavy use of `ld.b/st.b` instructions for pixel-level operations
4. **Modular Design**: Clear function boundaries via `bri` instructions

**Comparison with Section 3**:
- Section 1+2: ~37 basic hardware-accelerated 2D graphics commands (blit, fill, line, pixel ops)
- Section 3: 75 Display PostScript Level 1 operators (high-level paths, text, bezier curves)
- Two-tier architecture: Fast hardware primitives + advanced rendering layer

**For complete handler mapping, see**: `GRAPHICS_PRIMITIVES_MAP.md`

---

## Section 3: Operators & Services (32KB)

### Memory Layout

```
File Offset: 0x08000 - 0x0FFFF
DRAM Addr:   0xF8008000 - 0xF800FFFF
ROM Addr:    0xFFF08000 - 0xFFF0FFFF
Total Size:  32,768 bytes
```

### Subsection 3A: Operator Table (30.01KB)

```
File Offset: 0x08000 - 0x0F80B
DRAM Addr:   0xF8008000 - 0xF800F80B
ROM Addr:    0xFFF08000 - 0xFFF0F80B
Total Size:  30,732 bytes
```

**Contents**:
- **75 operator implementations** (see complete table below)
- Entry point markers: `st.b %r8,16412(%r8)` debug trace
- Average operator size: 429 bytes
- Size range: 48 bytes (smallest) to 6,232 bytes (largest)

**Padding**: 6,686 bytes (21.8%) embedded as:
- String terminators (0x00 bytes in PostScript strings)
- Alignment gaps between operators
- Data structure padding

### Subsection 3B: Mach Services (1.99KB)

```
File Offset: 0x0F80C - 0x0FFFF
DRAM Addr:   0xF800F80C - 0xF800FFFF
ROM Addr:    0xFFF0F80C - 0xFFF0FFFF
Total Size:  2,036 bytes
```

**Contents**:
- Mailbox IPC finalization
- Token parser support
- Helper functions
- Cleanup routines
- File terminator

**Padding**: 60 bytes (2.9%)

---

## All 75 Operator Entry Points

### Complete Operator Table

**Format**: Entry point addresses are shown as DRAM (runtime) / ROM (disassembly)

```
┌──────┬─────────────────────────┬─────────┬──────────────────────────┐
│ ID # │ Entry Point (DRAM/ROM)  │ Size    │ Likely Function          │
├──────┼─────────────────────────┼─────────┼──────────────────────────┤
│    1 │ 0xF8008014 / 0xFFF08014 │   132 B │ Basic operation          │
│    2 │ 0xF8008098 / 0xFFF08098 │    92 B │ Simple operation         │
│    3 │ 0xF80080F4 / 0xFFF080F4 │   384 B │ Graphics state ops       │
│    4 │ 0xF8008274 / 0xFFF08274 │    56 B │ Stack/state operation    │
│    5 │ 0xF80082AC / 0xFFF082AC │   384 B │ Graphics state ops       │
│    6 │ 0xF800842C / 0xFFF0842C │   864 B │ Clipping operations      │
│    7 │ 0xF800878C / 0xFFF0878C │   952 B │ Pattern operations       │
│    8 │ 0xF8008B44 / 0xFFF08B44 │   656 B │ Matrix operations        │
│    9 │ 0xF8008DD4 / 0xFFF08DD4 │    76 B │ Simple operation         │
│   10 │ 0xF8008E20 / 0xFFF08E20 │    80 B │ Simple operation         │
│   11 │ 0xF8008E70 / 0xFFF08E70 │    60 B │ Stack/state operation    │
│   12 │ 0xF8008EAC / 0xFFF08EAC │    56 B │ Stack/state operation    │
│   13 │ 0xF8008EE4 / 0xFFF08EE4 │    60 B │ Stack/state operation    │
│   14 │ 0xF8008F20 / 0xFFF08F20 │    60 B │ Stack/state operation    │
│   15 │ 0xF8008F5C / 0xFFF08F5C │    60 B │ Stack/state operation    │
│   16 │ 0xF8008F98 / 0xFFF08F98 │   316 B │ Path construction        │
│   17 │ 0xF80090D4 / 0xFFF090D4 │   152 B │ Path construction        │
│   18 │ 0xF800916C / 0xFFF0916C │   128 B │ Path operations          │
│   19 │ 0xF80091EC / 0xFFF091EC │   132 B │ Path operations          │
│   20 │ 0xF8009270 / 0xFFF09270 │   236 B │ Path construction        │
│   21 │ 0xF800935C / 0xFFF0935C │   196 B │ Path operations          │
│   22 │ 0xF8009420 / 0xFFF09420 │   220 B │ Path operations          │
│   23 │ 0xF80094FC / 0xFFF094FC │  1516 B │ Text rendering (show)    │
│   24 │ 0xF8009AE8 / 0xFFF09AE8 │  1444 B │ Arc / arcn / arcto       │
│   25 │ 0xF800A08C / 0xFFF0A08C │    48 B │ Stack/state (smallest)   │
│   26 │ 0xF800A0BC / 0xFFF0A0BC │   268 B │ Coordinate operations    │
│   27 │ 0xF800A1C8 / 0xFFF0A1C8 │   644 B │ Path operations          │
│   28 │ 0xF800A44C / 0xFFF0A44C │   264 B │ Path operations          │
│   29 │ 0xF800A554 / 0xFFF0A554 │   300 B │ Path operations          │
│   30 │ 0xF800A680 / 0xFFF0A680 │  2284 B │ Fill / clip path         │
│   31 │ 0xF800AF6C / 0xFFF0AF6C │  1056 B │ Image / imagemask        │
│   32 │ 0xF800B38C / 0xFFF0B38C │   112 B │ Font/text operations     │
│   33 │ 0xF800B3FC / 0xFFF0B3FC │   264 B │ Font/text operations     │
│   34 │ 0xF800B504 / 0xFFF0B504 │   292 B │ Font metrics             │
│   35 │ 0xF800B628 / 0xFFF0B628 │   396 B │ Path flatten/reverse     │
│   36 │ 0xF800B7B4 / 0xFFF0B7B4 │   136 B │ Text operations          │
│   37 │ 0xF800B83C / 0xFFF0B83C │   200 B │ Text operations          │
│   38 │ 0xF800B904 / 0xFFF0B904 │   220 B │ Font/text operations     │
│   39 │ 0xF800B9E0 / 0xFFF0B9E0 │   384 B │ Font operations          │
│   40 │ 0xF800BB60 / 0xFFF0BB60 │   264 B │ Text operations          │
│   41 │ 0xF800BC68 / 0xFFF0BC68 │   308 B │ Text width calculation   │
│   42 │ 0xF800BD9C / 0xFFF0BD9C │   472 B │ Color operations         │
│   43 │ 0xF800BF74 / 0xFFF0BF74 │   168 B │ Path operations          │
│   44 │ 0xF800C01C / 0xFFF0C01C │   204 B │ Path query               │
│   45 │ 0xF800C0E8 / 0xFFF0C0E8 │   172 B │ Path operations          │
│   46 │ 0xF800C194 / 0xFFF0C194 │   272 B │ Path query               │
│   47 │ 0xF800C2A4 / 0xFFF0C2A4 │   336 B │ Coordinate transform     │
│   48 │ 0xF800C3F4 / 0xFFF0C3F4 │   100 B │ State/control operation  │
│   49 │ 0xF800C458 / 0xFFF0C458 │   100 B │ State/control operation  │
│   50 │ 0xF800C4BC / 0xFFF0C4BC │   100 B │ State/control operation  │
│   51 │ 0xF800C520 / 0xFFF0C520 │   100 B │ State/control operation  │
│   52 │ 0xF800C584 / 0xFFF0C584 │   172 B │ Color/pattern ops        │
│   53 │ 0xF800C630 / 0xFFF0C630 │   100 B │ State/control operation  │
│   54 │ 0xF800C694 / 0xFFF0C694 │   264 B │ Color operations         │
│   55 │ 0xF800C79C / 0xFFF0C79C │   288 B │ Color space operations   │
│   56 │ 0xF800C8BC / 0xFFF0C8BC │   168 B │ Graphics control         │
│   57 │ 0xF800C964 / 0xFFF0C964 │   232 B │ Rendering operations     │
│   58 │ 0xF800CA4C / 0xFFF0CA4C │   208 B │ Graphics state           │
│   59 │ 0xF800CB1C / 0xFFF0CB1C │   128 B │ Graphics state           │
│   60 │ 0xF800CB9C / 0xFFF0CB9C │   100 B │ State/control operation  │
│   61 │ 0xF800CC00 / 0xFFF0CC00 │   228 B │ Graphics control         │
│   62 │ 0xF800CCE4 / 0xFFF0CCE4 │   128 B │ Rendering control        │
│   63 │ 0xF800CD64 / 0xFFF0CD64 │   100 B │ State/control operation  │
│   64 │ 0xF800CDC8 / 0xFFF0CDC8 │   296 B │ Rendering control        │
│   65 │ 0xF800CEF0 / 0xFFF0CEF0 │   156 B │ Rendering operations     │
│   66 │ 0xF800CF8C / 0xFFF0CF8C │   128 B │ Rendering control        │
│   67 │ 0xF800D00C / 0xFFF0D00C │   224 B │ Rendering operations     │
│   68 │ 0xF800D0EC / 0xFFF0D0EC │  2664 B │ Stroke / complex path    │
│   69 │ 0xF800DB54 / 0xFFF0DB54 │   196 B │ Rendering control        │
│   70 │ 0xF800DC18 / 0xFFF0DC18 │   100 B │ State/control operation  │
│   71 │ 0xF800DC7C / 0xFFF0DC7C │  6232 B │ Complex rendering engine │
│   72 │ 0xF800F4D4 / 0xFFF0F4D4 │   568 B │ Transform operations     │
│   73 │ 0xF800F70C / 0xFFF0F70C │   112 B │ Helper operations        │
│   74 │ 0xF800F77C / 0xFFF0F77C │   144 B │ Helper operations        │
│   75 │ 0xF800F80C / 0xFFF0F80C │   268 B │ Section terminator / finalize │
└──────┴─────────────────────────┴─────────┴──────────────────────────┘

TOTAL OPERATOR TABLE: 30,980 bytes (75 functions)
```

### Operator Size Distribution

```
┌───────────────────────────────────────────────────────────────┐
│ Size Range     │ Count │ Percentage │ Likely Category         │
├────────────────┼───────┼────────────┼─────────────────────────┤
│ 48-60 bytes    │   7   │   9.3%     │ Stack/state (simple)    │
│ 61-100 bytes   │  11   │  14.7%     │ Control/query           │
│ 101-200 bytes  │  23   │  30.7%     │ Basic operations        │
│ 201-400 bytes  │  22   │  29.3%     │ Path/graphics ops       │
│ 401-1000 bytes │   9   │  12.0%     │ Complex operations      │
│ 1001+ bytes    │   3   │   4.0%     │ Rendering engines       │
├────────────────┼───────┼────────────┼─────────────────────────┤
│ TOTAL          │  75   │ 100.0%     │                         │
└───────────────────────────────────────────────────────────────┘
```

---

## Memory Usage Statistics

### Overall Breakdown

```
╔═══════════════════════════════════════════════════════════════╗
║                    GACK KERNEL MEMORY USAGE                   ║
╠═══════════════════════════════════════════════════════════════╣
║ Total File Size:        65,536 bytes (64.00 KB)     100.00%   ║
║ ───────────────────────────────────────────────────────────── ║
║ Actual Code/Data:       47,405 bytes (46.29 KB)      72.33%   ║
║ Padding/Zeros:          18,131 bytes (17.71 KB)      27.67%   ║
╚═══════════════════════════════════════════════════════════════╝

Verification: 47,405 + 18,131 = 65,536 ✓
```

### Per-Section Statistics

#### Section 1+2: Bootstrap & Graphics (32KB)

```
Total:   32,768 bytes (100.0%)
Code:    21,383 bytes ( 65.3%)
Padding: 11,385 bytes ( 34.7%)

Padding breakdown:
  - Large alignment gap: 3,891 bytes (34.2% of padding)
  - Small alignment gaps:   387 bytes ( 3.4% of padding)
  - Embedded zeros:       7,106 bytes (62.4% of padding)
  - Section terminator:       1 byte  ( 0.0% of padding)
```

#### Section 3: Operators & Services (32KB)

```
Total:   32,768 bytes (100.0%)
Code:    26,022 bytes ( 79.4%)
Padding:  6,746 bytes ( 20.6%)

Breakdown:
  Operator table:  30,732 bytes (24,046 code + 6,686 padding)
  Mach services:    2,036 bytes ( 1,976 code +    60 padding)
```

### Code Density Comparison

```
┌───────────────────────────────────────────────────────────┐
│ Section    │ Total   │ Code %  │ Padding % │ Efficiency   │
├────────────┼─────────┼─────────┼───────────┼──────────────┤
│ Section 1+2│ 32,768B │  65.3%  │   34.7%   │ Moderate     │
│ Section 3  │ 32,768B │  79.4%  │   20.6%   │ Good         │
├────────────┼─────────┼─────────┼───────────┼──────────────┤
│ OVERALL    │ 65,536B │  72.3%  │   27.7%   │ Good         │
└───────────────────────────────────────────────────────────┘
```

---

## Special Memory Regions

### Debug Trace Buffer (DRAM)

```
Location:    0x0000401C - 0x0000410B (i860 DRAM, not in kernel file)
Size:        240 bytes
Purpose:     Operator execution trace
Access:      Write-only from operator entry points

Structure:
  Memory[operator_id + 0x401C] = operator_id

  Example:
    Operator ID 5 writes byte 5 to address 0x00004021
    Operator ID 75 writes byte 75 to address 0x0000406B

  Buffer spans operator IDs 0-239 (75 actually used)
```

### Mailbox Communication (MMIO)

```
Location:    0x02000000 - 0x0200003F (MMIO, not in kernel)
Size:        64 bytes
Purpose:     Host ↔ i860 communication

Structure (documented in nextdimension_hardware.h):
  +0x00: Status byte
  +0x01: Opcode/command
  +0x02: Flags
  +0x04: Data pointer (host memory)
  +0x08: Width
  +0x0A: Height
  +0x0C: X coordinate
  +0x0E: Y coordinate
  +0x10: Color value
  +0x14-0x3F: Command-specific parameters
```

### VRAM Frame Buffer (i860 View)

```
Location:    0x10000000 - 0x103FFFFF
Size:        4 MB
Resolution:  1120 × 832 pixels
Depth:       32-bit color (RGBA)
Purpose:     Display frame buffer

Pixel format: 0xAARRGGBB (big-endian)
  AA = Alpha channel
  RR = Red channel
  GG = Green channel
  BB = Blue channel
```

### Host Shared Memory Window

```
Location:    0x08000000 - 0x0BFFFFFF (i860 view)
Size:        64 MB window
Purpose:     Access to host 68040 RAM
Usage:       Kernel download, data transfer, shared buffers
```

---

## Address Translation Reference

### Conversion Formulas

```
Given FILE offset (0x00000-0x0FFFF):
  DRAM address = FILE + 0xF8000000
  ROM address  = FILE + 0xFFF00000

Given DRAM address (0xF8000000-0xF800FFFF):
  FILE offset = DRAM - 0xF8000000
  ROM address = DRAM + 0x07F00000

Given ROM address (0xFFF00000-0xFFF0FFFF):
  FILE offset = ROM - 0xFFF00000
  DRAM address = ROM - 0x07F00000
```

### Worked Examples

**Example 1: Largest operator entry point**

```
Operator #1 (6232 bytes):
  FILE offset:  0x0DC70
  DRAM address: 0xF800DC70  (execution address)
  ROM address:  0xFFF0DC70  (disassembly view)

In disassembly file: line number ~13,500
```

**Example 2: Section boundary**

```
Section 3 start:
  FILE offset:  0x08000
  DRAM address: 0xF8008000  (where Section 3 begins execution)
  ROM address:  0xFFF08000  (disassembly shows this)

Marks transition: Bootstrap → Operators
```

**Example 3: Debug trace buffer**

```
Trace buffer (NOT in kernel file, in DRAM at runtime):
  DRAM address: 0x0000401C

This is in LOW DRAM, not near kernel at 0xF8000000
Used by st.b %r8,16412(%r8) instruction
```

### Quick Conversion Table

```
┌─────────────┬──────────────┬──────────────┬─────────────────────┐
│ FILE Offset │ DRAM Address │ ROM Address  │ Description         │
├─────────────┼──────────────┼──────────────┼─────────────────────┤
│   0x00000   │  0xF8000000  │  0xFFF00000  │ Kernel start        │
│   0x00001   │  0xF8000001  │  0xFFF00001  │ Bootstrap entry+1   │
│   0x01348   │  0xF8001348  │  0xFFF01348  │ Main code start     │
│   0x08000   │  0xF8008000  │  0xFFF08000  │ Section 3 start     │
│   0x08008   │  0xF8008008  │  0xFFF08008  │ Operator #50        │
│   0x0DC70   │  0xF800DC70  │  0xFFF0DC70  │ Operator #1 (large) │
│   0x0F80C   │  0xF800F80C  │  0xFFF0F80C  │ Mach services start │
│   0x0FFFF   │  0xF800FFFF  │  0xFFF0FFFF  │ Kernel end          │
└─────────────┴──────────────┴──────────────┴─────────────────────┘
```

---

## Quick Reference

### Essential Addresses (DRAM)

```
Bootstrap Entry:          0xF8000000
Exception Vectors:        0xF8000000 - 0xF8000FFF
Bootstrap Init:           0xF8000348 (entry point)
Main Kernel Code:         0xF8001348 - 0xF8007FFF
Graphics Dispatcher:      0xF80014C4 (bri %r8 - computed indirect branch)

Graphics Handlers (Section 1+2):
  Math/Utility Library:   0xF8001A7C (4172 bytes)
  Standard Blit:          0xF800158C (864 bytes)
  Line Drawing:           0xF8003840 (780 bytes)
  Rectangle Fill:         0xF8006F74 (732 bytes)
  Text Rendering:         0xF80030EC (1876 bytes)

Section 3 Start:          0xF8008000
First Operator:           0xF8008014
Largest Operator:         0xF800DC7C (6232 bytes - Operator #71)
Smallest Operator:        0xF800A08C (48 bytes - Operator #25)
PostScript Dictionary:    0xF800F918 - 0xF800FFFF
Kernel End:               0xF800FFFF
```

### File Markers

```
Section 1+2 End:          0x07FFF
Section 3 Start:          0x08000
Operators End:            0x0F80B
Mach Services Start:      0x0F80C
File End:                 0x0FFFF
```

### External Memory (i860 View)

```
Trace Buffer:             0x0000401C (DRAM)
Mailbox:                  0x02000000 (MMIO)
VRAM:                     0x10000000 (4MB)
Host Window:              0x08000000 (64MB)
```

### Key Statistics

```
Total Size:               65,536 bytes (64 KB)
Code/Data:                47,405 bytes (72.33%)
Padding:                  18,131 bytes (27.67%)
Operators:                75 implementations
Avg Operator Size:        429 bytes
Size Range:               48 - 6,232 bytes
```

### Related Documents

- **GRAPHICS_PRIMITIVES_MAP.md**: Complete mapping of all ~39 graphics handlers in Sections 1+2
- **POSTSCRIPT_OPERATORS_CORRECTED.md**: Complete mapping of 75 PostScript operators in Section 3
- **PHASE4_DEEP_ANALYSIS.md**: Detailed analysis and findings
- **PHASE4_VERIFICATION_REPORT.md**: Verification methodology
- **nextdimension_hardware.h**: Hardware interface definitions
- **ND_ROM_STRUCTURE.md**: Boot ROM analysis (separate 128KB ROM)
- **MAILBOX_PROTOCOL.md**: Host communication protocol
- **GACKLING_IMPLEMENTATION_GUIDE.md**: Emulator implementation guide

---

**Document Version**: 1.0
**Last Updated**: 2025-11-05
**Status**: Complete - All 64KB accounted for

**END OF GACK KERNEL MEMORY MAP**
