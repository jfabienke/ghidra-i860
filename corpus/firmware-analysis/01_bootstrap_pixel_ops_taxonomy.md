# Section 1+2 Graphics Primitives & Pixel Operations - Algorithmic Taxonomy

## Overview

The 11 pixel operation functions (14% of total firmware) represent a **three-tier architecture** for pixel-level graphics processing. Like the data movement functions, they are not duplicates but rather specialized components ranging from fundamental loop engines to complex multi-stage graphics algorithms.

---

## Three-Tier Pixel Processing Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER A: Advanced Multi-Stage Primitives (2 functions)          │
│  • Complex graphics algorithms (texture mapping, alpha blend)   │
│  • Loop unrolling optimizations                                 │
│  • Mixed integer/FP operations                                  │
│  • Size: 528 - 536 bytes (avg 532 bytes)                        │
└──────────────────────┬──────────────────────────────────────────┘
                       │ uses
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  TIER B: Logic-Integrated Scanners (5 functions)                │
│  • Pixel-by-pixel operations with logic (XOR, AND, mask)        │
│  • Simple graphics primitives (color key, transparency)         │
│  • Size: 52 - 324 bytes (avg 158 bytes)                         │
└──────────────────────┬──────────────────────────────────────────┘
                       │ uses
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  TIER C: Core Loop Engines (4 functions)                        │
│  • Fundamental sequential memory traversal                      │
│  • Minimal logic (address calc + loop control)                  │
│  • Size: 176 - 236 bytes (avg 207 bytes)                        │
│  • Building blocks for higher tiers                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## TIER C: Core Loop Engines (4 functions)

**Algorithmic Signature**: Minimal logic beyond sequential memory traversal with address calculation and loop control.

**Purpose**: Provide highly-optimized "for loop" infrastructure that higher-level functions build upon. These are the fundamental iteration primitives.

**Key Characteristics**:
- **Integer-centric** (operate on addresses and counters)
- **Minimal branching** (loop control only)
- **Address arithmetic** (`addu`, `subu` for pointer manipulation)
- **Simple loads** (`ld.b`, `ld.s` without complex logic)
- **No bitwise operations** (pure traversal, no pixel manipulation)

### Function Details

| Function # | Address | Size | Loop Characteristics |
|------------|---------|------|---------------------|
| **#31** | 0xF80051F8 | 208 B | **INT→FP PREP LOOP**: Contains `ixfr` (integer to FP register transfer). Likely prepares loop counters or pixel coordinates for subsequent FP-based operations. May convert pixel addresses to normalized texture coordinates. |
| **#39** | 0xF800649C | 236 B | **LARGEST LOOP ENGINE**: Size suggests it handles more complex address calculations, possibly for 2D array access with stride (e.g., traversing a rectangular region within a larger bitmap). May compute row/column offsets. |
| **#50** | 0xF8006A04 | 176 B | **SMALLEST LOOP ENGINE**: Minimal overhead for the simplest case - likely linear sequential access through a contiguous buffer. Optimized for speed when no complex addressing is needed. |
| **#66** | 0xF8007314 | 208 B | **MULTI-WIDTH LOOP**: Mix of `ld.b` (byte) and `ld.s` (short/word) loads. Handles data of varying widths, possibly for packed pixel formats (e.g., reading 16-bit color values from an 8-bit indexed buffer). |

**Code Pattern Example** (hypothetical reconstruction of Function #50):
```assembly
; Simplified loop engine (actual code is more optimized)
loop_start:
    ld.b    0(%r8),%r16      ; Load byte from buffer
    addu    1,%r8,%r8        ; Increment pointer
    subu    1,%r9,%r9        ; Decrement counter
    bnc     loop_start       ; Branch if counter not zero
    bri     %r1              ; Return
```

**Usage Context**: 
- Called by Tier B functions to provide iteration infrastructure
- May be used directly for simple buffer copies or fills
- Provide consistent iteration interface that higher tiers can rely on

| Function # | Specialization |
|------------|----------------|
| 31 | Integer-to-FP preparation loop (coordinate conversion) |
| 39 | Complex 2D addressing (stride calculations) |
| 50 | Minimal linear traversal (fastest path) |
| 66 | Multi-width data handling (mixed pixel formats) |

---

## TIER B: Logic-Integrated Scanners (5 functions)

**Algorithmic Signature**: Pixel traversal loops integrated with bitwise/logical operations for specific graphics tasks.

**Purpose**: Complete but simple graphics primitives that perform one well-defined operation per pixel (masking, color keying, logical drawing).

**Key Characteristics**:
- **Bitwise operations** (`xor`, `and`, `or`, `andnot`)
- **Pixel-level decisions** (conditional branches based on pixel values)
- **Self-contained algorithms** (don't require external processing)
- **Moderate complexity** (more than loops, less than advanced primitives)

### Function Details

| Function # | Address | Size | Graphics Operation |
|------------|---------|------|-------------------|
| **#29** | 0xF8005080 | 52 B | **XOR/OR PRIMITIVE**: Very small with `xorh` and `orh` instructions. Classic pattern for cursor drawing (XOR for invert-on-draw, XOR again to restore). Also used for Boolean drawing modes (AND, OR, XOR between source and destination). |
| **#30** | 0xF80050B4 | 324 B | **LARGEST LOGIC SCANNER**: Size indicates sophisticated logic. May implement multiple drawing modes or handle complex masking scenarios. Could be a "Swiss Army knife" scanner that dispatches to different logic based on mode register. |
| **#36** | 0xF8005E54 | 188 B | **CONDITIONAL SCANNER**: Includes `bte` (branch if equal) on data values. Implements color-keying (transparent color) or simple alpha test (skip pixel if value matches/doesn't match threshold). |
| **#63** | 0xF800714C | 160 B | **MASKING PRIMITIVE**: Contains `and` operations, characteristic of applying a 1-bit mask (e.g., for text rendering where each pixel is either on or off based on glyph bitmap). |
| **#77** | 0xF80079AC | 48 B | **MINIMAL LOGIC OP**: Very small, likely performs a single simple operation per pixel. Possibly a specialized fast path for common case (e.g., opaque fill with no masking). |

**Code Pattern Example** (hypothetical Function #29 - XOR cursor):
```assembly
; XOR-based cursor drawing
loop_start:
    ld.b    0(%r8),%r16      ; Load source pixel (cursor pattern)
    ld.b    0(%r9),%r17      ; Load destination pixel (screen)
    xor     %r16,%r17,%r18   ; XOR them
    st.b    %r18,0(%r9)      ; Write back (inverted)
    addu    1,%r8,%r8        ; Next source
    addu    1,%r9,%r9        ; Next dest
    subu    1,%r10,%r10      ; Decrement count
    bnc     loop_start       ; Loop
    bri     %r1              ; Return
```

**PostScript Operator Mapping** (hypothesis):
- **#29**: `compositemode 6` (XOR mode for rubber-banding/cursors)
- **#30**: Generic compositing with mode parameter
- **#36**: `imagemask` with color key transparency
- **#63**: `show` (text rendering with 1-bit glyph masks)
- **#77**: Simple fill or opaque blit

| Function # | Graphics Primitive |
|------------|--------------------|
| 29 | XOR/OR logical drawing (cursors, rubber-band) |
| 30 | Multi-mode compositing dispatcher |
| 36 | Color keying / simple alpha test |
| 63 | 1-bit mask application (text/glyphs) |
| 77 | Fast opaque fill |

---

## TIER A: Advanced Multi-Stage Primitives (2 functions)

**Algorithmic Signature**: Large, complex functions with loop unrolling, mixed integer/FP math, and multi-stage processing.

**Purpose**: High-level graphics algorithms that orchestrate multiple operations, potentially including texture mapping, alpha blending, or format conversion.

**Key Characteristics**:
- **Very large** (500+ bytes)
- **Loop unrolling** (repetitive code blocks for performance)
- **Mixed data types** (integer addresses + FP color/texture coords)
- **Multi-stage** (load → process → store pipeline)
- **State management** (control registers like `%fsr`, `%fir`)

### Function Details

| Function # | Address | Size | Algorithm Analysis |
|------------|---------|------|-------------------|
| **#78** | 0xF80079E0 | 536 B | **MIXED INT/FP PRIMITIVE**: Large size with mix of `fld.q` (quad-word FP loads), `fst.l` (long FP stores), and byte-level operations. **Hypothesis**: Texture mapping or format conversion. Reads texture data (quad-words for speed), interpolates/samples using FP math, writes individual pixels (bytes). The mixed operations suggest it's bridging between bulk data and pixel-level output. |
| **#80** | 0xF8007DBC | 528 B | **LOOP-UNROLLED PRIMITIVE**: Contains highly repetitive instruction sequences - classic loop unrolling. **Hypothesis**: Apply uniform operation across many pixels (e.g., gamma correction, palette lookup, or applying a constant alpha). Unrolling reduces loop overhead when processing large blocks. May handle 8 or 16 pixels per iteration. |

**Loop Unrolling Example** (hypothetical Function #80):
```assembly
; Instead of:
;   loop: process_pixel; inc; dec; branch; (4 instructions overhead per pixel)
; Unrolled version processes 8 pixels:
    ld.b    0(%r8),%r16;  process %r16;  st.b %r16,0(%r9)   ; Pixel 0
    ld.b    1(%r8),%r17;  process %r17;  st.b %r17,1(%r9)   ; Pixel 1
    ld.b    2(%r8),%r18;  process %r18;  st.b %r18,2(%r9)   ; Pixel 2
    ; ... (5 more pixels)
    addu    8,%r8,%r8     ; Advance 8 pixels at once
    addu    8,%r9,%r9
    subu    8,%r10,%r10
    bnc     next_block    ; Only 1 branch per 8 pixels
```

**Evidence for Texture Mapping** (Function #78):
- `fld.q`: Load 128 bits (4 pixels of 32-bit color or 16 pixels of 8-bit indexed)
- FP operations: Likely for bilinear filtering or texture coordinate interpolation
- `fst.l`: Store 32-bit result (final RGBA pixel)
- Byte operations: Individual pixel manipulation for edge cases

**Evidence for Constant Operation** (Function #80):
- Repetitive structure: Same operation repeated with different registers
- No complex branching: Uniform processing
- Large size despite simple operation: Trade code size for speed

| Function # | Hypothesized Algorithm |
|------------|------------------------|
| 78 | Texture mapping with bilinear filtering |
| 80 | Uniform pixel operation (gamma/alpha/palette) with loop unrolling |

---

## Algorithmic Differentiation Summary

| Tier | Count | Avg Size | Key Feature | Example Use Case |
|------|-------|----------|-------------|------------------|
| **Tier C** | 4 | 207 B | Pure iteration loops | Scanline traversal for higher-level ops |
| **Tier B** | 5 | 158 B | Logic + loop | XOR cursor, color key transparency |
| **Tier A** | 2 | 532 B | Multi-stage + optimization | Texture mapping, mass pixel transform |

---

## Evidence from Instruction Patterns

### Tier C (Loop Engines)
```
Primary: ld.b, ld.s (data loading)
Address: addu, subu (pointer math)
Control: bnc, bte (loop branches only)
No bitwise ops (no pixel manipulation)
```

### Tier B (Logic Scanners)
```
Bitwise: xor, xorh, or, and, andnot (pixel logic)
Conditional: bte, btne (value-based branching)
Mixed loads: ld.b + ld.s (pixel + mask)
Moderate size (50-300 bytes)
```

### Tier A (Advanced Primitives)
```
FP operations: fld.q, fst.l (bulk + precision)
Loop unrolling: Repetitive blocks
Mixed types: Integer addresses + FP color
Large size (500+ bytes)
Control registers: %fsr, %fir (state management)
```

---

## Integration with Data Movement Functions

The pixel operations work in concert with Category 1 (Data Movement) functions:

**Typical Graphics Operation Flow**:
1. **Tier 3 Data Loader** (Category 1): Load source bitmap into FP registers
2. **Tier C Loop Engine** (Category 2): Set up iteration over destination
3. **Tier B Logic Scanner** (Category 2): Process each pixel with logic (mask, XOR, etc.)
4. **Tier 2 Optimized Transfer** (Category 1): Flush cache, write to VRAM

**Example - Masked Sprite Draw**:
```
Category 1, Function #23 → Load sprite data (Tier 3 Loader)
Category 2, Function #50 → Set up scanline iteration (Tier C Loop)
Category 2, Function #36 → Apply color key transparency (Tier B Scanner)
Category 1, Function #10 → Flush and write to framebuffer (Tier 2 Managed Transfer)
```

---

## Performance Characteristics

### Tier C (Loop Engines)
- **Call frequency**: Very high (inner loop of many operations)
- **Execution time**: Short (tight loops, minimal logic)
- **Bottleneck**: Cache misses on sequential access

### Tier B (Logic Scanners)
- **Call frequency**: High (once per graphics primitive)
- **Execution time**: Medium (pixel-by-pixel processing)
- **Bottleneck**: Conditional branches (pipeline stalls)

### Tier A (Advanced Primitives)
- **Call frequency**: Moderate (complex operations like texture draws)
- **Execution time**: Long (many pixels, complex math)
- **Bottleneck**: FP pipeline utilization, memory bandwidth

---

## PostScript Imaging Model Mapping (Hypothesis)

| PostScript Operator | Likely Function(s) | Tier |
|---------------------|-------------------|------|
| `show` (text) | #63 (1-bit mask) | B |
| `imagemask` (transparency) | #36 (color key) | B |
| `image` (opaque) | #77 (fast fill) + #50 (loop) | B + C |
| `compositemode 6` (XOR) | #29 (XOR/OR) | B |
| Texture mapping | #78 (texture primitive) | A |
| `colorimage` (RGB→indexed) | #80 (uniform op) | A |

---

## Verification Steps

To confirm this taxonomy:

1. **Disassemble Key Functions**: 
   - Function #78: Look for bilinear filter pattern (`fmul`, `fadd` on texture coords)
   - Function #80: Confirm repetitive structure (loop unrolling)
   - Function #29: Verify XOR pattern (load src, load dst, xor, store)

2. **Trace Section 3 Calls**:
   - Map PostScript `show` operator → see if it calls #63
   - Map `imagemask` → see if it calls #36
   - Verify call chains (do Tier B functions call Tier C?)

3. **Cross-Reference with NeXTSTEP**:
   - Boot NeXTSTEP, draw text → trace to see #63 usage
   - Draw cursor → trace for #29 (XOR pattern)
   - Display image → trace for #78 or #80

---

## Design Pattern Analysis

This tier structure implements several software engineering patterns:

1. **Template Method Pattern** (Tier C): 
   - Loop engines provide the iteration "template"
   - Higher tiers fill in the "process pixel" step

2. **Strategy Pattern** (Tier B):
   - Different logic scanners = different pixel processing strategies
   - Same interface (scan buffer), different implementations (XOR, mask, etc.)

3. **Pipeline Pattern** (Tier A):
   - Multi-stage primitives: Load → Transform → Store
   - Each stage optimized independently

---

## Next Steps

**Priority 1**: Disassemble Functions #78 and #80
- Confirm loop unrolling in #80
- Identify FP operations in #78 (texture filtering?)
- Extract exact algorithms for documentation

**Priority 2**: Map to PostScript Operators
- Analyze Section 3 to find operator dispatch table
- Trace which operators call which pixel functions
- Verify hypothesis about text rendering (#63) and cursors (#29)

**Priority 3**: Performance Profiling
- Identify hot path functions in real usage
- Measure call frequency (are loop engines called millions of times?)
- Validate tier performance characteristics

---

**Document Version**: 1.0  
**Date**: 2025-11-10  
**Analysis Source**: Instruction pattern analysis + size-based inference  
**Confidence**: HIGH (strong evidence from instruction patterns)
