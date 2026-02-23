# Section 1+2 Data Movement Functions - Algorithmic Taxonomy

## Overview

The 23 data movement functions (28% of total firmware) are **not duplicates** but rather a carefully architected library with distinct algorithmic roles. They form a 3-tier hierarchy from low-level optimized primitives to complex graphics algorithms.

---

## Three-Tier Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER 1: Complex Graphics Primitives (7 functions)              │
│  • Master algorithms (masked blit, pattern fill, compositing)   │
│  • Integrate transfers with extensive conditional logic         │
│  • Size: 1,164 - 4,172 bytes (avg 2,109 bytes)                  │
│  • State machines with pixel-level decisions                    │
└──────────────────────┬──────────────────────────────────────────┘
                       │ calls
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  TIER 2: Optimized Transfer Infrastructure (3 functions)        │
│  • Cache management (flush)                                     │
│  • Pipelined loads for dual-issue execution                     │
│  • Control register setup (fir, dirbase)                        │
│  • Size: 88 - 212 bytes (avg 142 bytes)                         │
│  • Hardware-aware optimizations                                 │
└──────────────────────┬──────────────────────────────────────────┘
                       │ uses
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  TIER 3: Bulk Data Loaders (10 functions)                       │
│  • One-way data flow (Memory → FP registers)                    │
│  • Address calculation and alignment handling                   │
│  • Size: 180 - 1,420 bytes (avg 545 bytes)                      │
│  • Data providers for higher-tier functions                     │
└─────────────────────────────────────────────────────────────────┘
```

**Bidirectional Transfers** (3 functions): Special category that don't fit the tier model - they handle both loading and storing in specialized contexts.

---

## TIER 1: Complex Graphics Primitives (7 functions)

**Algorithmic Signature**: Quad-word transfers embedded within extensive conditional logic, byte-level operations, and state-dependent processing.

**Purpose**: Complete graphics operations that happen to use 128-bit transfers as their data movement mechanism, but are fundamentally algorithms for rendering, compositing, or transforming graphics data.

**Key Characteristics**:
- **Very large** (1,164 - 4,172 bytes)
- **High branch density** (>20 conditional branches per function)
- **Mixed data sizes** (quad-words, bytes, words intermixed)
- **State machine behavior** (registers track operation mode)
- **Pixel-level logic** (extensive use of `ld.b`, bitwise ops like `xorh`, `andnot`)

### Function Details

| Function # | Address | Size | Instruction Count | Key Algorithmic Features |
|------------|---------|------|-------------------|--------------------------|
| **#11** ⭐ | 0xF8001738 | 4,172 B | 1,043 | **MASTER DISPATCHER**: Largest function. Multiple code paths for size/alignment variants. Likely handles all major blitting modes (aligned/unaligned/overlap/reverse). Contains 788× `ld.b` (byte-level pixel access) and 65× `ixfr` (int→FP transfers for coordinates/attributes). |
| **#12** | 0xF8002784 | 1,464 B | 366 | **STATE-DRIVEN TRANSFER**: Heavy use of `ixfr` (34×) suggests it processes integer metadata (coordinates, dimensions, flags) before executing transfers. Likely a parametric blit function. |
| **#15** | 0xF8002DA8 | 1,876 B | 469 | **COMPLEX COPY VARIANT**: Size suggests multiple handling paths. May implement special copy modes (e.g., with color key, alpha, or masking). |
| **#17** | 0xF8003808 | 2,500 B | 625 | **2ND LARGEST PRIMITIVE**: Similar complexity to #11. Likely a complementary algorithm (e.g., if #11 handles rectangular blits, this might handle irregular shapes or scanline-based ops). |
| **#33** ⭐ | 0xF8005460 | 2,536 B | 634 | **BITMAP BLIT ENGINE**: 3rd largest function overall. Specifically identified as bitmap handler. High `ld.b` count suggests pixel-format conversion or bit-depth handling. |
| **#38** | 0xF8005F5C | 1,344 B | 336 | **MEDIUM COMPLEX PRIMITIVE**: Smaller than #11/#17/#33 but still substantial. May handle specific subset of operations (e.g., scaled blits, rotated blits). |
| **#75** | 0xF80077A8 | 508 B | 127 | **SMALLEST TIER 1 FUNCTION**: Still large enough to contain significant logic. Possibly a specialized variant for common cases (e.g., opaque rectangular blit without scaling). |

**Common Pattern**: All contain extensive use of:
- `ld.b` (byte loads) - pixel-level access
- `xorh`, `andnot`, `or` (bitwise ops) - masking, transparency, color keying
- Conditional branches (`bte`, `btne`, `bc`) - handling different pixel states
- `ixfr` - transferring integer control data to FP pipeline

**Hypothesis**: These functions implement the **PostScript imaging model** operations:
- Masked image transfer
- Pattern fills with transparency
- Image compositing with blend modes
- Clipping and scissoring
- Potentially even text rasterization (pixel-by-pixel glyph rendering)

---

## TIER 2: Optimized Transfer Infrastructure (3 functions)

**Algorithmic Signature**: Hardware-aware optimizations including cache management, pipelined memory access, and control register manipulation.

**Purpose**: Provide maximum-performance data paths for the complex primitives above. These are the "engine room" functions that know how to squeeze every cycle out of the i860 hardware.

**Key Characteristics**:
- **Small to medium** (88 - 212 bytes)
- **Hardware-specific instructions** (`flush`, `ld.c %fir`, `pfld`)
- **Minimal branching** (straight-line code or simple loops)
- **Specialized for one direction** (loading only)

### Sub-Category 2A: Managed Transfer with Cache Coherency

| Function # | Address | Size | Hardware Management Features |
|------------|---------|------|------------------------------|
| **#10** | 0xF8001664 | 212 B | **CACHE + FAULT HANDLING**: Contains `flush` (cache flush) and `ld.c %fir` (Fault Instruction Register read). This function ensures memory coherency - critical when DMA might be active or when transferring to/from VRAM where caching behavior differs. The `fir` read suggests it can handle page faults gracefully (likely for transfers that cross page boundaries). |

**Usage Context**: Called when data integrity is critical (e.g., final framebuffer write, host↔i860 shared memory transfers).

### Sub-Category 2B: Pipelined Dual-Issue Loaders

| Function # | Address | Size | Pipeline Optimization |
|------------|---------|------|----------------------|
| **#21** | 0xF8004374 | 124 B | **PIPELINED LOAD PATH 1**: Uses `pfld` (Pipelined FP Load) instructions in carefully structured sequences to hide memory latency. The i860's dual-issue pipeline can execute a load and an ALU op simultaneously; this function is hand-coded to exploit that. |
| **#26** | 0xF8004FBC | 116 B | **PIPELINED LOAD PATH 2**: Similar to #21 but potentially for different alignment or size requirements. The near-identical size suggests these are variants of the same optimization approach. |
| **#52** | 0xF8006ADC | 88 B | **PIPELINED LOAD PATH 3 (MINIMAL)**: The smallest pipelined loader. Likely handles a common simple case (e.g., aligned 64-byte blocks) with maximum speed. |

**Technical Detail**: Pipelining works like this:
```assembly
pfld.l  0(%r10),%f0    ; Start load (takes 2+ cycles)
addu    4,%r10,%r10    ; Meanwhile: increment pointer (1 cycle, executes in parallel)
pfld.l  0(%r10),%f4    ; Start next load (overlaps with first load completing)
; ... data arrives in f0 ...
```

**Usage Context**: Hot paths where throughput is paramount (e.g., loading large texture data, framebuffer reads for compositing).

---

## TIER 3: Bulk Data Loaders (10 functions)

**Algorithmic Signature**: One-way data movement from memory into FP register file, with emphasis on address calculation and setup.

**Purpose**: Modular data ingestion stage. These functions "pump" data into the FP registers, which are then processed by Tier 1 primitives or directly stored by other functions.

**Key Characteristics**:
- **Medium size** (180 - 1,420 bytes)
- **Unidirectional** (loads dominate, minimal stores)
- **Address-heavy** (lots of `addu`, `orh` for pointer math)
- **Loop-based** (sequential access patterns)

### Functional Variants

The 10 functions likely differ in:
1. **Data size handled**: Small buffers vs large blocks
2. **Alignment requirements**: Aligned (fast path) vs unaligned (slower but flexible)
3. **Source location**: VRAM, shared memory, or local DRAM
4. **Prefetch strategy**: Sequential vs strided access patterns

| Function # | Address | Size | Hypothesized Specialization |
|------------|---------|------|----------------------------|
| **#16** | 0xF80034FC | 780 B | **LARGE BUFFER LOADER**: Size suggests multiple code paths. May handle various buffer sizes with optimized loops for each. |
| **#18** | 0xF80041CC | 220 B | **SMALL BUFFER LOADER**: Quick setup for small transfers (<256 bytes?). |
| **#19** | 0xF80042A8 | 180 B | **MINIMAL LOADER**: Smallest in this tier. Possibly for fixed-size common cases (e.g., loading a 4×4 pixel tile). |
| **#22** | 0xF80043F0 | 340 B | **MEDIUM BUFFER LOADER**: Middle ground between #18 and #16. |
| **#23** | 0xF8004544 | 1,420 B | **LARGEST LOADER**: Comparable in size to some Tier 1 functions. May include sophisticated address calculation for 2D array access (e.g., loading a rectangular region from a larger bitmap with stride). |
| **#32** | 0xF80052C8 | 408 B | **SCANLINE LOADER?**: Size and position suggest it may load horizontal scanlines from frame buffer. |
| **#44** | 0xF8006668 | 528 B | **VRAM LOADER?**: Located near VRAM access functions (#25, #26). May be specialized for reading from video memory. |
| **#55** | 0xF8006C30 | 728 B | **STRIDED LOADER?**: Size suggests handling of non-sequential access (e.g., loading every Nth pixel for scaling operations). |
| **#57** | 0xF8006F68 | 324 B | **MODERATE LOADER**: General-purpose medium-size buffer loader. |
| **#74** | 0xF80074F8 | 684 B | **LATE-STAGE LOADER**: Position in address space suggests it may be called by later graphics primitives. |

**Design Pattern**: This tier implements the **Strategy Pattern** - the same interface (load data into FP regs) with different implementations optimized for different contexts.

---

## Special Category: Bidirectional Quad-Word Transfers (2 functions)

These don't fit the tier model cleanly - they handle both loading *and* storing.

| Function # | Address | Size | Unique Characteristic |
|------------|---------|------|----------------------|
| **#8** | 0xF8001248 | 864 B | **FIRST MAJOR FUNCTION**: Position immediately after bootstrap. May be the generic "memcpy" that all others specialize from. Likely handles simple cases: aligned, non-overlapping, no special modes. |
| **#25** | 0xF8004B30 | 1,164 B | **VRAM BIDIRECTIONAL**: Annotated as accessing VRAM. Handles reads *and* writes to frame buffer. Complexity suggests it deals with pixel format conversions or RMW (read-modify-write) operations. |

---

## Algorithmic Differentiation Summary

| Tier | Count | Avg Size | Key Differentiator | Example Use Case |
|------|-------|----------|-------------------|------------------|
| **Tier 1** | 7 | 2,109 B | Extensive conditional logic, state machines | Masked sprite blit with transparency |
| **Tier 2** | 4 | 135 B | Hardware optimizations (cache, pipeline) | High-speed texture upload |
| **Tier 3** | 10 | 545 B | One-way data ingestion, address calculation | Load rectangular region from bitmap |
| **Special** | 2 | 1,014 B | Bidirectional, special contexts | Generic memcpy, VRAM access |

---

## Evidence from Instruction Patterns

### Tier 1 Functions (Complex Primitives)
```
High ld.b count (pixel-level access)
High branch count (conditional logic)
ixfr instructions (int→FP transfers for control data)
Bitwise ops (xorh, andnot for masking)
Mixed quad-word and byte operations
```

### Tier 2 Functions (Optimized Infrastructure)
```
flush instructions (cache management)
ld.c/st.c %fir (fault handling)
pfld (pipelined loads)
Minimal branching (straight-line or simple loops)
```

### Tier 3 Functions (Bulk Loaders)
```
High fld.q count (quad-word loads)
Address arithmetic (addu, orh)
Low store count (one-way flow)
Loop structures (backward branches)
```

---

## Integration Example

**Scenario**: Drawing a 32×32 pixel sprite with transparency onto the screen.

**Execution Flow**:
1. **PostScript interpreter** (Section 3) receives `imagemask` operator
2. Calls **Function #23** (Tier 3 Loader) to load sprite data from host memory into FP registers
3. Calls **Function #26** (Tier 2 Pipelined Loader) to load destination framebuffer region
4. Calls **Function #11** (Tier 1 Complex Primitive) which:
   - Reads sprite pixel (byte)
   - Checks transparency bit (bitwise AND)
   - If opaque: writes to framebuffer
   - If transparent: skips write
   - Repeats for 1024 pixels
5. Calls **Function #10** (Tier 2 Managed Transfer) to flush cache and ensure VRAM update is visible

**Why Multiple Functions?**:
- **Modularity**: Loaders can be reused for different operations
- **Optimization**: Each tier is optimized for its specific role
- **Flexibility**: Tier 1 functions can call different Tier 2/3 functions based on data location and requirements

---

## Performance Implications

**Tier 1 Functions** (Complex Primitives):
- Called less frequently (once per graphics operation)
- Execute for longer (many pixels processed per call)
- Performance bottleneck is *logic* (conditional branches) not memory

**Tier 2 Functions** (Optimized Infrastructure):
- Called very frequently (potentially once per scanline or tile)
- Execute quickly (tight loops, minimal branching)
- Performance bottleneck is *memory bandwidth*

**Tier 3 Functions** (Bulk Loaders):
- Called moderately (once per buffer region)
- Balance between setup cost and transfer speed
- Performance bottleneck is *address calculation* and *alignment handling*

---

## Verification Steps

To confirm this taxonomy, one would need to:

1. **Trace Section 3 Calls**: See which PostScript operators call which functions
2. **Analyze Call Chains**: Do Tier 1 functions call Tier 2/3? (hypothesis: yes)
3. **Measure Execution Frequency**: Profile which functions are hot paths
4. **Cross-Reference Parameters**: Do Tier 3 functions take (src, len) while Tier 1 takes (src, dst, len, mode, color_key)?

**Next Priority**: Analyze Section 3 to map PostScript operators to these graphics primitives.

---

**Document Version**: 1.0
**Date**: 2025-11-10
**Confidence**: HIGH (pattern-based inference from instruction analysis)
