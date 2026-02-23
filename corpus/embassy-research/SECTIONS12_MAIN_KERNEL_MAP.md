# Sections 1+2 Main Kernel Region Memory Map
## Detailed Breakdown: 0x01348-0x07FFF (27,832 bytes)

**Date**: 2025-11-05
**Region**: Main Mach kernel + graphics primitives
**Analysis**: Based on MAME i860 disassembler + bri boundary analysis

---

## Memory Map Summary

```
FILE      DRAM          ROM           SIZE    CONTENT
OFFSET    ADDRESS       ADDRESS
─────────────────────────────────────────────────────────────────────
0x01348 | 0xF8001348 | 0xFFF01348 |   380 B | Kernel initialization & setup
0x014C4 | 0xF80014C4 | 0xFFF014C4 |     4 B | ★ DISPATCH POINT (bri %r8)
0x014C8 | 0xF80014C8 | 0xFFF014C8 |   192 B | Dispatch support & sync
0x0158C | 0xF800158C | 0xFFF0158C |   864 B | Standard Blit
0x018EC | 0xF80018EC | 0xFFF018EC |   188 B | Pixel Read
0x019A8 | 0xF80019A8 | 0xFFF019A8 |   212 B | Synchronization
0x01A7C | 0xF8001A7C | 0xFFF01A7C | 4,172 B | ★ Math/Utility Library (shared)
        |            |            |         |
0x02AC8 | 0xF8002AC8 | 0xFFF02AC8 | 1,464 B | Advanced Blit
0x030EC | 0xF80030EC | 0xFFF030EC | 1,876 B | Text Rendering
0x03840 | 0xF8003840 | 0xFFF03840 |   780 B | Line Drawing
0x03B4C | 0xF8003B4C | 0xFFF03B4C | 2,500 B | Bezier/Curve Rendering
        |            |            |         |
0x04510 | 0xF8004510 | 0xFFF04510 |   220 B | Point Drawing
0x045EC | 0xF80045EC | 0xFFF045EC |   176 B | Horizontal Line
0x046B8 | 0xF80046B8 | 0xFFF046B8 |   180 B | Simple Fill
0x04734 | 0xF8004734 | 0xFFF04734 |   340 B | Gradient Fill
0x04888 | 0xF8004888 | 0xFFF04888 | 1,420 B | Image Scaling
0x04E14 | 0xF8004E14 | 0xFFF04E14 |   148 B | Color Lookup
0x04E74 | 0xF8004E74 | 0xFFF04E74 | 1,164 B | Polygon Fill
        |            |            |         |
0x053C4 | 0xF80053C4 | 0xFFF053C4 |   136 B | Memory Barrier
0x053F8 | 0xF80053F8 | 0xFFF053F8 |   324 B | Antialiasing
0x0553C | 0xF800553C | 0xFFF0553C |   208 B | Dithering
0x0560C | 0xF800560C | 0xFFF0560C |   408 B | Coordinate Transform
0x057A4 | 0xF80057A4 | 0xFFF057A4 | 2,536 B | Complex Compositing
        |            |            |         |
0x06198 | 0xF8006198 | 0xFFF06198 |   188 B | Pixel Write
0x062A0 | 0xF80062A0 | 0xFFF062A0 | 1,344 B | Pattern Fill
0x067E0 | 0xF80067E0 | 0xFFF067E0 |   236 B | Pixel Format Convert
0x068D0 | 0xF80068D0 | 0xFFF068D0 |   124 B | Status Query
0x06940 | 0xF8006940 | 0xFFF06940 |   132 B | Bounding Box
0x069AC | 0xF80069AC | 0xFFF069AC |   532 B | Mask Operations
0x06C58 | 0xF8006C58 | 0xFFF06C58 |   224 B | Screen Clear
0x06E7C | 0xF8006E7C | 0xFFF06E7C |   212 B | VRAM Copy
0x06F74 | 0xF8006F74 | 0xFFF06F74 |   732 B | Rectangle Fill
        |            |            |         |
0x072AC | 0xF80072AC | 0xFFF072AC |   328 B | Texture Mapping
0x0738C | 0xF800738C | 0xFFF0738C |   152 B | Vertical Line
0x07590 | 0xF8007590 | 0xFFF07590 |   200 B | Viewport Operations
0x07658 | 0xF8007658 | 0xFFF07658 |   212 B | Cursor Operations
0x0783C | 0xF800783C | 0xFFF0783C |   688 B | Alpha Compositing
0x07AEC | 0xF8007AEC | 0xFFF07AEC |   512 B | Pixel Block Ops
0x07D24 | 0xF8007D24 | 0xFFF07D24 |   540 B | Color Conversion
0x07F40 | 0xF8007F40 | 0xFFF07F40 |   192 B | Buffer Swap
        |            |            |         |
0x08000 | Section 3 boundary (PostScript operators begin)
─────────────────────────────────────────────────────────────────────
TOTAL: 27,832 bytes (37 substantial handlers + 28 stubs + ~6.7KB padding)
```

---

## Region Breakdown by Function

### Dispatch & Initialization (0x01348-0x01A7B, 1,843 bytes)

```
0xFFF01348-0xFFF014C3: Kernel init, mailbox setup, state management
0xFFF014C4:            ★ PRIMARY DISPATCH (bri %r8)
0xFFF014C8-0xFFF0158B: Dispatch support, synchronization
```

**Key Code**:
```assembly
; Dispatch mechanism
fff01464:  btne  %r8,%r12,0x00000190   ; Command range check
fff01468:  btne  8,%r12,0x00010194     ; Validate command ID
fff0146c:  bte   %r8,%r12,0xfffe0198   ; Branch if valid
fff01470:  bte   8,%r12,0xffff019c     ; Additional validation
  ...
fff014c4:  bri   %r8                   ; ★ DISPATCH to handler
```

### Shared Math Library (0x01A7C-0x02AC7, 4,172 bytes)

```
0xFFF01A7C: Math/Utility Library (4,172 bytes)
  - Floating-point operations
  - Trigonometric functions (sin, cos, tan)
  - Square root, logarithm
  - Matrix math
  - Called by other handlers via subroutine calls
```

**Shared Library Pattern**: This is NOT a command handler but a utility library used by multiple graphics primitives.

### Memory & Blit Operations (0x02AC8-0x030EB, 1,572 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF02AC8     | 1464B | Advanced Blit (complex memory transfers)   |

### Text & Path Rendering (0x030EC-0x04509, 5,148 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF030EC     | 1876B | Text Rendering (glyph/font operations)     |
| 0xFFF03840     |  780B | Line Drawing (Bresenham algorithm)         |
| 0xFFF03B4C     | 2500B | Bezier/Curve Rendering (path operations)   |

### Primitive Drawing (0x04510-0x04E13, 2,308 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF04510     |  220B | Point Drawing                              |
| 0xFFF045EC     |  176B | Horizontal Line (optimized)                |
| 0xFFF046B8     |  180B | Simple Fill                                |
| 0xFFF04734     |  340B | Gradient Fill (linear/radial)              |
| 0xFFF04888     | 1420B | Image Scaling (resize/interpolation)       |
| 0xFFF04E14     |  148B | Color Lookup (palette operations)          |

### Polygon & Fill Operations (0x04E74-0x05609, 3,748 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF04E74     | 1164B | Polygon Fill (complex shape filling)       |
| 0xFFF053C4     |  136B | Memory Barrier (cache flush/sync)          |
| 0xFFF053F8     |  324B | Antialiasing (edge smoothing)              |
| 0xFFF0553C     |  208B | Dithering (color reduction)                |
| 0xFFF0560C     |  408B | Coordinate Transform (rotation/scale)      |

### Advanced Compositing (0x057A4-0x06197, 2,536 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF057A4     | 2536B | Complex Compositing (advanced blending)    |

### Pixel & Buffer Operations (0x06198-0x072AB, 4,372 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF06198     |  188B | Pixel Write (framebuffer write)            |
| 0xFFF062A0     | 1344B | Pattern Fill (tiled patterns)              |
| 0xFFF067E0     |  236B | Pixel Format Convert (depth conversion)    |
| 0xFFF068D0     |  124B | Status Query (graphics state)              |
| 0xFFF06940     |  132B | Bounding Box (rectangle intersection)      |
| 0xFFF069AC     |  532B | Mask Operations (clipping/masking)         |
| 0xFFF06C58     |  224B | Screen Clear (fast buffer clear)           |
| 0xFFF06E7C     |  212B | VRAM Copy (video memory operations)        |
| 0xFFF06F74     |  732B | Rectangle Fill (solid color fills)         |

### Advanced Operations (0x072AC-0x07FFF, 2,132 bytes)

| Address (ROM)  | Size  | Handler                                    |
|----------------|-------|--------------------------------------------|
| 0xFFF072AC     |  328B | Texture Mapping (simple texturing)         |
| 0xFFF0738C     |  152B | Vertical Line (optimized)                  |
| 0xFFF07590     |  200B | Viewport Operations (clipping regions)     |
| 0xFFF07658     |  212B | Cursor Operations (hardware cursor)        |
| 0xFFF0783C     |  688B | Alpha Compositing (transparency ops)       |
| 0xFFF07AEC     |  512B | Pixel Block Ops (bulk pixel operations)    |
| 0xFFF07D24     |  540B | Color Conversion (RGB/CMYK transforms)     |
| 0xFFF07F40     |  192B | Buffer Swap (double buffering)             |

---

## Statistics

### Handler Count by Size Category

```
┌──────────────────────────────────────────────────────────────┐
│ Size Range    │ Count │ Total Size │ Example Operations      │
├───────────────┼───────┼────────────┼─────────────────────────┤
│ 1000+ bytes   │   8   │  15,076 B  │ Math lib, compositing   │
│ 200-1000 bytes│  19   │   9,152 B  │ Blit, line, fill, mask  │
│ 50-200 bytes  │  24   │   2,960 B  │ Pixel ops, sync, clear  │
│ <50 bytes     │  28   │     644 B  │ Stubs, trampolines      │
├───────────────┼───────┼────────────┼─────────────────────────┤
│ TOTAL         │  79   │  27,832 B  │                         │
└──────────────────────────────────────────────────────────────┘

Code/padding breakdown:
  Actual code:     ~21,100 bytes (75.8%)
  Embedded padding: ~6,732 bytes (24.2%)
```

### Largest Handlers (Top 10)

```
Rank  Address (ROM)  Size   Handler
────  ─────────────  ─────  ────────────────────────────────
  1.  0xFFF01A7C     4172B  Math/Utility Library (shared)
  2.  0xFFF057A4     2536B  Complex Compositing
  3.  0xFFF03B4C     2500B  Bezier/Curve Rendering
  4.  0xFFF030EC     1876B  Text Rendering
  5.  0xFFF02AC8     1464B  Advanced Blit
  6.  0xFFF04888     1420B  Image Scaling
  7.  0xFFF062A0     1344B  Pattern Fill
  8.  0xFFF04E74     1164B  Polygon Fill
  9.  0xFFF0158C      864B  Standard Blit
 10.  0xFFF03840      780B  Line Drawing
```

---

## Memory Layout Visualization

```
0x01348  ┌─────────────────────────────────────────┐
         │ Kernel Init & Dispatch Setup            │
0x014C4  │ ★ DISPATCH POINT (bri %r8)              │
         ├─────────────────────────────────────────┤
0x01A7C  │                                         │
         │ MATH/UTILITY LIBRARY (4KB)              │
         │ (Called by other handlers)              │
         │                                         │
0x02AC8  ├─────────────────────────────────────────┤
         │ Advanced Blit                           │
0x030EC  ├─────────────────────────────────────────┤
         │ Text Rendering                          │
0x03840  ├─────────────────────────────────────────┤
         │ Line Drawing                            │
0x03B4C  ├─────────────────────────────────────────┤
         │                                         │
         │ Bezier/Curve Rendering (2.5KB)          │
         │                                         │
0x04510  ├─────────────────────────────────────────┤
         │ Point, Line, Fill Primitives            │
0x04888  ├─────────────────────────────────────────┤
         │ Image Scaling                           │
0x04E74  ├─────────────────────────────────────────┤
         │ Polygon Fill                            │
0x053C4  ├─────────────────────────────────────────┤
         │ Antialiasing, Dithering, Transform      │
0x057A4  ├─────────────────────────────────────────┤
         │                                         │
         │ Complex Compositing (2.5KB)             │
         │                                         │
0x06198  ├─────────────────────────────────────────┤
         │ Pixel Write                             │
0x062A0  ├─────────────────────────────────────────┤
         │ Pattern Fill                            │
0x067E0  ├─────────────────────────────────────────┤
         │ Pixel/Buffer/Mask Operations            │
0x06F74  ├─────────────────────────────────────────┤
         │ Rectangle Fill                          │
0x072AC  ├─────────────────────────────────────────┤
         │ Texture, Line, Viewport, Cursor         │
0x0783C  ├─────────────────────────────────────────┤
         │ Alpha Compositing                       │
0x07AEC  ├─────────────────────────────────────────┤
         │ Pixel Block Ops, Color Convert          │
0x07F40  ├─────────────────────────────────────────┤
         │ Buffer Swap                             │
0x08000  └─────────────────────────────────────────┘
         Section 3 begins (PostScript operators)
```

---

## Key Insights

### Architectural Design

1. **Single Dispatch Point**: All graphics commands flow through 0xFFF014C4 (`bri %r8`)
2. **Shared Library**: 4KB math library at 0xFFF01A7C used by multiple handlers
3. **Size-Function Correlation**: Larger handlers = more complex operations
4. **Memory-Intensive**: Heavy use of `ld.b`/`st.b` for pixel-level work
5. **Function Boundaries**: Marked by `bri` (branch indirect) serving as returns

### Performance Characteristics

- **Hot paths**: Likely blit, fill, line drawing (most common operations)
- **Cold paths**: Complex operations like bezier, compositing (less frequent but feature-rich)
- **Stubs**: 28 tiny handlers may be unimplemented or reserved commands

### Comparison with Section 3

```
┌────────────┬────────────┬─────────────────────────────────┐
│ Region     │ Handlers   │ Purpose                         │
├────────────┼────────────┼─────────────────────────────────┤
│ Section1+2 │ ~37 cmds   │ Hardware-accelerated 2D         │
│ (Kernel)   │ >100 bytes │ - Fast pixel operations         │
│            │            │ - Basic shapes (line, rect)     │
│            │            │ - Memory transfers (blit)       │
│            │            │ - Low-level primitives          │
├────────────┼────────────┼─────────────────────────────────┤
│ Section 3  │ 75 ops     │ Display PostScript Level 1      │
│ (PS Ops)   │            │ - High-level path construction  │
│            │            │ - Text/font rendering           │
│            │            │ - Complex transformations       │
│            │            │ - Vector graphics               │
└────────────┴────────────┴─────────────────────────────────┘
```

**Two-Tier Architecture**: Fast hardware primitives (Section 1+2) provide foundation for high-level PostScript operators (Section 3).

---

## Command Dispatch Flow

```
Host (68040)
    │
    │ Mailbox write: Command ID + parameters
    ↓
i860 Mailbox Handler (0xFFF01348+)
    │
    │ 1. Read command ID from mailbox
    │ 2. Validate command range (btne/bte checks)
    │ 3. Compute handler address → %r8
    ↓
Primary Dispatcher (0xFFF014C4)
    │
    │ bri %r8  ; Branch to computed address
    ↓
Graphics Handler (one of ~37)
    │
    │ Execute primitive operation:
    │   - Access VRAM at 0x10000000
    │   - Read parameters from mailbox
    │   - Call shared math library if needed
    │   - Modify frame buffer
    │   - Update status
    ↓
Handler Return (bri instruction)
    │
    │ Return to mailbox loop
    ↓
Write result to mailbox
    │
    │ Signal completion
    ↓
Host continues
```

---

**Document Status**: COMPLETE
**Based on**: GRAPHICS_PRIMITIVES_MAP.md + MAME i860 disassembly
**Confidence**: High (90%+) for addresses and sizes, Medium (70%) for function names
**See also**: GACK_KERNEL_MEMORY_MAP.md, GRAPHICS_PRIMITIVES_MAP.md
