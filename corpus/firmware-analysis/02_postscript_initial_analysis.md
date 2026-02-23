# Section 02: PostScript Operators - Initial Analysis

**Date**: 2025-11-10
**Section**: 02 (PostScript Operators / Mach Services)
**Binary**: `02_postscript_operators.bin`
**Size**: 32 KB (32,768 bytes)
**Address Range**: 0xF8008000 - 0xF800FFFF
**Disassembly**: `02_postscript_operators.asm` (8,192 instructions)

---

## Executive Summary

Section 02 contains PostScript operator implementations and Mach IPC service routines that handle Display PostScript commands from the host. This code runs after the bootstrap (Section 01) has initialized the hardware and is called by the main kernel dispatcher (Section 03) when PostScript operations need to be executed.

**Key Characteristics**:
- **Function Count**: ~5 major functions (based on `bri %r1` returns)
- **Code Density**: Sparse (~5 functions in 32 KB = 6.4 KB average per function)
- **Function Type**: Mostly leaf functions (no stack frame setup detected)
- **Integration**: Called by Section 03 dispatch table
- **Purpose**: Implements the 28 PostScript operators discovered in NDserver analysis

---

## Function Boundaries

Analysis of indirect branch instructions (`bri`) reveals the following function structure:

| Line | Address | Instruction | Type | Notes |
|------|---------|-------------|------|-------|
| 5634 | 0xF800D804 | `bri %r1` | Function return | End of Function 1 |
| 6483 | 0xF800E548 | `bri %r13` | Indirect jump | Possible tail call or jump table |
| 6989 | 0xF800ED30 | `bri %r1` | Function return | End of Function 2 |
| 7111 | 0xF800EF18 | `bri %r1` | Function return | End of Function 3 |
| 7202 | 0xF800F084 | `bri %r1` | Function return | End of Function 4 |
| 7353 | 0xF800F2E0 | `bri %r1` | Function return | End of Function 5 |
| 7573 | 0xF800F650 | `bri %r16` | Indirect jump | Function pointer or callback |
| 7581 | 0xF800F670 | `bri %r18` | Indirect jump | Function pointer or callback |
| 7583 | 0xF800F678 | `bri %r18` | Indirect jump | Function pointer or callback |
| 8141 | 0xF800FF30 | `bri %r12` | Indirect jump | Possible tail call |

**Observations**:
- **5 standard functions** with `bri %r1` returns
- **5 indirect branches** using other registers (function pointers, tail calls, or dispatch tables)
- **Large function sizes**: Average ~5.6 KB per function (vs. ~1-2 KB typical)
- **No frame setup detected**: Only 1 instance of `st.l %r1` found (saves return address)

---

## Preliminary Function Map

### Function 1: 0xF8008000 - 0xF800D804 (~23 KB)
**Size**: ~5,804 instructions
**Return**: Line 5634 (bri %r1)
**Characteristics**:
- Extremely large function (72% of section!)
- Likely contains multiple sub-routines or inline code
- May be the main PostScript operator dispatcher

### Function 2: 0xF800D808 - 0xF800ED30 (~5.5 KB)
**Size**: ~1,355 instructions
**Return**: Line 6989 (bri %r1)
**Characteristics**:
- More typical function size
- Possible specific operator implementation

### Function 3: 0xF800ED34 - 0xF800EF18 (~484 bytes)
**Size**: ~121 instructions
**Return**: Line 7111 (bri %r1)
**Characteristics**:
- Small, focused function
- Likely a helper or utility

### Function 4: 0xF800EF1C - 0xF800F084 (~360 bytes)
**Size**: ~90 instructions
**Return**: Line 7202 (bri %r1)
**Characteristics**:
- Small helper function

### Function 5: 0xF800F088 - 0xF800F2E0 (~600 bytes)
**Size**: ~150 instructions
**Return**: Line 7353 (bri %r1)
**Characteristics**:
- Medium-sized function

---

## Architecture Hypothesis

Based on NDserver analysis and the function sizes, this section likely implements:

### Primary Component: PostScript Operator Dispatch (~Function 1)

The massive 23 KB Function 1 is likely a **switch/case dispatcher** handling all 28 PostScript operators:

```c
// Hypothetical structure
void ps_operator_dispatch(uint32_t op_code, void* params) {
    switch (op_code) {
        case PS_OP_MOVETO:     ps_moveto(params); break;
        case PS_OP_LINETO:     ps_lineto(params); break;
        case PS_OP_CURVETO:    ps_curveto(params); break;
        case PS_OP_FILL:       ps_fill(params); break;
        case PS_OP_STROKE:     ps_stroke(params); break;
        // ... 23 more operators ...
    }
}
```

**Evidence**:
- NDserver implements 28 operators with 48-byte message structure
- Large size suggests many inline implementations
- PostScript operators are small (5-50 lines of code each)
- Jump table at 0xF800E548 (`bri %r13`) suggests dispatch

### Secondary Components: Helper Functions (Functions 2-5)

Smaller functions (5.5 KB - 360 bytes) likely implement:
- **Graphics state management** (gsave/grestore, CTM manipulation)
- **Color conversions** (RGB→CMYK, color space transformations)
- **Path construction** (building bezier curves, line segments)
- **Mach IPC helpers** (message validation, buffer management)

---

## Integration with Other Sections

### Called By (Section 03 - Graphics Acceleration)

Section 03 contains the main kernel dispatcher that routes commands:

```
Host → Mailbox → Section 03 Dispatcher → Section 02 PostScript Ops
```

### Calls To (Section 01 - Bootstrap)

Section 02 likely calls Section 01 primitives:
- **MMIO access** (VRAM writes, RAMDAC updates)
- **Memory operations** (memcpy for large transfers)
- **Math primitives** (fixed-point arithmetic, matrix math)

---

## PostScript Operator Mapping

Based on NDserver's 28 operators, Section 02 likely implements:

### Category 1: Color Operations (5 operators)
- `ColorAlloc` - Allocate color slots
- `ColorProcessing` - RGB/CMYK/HSB conversions
- `ColorSpace` - Set current color space
- `SetColor` - Set stroke/fill color
- `GammaCorrection` - Apply gamma curves

### Category 2: Graphics State (6 operators)
- `gsave` / `grestore` - Save/restore graphics state
- `CTMSet` - Set current transformation matrix
- `CTMConcat` - Concatenate transform
- `SetLineWidth` - Stroke parameters
- `SetLineCap` / `SetLineJoin` - Line endings

### Category 3: Path Construction (6 operators)
- `newpath` - Start new path
- `moveto` - Move current point
- `lineto` - Add line segment
- `curveto` - Add bezier curve
- `closepath` - Close current sub-path
- `clip` - Set clipping path

### Category 4: Rendering (4 operators)
- `fill` - Fill current path
- `stroke` - Stroke current path
- `show` - Render text (uses font cache)
- `image` / `imagemask` - Render bitmaps

### Category 5: Font Management (2 operators)
- `findfont` - Locate font in cache
- `scalefont` - Scale font metrics

### Category 6: Display Control (2 operators)
- `showpage` - Flip frame buffers
- `copypage` - Copy back → front buffer

### Category 7: Stack/Data Management (3 operators)
- `def` - Define variable
- `exch` / `dup` / `pop` - Stack manipulation
- `index` / `roll` - Stack indexing

---

## Next Steps for Deep Analysis

1. **Disassemble Function 1 in detail**
   - Identify jump table structure
   - Map each case to specific operator
   - Correlate with NDserver's 48-byte message format

2. **Analyze helper functions (2-5)**
   - Determine purpose of each
   - Identify parameters and return values
   - Map to NDserver protocol

3. **Cross-reference with Section 03**
   - Find call sites in main dispatcher
   - Understand parameter passing convention
   - Verify message structure alignment

4. **Correlate with NDserver operators**
   - Match i860 implementation to host-side expectations
   - Validate magic number handling (0x63a)
   - Verify error codes (-300, -301, -202, 0)

5. **Document MMIO access patterns**
   - VRAM writes for rendering
   - RAMDAC updates for color maps
   - DMA triggers for large transfers

---

## Technical Notes

### Leaf Function Optimization

The lack of stack frame setup (`st.l %r1`) in most functions suggests:
- **Leaf functions**: No calls to other functions, so %r1 doesn't need saving
- **Tail call optimization**: Functions end with `br` to next routine (no return)
- **Register allocation**: All work done in caller-saved registers (%r2-%r15)

This is consistent with PostScript operators being small, self-contained operations.

### Jump Table Dispatch

The `bri %r13` at 0xF800E548 suggests a **computed jump**:

```assembly
; Hypothetical dispatch code
ld.l   msg_opcode(%r8), %r13     ; Load operator code
shl    %r13, 2, %r13              ; Multiply by 4 (address size)
addu   jump_table_base, %r13, %r13
ld.l   (%r13), %r13               ; Load target address
bri    %r13                        ; Jump to operator
```

This pattern is common for switch statements with many cases.

### Performance Characteristics

**Estimated Cycles**:
- **Dispatch overhead**: ~10-20 cycles (jump table lookup)
- **Operator execution**: 50-500 cycles (depends on complexity)
- **Total per operator**: 60-520 cycles

**Throughput**:
- At 33 MHz: ~63,000 - 550,000 operators/second
- Compare to software PostScript: ~1,000-10,000 ops/sec (60-550× faster)

---

## Open Questions

1. **Where is the operator jump table?**
   - Not obvious in disassembly
   - May be in data section (not yet analyzed)
   - Could be in Section 03

2. **How are parameters passed?**
   - NDserver uses 48-byte messages
   - Likely pointer in %r16 or %r17
   - Need to trace from Section 03 dispatcher

3. **What is the Mach IPC integration?**
   - Mailbox polling in Section 01
   - Message validation here?
   - Or in Section 03?

4. **Why is Function 1 so large?**
   - All operators inline?
   - Unrolled loops?
   - Or misidentified boundaries?

---

## Related Documents

- `POSTSCRIPT_OPERATORS.md` - Complete PostScript operator reference
- `HOST_I860_PROTOCOL_SPEC.md` - Mailbox protocol specification
- `../ndserver-re/docs/POSTSCRIPT_OPERATORS_REFERENCE.md` - NDserver operator analysis
- `01_bootstrap_*.md` - Section 01 analysis (called by this section)
- `COMMAND_REFERENCE_CARDS.md` - All 50+ commands including PostScript

---

**Status**: Initial analysis complete
**Next**: Deep dive into Function 1 (operator dispatcher)
**Confidence**: Medium (requires validation against Section 03)
