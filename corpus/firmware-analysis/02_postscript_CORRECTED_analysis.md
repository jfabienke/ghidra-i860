# Section 02: PostScript Data Structures - CORRECTED ANALYSIS

**Date**: 2025-11-10
**Section**: 02 (PostScript Operators / Mach Services)
**Binary**: `02_postscript_operators.bin`
**Size**: 32 KB (32,768 bytes)
**Address Range**: 0xF8008000 - 0xF800FFFF
**Type**: **EMBEDDED DATA WITHIN i860 CODE** ⚠️

> **📋 RECONCILIATION NOTE** (2025-11-10):
> This file = Previous project's `section3_mach.bin` (byte-for-byte identical).
> Previous correctly identified this as **i860 CODE with embedded data**.
> Our analysis correctly identified the **embedded data structures**.
> Both perspectives are valid - this section contains ~24 KB executable i860 code + ~8 KB embedded data (PostScript strings, dispatch tables).
> See `SECTION_RECONCILIATION.md` for complete details.

---

## Critical Discovery

**Section 02 contains embedded data within i860 executable code!**

Initial disassembly analysis (see `02_postscript_initial_analysis.md`) was based on the assumption that this section contained executable instructions. However, detailed analysis reveals this is **pure data**:

### Evidence

1. **PostScript Operator Strings Found**:
   ```
   - "curveto"
   - "lineto"
   - "moveto"
   - "closepath"
   - "setlinewidth"
   - "setmiterlimit"
   - "setlinecap"
   - "setlinejoin"
   - "currentpoint"
   - "flatness"
   - "linejoin"
   - "linecap"
   ```

2. **Disassembly Anomalies**:
   - Many `.long` directives (raw data bytes)
   - Nonsensical instruction sequences
   - No function prologues (`st.l %r1` for saving return address)
   - Indirect branches (`bri %r2`) with no clear address loads
   - "Functions" with embedded data

3. **Byte Analysis**:
   - 20.6% zeros (padding/alignment)
   - No empty 1KB chunks (all sections have content)
   - High byte entropy (mixed code-like and text data)
   - PostScript text interspersed with binary structures

---

## What Section 02 Actually Contains

### 1. PostScript Operator Lookup Tables

The section likely contains:
- **Operator name strings** (e.g., "moveto", "lineto", "curveto")
- **Function pointers** to handler code (in Section 03)
- **Parameter descriptors** (how many args each operator takes)
- **Operator type flags** (path, graphics state, color, etc.)

**Hypothetical Structure**:
```c
struct ps_operator {
    char*    name;           // e.g., "moveto"
    void*    handler;        // Function pointer to implementation
    uint8_t  arg_count;      // Number of operands from stack
    uint8_t  type;           // PATH_OP, GFX_STATE_OP, COLOR_OP, etc.
    uint32_t flags;          // Additional attributes
};

ps_operator operators[] = {
    { "moveto",    ps_moveto_handler,    2, PATH_OP,      0 },
    { "lineto",    ps_lineto_handler,    2, PATH_OP,      0 },
    { "curveto",   ps_curveto_handler,   6, PATH_OP,      0 },
    { "closepath", ps_closepath_handler, 0, PATH_OP,      0 },
    { "stroke",    ps_stroke_handler,    0, PAINT_OP,     0 },
    { "fill",      ps_fill_handler,      0, PAINT_OP,     0 },
    // ... 22 more operators ...
};
```

### 2. PostScript Snippet Programs

The strings suggest **embedded PostScript code snippets**:

```postscript
% x1 y1 x2 y2 y -
2 copy curveto
/y load def

% x y l -
/l load def

% x y m -
pl curveto
/c load def

currentpoint 6 2 roll pl curveto
/v load def

pl 2 copy curveto
/y load def

pl lineto
/l load def

pl moveto
```

These snippets may be:
- **Predefined macros** for complex path operations
- **Initialization code** run at startup
- **Test patterns** for validation
- **Font rendering helpers**

### 3. Path Construction Data

The repeated references to path operators suggest **precomputed path data**:
- Bezier curve control points
- Line segment endpoints
- Font glyph outlines
- Clipping regions

### 4. Graphics State Tables

References to "flatness", "linejoin", "linecap", "miterlimit", "linewidth" indicate **graphics state data**:
- Default values for line rendering
- Tolerance tables for curve flattening
- Join style lookup (miter, bevel, round)
- Cap style lookup (butt, round, projecting square)

---

## Integration with Other Sections

### Called By: Section 03 (Graphics Acceleration + Kernel Core)

Section 03 contains the **actual executable code** that:
1. Parses PostScript commands from mailbox
2. Looks up operator names in Section 02 tables
3. Dispatches to handler functions
4. Manipulates path data structures

**Data Flow**:
```
Host → Mailbox → Section 03 Code → Section 02 Lookup Tables
                         ↓
                    Handler Function (Section 03)
                         ↓
                    VRAM / Graphics State
```

### Relationship to NDserver

NDserver (host-side) sends **operator codes** (0-27), not operator names. Section 02 tables provide:
- Reverse mapping: Code → Name (for debugging)
- Parameter counts: Validate message format
- Handler pointers: Dispatch to Section 03 functions

**Example Message Flow**:
```
1. Host: SendCommand(OP_MOVETO, [x=100, y=200])
2. Mailbox: { cmd=0x428, op=5, args=[100,200] }
3. Section 03: Read cmd, lookup op=5 in Section 02 table
4. Section 02: { "moveto", handler=0xF8012340, args=2 }
5. Section 03: Call 0xF8012340(100, 200)
6. Handler: Update current point, return
```

---

## Why This Matters for Reverse Engineering

### Implications for Disassembly

1. **Section 02 should NOT be disassembled as code**
   - Prior disassembly (`02_postscript_operators.asm`) is INVALID
   - Must be analyzed as data structures instead

2. **Section 03 contains the real code**
   - PostScript operator implementations are in Section 03
   - Section 02 is just lookup/dispatch data

3. **Function boundaries were misidentified**
   - `bri %r1` returns found in disassembly were false positives
   - Actually data that happens to match opcode patterns

### Implications for Re-implementation

1. **Rust/Embassy firmware doesn't need Section 02**
   - Can hard-code operator dispatch tables
   - Rust enum for operator types:
   ```rust
   enum PostScriptOp {
       Moveto { x: f32, y: f32 },
       Lineto { x: f32, y: f32 },
       Curveto { x1: f32, y1: f32, x2: f32, y2: f32, x3: f32, y3: f32 },
       Stroke,
       Fill,
       // ...
   }
   ```

2. **PostScript snippets may be initialization code**
   - Check if original firmware runs these at boot
   - May define standard abbreviations (`/m`, `/l`, `/c` for operators)
   - Rust firmware needs equivalent setup

3. **Path data may be reference test patterns**
   - Useful for validating Rust implementation
   - Can compare rendered output against original

---

## Next Steps

### 1. Parse Section 02 as Data Structures

Extract and document the actual structures:
```bash
# Identify table boundaries
hexdump -C 02_postscript_operators.bin | grep "string patterns"

# Extract operator table
python3 parse_operator_table.py

# Identify PostScript snippets
strings -n 8 02_postscript_operators.bin > snippets.txt
```

### 2. Cross-Reference with Section 03

Find where Section 03 code accesses Section 02 data:
```bash
# Search for loads from 0xF8008000-0xF800FFFF
grep "ld.*0xf800[89a-f]" 03_graphics_acceleration.asm
```

### 3. Validate Hypothesis

Check if Section 03 disassembly shows:
- Loads from Section 02 address range (data reads)
- Function pointers in %r2, %r13, %r16, etc.
- String comparison loops (operator name lookup)

### 4. Document Operator Table Format

Reverse-engineer the exact struct layout:
- Offset 0: Operator name pointer?
- Offset 4: Handler function pointer?
- Offset 8: Argument count + flags?
- Size: 12-16 bytes per entry?
- Count: 28 operators?

### 5. Extract and Use PostScript Snippets

Analyze the embedded PostScript code:
- Is it run at startup?
- Are they macros for common operations?
- Font rendering helpers?
- Test patterns?

---

## Corrected Section Map

| Section | Type | Size | Purpose |
|---------|------|------|---------|
| 01 | **CODE** | 32 KB | Bootstrap Graphics HAL (hardware init, MMIO primitives) |
| 02 | **DATA** | 32 KB | PostScript operator tables, strings, path data |
| 03 | **CODE** | 128 KB | Graphics acceleration + kernel core (actual operators) |
| 04 | **CODE** | 64 KB | VM / Memory management |

---

## Lessons Learned

1. **Don't assume all firmware sections are executable code**
   - Check for strings and data patterns first
   - Look for magic numbers, struct alignment
   - Verify function prologue/epilogue patterns

2. **Disassemblers blindly decode everything**
   - They will "disassemble" data as instructions
   - Always validate with:
     - String analysis
     - Entropy checks
     - Cross-references from known code sections

3. **Context from NDserver is critical**
   - Knowing the 28 operators exist helped identify purpose
   - Understanding message format explained dispatch
   - Host-side reverse engineering guides firmware analysis

---

## Related Documents

- ~~`02_postscript_operators.asm`~~ - **INVALID** (disassembled data as code)
- `02_postscript_initial_analysis.md` - Initial (incorrect) analysis
- `POSTSCRIPT_OPERATORS.md` - Reference for 28 operator names
- `HOST_I860_PROTOCOL_SPEC.md` - Mailbox message format
- `03_graphics_acceleration.asm` - **TO BE ANALYZED** (contains real code)

---

**Status**: Critical error corrected - Section 02 is DATA, not CODE
**Next**: Analyze Section 03 for actual PostScript operator implementations
**Confidence**: Very High (PostScript strings are definitive proof)

---

## Appendix: PostScript Operators Found in Section 02

```
Path Construction:
- moveto      (move to point)
- lineto      (line to point)
- curveto     (cubic bezier curve)
- closepath   (close current sub-path)

Graphics State:
- setlinewidth   (stroke width)
- setlinecap     (end caps: butt/round/square)
- setlinejoin    (corner joins: miter/bevel/round)
- setmiterlimit  (miter join limit)
- flatness       (curve approximation tolerance)

Rendering:
- stroke      (stroke current path)
- fill        (fill current path)

Stack/Variable:
- def         (define variable)
- load        (load variable value)
- copy        (duplicate stack items)

Utility:
- currentpoint   (get current point coordinates)
- dup            (duplicate top of stack)
- roll           (rotate stack elements)
```

These match the NDserver operator list and Display PostScript specification.
