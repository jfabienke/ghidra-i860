# Section 02: PostScript Data - Quick Reference Card

> **📋 RECONCILIATION NOTE**: This file = Previous project's Section 3 (Mach Services).
> Contains ~24 KB i860 CODE + ~8 KB embedded data. See `SECTION_RECONCILIATION.md`.

**Type**: EMBEDDED DATA within i860 executable code
**Size**: 32 KB @ 0xF8008000-0xF800FFFF
**Purpose**: Operator tables, PostScript init code, graphics state defaults (accessed by i860 code)

---

## Data Components

| Component | Est. Address | Est. Size | Purpose |
|-----------|--------------|-----------|---------|
| String Table | 0xF8008000 | ~8 KB | Operator name strings |
| Operator Table | 0xF800A000 | ~1 KB | 28 operator entries w/ handlers |
| PS Init Code | 0xF800B000 | ~10 KB | PostScript initialization snippets |
| GFX Defaults | 0xF800C000 | ~256 B | Line style, color, CTM defaults |
| Path Macros | 0xF800D000 | ~8 KB | Compact path encoding data |
| Reserved | 0xF800F000 | ~4 KB | Unused/future |

---

## PostScript Operators (28 total)

### Path Construction (6)
```
moveto, lineto, curveto, closepath, newpath, clip
```

### Graphics State (8)
```
setlinewidth, setlinecap, setlinejoin, setmiterlimit
setflat, setdash, gsave, grestore
```

### Rendering (4)
```
stroke, fill, eofill, show
```

### Color (4)
```
setgray, setrgbcolor, sethsbcolor, setcmykcolor
```

### Stack/Control (6)
```
def, load, copy, pop, dup, roll
```

---

## Operator Table Structure (Hypothetical)

```c
struct ps_operator_entry {  // ~36 bytes each
    const char*  name;           // +0:  Pointer to string
    uint8_t      opcode;         // +4:  0-27
    uint8_t      category;       // +5:  PATH/GFX/PAINT/etc
    uint16_t     flags;          // +6:  Operational flags
    void*        handler;        // +8:  Function in Section 03
    int8_t       operand_count;  // +12: Stack args consumed
    int8_t       result_count;   // +13: Stack args produced
    uint8_t      operand_types[8]; // +14: Type constraints
    uint16_t     affects_state;  // +22: State modification mask
    uint16_t     invalidates;    // +24: Invalidation flags
    uint32_t     reserved[2];    // +26: Padding
};
```

---

## PostScript Initialization Macros

```postscript
% Abbreviations
/m { moveto } def
/l { lineto } def
/c { curveto } def
/v { currentpoint 6 2 roll curveto } def
/y { 2 copy curveto } def

% Clipping
/_doClip 0 ddef
_doClip 1 eq {clip /_doClip 0 ddef} if

% Rendering mode
/CRender {S} ddef  % Stroke
/CRender {F} ddef  % Fill
/CRender {N} ddef  % No-op
/CRender {B} ddef  % Both

% State preservation
gsave _ps grestore clip newpath /_lp /none ddef _sc
gsave _pf grestore clip newpath /_lp /none ddef _fc
```

---

## Graphics State Defaults

```c
struct graphics_state_defaults {
    float    linewidth;      // 1.0
    uint8_t  linecap;        // 0 (butt)
    uint8_t  linejoin;       // 0 (miter)
    float    miterlimit;     // 10.0
    float    flatness;       // 1.0
    float    dash_array[16]; // [0] = solid
    uint8_t  dash_count;     // 0
    float    dash_phase;     // 0.0
    float    gray;           // 0.0 (black)
    float    ctm[6];         // Identity matrix
};
```

---

## Integration with Section 03

### Initialization (at firmware startup)
```c
1. Load operator table from 0xF800A000
2. Execute PostScript init snippets from 0xF800B000
3. Load graphics state defaults from 0xF800C000
4. Ready to process commands from host
```

### Operator Dispatch (per command)
```c
1. Receive operator code (0-27) from mailbox
2. Lookup entry: op = operator_table[opcode]
3. Validate operand count on stack
4. Call handler: op->handler()
5. Return result to host
```

### Data Access Pattern
```assembly
; Load operator table base
orh   0xF800, %r0, %r20
or    0xA000, %r20, %r20       ; %r20 = 0xF800A000

; Index by opcode (in %r16)
shl   %r16, 5, %r17            ; Multiply by 32 bytes
addu  %r17, %r20, %r17         ; %r17 = &operator_table[opcode]

; Load handler address (offset +8)
ld.l  8(%r17), %r2
bri   %r2                       ; Jump to handler in Section 03
```

---

## Rust Re-implementation Strategy

### Option 1: Hard-Coded Table (Recommended)
```rust
const OPERATORS: &[OpEntry] = &[
    OpEntry { name: "moveto", handler: op_moveto, args: 2 },
    OpEntry { name: "lineto", handler: op_lineto, args: 2 },
    // ... 26 more ...
];

fn dispatch(opcode: u8) {
    OPERATORS[opcode as usize].handler();
}
```

### Option 2: Include Binary Data
```rust
#[link_section = ".rodata"]
static PS_DATA: [u8; 32768] =
    *include_bytes!("02_postscript_operators.bin");
```

---

## Binary Analysis Tools

### Find Pointers
```python
for i in range(0, len(data), 4):
    ptr = struct.unpack('>I', data[i:i+4])[0]
    if 0xF8008000 <= ptr <= 0xF800FFFF:
        print(f"0x{i:04x}: -> 0x{ptr:08x}")
```

### Extract Strings
```bash
strings -n 8 02_postscript_operators.bin | sort | uniq
```

### Find Table Boundaries
```python
# Look for repeating struct patterns
for offset in range(0, len(data), 32):
    if looks_like_operator_entry(data[offset:offset+32]):
        print(f"Table entry at 0x{offset:04x}")
```

---

## Key Insights

1. **Not executable code** - Disassembly produces nonsense
2. **Data segment** - Tables + strings + PostScript text
3. **Referenced by Section 03** - Actual operator implementations
4. **PostScript DSL** - Init code defines abbreviations
5. **Compact encoding** - Binary path formats for efficiency

---

## Next Steps

1. ✅ Identify as data (not code)
2. ✅ Extract PostScript strings
3. ⏳ Parse operator table structure
4. ⏳ Locate graphics state defaults
5. ⏳ Cross-reference with Section 03 code
6. ⏳ Document final memory map

---

## Related Documents

| Document | Purpose |
|----------|---------|
| `02_postscript_CORRECTED_analysis.md` | Discovery that Section 02 is data |
| `02_postscript_data_architecture.md` | High-level architecture |
| `02_postscript_data_structures_detailed.md` | Detailed structure analysis |
| `03_graphics_acceleration_*.md` | Actual operator implementations (TBD) |
| `POSTSCRIPT_OPERATORS.md` | Reference for all 28 operators |

---

**Status**: Structure documented, binary parsing in progress
**Confidence**: Very High (PostScript strings are definitive proof)
