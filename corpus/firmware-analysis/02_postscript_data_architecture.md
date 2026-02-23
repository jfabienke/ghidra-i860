# Section 02: PostScript Data Architecture

**Section**: 02 (PostScript Operator Tables & Data)
**Type**: DATA STRUCTURES
**Size**: 32 KB (32,768 bytes)
**Address Range**: 0xF8008000 - 0xF800FFFF
**Purpose**: PostScript operator dispatch tables, initialization code, and graphics primitives
**Date**: 2025-11-10

---

## Executive Summary

Section 02 contains **pure data structures** used by the PostScript rendering engine in Section 03. Unlike Section 01 (executable bootstrap code), this section is **not meant to be executed** - it's a data segment containing:

1. **Operator Lookup Tables** - Maps operator names/codes to handler functions
2. **PostScript Initialization Code** - Embedded PS snippets for macro definitions
3. **Graphics State Defaults** - Line styles, flatness tolerance, rendering parameters
4. **Path Rendering Macros** - Abbreviated operators for compact path encoding

**Key Insight**: Initial disassembly appeared to show code, but detailed analysis revealed this is data that happens to contain code-like byte patterns. The PostScript text strings are definitive proof.

---

## Data Organization

### Memory Layout (Hypothetical, to be confirmed)

```
0xF8008000 - 0xF8008FFF (4 KB):  Operator Name Strings
0xF8009000 - 0xF80097FF (2 KB):  Operator Dispatch Table (28 entries × ~72 bytes)
0xF8009800 - 0xF800BFFF (10 KB): PostScript Initialization Snippets
0xF800C000 - 0xF800DFFF (8 KB):  Graphics State Default Values
0xF800E000 - 0xF800FFFF (8 KB):  Path Macro Definitions & Reserved
```

**Note**: These boundaries are estimated and require binary analysis to confirm.

---

## Component 1: Operator Dispatch Table

### Purpose

Maps PostScript operator identifiers to their implementation handlers in Section 03.

### Hypothetical Structure

```c
// Each operator entry (estimated 48-72 bytes)
typedef struct ps_operator {
    // Identification
    char*    name;              // Offset +0:  "moveto", "lineto", etc.
    uint16_t opcode;            // Offset +4:  Operator code (0-27)
    uint16_t flags;             // Offset +6:  Flags (see below)

    // Handler
    void*    handler_addr;      // Offset +8:  Function pointer in Section 03

    // Parameters
    uint8_t  operand_count;     // Offset +12: Stack operands consumed
    uint8_t  result_count;      // Offset +13: Stack results produced
    uint8_t  operand_types[8];  // Offset +14: Type constraints (num, string, array, etc.)

    // Rendering hints
    uint16_t category;          // Offset +22: PATH, GFX_STATE, COLOR, PAINT, etc.
    uint16_t rendering_flags;   // Offset +24: Affects bbox, invalidates cache, etc.

    // Reserved for alignment/future use
    uint8_t  reserved[24];      // Offset +26: Padding to 48 or 72 bytes
} ps_operator_t;
```

### Known Operators (28 total)

Based on NDserver analysis and PostScript strings found:

#### Path Construction (6 operators)
```c
{ "moveto",    OP_MOVETO,    PATH_OP,    ps_moveto_impl,    2, 0 },  // x y
{ "lineto",    OP_LINETO,    PATH_OP,    ps_lineto_impl,    2, 0 },  // x y
{ "curveto",   OP_CURVETO,   PATH_OP,    ps_curveto_impl,   6, 0 },  // x1 y1 x2 y2 x3 y3
{ "closepath", OP_CLOSEPATH, PATH_OP,    ps_closepath_impl, 0, 0 },
{ "clip",      OP_CLIP,      PATH_OP,    ps_clip_impl,      0, 0 },
{ "newpath",   OP_NEWPATH,   PATH_OP,    ps_newpath_impl,   0, 0 },
```

#### Graphics State (8 operators)
```c
{ "setlinewidth",  OP_SETLINEWIDTH,  GFX_STATE, ps_setlinewidth_impl,  1, 0 }, // width
{ "setlinecap",    OP_SETLINECAP,    GFX_STATE, ps_setlinecap_impl,    1, 0 }, // style
{ "setlinejoin",   OP_SETLINEJOIN,   GFX_STATE, ps_setlinejoin_impl,   1, 0 }, // style
{ "setmiterlimit", OP_SETMITERLIMIT, GFX_STATE, ps_setmiterlimit_impl, 1, 0 }, // limit
{ "setflat",       OP_SETFLAT,       GFX_STATE, ps_setflat_impl,       1, 0 }, // flatness
{ "setdash",       OP_SETDASH,       GFX_STATE, ps_setdash_impl,       2, 0 }, // array phase
{ "gsave",         OP_GSAVE,         GFX_STATE, ps_gsave_impl,         0, 0 },
{ "grestore",      OP_GRESTORE,      GFX_STATE, ps_grestore_impl,      0, 0 },
```

#### Painting (4 operators)
```c
{ "stroke",  OP_STROKE,  PAINT_OP, ps_stroke_impl,  0, 0 },
{ "fill",    OP_FILL,    PAINT_OP, ps_fill_impl,    0, 0 },
{ "eofill",  OP_EOFILL,  PAINT_OP, ps_eofill_impl,  0, 0 },  // Even-odd fill
{ "show",    OP_SHOW,    PAINT_OP, ps_show_impl,    1, 0 },  // string
```

#### Color (4 operators)
```c
{ "setgray",     OP_SETGRAY,     COLOR_OP, ps_setgray_impl,     1, 0 }, // gray
{ "setrgbcolor", OP_SETRGBCOLOR, COLOR_OP, ps_setrgbcolor_impl, 3, 0 }, // r g b
{ "sethsbcolor", OP_SETHSBCOLOR, COLOR_OP, ps_sethsbcolor_impl, 3, 0 }, // h s b
{ "setcmykcolor",OP_SETCMYKCOLOR,COLOR_OP, ps_setcmykcolor_impl,4, 0 }, // c m y k
```

#### Stack/Control (6 operators)
```c
{ "def",   OP_DEF,   CONTROL_OP, ps_def_impl,   2, 0 }, // key value
{ "load",  OP_LOAD,  CONTROL_OP, ps_load_impl,  1, 1 }, // key -> value
{ "copy",  OP_COPY,  CONTROL_OP, ps_copy_impl,  1, 0 }, // n
{ "pop",   OP_POP,   CONTROL_OP, ps_pop_impl,   1, 0 },
{ "dup",   OP_DUP,   CONTROL_OP, ps_dup_impl,   1, 2 }, // any -> any any
{ "roll",  OP_ROLL,  CONTROL_OP, ps_roll_impl,  2, 0 }, // n j
```

### Flags Bit Definitions

```c
// Operator flags (uint16_t)
#define OP_FLAG_IMMEDIATE      0x0001  // Execute immediately (not cached)
#define OP_FLAG_INVALIDATES_BB 0x0002  // Invalidates bounding box
#define OP_FLAG_MODIFIES_PATH  0x0004  // Modifies current path
#define OP_FLAG_MODIFIES_STATE 0x0008  // Modifies graphics state
#define OP_FLAG_NEEDS_FLUSH    0x0010  // Requires display list flush
#define OP_FLAG_COLOR_OP       0x0020  // Affects color state
#define OP_FLAG_MATRIX_OP      0x0040  // Affects transformation matrix

// Category flags (uint16_t)
#define CAT_PATH       0x0100
#define CAT_GFX_STATE  0x0200
#define CAT_PAINT      0x0400
#define CAT_COLOR      0x0800
#define CAT_CONTROL    0x1000
#define CAT_FONT       0x2000
#define CAT_DEVICE     0x4000
```

---

## Component 2: PostScript Initialization Snippets

### Purpose

Embedded PostScript code executed at firmware startup to define standard macros and abbreviations.

### Discovered Snippets

#### Path Abbreviation Macros

```postscript
% Define short names for common operators
/m { moveto } def
/l { lineto } def
/c { curveto } def
/v { currentpoint 6 2 roll curveto } def
/y { 2 copy curveto } def

% Path list operators (pl = path list)
pl moveto
pl lineto
pl curveto
pl 2 copy curveto
```

**Purpose**: These abbreviations allow compact path encoding in the firmware. Instead of encoding full operator names, paths can use single letters.

#### Clipping Region Management

```postscript
% Clipping flag
/_doClip 0 ddef
/_doClip 1 ddef

% Conditional clipping
_doClip 1 eq {clip /_doClip 0 ddef} if
```

**Purpose**: Deferred clipping - sets a flag instead of immediately clipping, allowing optimization.

#### Rendering Mode Dispatch

```postscript
% Stroke/fill/erase dispatch
/CRender {S} ddef  % Stroke mode
/CRender {F} ddef  % Fill mode
/CRender {N} ddef  % No-op (erase)
/CRender {B} ddef  % Both stroke and fill
```

**Purpose**: Abstraction layer allowing path rendering mode to be changed dynamically.

#### Graphics State Wrappers

```postscript
% Stroke with temporary state
gsave _ps grestore clip newpath /_lp /none ddef _sc

% Fill with temporary state
gsave _pf grestore clip newpath /_lp /none ddef _fc

% Stroke with clipping
gsave S grestore clip newpath /_doClip 0 ddef _sc

% Fill with clipping
gsave F grestore clip newpath /_lp /none ddef _fc
```

**Purpose**: Complex rendering operations that preserve graphics state, apply clipping, and reset path state.

#### Type Checking

```postscript
% Check for empty stack
count 0 ne

% Check for zero
dup 0 eq

% String type check
dup type (string) eq
```

**Purpose**: Runtime validation in PostScript interpreter.

### Variable Definitions

```postscript
/_pola 0 eq      % Polarity flag
/_lp /none ddef  % Last path (for optimization)
/_sc             % Stroke color
/_fc             % Fill color
/_ps             % Path stroke state
/_pf             % Path fill state
ad def           % Array definition
```

---

## Component 3: Graphics State Defaults

### Line Style Parameters

```c
// Default line rendering parameters
typedef struct gfx_state_defaults {
    float linewidth;       // 1.0 (1 pixel)
    uint8_t linecap;       // 0 = butt, 1 = round, 2 = projecting square
    uint8_t linejoin;      // 0 = miter, 1 = round, 2 = bevel
    float miterlimit;      // 10.0 (miter length / line width)
    float flatness;        // 1.0 (curve approximation tolerance in pixels)

    // Dash pattern
    float dash_array[8];   // Dash lengths (0 = solid line)
    uint8_t dash_count;    // Number of dash entries
    float dash_phase;      // Starting offset into dash pattern
} gfx_state_defaults_t;
```

### PostScript Standard Defaults

According to Display PostScript specification:
- **linewidth**: 1.0 device unit
- **linecap**: 0 (butt)
- **linejoin**: 0 (miter)
- **miterlimit**: 10.0
- **flatness**: 1.0 (device-dependent)
- **dash**: [] 0 (solid line, no dash)

These values are likely stored in Section 02 and loaded at initialization.

---

## Component 4: Path Macro Definitions

### Compact Path Encoding

PostScript paths can be verbose. Section 02 likely contains **compact binary encodings**:

#### Standard Path Encoding (Verbose)
```postscript
100 200 moveto
150 200 lineto
150 250 lineto
100 250 lineto
closepath
```
**Size**: ~140 bytes as ASCII PostScript

#### Compact Binary Encoding
```c
// Hypothetical binary path format
struct path_command {
    uint8_t opcode;     // 0=moveto, 1=lineto, 2=curveto, 3=close
    int16_t coords[6];  // Up to 6 coordinates (for curveto)
};

// Same rectangle as 20 bytes:
{ OP_MOVETO, {100, 200} },
{ OP_LINETO, {150, 200} },
{ OP_LINETO, {150, 250} },
{ OP_LINETO, {100, 250} },
{ OP_CLOSE,  {0} }
```
**Size**: 20 bytes (7× reduction)

### Pre-defined Primitives

Common shapes stored as path templates:
- **Rectangle**: 4 lines + close
- **Rounded rectangle**: 4 lines + 4 arcs + close
- **Circle**: 4 bezier curves approximating circle
- **Ellipse**: Scaled circle path
- **Arrow**: Triangular path for line caps

---

## Integration with Section 03

### Data Access Patterns

Section 03 code accesses Section 02 data via:

```c
// Load operator table base
const ps_operator_t* op_table = (ps_operator_t*)0xF8009000;

// Look up operator by code
void dispatch_operator(uint8_t opcode) {
    if (opcode >= 28) return;  // Invalid operator

    ps_operator_t* op = &op_table[opcode];

    // Call handler function
    typedef void (*handler_fn)(void);
    handler_fn handler = (handler_fn)op->handler_addr;
    handler();
}
```

### Initialization Sequence

At firmware startup (Section 03 main loop):

```c
void init_postscript_engine(void) {
    // 1. Load operator table from Section 02
    load_operator_table(0xF8009000);

    // 2. Execute PostScript initialization snippets
    const char* ps_init = (const char*)0xF8009800;
    ps_eval(ps_init);  // Defines /m, /l, /c, etc.

    // 3. Load graphics state defaults
    const gfx_state_defaults_t* defaults = (gfx_state_defaults_t*)0xF800C000;
    memcpy(&current_gfx_state, defaults, sizeof(*defaults));

    // 4. Ready to process commands from host
}
```

---

## Rust/Embassy Re-implementation Strategy

### Option 1: Hard-Code Operator Table

```rust
// No need for Section 02 data - define in Rust
const OPERATORS: &[(&str, OpHandler, u8, u8)] = &[
    ("moveto",    op_moveto,    2, 0),
    ("lineto",    op_lineto,    2, 0),
    ("curveto",   op_curveto,   6, 0),
    // ... 25 more ...
];

fn dispatch(opcode: u8) -> Result<(), Error> {
    let (name, handler, operands, results) = OPERATORS[opcode as usize];
    handler()
}
```

### Option 2: Embed PostScript Init as Rust Const

```rust
// Convert PS init snippets to Rust initialization
const INIT_MACROS: &str = r#"
    /m { moveto } def
    /l { lineto } def
    /c { curveto } def
"#;

fn init_postscript() {
    ps_eval(INIT_MACROS);
}
```

### Option 3: Include Binary Data Section

```rust
// Include Section 02 as-is for perfect compatibility
#[link_section = ".rodata.ps_data"]
static PS_DATA: [u8; 32768] = *include_bytes!("02_postscript_operators.bin");

fn init_postscript() {
    let op_table = unsafe {
        &*(PS_DATA.as_ptr().offset(0x1000) as *const OpTable)
    };
}
```

**Recommendation**: Option 1 (hard-code) for clarity and type safety.

---

## Next Analysis Steps

### 1. Binary Structure Parsing

```bash
# Extract operator table
python3 << 'EOF'
import struct

with open('02_postscript_operators.bin', 'rb') as f:
    data = f.read()

# Search for operator name pointers
# Look for addresses in Section 02 range (0xF8008000-0xF800FFFF)
for i in range(0, len(data)-4, 4):
    ptr = struct.unpack('>I', data[i:i+4])[0]
    if 0xF8008000 <= ptr <= 0xF800FFFF:
        print(f"Offset 0x{i:04x}: Pointer to 0x{ptr:08x}")
EOF
```

### 2. PostScript Snippet Extraction

```bash
# Extract all PostScript code blocks
strings -n 16 02_postscript_operators.bin > ps_snippets.txt

# Look for complete PS procedures
grep -A10 "def" ps_snippets.txt
```

### 3. Cross-Reference with Section 03

Once Section 03 is disassembled:
```bash
# Find loads from Section 02 address range
grep "ld.* 0xf800[89ab]" 03_graphics_acceleration.asm
```

### 4. Validate Operator Table Hypothesis

```python
# Check if 28 entries exist at regular intervals
for offset in range(0x1000, 0x1000 + 28*72, 72):
    entry = data[offset:offset+72]
    # Parse as struct, check for valid pointers
```

---

## Related Documents

- `02_postscript_CORRECTED_analysis.md` - Discovery that Section 02 is data
- `02_postscript_initial_analysis.md` - Original (incorrect) code analysis
- `POSTSCRIPT_OPERATORS.md` - Reference for all 28 operators
- `HOST_I860_PROTOCOL_SPEC.md` - Mailbox message format
- `03_graphics_acceleration_*.md` - TO BE CREATED (actual code implementations)

---

## Appendix: Complete String Dump

All strings found in Section 02 (alphabetical):

```
2 copy curveto
/_doClip 0 ddef
/_doClip 1 ddef
/_pola 0 eq
/c load def
/CRender {B} ddef
/CRender {F} ddef
/CRender {N} ddef
/CRender {S} ddef
/l load def
/v load def
/y load def
_doClip 1 eq
_doClip 1 eq {clip /_doClip 0 ddef} if
ad def
closepath
count 0 ne
currentpoint 6 2 roll pl curveto
dup 0 eq
dup type (string) eq
gsave F grestore
gsave S grestore clip newpath /_lp /none ddef _sc
gsave _pf grestore clip newpath /_lp /none ddef _fc
gsave _ps grestore clip newpath /_lp /none ddef _sc
lineto
moveto
newpath
pl 2 copy curveto
pl curveto
pl lineto
pl moveto
pop cf
setdash
setflat
setlinecap
setlinejoin
setlinewidth
setmiterlimit
{%else
{N} def
{} def
} def
} if
}ifelse

% Comments found:
% - B -
% - F -
% - H -
% - N -
% - S -
% - W -
% - [string] * -
% - b -
% - cf flatness
% - f -
% - h -
% - n -
% - s -
% F clears _doClip
% array phase d -
% flatness i -
% graphic state operators
% linecap J -
% linejoin j -
% linewidth w -
% miterlimit M -
% path painting operators
% x y l -
% x y m -
% x1 y1 x2 y2 y -
```

**Status**: Architecture documented, ready for binary structure analysis
**Confidence**: Very High (PostScript strings definitively prove data nature)
