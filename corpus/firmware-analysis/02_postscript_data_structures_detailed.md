# Section 02: Data Structures - Detailed Analysis

**Section**: 02 (PostScript Operator Tables & Data)
**Type**: DATA STRUCTURES
**Size**: 32 KB (32,768 bytes)
**Address Range**: 0xF8008000 - 0xF800FFFF
**Date**: 2025-11-10

---

## Table of Contents

1. [Binary Layout Analysis](#binary-layout-analysis)
2. [String Table](#string-table)
3. [Operator Dispatch Table](#operator-dispatch-table)
4. [PostScript Initialization Code](#postscript-initialization-code)
5. [Graphics State Defaults](#graphics-state-defaults)
6. [Path Encoding Structures](#path-encoding-structures)
7. [Alignment and Padding](#alignment-and-padding)
8. [Cross-References to Section 03](#cross-references-to-section-03)

---

## Binary Layout Analysis

### Byte Distribution

```
Total Size:      32,768 bytes
Zero bytes:      6,746 (20.6%) - Padding and unused space
0xFF bytes:      1,172 (3.6%)  - Possible markers or unused
Data bytes:      24,850 (75.8%) - Actual content
```

### Entropy Analysis

```
Empty 1KB chunks: 0/32 - All sections contain some data
```

**Implication**: The entire 32 KB section is utilized, though 20% is padding for alignment.

### Hexdump Analysis (First 512 bytes)

```
Offset 0x0000-0x00FF: Mixed binary data and code-like patterns
Offset 0x0100-0x01FF: More binary structures
Offset 0x0200-0x02FF: Continued binary data
Offset 0x0300-0x03FF: Start of string data ("moveto", "lineto" visible)
```

**Pattern**: Initial sections appear to be binary structures (tables), followed by string data.

---

## String Table

### Location (Estimated)

**Address Range**: 0xF8008000 - 0xF8009FFF (approx 8 KB)

### Discovered Strings

#### Operator Names (28 strings)

**Path Construction Operators**:
```
Address (est)  String
-------------  ------
0xF8008xxx     "moveto"
0xF8008xxx     "lineto"
0xF8008xxx     "curveto"
0xF8008xxx     "closepath"
0xF8008xxx     "newpath"
0xF8008xxx     "clip"
```

**Graphics State Operators**:
```
0xF8008xxx     "setlinewidth"
0xF8008xxx     "setlinecap"
0xF8008xxx     "setlinejoin"
0xF8008xxx     "setmiterlimit"
0xF8008xxx     "setflat"
0xF8008xxx     "setdash"
0xF8008xxx     "gsave"
0xF8008xxx     "grestore"
```

**Rendering Operators**:
```
0xF8008xxx     "stroke"
0xF8008xxx     "fill"
0xF8008xxx     "show"
```

#### Variable Names (PostScript Initialization)

```
0xF8009xxx     "/m"
0xF8009xxx     "/l"
0xF8009xxx     "/c"
0xF8009xxx     "/v"
0xF8009xxx     "/y"
0xF8009xxx     "/CRender"
0xF8009xxx     "/_doClip"
0xF8009xxx     "/_pola"
0xF8009xxx     "/_lp"
0xF8009xxx     "/_sc"
0xF8009xxx     "/_fc"
0xF8009xxx     "/_ps"
0xF8009xxx     "/_pf"
0xF8009xxx     "pl"
```

#### String Storage Format

```c
// Null-terminated C strings
typedef struct {
    char data[];  // Variable length, \0 terminated
} ps_string_t;

// Example layout in memory:
// 0xF8008100: "moveto\0"    (7 bytes)
// 0xF8008107: "lineto\0"    (7 bytes)
// 0xF800810E: "curveto\0"   (8 bytes)
// 0xF8008116: "closepath\0" (10 bytes)
```

**Alignment**: Strings appear to be packed (no alignment padding between strings).

---

## Operator Dispatch Table

### Hypothetical Structure

Based on NDserver analysis showing 28 operators and typical dispatch table patterns:

```c
#define PS_OPERATOR_COUNT 28

typedef struct ps_operator_entry {
    // String identification
    const char*  name;           // Pointer to name in string table (4 bytes)
    uint8_t      opcode;         // 0-27 (1 byte)
    uint8_t      category;       // PATH, GFX_STATE, PAINT, COLOR, CONTROL (1 byte)
    uint16_t     flags;          // Operational flags (2 bytes)

    // Handler function
    void*        handler;        // Function pointer in Section 03 (4 bytes)

    // Stack operations
    int8_t       operand_count;  // Negative = variable args (1 byte)
    int8_t       result_count;   // Negative = variable results (1 byte)
    uint8_t      operand_types[8]; // Type constraints (8 bytes)

    // Rendering metadata
    uint16_t     affects_state;  // Bitmask of state components modified (2 bytes)
    uint16_t     invalidates;    // What gets invalidated (bbox, cache, etc.) (2 bytes)

    // Reserved for future use
    uint32_t     reserved[2];    // Padding/extension (8 bytes)
} ps_operator_entry_t;

// Total: 36 bytes per entry
// 28 entries × 36 bytes = 1,008 bytes
```

### Estimated Location

**Address Range**: 0xF800A000 - 0xF800A3FF (1 KB, with room for expansion)

### Entry Size Analysis

Possible sizes:
- **Minimal (20 bytes)**: name ptr (4) + handler ptr (4) + opcode (1) + operand_count (1) + padding (10)
- **Standard (36 bytes)**: Full metadata as shown above
- **Extended (48-64 bytes)**: Additional rendering hints, optimization flags

**Verification needed**: Disassemble Section 03 to find table access patterns.

---

## PostScript Initialization Code

### Purpose

Executed once at firmware startup to configure the PostScript interpreter environment.

### Complete Snippet Collection

```postscript
% ============================================================================
% PATH ABBREVIATION MACROS
% ============================================================================
% Single-letter abbreviations for common path operators
/m { moveto } def
/l { lineto } def
/c { curveto } def

% Compound path operators
/v { currentpoint 6 2 roll curveto } def    % Current point + 4 control points
/y { 2 copy curveto } def                    % Duplicate last 2 coords as start

% Path list (pl) operators - operate on path data structures
pl moveto     % Apply moveto to path list
pl lineto     % Apply lineto to path list
pl curveto    % Apply curveto to path list
pl 2 copy curveto  % Duplicate and curve

% ============================================================================
% CLIPPING STATE MANAGEMENT
% ============================================================================
/_doClip 0 ddef    % Clipping disabled
/_doClip 1 ddef    % Clipping enabled

% Deferred clipping - only clip if flag is set
_doClip 1 eq {clip /_doClip 0 ddef} if

% ============================================================================
% RENDERING MODE DISPATCH
% ============================================================================
% CRender abstraction allows changing rendering strategy
/CRender {S} ddef    % Strategy: Stroke only
/CRender {F} ddef    % Strategy: Fill only
/CRender {N} ddef    % Strategy: No-op (path construction only)
/CRender {B} ddef    % Strategy: Both stroke and fill

% ============================================================================
% GRAPHICS STATE PRESERVATION WRAPPERS
% ============================================================================
% Stroke with automatic state save/restore
gsave _ps grestore clip newpath /_lp /none ddef _sc

% Fill with automatic state save/restore
gsave _pf grestore clip newpath /_lp /none ddef _fc

% Stroke + clip (for windowing operations)
gsave S grestore clip newpath /_doClip 0 ddef _sc

% Fill + clip (for masked fills)
gsave F grestore clip newpath /_lp /none ddef _fc

% ============================================================================
% STATE VARIABLE INITIALIZATION
% ============================================================================
/_pola 0 eq         % Polarity flag (0 = normal, 1 = inverted)
/_lp /none ddef     % Last path (for caching/optimization)
/_sc                % Stroke color cache
/_fc                % Fill color cache
/_ps                % Path stroke state snapshot
/_pf                % Path fill state snapshot
ad def              % Array definition utility

% ============================================================================
% VALIDATION AND TYPE CHECKING
% ============================================================================
count 0 ne          % Check stack not empty
dup 0 eq            % Check for zero value
dup type (string) eq % Check if value is string

% ============================================================================
% GRAPHICS STATE OPERATORS WITH ABBREVIATED NAMES
% ============================================================================
% These map single-letter codes to full operator names
% Used for compact binary encoding from host

% B = Both (stroke and fill)
% F = Fill
% H = ? (horizontal line?)
% N = No-op (path only, no rendering)
% S = Stroke
% W = ? (winding rule?)
% b = ? (begin path?)
% f = fill (lowercase variant)
% h = ? (close path, from PDF 'h')
% n = newpath (lowercase variant)
% s = stroke (lowercase variant)

% Path painting operators (PDF compatibility layer?)
% - [string] * -   String rendering
% - cf flatness    Set curve flatness
% array phase d -  Set dash pattern
% flatness i -     Set flatness (integer)
% linecap J -      Set line cap style
% linejoin j -     Set line join style
% linewidth w -    Set line width
% miterlimit M -   Set miter limit

% Path construction shortcuts
% x y m -          Moveto with abbreviated syntax
% x y l -          Lineto with abbreviated syntax
% x1 y1 x2 y2 y -  Curveto with abbreviated syntax
```

### Initialization Sequence (Hypothetical)

```c
// Called by Section 03 during firmware init
void init_postscript_environment(void) {
    // 1. Load PostScript init code from Section 02
    const char* ps_init_code = (const char*)0xF800B000;  // Estimated
    size_t code_length = 4096;  // Estimated

    // 2. Execute initialization snippets
    // This defines /m, /l, /c, /_doClip, /CRender, etc.
    ps_interpreter_eval(ps_init_code, code_length);

    // 3. PostScript environment now ready
    // Host can send commands using abbreviated operators
}
```

---

## Graphics State Defaults

### Default Values (PostScript/Display PS Standard)

```c
typedef struct graphics_state_defaults {
    // Line style
    float    linewidth;      // 1.0 (1 device unit)
    uint8_t  linecap;        // 0 (butt)
    uint8_t  linejoin;       // 0 (miter)
    float    miterlimit;     // 10.0
    float    flatness;       // 1.0 (device-dependent)

    // Dash pattern
    float    dash_array[16]; // [0] = solid line
    uint8_t  dash_count;     // 0
    float    dash_phase;     // 0.0

    // Color (grayscale default)
    float    gray;           // 0.0 (black)

    // Transformation matrix (identity)
    float    ctm[6];         // [1, 0, 0, 1, 0, 0]

    // Clipping (whole page)
    // (defined by bounding box, not stored here)

    // Font (none initially)
    void*    current_font;   // NULL

    // Reserved
    uint8_t  reserved[64];
} graphics_state_defaults_t;

// Size: ~256 bytes (with padding)
```

### Estimated Location

**Address Range**: 0xF800C000 - 0xF800C0FF (256 bytes)

### Binary Layout (Hypothetical)

```
Offset  Size  Field
------  ----  -----
+0x00   4     linewidth (float32, 1.0)
+0x04   1     linecap (uint8, 0)
+0x05   1     linejoin (uint8, 0)
+0x06   2     padding
+0x08   4     miterlimit (float32, 10.0)
+0x0C   4     flatness (float32, 1.0)
+0x10   64    dash_array (16× float32, all 0)
+0x50   1     dash_count (uint8, 0)
+0x51   3     padding
+0x54   4     dash_phase (float32, 0.0)
+0x58   4     gray (float32, 0.0)
+0x5C   24    ctm (6× float32, identity matrix)
+0x74   4     current_font (ptr, NULL)
+0x78   8     reserved
```

---

## Path Encoding Structures

### Compact Binary Path Format

PostScript paths can be encoded compactly for efficient storage and transmission.

#### Standard PostScript (Text Encoding)

```postscript
100 200 moveto
150 200 lineto
150 250 lineto
100 250 lineto
closepath
stroke
```

**Size**: ~140 bytes as ASCII text

#### Compact Binary Encoding (Type 1)

```c
// Command-based encoding
typedef struct path_command {
    uint8_t  opcode;      // 0=moveto, 1=lineto, 2=curveto, 3=closepath
    uint8_t  reserved;    // Alignment
    int16_t  coords[6];   // Coordinates (up to 6 for curveto)
} path_command_t;

// Same rectangle as 5 commands × 16 bytes = 80 bytes
```

**Size**: 80 bytes (1.75× reduction)

#### Compact Binary Encoding (Type 2 - Variable Length)

```c
// Variable-length encoding with packed coordinates
typedef struct {
    uint8_t opcode : 4;      // 0-15 (16 opcodes)
    uint8_t coord_size : 2;  // 0=none, 1=8bit, 2=16bit, 3=32bit
    uint8_t coord_count : 2; // 0-3 (scaled: 0, 2, 4, 6 coords)
    // Followed by variable-length coordinate data
} packed_path_command_t;

// Same rectangle with 8-bit coords (relative):
// moveto 100,200:  [0x11] [100] [200]           = 3 bytes
// lineto  50,  0:  [0x15] [ 50] [  0]           = 3 bytes
// lineto   0, 50:  [0x15] [  0] [ 50]           = 3 bytes
// lineto -50,  0:  [0x15] [-50] [  0]           = 3 bytes
// closepath:       [0x30]                       = 1 byte
// Total: 13 bytes (10.8× reduction!)
```

**Size**: 13 bytes

### Pre-defined Primitives

Section 02 may contain pre-encoded common shapes:

```c
typedef struct primitive_path {
    uint16_t  primitive_id;   // 0=rect, 1=rrect, 2=ellipse, 3=circle, ...
    uint16_t  param_count;    // Number of parameters
    float     params[8];      // Parameters (x, y, w, h, radius, etc.)
} primitive_path_t;

// Examples:
// Rectangle:  {PRIM_RECT, 4, {x, y, width, height}}            = 20 bytes
// RRect:      {PRIM_RRECT, 5, {x, y, width, height, radius}}   = 24 bytes
// Circle:     {PRIM_CIRCLE, 3, {cx, cy, radius}}               = 16 bytes
// Ellipse:    {PRIM_ELLIPSE, 4, {cx, cy, rx, ry}}              = 20 bytes
```

**Advantage**: Even more compact than binary commands, and can be rendered with optimized hardware-specific code.

---

## Alignment and Padding

### Observed Patterns

1. **20.6% zero bytes** suggests 4-byte or 8-byte alignment padding
2. **No empty 1KB chunks** indicates dense packing with strategic padding
3. **String table** likely byte-aligned (packed)
4. **Operator table** likely 4-byte or 8-byte aligned (for pointer access)
5. **Float arrays** (graphics state defaults) likely 4-byte aligned

### Hypothetical Memory Map with Alignment

```
Address Range          Size    Alignment  Content
---------------------  ------  ---------  -------
0xF8008000-0xF80087FF  2 KB    1-byte     String table (packed)
0xF8008800-0xF8008FFF  2 KB    -          Padding
0xF8009000-0xF80093FF  1 KB    4-byte     Operator dispatch table
0xF8009400-0xF80097FF  1 KB    -          Padding
0xF8009800-0xF800BFFF  10 KB   1-byte     PostScript init snippets
0xF800C000-0xF800C0FF  256 B   4-byte     Graphics state defaults
0xF800C100-0xF800CFFF  ~4 KB   -          Padding
0xF800D000-0xF800EFFF  8 KB    4-byte     Path primitives & macros
0xF800F000-0xF800FFFF  4 KB    -          Reserved/unused
```

---

## Cross-References to Section 03

### Expected Access Patterns

Section 03 code will access Section 02 data via:

1. **Global pointers loaded at init**:
   ```c
   const ps_operator_entry_t* g_op_table = (ps_operator_entry_t*)0xF8009000;
   ```

2. **Indexed lookups**:
   ```c
   ps_operator_entry_t* op = &g_op_table[opcode];
   void (*handler)(void) = op->handler;
   handler();
   ```

3. **String comparisons** (if operator lookup by name):
   ```c
   for (int i = 0; i < 28; i++) {
       if (strcmp(name, g_op_table[i].name) == 0) {
           return g_op_table[i].handler;
       }
   }
   ```

4. **Direct address loads**:
   ```asm
   ; Load operator table base
   orh   0xF800, %r0, %r20        ; High 16 bits
   or    0x9000, %r20, %r20       ; Low 16 bits (0xF8009000)

   ; Index into table (opcode in %r16)
   shl   %r16, 5, %r17            ; Multiply by 32 (assuming 32-byte entries)
   addu  %r17, %r20, %r17         ; Add to base

   ; Load handler pointer (offset +8)
   ld.l  8(%r17), %r2             ; Load handler address
   bri   %r2                       ; Jump to handler
   ```

### Verification Strategy

Once Section 03 is disassembled, search for:
- Loads from 0xF8008xxx-0xF800Fxxx range
- Pointer arithmetic with these addresses
- Indirect branches using loaded addresses
- String comparison loops

---

## Analysis Tools and Scripts

### Binary Structure Parser

```python
#!/usr/bin/env python3
"""Parse Section 02 data structures"""

import struct
from pathlib import Path

def find_pointers(data, min_addr=0xF8008000, max_addr=0xF800FFFF):
    """Find potential pointers to Section 02 addresses"""
    pointers = []
    for i in range(0, len(data)-4, 4):
        ptr = struct.unpack('>I', data[i:i+4])[0]
        if min_addr <= ptr <= max_addr:
            pointers.append((i, ptr))
    return pointers

def find_strings(data):
    """Extract null-terminated strings"""
    strings = []
    current = bytearray()
    offset = 0

    for i, byte in enumerate(data):
        if byte == 0:
            if len(current) >= 4:  # Min 4 chars
                try:
                    s = current.decode('ascii')
                    strings.append((offset, s))
                except:
                    pass
            current = bytearray()
            offset = i + 1
        elif 32 <= byte <= 126:  # Printable ASCII
            current.append(byte)
        else:
            current = bytearray()
            offset = i + 1

    return strings

def analyze_section_02(filename):
    data = Path(filename).read_bytes()

    print("=== Section 02 Binary Analysis ===")
    print(f"Total size: {len(data)} bytes\n")

    # Find pointers
    pointers = find_pointers(data)
    print(f"Found {len(pointers)} potential pointers:")
    for offset, ptr in pointers[:20]:  # Show first 20
        print(f"  Offset 0x{offset:04x}: -> 0x{ptr:08x}")
    print()

    # Find strings
    strings = find_strings(data)
    print(f"Found {len(strings)} strings:")
    for offset, s in sorted(strings, key=lambda x: len(x[1]), reverse=True)[:30]:
        print(f"  Offset 0x{offset:04x}: '{s}'")

if __name__ == '__main__':
    analyze_section_02('02_postscript_operators.bin')
```

### Run Analysis

```bash
cd /Users/jvindahl/Development/nextdimension/firmware_clean
python3 02_parse_structures.py
```

---

## Next Steps

1. **Run binary structure parser** to locate:
   - Operator table boundaries
   - String table layout
   - PostScript snippet locations

2. **Disassemble Section 03** to find:
   - Data access patterns
   - Operator handler addresses
   - String comparison code

3. **Cross-reference findings**:
   - Match handler addresses to Section 03 functions
   - Verify operator table structure
   - Confirm PostScript init execution

4. **Document final structure**:
   - Create definitive memory map
   - Write C header file for data structures
   - Generate Rust bindings for re-implementation

---

**Status**: Structure hypothesized, awaiting binary analysis confirmation
**Next**: Parse binary structures, cross-reference with Section 03
**Confidence**: High (PostScript strings are definitive, table structure is standard)
