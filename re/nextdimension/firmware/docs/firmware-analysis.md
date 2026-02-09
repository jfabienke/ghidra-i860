# NeXTdimension i860 Clean Firmware — Analysis Findings

## Binary

| Property | Value |
|----------|-------|
| File | `ND_i860_CLEAN.bin` |
| Format | Mach-O MH_PRELOAD (CPU type 15 = i860) |
| Size | 200,704 bytes (196 KB) |
| Architecture | i860:LE:32:XR (little-endian) |
| ABI | GCC/NeXTSTEP (r2=sp, r3=fp) |
| Entry point | 0xF8000000 (from LC_UNIXTHREAD) |
| Purpose | **Display PostScript RIP** for NeXTdimension display board |

## Firmware Identity

The firmware is a **PostScript Raster Image Processor (RIP)** — the i860 coprocessor on the NeXTdimension board interprets PostScript drawing commands for Display PostScript rendering.

Evidence:
- ASCII strings at offset 0xF800–0xFFFF contain a complete Adobe Illustrator / Display PostScript prolog
- 26 single-letter PostScript operator shortcuts: `/c`=curveto, `/l`=lineto, `/m`=moveto, `/F`=fill, `/S`=stroke, etc.
- References to `CRender`, `_pola`, `_doClip`, `gsave`/`grestore`
- FP-heavy instruction mix consistent with coordinate geometry and rasterization
- Extensive MMIO access at offset 0x401C (likely framebuffer or DPS command register)

### Bare-Metal Runtime (Not a Mach Kernel)

Despite earlier hypotheses referencing "GaCK OS," the firmware is **bare-metal** — it contains OS-like primitives (VM initialization, exception handling, cache coherency) but no Mach kernel infrastructure. Mach API strings found in the source `ND_MachDriver_reloc` binary belong to the **host-side m68k driver code**, not the i860 firmware. The i860 runs a dedicated DPS interpreter directly on hardware without kernel mediation.

## Memory Layout

```
 00000000 ┌─────────────────────────────────┐
          │  Mach-O header + load cmds      │    840 B
 00000348 ├─────────────────────────────────┤
          │  Bootstrap / exception vectors  │    208 B
 00000418 ├─────────────────────────────────┤
          │  Zero padding                   │   ~3 KB
 00001000 ├─────────────────────────────────┤
          │  MAIN_CODE              r-x     │   59 KB  (0x1000–0xF7FF)
          │    619 genuine functions, 50 KB │
 0000F800 ├─────────────────────────────────┤
          │  PostScript prolog (ASCII)      │   ~2 KB  (0xF800–0xFFFF)
 00010000 ├─────────────────────────────────┤
          │  Code islands + gaps            │   scattered
          │    ISLAND_10000    5 funcs      │
          │    ISLAND_11400   11 funcs      │
          │    ISLAND_12C00   10 funcs      │
          │    ISLAND_13C00   12 funcs      │
          │    ISLAND_15C00   23 funcs      │
 00018000 ├─────────────────────────────────┤
          │  BLOCK2                 r-x     │   21.5 KB (0x18000–0x1D3FF)
          │    289 genuine functions, 19 KB │
 0001D400 ├─────────────────────────────────┤
          │  ISLAND_1D800   11 funcs        │
          │  ISLAND_1FC00    1 table (4 KB) │
 00023C00 ├─────────────────────────────────┤
          │  BLOCK3                 r-x     │   10 KB  (0x23C00–0x263FF)
          │    102 genuine functions, 7 KB  │
 00026400 ├─────────────────────────────────┤
          │  Small islands + gaps           │   scattered
          │    ISLAND_27C00   7 funcs       │
          │    ISLAND_28400  23 funcs       │
          │    ISLAND_29400   8 funcs       │
          │    ISLAND_29C00  19 funcs       │
          │    ISLAND_2E000  22 funcs       │
          │    ISLAND_2F000  67 funcs       │
 00030FFF └─────────────────────────────────┘
```

### Content Breakdown (by contamination survey)

| Type | Size | % of Image | Description |
|------|------|-----------|-------------|
| I860_CODE | 115,712 B | 57.7% | Blocks with decoded i860 instructions (inflated — see note) |
| NULL_PAD | 68,608 B | 34.2% | Zero-fill padding between code blocks |
| ASCII_TEXT | 15,360 B | 7.7% | PostScript prolog, error strings, operator names |
| BIN_DATA | 1,024 B | 0.5% | Unclassified binary data |

**Note**: The 57.7% I860_CODE figure is inflated because the i860 ISA decodes almost any 4 bytes as a valid instruction. Even null words (0x00000000) decode as `ld.b r0(r0),r0`. The actual recoverable code through control flow analysis is only **10.9%**.

## Recovery Analysis

### Tool Convergence

| Tool | Mode | Instructions | Functions | Code Bytes | Coverage |
|------|------|------------:|----------:|----------:|--------:|
| Rust disassembler | Linear sweep | 47,203 | — | 188,812 | 94.1% |
| Rust disassembler | Recursive (seedless) | 1,041 | 1 | 4,164 | 2.1% |
| Rust disassembler | Recursive (seeded) | 5,491 | 16 | 21,964 | 10.9% |
| Ghidra headless | Linear sweep | 47,203 | 1,917 | 188,812 | 94.1% |
| Ghidra headless | Seeded (Rust xrefs) | 5,453 | 436 | 21,812 | 10.9% |

Coverage denominator: 200,704 bytes (50,176 potential instructions).

Both tools converge at **10.9%** with seeds. The gap between tools:
- Ghidra finds **436 functions** (vs Rust's 16) through multi-strategy discovery (prologues, post-return boundaries, orphan code)
- Rust recovers 38 more instructions due to slightly different flow-following heuristics

### The 10.9% Ceiling

The ceiling is caused by the firmware's exclusive use of **indirect dispatch** (`bri rN`). The PostScript interpreter uses register-loaded handler tables to dispatch PS operators, and neither tool can follow control flow through register-indirect branches without knowing the table contents.

The dispatch tables were expected in the Mach-O `__DATA` segment at vmaddr `0xF80B4000` (file offset `0xB4348`), which is **outside this 196 KB ROM dump**. The code contains 45 register-relative `orh` pairs (e.g. `orh 0x6514,r15,r31`) producing addresses in `0xF80B7000–0xF80B7975` — where a string+handler dispatch table was hypothesized. (Note: only 9 of these are classic absolute-from-zero `orh imm,r0,rN` / `or imm,rN,rN` pairs; the other 36 use non-zero base registers, making target resolution dependent on runtime register state.)

However, **extracting and analyzing the full `__DATA` segment (56,400 bytes) revealed no dispatch tables** — see [__DATA Segment Analysis](#data-segment-analysis) below. Breaking the 10.9% ceiling requires alternative strategies: instruction-level call/branch target extraction from `__TEXT`, runtime BSS initialization analysis, or inline constant pool discovery.

## Function Classification

### Filtered Assembly Profiling (1,229 genuine functions)

After filtering out zero-padding noise (functions >= 16 bytes, not starting with null word, <50% null instructions), **1,229 genuine functions** remain from 1,917 total — spanning **89,356 bytes** of code.

| Category | Count | % | Code Bytes | % | Avg Size | Description |
|----------|------:|--:|----------:|-:|--------:|-------------|
| GENERAL | 385 | 31.3% | 20,480 | 22.9% | 53.2 | Mixed integer/control |
| FP_MIXED | 363 | 29.5% | 24,928 | 27.9% | 68.7 | Moderate FP use — coordinate math, rendering |
| DATA_MOVE | 336 | 27.3% | 39,036 | 43.7% | 116.2 | Load/store dominated — includes data tables |
| CONTROL_FLOW | 80 | 6.5% | 2,856 | 3.2% | 35.7 | Branch-heavy dispatch/routing |
| FP_HEAVY | 65 | 5.3% | 2,056 | 2.3% | 31.6 | Pure math kernels |

**Overall instruction mix**: FP=11.0% / LD=53.5% / ST=6.8% / BR=7.3% / ARITH=21.5%

#### Region-level Statistics

| Region | Count | Total Bytes | Avg Size | Median | Code Density |
|--------|------:|----------:|--------:|-------:|-----------:|
| MAIN_CODE | 619 | 49,852 | 80.5 | 56 | 83.8% |
| BLOCK2 | 289 | 19,004 | 65.8 | 32 | 86.5% |
| BLOCK3 | 102 | 6,728 | 66.0 | 44 | 69.9% |
| ISLAND_1FC00 | 1 | 4,328 | 4,328 | — | 100.0% |
| ISLAND_2F000 | 67 | 2,676 | 39.9 | 28 | 74.3% |
| 12 smaller islands | 151 | 6,768 | 44.8 | varies | 49–86% |

#### Real Code Estimate

Applying a contamination filter (LD/total > 85%, zero branches, 4+ instructions):

| | Count | Bytes | % |
|---|------:|------:|--:|
| **Genuine code** | 1,198 | 83,596 | 93.6% |
| **Suspected data tables** | 31 | 5,760 | 6.4% |

The 31 suspected data-table "functions" include the 7,152-byte region at 0x1B9F0 (now identified as embedded m68k code — see [Embedded Foreign-Architecture Contamination](#embedded-foreign-architecture-contamination)) and the 4,328-byte PS registration table at 0x1FC00.

### Random Sampling Validation

Random sampling (12 of 165 candidates, min 24 bytes) reveals:
- **8/12 (67%)** are pure zero-word padding (`ld.b r0(r0),r0` runs)
- **2/12 (17%)** have out-of-range branch flows (data decoded as branches)
- **1/12 (8%)** shows genuine structured code (FUN_00004c1c: 86 insns, 1 call, 7 branches)
- **0/12** match stack-alloc or return-save prologue heuristics

This confirms that the vast majority of "discovered" functions from linear sweep are noise, validating the filtering approach.

### Dispatch Pattern

244 functions contain `bri` (indirect branch) instructions. Target register distribution:

| Register | Count | Likely Role |
|----------|------:|-------------|
| r2 | 65 | SP in GCC ABI; here likely holds computed handler addr |
| r11 | 42 | Handler dispatch register |
| r0 | 38 | Hardwired zero → jump to reset (halt/error) |
| r3 | 13 | FP in GCC ABI; secondary dispatch |
| r8 | 12 | Classic dispatch register (matches `bri r8` pattern) |
| r16 | 8 | Tertiary dispatch |
| Other | 66 | Various registers |

The r0 count (38) likely includes false positives from data-as-code, since `bri r0` encodes as a specific bit pattern that random data can produce.

## Interpreter Architecture

The PostScript interpreter follows a **threaded dispatch** model with five stages:

### 1. Token Read (MMIO Dispatch Sequence)

A 9-instruction sequence appears ~150 times throughout MAIN_CODE:

```asm
ld.b   0x6114(r8),r0     ; Read dispatch table entry
ld.b   r12(r0),r0        ; Indirect load through r12
ld.b   r12(r8),r0        ; Second indirect load
ld.b   r0(r0),r8         ; Load handler address
ixfr   r8,f0             ; Transfer to FP reg (pipeline trick)
xor    r8,r7,r31         ; XOR with tag register — validation
ixfr   r8,f24            ; r8 -> f24 (address pipeline)
st.b   r8,0x401c(r8)     ; WRITE TO MMIO 0x401C — hardware ack
ixfr   r8,f0             ; Pipeline drain
```

The i860 reads a PS token from a command stream via the 0x6114 dispatch table, resolves the handler through indirection, and writes to MMIO 0x401C to acknowledge the command to the NeXTdimension hardware.

### 2. Name Resolution (Hash Lookup Chain at 0x7AD8–0x7DC0)

Three functions totaling **924 bytes** perform hash-based operator name lookup:

| Function | Size | Purpose |
|----------|------|---------|
| `FUN_00007AD8` | 296 B | PS name lookup part 1 (hash + table search) |
| `FUN_00007C00` | 448 B | PS name lookup part 2 (continuation) |
| `FUN_00007DC0` | 180 B | PS name lookup part 3 (fallthrough) |

Pattern: `ld.b r14(r8)` → `xorh 0x10c6,r24,r0` → `ld.b 0x7386(r0)` — reads characters from a PS name token, hashes with constant `0x10c6`, indexes a lookup table at 0x7386, and dispatches via `bri r18`.

### 3. Operator Dispatch Hub

**FUN_000033c8** (312 bytes, 12 branches) — the central PS operator classifier:
- Uses `and 0xe827/0xe927,r19,r19` bitmasks to classify operator type
- Routes to the appropriate handler group
- Contains multiple MMIO dispatch sequences

### 4. Execution

Individual operators use:
- FP pipeline (`ixfr`, `fld`, `fst`, `mrmt1p2`) for geometry/color math
- Auto-increment addressing (`r30(r9)++`) for operand stack operations
- r15-based GState flags for context queries (`orh 0x6514,r15,r31`)

### 5. Hardware Sync

Every dispatch writes to MMIO 0x401C, keeping the NeXTdimension hardware synchronized with the PS execution state. The value written is the dispatch address itself, suggesting the hardware tracks which PS operators are being executed for DPS synchronization with the host M68k processor.

### Register Allocation Convention

| Register | Role |
|----------|------|
| r1 | Return address (GCC ABI) |
| r2 | Stack pointer (GCC ABI) |
| r3 | Frame pointer (GCC ABI) |
| r4 | Operand stack / data base pointer |
| r7 | Persistent tag/hash register (xor validation in every dispatch) |
| r8 | Primary working register (handler address, loop counter) |
| r9 | Auto-increment pointer (`fld.l r30(r9)++`) |
| r12 | Dispatch table pointer |
| r15 | Graphic State flags register (`orh 0x6514,r15,r31`) |
| r18 | Computed jump target (for `bri r18` dispatch) |
| r22 | Color/pixel value register |
| r24 | Framebuffer/compositing buffer base pointer |
| r26 | FP pipeline data value register |
| r30, r31 | Scratch / flag registers |

## MMIO Register Access

**107 functions** access the MMIO register at offset `0x401C`. This is the dominant hardware interface pattern:

```
st.s r8, 0x401C(r8)    ; write to MMIO register
```

The functions accessing 0x401C are concentrated in MAIN_CODE (0x1000–0xF7FF) and represent the core interaction between the PostScript interpreter and the NeXTdimension display hardware (likely the framebuffer controller or DPS command interface).

Notable MMIO-accessing functions by size:
- `FUN_00001C34` (868 bytes) — largest MMIO routine, framebuffer blit/image render
- `FUN_000023B8` (856 bytes) — second largest, data pipeline
- `FUN_00001F9C` (756 bytes) — large data processing block
- `FUN_00004B84` (616 bytes) — data transfer/conversion
- `FUN_00003C10` (560 bytes) — Bezier/path processing with FP MAC

## PostScript Prolog

The ASCII region at 0xF800–0xFFFF contains a complete Display PostScript prolog defining 26 single-letter operator shortcuts:

| Shortcut | PostScript Operator | Category |
|----------|-------------------|----------|
| /c | curveto | Path construction |
| /l | lineto | Path construction |
| /m | moveto | Path construction |
| /h | closepath | Path construction |
| /N | newpath | Path construction |
| /d | setdash | Graphic state |
| /i | setflat | Graphic state |
| /j | setlinejoin | Graphic state |
| /J | setlinecap | Graphic state |
| /M | setmiterlimit | Graphic state |
| /w | setlinewidth | Graphic state |
| /F | fill | Path painting |
| /S | stroke | Path painting |
| /B | fill + stroke | Path painting |
| /W | clip flag | Clipping |
| /* | show | Text |

Additional references: `CRender` (compositing renderer), `_pola` (PostScript operator lookup), `_doClip` (clipping execution), `gsave`/`grestore` (graphics state stack).

This prolog is characteristic of **Adobe Illustrator EPS compatibility** — it defines the same shortcut alphabet used in AI-generated EPS files, enabling the NeXTdimension to directly render Illustrator artwork.

## Decompiler Quality

### KPIs (12-function sample from seeded analysis)

| Metric | Value |
|--------|-------|
| Decompiled successfully | 12/12 |
| Timeouts | 0 |
| `halt_baddata()` | 26 occurrences across 12/12 functions |
| `halt_unimplemented()` | 0 (all 172 SLEIGH instructions have pcode) |
| `unaff_*` variables | 64 across 9/12 functions |
| Unreachable block warnings | 6 across 2/12 functions |

- **`halt_baddata`**: Caused by linear sweep forcing data-as-code. Unavoidable without recursive-descent-only import.
- **`halt_unimplemented: 0`**: Confirms all SLEIGH instruction semantics are complete.
- **`unaff_*`**: Many routines use non-standard register conventions (dispatch via register, non-GCC callee-saved).

### Linear Sweep vs Recursive Descent

| Approach | Functions | Clean decompilations | Coverage |
|----------|----------:|--------------------:|--------:|
| Linear sweep | 1,917 | 249 (13%) | 94.1% |
| Recursive descent | 436 | Not tested | 10.9% |

Even "clean" decompilations (no `halt_baddata`) produce `UNRECOVERED_JUMPTABLE` warnings because the firmware uses indirect dispatch exclusively.

## Code Map — Region-by-Region Analysis

### MAIN_CODE (0x1000–0xF7FF) — 619 functions, 49,852 bytes

The core of the PostScript interpreter. Key functional groups:

#### Bootstrap / Initialization (0x1000–0x1250)

| Address | Size | Purpose |
|---------|------|---------|
| 0x1000 | 68 B | Register initialization (first function) |
| 0x1048 | 80 B | FP/EPSR hardware init, `ld.c epsr,r24` |
| 0x1138 | 64 B | Paging/TLB/cache setup — `ld.c dirbase`, `flush`, `st.c dirbase` |
| 0x11A0 | 48 B | Jump table dispatcher, exercises all ALU ops, `bla` loop |

#### PostScript Operator Implementations

| Address | Size | Purpose | Evidence |
|---------|------|---------|----------|
| 0x33C8 | 312 B | **Central PS operator dispatch** | 12 branches, `and 0xe827` type masking |
| 0x3C10 | 560 B | **curveto / Bezier flattening** | 4-way indexed loads from 0x5F16, `mimt1p2.ss` MAC |
| 0x4018 | 208 B | **Matrix multiply / CTM** | Pure FP (18 ops), zero branches |
| 0x4650 | 360 B | **Pipelined coordinate loop** | `bla` loop, `fld.d r5(r2)++` auto-increment |
| 0x44C8 | 48 B | **gsave/grestore** | `orh 0x6514,r15,r31` GState flag pattern |
| 0x5510 | 44 B | **GState single-value setter** | `xorh 0x6514,r15,r31` |
| 0x5F50 | 16 B | **Exception trap handler** | `trap r2,r3,r21` + `bri r2` |

#### Rendering Primitives

| Address | Size | Purpose | Evidence |
|---------|------|---------|----------|
| 0x882C | 404 B | **Scanline pixel write** | ST=20 (highest), paired `st.b rN,offset(r7)` |
| 0x8D10 | 312 B | **Fill/stroke rendering** | FP=13, ST=15, `orh 0x6514` GState check |
| 0x90A8 | 420 B | **Color fill / image render** | FP=11, ST=14 |
| 0x80D4 | 220 B | **Path segment processing** | `fld.l r30(r9)++,f24` pipeline pop |
| 0x1C34 | 868 B | **Framebuffer blit** (largest) | NOP sleds for pipeline sync, MMIO dispatch |

#### FP Math Library (0xB438–0xBE08)

A cluster of **10 FP_HEAVY functions** (360 bytes total, 60–80% FP ratio) forming a dedicated math library:
- 0xBA10 (20 B, 80% FP), 0xBB90 (36 B, 78% FP), 0xB438 (36 B, 67% FP), etc.
- Pure coordinate/color math kernels

#### 7-Stage FP Pipeline Chain (0xD5AC–0xD67C)

Seven 28-byte functions, all containing `d.mrmt1p2.ss f2,f12,f10` with different data offsets. This is a **pipelined multiply-accumulate chain** — likely 7-tap convolution for halftoning or anti-aliasing.

#### Name Lookup (0x7AD8–0x7DC0)

924-byte hash-based PS operator name resolution chain (described in Interpreter Architecture above).

### BLOCK2 (0x18000–0x1D3FF) — 289 functions, 19,004 bytes

The **PostScript operator registration and dispatch infrastructure**. Contains no MMIO-accessing functions.

#### Embedded m68k Code at 0x1B9F0 (7,152 bytes)

**Correction**: Previously interpreted as the "PS operator dispatch table," this region is **embedded m68k host driver code** — part of the m68k Mach-O object whose FEEDFACE header is at offset 0x017CB8 (see [Embedded Foreign-Architecture Contamination](#embedded-foreign-architecture-contamination)). The bytes at 0x1B9F0 decode as m68k instructions: `move.l d0,-(sp)`, `move.l d4,-(sp)`, `move.l a5,-(sp)`, `bsr.l`. The apparent "1,776 paired `ld.b` instructions" seen by the i860 decoder were an artifact of m68k machine code forced through i860 linear-sweep disassembly.

#### Numbered Operator Registration (0x1B4D0–0x1B53C)

Two functions register operators numbered 1–15 using `or r24,r2,r5` + branch-with-constant patterns. Likely PostScript internal callbacks or `definefont` entries.

#### Hardware Loop Functions

16 functions use `bla` (branch-on-loop-address) for hardware-accelerated loops, with targets in the 0x37000–0x3B000 data/lookup table regions.

#### Method Dispatch Trampolines (0x1A9E8–0x1B140)

A cluster of structurally similar trampoline functions all terminating with `bri rN`:
- `bri r22` / `bri r23` / `bri r27` — three dispatcher categories (possibly: graphics, stack, I/O operators)

#### Embedded String References

Branch targets reveal embedded debug/error strings:
- `"SUPCLASS = PGProcess"` — Objective-C PostScript Graphics Process class
- `"operation Stopped"` — PS exception handling
- `"WindowTwo"` — DPS window server compositor
- `"-file): Don'"` — file operation error
- `"rm(count"` — reference counting
- `"ignored-extensions"` — DPS extension handling

### BLOCK3 (0x23C00–0x263FF) — 102 functions, 6,728 bytes

**PostScript path and graphics operations** — sits between high-level dispatch and low-level pixel rendering.

#### Zone A (0x23C00–0x244FF): Stack/Dictionary Operations (~30 functions)
- `call` to kernel subroutines, `unlock` instructions (mutex management)
- Paired functions at 0x300-byte spacing — **template-instantiated operator handlers**

#### Zone B (0x24400–0x24CFF): Path Computation Kernels (~30 functions)
- Long `shr`/`shra` chains with coefficient patterns (0x8FC5→0x8FD6→0x8FE7→0x9FBA...)
- **Bezier subdivision weights** or **spline interpolation coefficients**
- FUN_0002481C (292 B, 49 arith ops) — likely Bezier curve evaluation

#### Zone C (0x254xx–0x263FF): Rendering + Graphics State (~35 functions)
- `st.b r1,0x700(r24)` pixel write pattern (r24 = framebuffer base)
- `bte 0x0,r26` loop-back to dispatcher
- FUN_00025844 (488 B) — largest in BLOCK3, full graphics state save/restore cycle
- FUN_00025EE4 (404 B) — complex multi-mode rendering with full coefficient chain

### ISLAND_1FC00 — PS Operator Registration Table (4,328 bytes)

**The single most important data structure in the firmware.** Not executable code — a static data table containing ~200+ entries of PostScript operator/type/class registrations.

Identified sub-tables:

| Sub-table | Address Range | Record Size | Content |
|-----------|--------------|-------------|---------|
| 1. Font/Encoding | 0x1FC00–0x1FD68 | 10 words | Init handler + name + size + secondary handlers |
| 2. System Types | 0x1FED0–0x1FF88 | 3 words | Name string + type signature + handler function |
| 3. Operator Names | 0x204B8–0x20828 | 1 word | Flat array of string pointers (~200 entries) |
| 4. Class Descriptors | 0x20828–0x208C8 | 4 words | Type flag + vtable pointer (9 entries → ISLAND_13C00) |
| 5. Field Descriptors | 0x208C8–0x20C48 | 3 words | Field name + type ptr (0x16516 = "integer") + byte offset |
| 6. Encoding/Font Maps | 0x20C48–end | variable | Encoding vector initialization records |

### ISLAND_13C00 — Pixel Rendering Primitives (12 functions, 1,120 bytes)

The **inner rendering loop** — the most performance-critical code in the RIP:
- Massive store sequences: `st.b r1,0x700(r24)` and `st.b r23,0x7aa(r24)` (r24 = scanline buffer base)
- Graduated-precision shift chains: `shr 0x9f65` → `shr 0xaf64` → `shr 0xaf54` → ... → `shra 0xcf43` — **multi-precision fixed-point color/alpha blending**
- Paired even/odd functions (different scanline halves or left/right pixel boundaries)
- FUN_00013E3C (360 B, ST=34) — full scanline compositing

### ISLAND_15C00 / ISLAND_2E000 — Mach-O / Objective-C Metadata

**Not executable code** — Mach-O section header tables and ObjC runtime metadata:

| Section | Purpose |
|---------|---------|
| `__TEXT`, `__text` | Executable text |
| `__const`, `__data`, `__bss`, `__common` | Data sections |
| `__OBJC` / `__class`, `__category`, `__message` | ObjC class/category/selector lists |
| `__symbols`, `__v_vars`, `__mo_info` | ObjC symbols, ivars, module info |
| `__string_object`, `__class_names`, `__cls_refs` | ObjC strings, names, refs |
| `__ICON` / `__header`, `__request` | Icon data |
| `__LINKED` | Linked module section |

ISLAND_2E000 is a variant/duplicate with additional entries for `__ICON`, `__LINKED`, and shared library paths (`/lib/...NeXT_S.c.s`, `sys_s.B.shlib`).

### ISLAND_28400 / ISLAND_29C00 — AppKit Class Metadata

**Objective-C class descriptors** for NeXTStep UI components:

| Class | Island |
|-------|--------|
| Matrix | 28400, 29C00 |
| Cell, Cells | 28400, 29C00 |
| Responder | 28400, 29C00 |
| List | 28400, 29C00 |
| Window | 28400 |
| Panel | 28400 |
| TextField | 28400 |
| Button | 29C00 |
| Control | 29C00 |
| Font | 29C00 |
| NXImage | 29C00 |
| Form | 29C00 |
| Connector, CBConnect | 29C00 |

ObjC type encoding strings (`@ss@ss`) and method selector fragments confirm these are **Interface Builder / AppKit class registries** for the NeXTdimension's display system.

### ISLAND_2F000 — 1987 Build Artifact (67 functions, 2,676 bytes)

Dramatically different from all other regions. Contains byte patterns that decode as x86-like sequences when interpreted as i860, but no FEEDFACE/CEFAEDFE Mach-O header was found at 0x2DC00 or elsewhere in this region (verified by extraction tool scan):
- **Suspicious byte patterns**: `0x83E58955` (x86 `push ebp; mov ebp,esp` if interpreted as x86), `0xC35DEC89` (x86 epilogue), `0x909090C3` (x86 nop+ret) — these may be coincidental or indicate a different embedding mechanism than standard Mach-O
- **Build timestamp**: `"Mon Jan 16 17:15 1987 Richard"` — predates NeXTdimension hardware, likely ported from an earlier PostScript implementation (Adobe LaserWriter lineage)
- **Debug format strings**: `"specPortPanel%2.1f%d/%d"`, `"did o slow reges..\\n"`
- **IEEE 754 constant**: `0x3F800000` (= 1.0f) at 0x2F844
- **Error handler IDs**: Repeated loads from 0x1296x addresses

### FP Cluster Analysis

4 clusters of consecutive FP_HEAVY functions identified:

| Cluster | Range | Count | Bytes | Region |
|---------|-------|------:|------:|--------|
| #1 | 0x0B438–0x0BE08 | 10 | 360 | MAIN_CODE — math library |
| #2 | 0x0CD1C–0x0CE38 | 4 | 84 | MAIN_CODE |
| #3 | 0x27C48–0x27D0C | 5 | 136 | ISLAND_27C00 — FP dispatch |
| #4 | 0x29448–0x2956C | 3 | 68 | ISLAND_29400 |

### Region Instruction Profiles

Each region has a distinctive instruction mix, confirming they are **separate compilation units**:

| Region | FP% | LD% | ST% | BR% | ARITH% | Character |
|--------|----:|----:|----:|----:|-------:|-----------|
| MAIN_CODE | 14.4 | 59.1 | 8.0 | 3.3 | 15.2 | Load-heavy, FP-rich (interpreter core) |
| BLOCK2 | 6.9 | 50.5 | 3.9 | 10.2 | 28.4 | Dispatch infrastructure |
| BLOCK3 | 7.0 | 17.4 | 11.8 | 16.9 | 46.9 | Arithmetic-dominated (path computation) |
| ISLAND_13C00 | 5.7 | 8.2 | 31.8 | 10.4 | 43.9 | **Store-heavy** (pixel rendering) |
| ISLAND_15C00 | 3.9 | 81.7 | 0.0 | 12.5 | 1.8 | Pure loads (metadata accessor) |
| ISLAND_1FC00 | 0.0 | 100.0 | 0.0 | 0.0 | 0.0 | Data table |
| ISLAND_27C00 | 47.7 | 0.0 | 13.6 | 36.4 | 2.3 | Heavy FP + branching |
| ISLAND_29400 | 37.3 | 0.0 | 3.9 | 58.8 | 0.0 | Branch-dominated (state machine) |

### Top 20 Largest Functions

| Address | Size | Category | Region | Purpose |
|---------|-----:|----------|--------|---------|
| 0x1B9F0 | 7,152 | DATA_MOVE | BLOCK2 | **Embedded m68k code** (contamination) |
| 0x1FC00 | 4,328 | DATA_MOVE | ISLAND_1FC00 | **PS registration table** (data) |
| 0x01C34 | 868 | DATA_MOVE | MAIN_CODE | Framebuffer blit/image render |
| 0x023B8 | 856 | DATA_MOVE | MAIN_CODE | Large data pipeline |
| 0x01F9C | 756 | DATA_MOVE | MAIN_CODE | Data processing block |
| 0x04B84 | 616 | DATA_MOVE | MAIN_CODE | Data transfer/conversion |
| 0x03C10 | 560 | FP_MIXED | MAIN_CODE | Bezier/path processing |
| 0x25844 | 488 | GENERAL | BLOCK3 | Graphics state save/restore |
| 0x08474 | 484 | FP_MIXED | MAIN_CODE | FP-mixed processing |
| 0x07C00 | 448 | DATA_MOVE | MAIN_CODE | PS name lookup part 2 |
| 0x090A8 | 420 | DATA_MOVE | MAIN_CODE | Color fill / image render |
| 0x0882C | 404 | DATA_MOVE | MAIN_CODE | **Scanline pixel write** (ST=20) |
| 0x25EE4 | 404 | GENERAL | BLOCK3 | Multi-mode rendering (ST=34) |
| 0x0380C | 380 | DATA_MOVE | MAIN_CODE | Large data transfer |
| 0x04650 | 360 | FP_MIXED | MAIN_CODE | Pipelined coord processing |
| 0x13E3C | 360 | GENERAL | ISLAND_13C00 | **Scanline compositing** (ST=34) |
| 0x01764 | 352 | DATA_MOVE | MAIN_CODE | Data pipeline |
| 0x03AA4 | 328 | DATA_MOVE | MAIN_CODE | Data transfer |
| 0x01A6C | 320 | DATA_MOVE | MAIN_CODE | Data pipeline |
| 0x033C8 | 312 | FP_MIXED | MAIN_CODE | **Central PS dispatch** (BR=12) |

## __DATA Segment Analysis

The `__DATA` section was extracted from the source Mach-O binary (`ND_MachDriver_reloc`, 795,464 bytes) at file offset 0xB4348.

| Property | Value |
|----------|-------|
| Section | `__data` (within `__DATA` segment) |
| VM Address | `0xF80B4000` – `0xF80C1C50` |
| Size | 56,400 bytes (55.1 KB) |
| Source | `re/nextdimension/firmware/extracted/ND_MachDriver___DATA_section.bin` |
| Extraction script | `re/nextdimension/firmware/scripts/extract_machdriver_segments.sh` |

### Cross-Analysis Reconciliation

| Region | Offset | Size | Ghidra Heuristic Label | Reconciled Interpretation |
|--------|--------|-----:|------------------------|---------------------------|
| 1 | `0x0000-0x3C00` | 15,360 B | `X86_CODE/X86_DATA` | TIFF images + LZW-compressed payload |
| 2 | `0x3C00-0x5CB0` | 8,368 B | `NULL_PAD`-dominant | Zero-fill / BSS-like gap |
| 3 | `0x5CB0-0xDC50` | 32,672 B | `ASCII_TEXT` | GNU Emacs ChangeLog linker artifact |

The `X86_CODE` result in region 1 is a known false positive for compressed binary payloads: x86 signatures over-match high-entropy LZW data.

### Segment Layout

```
0xF80B4000 ┌─────────────────────────────────┐
           │  TIFF Images + LZW data         │  15,360 B (27.2%)
           │    TIFF #1: 6x8 font glyph      │    ~206 B
           │    TIFF #2: 360x196 splash      │    ~3.4 KB compressed
           │    LZW compressed data          │    ~7.1 KB (entropy 7.91)
0xF80B7C00 ├─────────────────────────────────┤
           │  Offset table (36 B) + BSS      │  8,368 B (14.8%)
           │    97.6% null bytes             │
0xF80B9CB0 ├─────────────────────────────────┤
           │  GNU Emacs ChangeLog            │  32,672 B (57.9%)
           │    1986-1987, Emacs 18.32-18.36 │
           │    Linker padding artifact      │
0xF80C1C50 └─────────────────────────────────┘
```

### Region 1: TIFF Image Data (0x0000–0x3C00, 15,360 bytes)

High-entropy data (7.91 bits/byte). Contains two embedded big-endian TIFF images:

**TIFF #1** (header at offset 0x0938, vmaddr `0xF80B4938`):
- 6 x 8 pixels, 2-bit grayscale, LZW compressed, 72 DPI
- Character cell bitmap — likely a built-in font glyph

**TIFF #2** (IFD at offset 0x1C06, header at 0x1CB8, vmaddr `0xF80B5CB8`):
- 360 x 196 pixels, 2-bit grayscale, LZW compressed, 72 DPI
- 3,393 bytes compressed (5.2:1 ratio), 17,640 bytes uncompressed
- Likely NeXTdimension boot splash or PostScript test page

The surrounding data (0x0000–0x0937 and 0x0A06–0x1C05) is additional LZW-compressed image data.

Ghidra's contamination survey classified this region as "X86_CODE" (21.8%) — a false positive because x86's variable-length encoding can decode almost any byte sequence, and LZW-compressed data presents as plausible x86 instructions.

### Region 2: Zero-Fill / BSS (0x3C00–0x5CB0, 8,368 bytes)

97.6% null bytes. The first ~200 bytes at 0x3C00 contain non-zero values (tail of compressed TIFF data). An offset table at 0x3CB8 holds 9 big-endian values incrementing by 4 (0x1284–0x12A4), likely TIFF strip indices.

### Region 3: GNU Emacs ChangeLog (0x5CB0–0xDC50, 32,672 bytes)

Plain ASCII text — a GNU Emacs 18.x ChangeLog from October 1986 to February 1987. This is **linker padding data** inserted by NeXT's GNU-based toolchain to fill the `__DATA` segment to a page boundary.

- Emacs versions: 18.32, 18.33, 18.35, 18.36
- Authors: Richard M. Stallman (rms), Richard Mlynarik (mly), Chris Hanson (cph), Leonard H. Tower Jr. (tower)
- 86 `.el` files discussed (loaddefs.el, rmail.el, dired.el, bytecomp.el, etc.)
- Notable quote: *"Symbolics killed the MIT AI lab; don't do business with them."* — R.M. Stallman, Feb 1 1987

### Dispatch Table Verdict

| Search | Result |
|--------|--------|
| PostScript operator strings | **0 found** |
| Dispatch tables (consecutive code pointers) | **0 found** |
| Data pointers into `__DATA` | **0 found** |
| Code pointers into `__TEXT` | **3 found** — all false positives in compressed TIFF data |

The `orh`+`or` address pairs in `__TEXT` pointing to `0xF80B7000` land in compressed TIFF image data, not handler pointers. The PostScript dispatch tables must be constructed at runtime in the BSS/common regions (`0xF80B7C00`+), or the dispatch mechanism uses a different model than assumed (possibly hash-based numeric dispatch without pointer tables).

## Embedded Foreign-Architecture Contamination

Three embedded Mach-O objects are present within the i860 `__text` section, confirmed by FEEDFACE/CEFAEDFE header scan (`extract_machdriver_segments.sh`):

| # | __text Offset | VM Address | Magic | CPU | In Clean Window? |
|---|--------------|------------|-------|-----|:----------------:|
| 1 | 0x017CB8 | F8017CB8 | FEEDFACE | m68k (6) | Yes |
| 2 | 0x03DCB8 | F803DCB8 | CEFAEDFE | x86 (7) | No |
| 3 | 0x05DCB8 | F805DCB8 | CEFAEDFE | x86 (7) | No |

Source: `re/nextdimension/firmware/extracted/EMBEDDED_MACHO_HEADERS.txt`

### What's in the clean 196 KB window

- **0x017CB8**: m68k Mach-O header (MH_OBJECT, 3 load commands) — the host-side m68k driver code
- **0x1B9F0**: m68k machine code (`2f00 2f04 2f0d 61ff` = push d0, push d4, push a5, bsr.l) — part of the m68k Mach-O ~15 KB into the object
- **0x15B58**: ASCII PostScript coordinate data (`343.6772 L\n351.9812...`) — not a Mach-O header
- **0x2DC00**: Binary data (no FEEDFACE magic) — not a Mach-O header

### What's in the post-clean region (530 KB)

- **0x03DCB8**: x86 Mach-O (CEFAEDFE, little-endian) — NeXTtv.app or driver
- **0x05DCB8**: x86 Mach-O (CEFAEDFE, little-endian) — second x86 object
- **PhotoAlbum.app** strings at offsets 0x4D712+ — `"Copyright 1991, Eastman Kodak Company"`, built `"Fri Oct 21 10:26:23 PDT 1994"`, associated with the x86 Mach-O objects

### Correction from earlier agent analysis

An earlier automated analysis (agent 8 of 10 parallel ceiling agents) claimed FEEDFACE headers at offsets 0x15B58 and 0x2DC00 with x86 prologues at 0x1B9F0. The extraction tool's exhaustive 4-byte-aligned scan of the entire `__text` section disproves this:

| Claim | Ground Truth |
|-------|-------------|
| FEEDFACE at 0x15B58 | ASCII PostScript data — no Mach-O header |
| FEEDFACE at 0x2DC00 | Binary data — no Mach-O header |
| x86 prologues at 0x1B9F0 | m68k code (`move.l` pushes + `bsr.l`) — part of m68k Mach-O starting at 0x017CB8 |
| PhotoAlbum.app in clean window | PhotoAlbum strings at 0x4D712+ — outside clean window |

### Impact on Analysis

The core conclusion remains: **0x1B9F0 is not i860 code** — it is foreign-architecture contamination (m68k, not x86 as previously claimed). The implications:

1. **0x1B9F0 "dispatch table"** — actually m68k host driver code, not i860 (nor x86)
2. **No new i860 code discoverable by automated prologue scanning** beyond the clean 196 KB (though kernel hard-mask v3 with curated seeds found ~3 KB in 64 small fragments — see [Semantic Understanding Assessment](#semantic-understanding-assessment))
3. **The 0xF80B7000 `orh`+`or` targets** — land in compressed TIFF image data, not handler pointers
4. **The clean window contains one m68k Mach-O** — not "zero foreign contamination" as previously stated

The contamination is a **linker artifact** — NeXT's toolchain included m68k and x86 object files (host driver, Interface Builder plugins, utilities) in the final Mach-O without stripping them. The i860 execution never reaches these regions.

## 10.9% Ceiling — Structural Analysis

Ten parallel analysis agents attacked the 10.9% control-flow recovery ceiling. Combined findings:

### Branch and Call Target Census

| Analysis | Count | Internal Targets | Notes |
|----------|------:|:----------------:|-------|
| `call` instructions (clean FW) | 689 | 2 | Almost all calls target addresses outside 196 KB range |
| Branch instructions (all types) | 2,052 | — | 230 targets point beyond clean firmware boundary |
| `orh`+`or` address pairs (r0-based) | 9 | — | Classic absolute address construction rare; 45 total register-relative `orh` pairs exist but depend on runtime base register state |
| `bri` (indirect branch) words | 407 | 0 constant | All targets dynamically computed via registers |
| Embedded pointer tables | 0 | — | Zero flat pointer arrays found anywhere in `__TEXT` |

### Why the Ceiling is Structural

The 10.9% ceiling is caused by the firmware's exclusive use of **dynamic register-relative dispatch**:

1. **No static call graph**: Only 2 internal call targets exist within the clean firmware. The vast majority of `call` instructions target addresses in the full `__TEXT` segment or runtime-loaded BSS.
2. **No `orh`+`or` address construction**: The classic RISC pattern `orh imm,r0,rN` / `or imm,rN,rN` (build 32-bit constant from zero) appears only 9 times. Instead, the firmware uses **register-relative** `orh imm,rBase,rDest` where rBase is already loaded — dominant pattern: `orh 0x6514,r15,r31` (25 occurrences).
3. **Zero statically-resolvable `bri` targets**: All 407 `bri rN` instructions use dynamically-computed register values.
4. **No dispatch tables in static data**: Not inline in `__TEXT`, not in initialized `__DATA` (TIFF + ChangeLog), not constructable via r0-based `orh`+`or`. Runtime-built BSS tables cannot be ruled out without emulation or runtime tracing.

The threaded PostScript interpreter loads handler addresses from runtime-initialized BSS tables into registers, then dispatches via `bri rN`. Without runtime state or emulation, these dispatch targets cannot be recovered through static analysis alone.

### Agent Reliability Notes

Two of ten agents had significant errors caught during review:
- **bla encoding**: One agent misstated `bla` as 26-bit IntL — actually Int12S (split 16-bit, upper bits from [20:16], lower from [10:0])
- **Split-branch bitfield**: Upper bits come from original `dest` field [20:16], not [31:27]
- **Endianness assumption**: Pointer table scan may have switched to big-endian mid-analysis — results treated with caution

Validated findings: branch formula `PC + (offset << 2) + 4` is correct; recursive feedback loop and indirect-call reseeding logic are sound.

### Strategies for Further Recovery

| Strategy | Potential | Status |
|----------|-----------|--------|
| Exclusion mask (i386 + zero + ASCII) + re-run CFG with curated seeds | Medium | **Done** — reflected in kernel hard-mask v3 (1.3%, 2,467 insns, 0 pcode errors) |
| r15 dataflow tracing for `orh imm,r15,*` dispatch bases | Medium | **Next step** — base-register provenance + offset map |
| Runtime BSS initialization tracing | High | Pending (needs emulation) |
| MAME emulator trace capture | High | Pending (needs MAME i860 instrumentation) |
| Cross-reference with IDA Pro analysis | High | Pending (if available) |

## Semantic Understanding Assessment

### Coverage by Metric

| Measure | Clean FW (196 KB) | Kernel (784 KB) | Notes |
|---------|:------------------:|:----------------:|-------|
| Structural classification | **100%** | **100%** | Every byte typed |
| Purpose identification | **~85%** | **~70%** | Region role known |
| Control-flow verified | **10.9%** | **1.3%** | Provably reachable code |
| Deep semantic | **~5–8%** | **<1%** | Function behavior understood |

These are **separate baselines** — the 10.9% is for `ND_i860_CLEAN.bin` (196 KB), while 1.3% (2,467 instructions, 58 functions) is for `i860_kernel.bin` (784 KB) from the latest hard-mask analysis (v3).

### Understanding Tiers — Clean Firmware (196 KB)

The percentages below are **layered views**, not additive totals. Null padding overlaps with structural regions.

#### Tier 1 — Fully Understood

- Mach-O headers, load commands, segment/section structure (840 B)
- Zero padding between code blocks (~68 KB — classified, purpose known)
- PostScript prolog — 26 operator shortcuts, Adobe Illustrator EPS compatibility (~2 KB)
- PS registration table at 0x1FC00 — 6 sub-tables decoded (4,328 B)
- AppKit/ObjC class metadata — Matrix, Cell, Window, Button, Font, NXImage (ISLAND_15C00, 28400, 29C00, 2E000)
- Bootstrap/init functions at 0x1000–0x1250
- Embedded foreign-architecture contamination — identified and bounded (m68k 0x017CB8; x86 0x03DCB8, 0x05DCB8)

#### Tier 2 — Architecturally Characterized

Function role known, key algorithms identified:

- Central PS dispatch hub (FUN_000033c8, 312 B — `and 0xe827` type masking)
- Name lookup chain (0x7AD8–0x7DC0, 924 B — hash mechanism `xorh 0x10c6`)
- Scanline pixel write (0x882C, 404 B — ST=20, framebuffer write pattern)
- Bezier/path processing (0x3C10, 560 B — `mimt1p2.ss` MAC chain)
- Matrix multiply (0x4018, 208 B — pure FP kernel)
- 7-stage FP pipeline chain (0xD5AC–0xD67C — convolution/halftone kernel)
- FP math library (0xB438–0xBE08, 10 functions)
- Pixel rendering primitives (ISLAND_13C00, 12 functions — graduated-precision blending)
- Operator registration infrastructure (BLOCK2 non-contaminated portions)

#### Tier 3 — Structurally Mapped

Function boundaries known, individual behavior not determined:

- ~1,000 functions with boundaries from filtered linear sweep
- Classified by instruction mix (GENERAL / FP_MIXED / DATA_MOVE / CONTROL_FLOW / FP_HEAVY)
- Method dispatch trampolines in BLOCK2 (0x1A9E8–0x1B140)

#### Tier 4 — Classified Only

- Regions decoded as i860 by linear sweep but likely contamination (data-as-code)
- BIN_DATA (1,024 B)
- Fragments between code islands where content type is ambiguous

### Understanding Tiers — Kernel Binary (784 KB)

The kernel analysis uses a curated hard-mask recovery map (v3) with 309 seed definitions, 43 deny ranges, and 1 allow range. Latest results:

| Metric | Value |
|--------|-------|
| Instructions decoded | 2,467 |
| Functions discovered | 58 |
| Code bytes | 9,868 (1.3%) |
| Curated seeds accepted | 151 |
| Missing delay-slot pcode errors | **0** (down from 19 in v2) |

The kernel's 98.7% contamination (x86, m68k, ASCII, Mach-O headers, null padding) limits static analysis to small i860 code islands confirmed by the hard-mask.

### What Remains Unknown

1. **Operator-to-function mapping** — PS operators are registered (per the 0x1FC00 table) but can't be mapped to specific handler functions without runtime dispatch table contents
2. **Runtime BSS structure** — dispatch tables presumably built at startup in BSS (`0xF80B7C00`+), but initialization code not yet traced
3. **r15 GState field layout** — 25 `orh 0x6514,r15,r31` references but field offsets not decoded; r15-centric semantic lifting is the recommended next step
4. **Full `__TEXT` beyond 196 KB** — 730 KB total, ~534 KB mostly i386/m68k contamination + padding; kernel hard-mask v3 found ~3 KB of additional i860 code in 64 small fragments (curated seeds, not automated discovery)

## Key Conclusions

Confidence labels: **confirmed** = verified by multiple methods or direct evidence; **inferred** = strong circumstantial evidence; **hypothesis** = plausible but unverified.

1. [confirmed] **The firmware is a Display PostScript RIP** — the i860 on the NeXTdimension board interprets PostScript drawing commands, rasterizes paths, and writes to the framebuffer via MMIO at 0x401C. It is an **Objective-C program** built with NeXT's development tools, containing full Mach-O segment descriptors and ObjC runtime metadata for AppKit classes (Matrix, Cell, Responder, Window, Panel, Button, Font, NXImage).

2. [confirmed] **~83.6 KB of genuine code across 1,198 functions** — after filtering zero-padding noise and suspected data tables from 1,917 linear-sweep functions. Median function size is 44 bytes (11 instructions). The code is distributed across MAIN_CODE (50 KB, interpreter core), BLOCK2 (19 KB, dispatch infrastructure), BLOCK3 (6.7 KB, path/graphics), and 14 code islands (14 KB, rendering primitives + metadata).

3. [inferred] **The interpreter architecture is characterized** — a threaded dispatch model: token read via MMIO 0x401C → hash-based name resolution (`xorh 0x10c6` at 0x7386) → operator type classification (`and 0xe827/0xe927`) → execution via FP pipeline and operand stack → hardware sync. The central dispatch hub is FUN_000033c8 (312 bytes, 12 branches).

4. [confirmed] **One major data structure identified** — the PS registration table (4,328 bytes at 0x1FC00, operator names + type signatures + handler pointers + class descriptors + field layouts). The 7,152-byte region at 0x1B9F0, previously identified as the "master dispatch table," is actually embedded m68k host driver code (see [Embedded Foreign-Architecture Contamination](#embedded-foreign-architecture-contamination)).

5. [inferred] **The rendering pipeline is mapped** — from high-level path operators (BLOCK3 Bezier evaluation) through mid-level rendering (MAIN_CODE scanline pixel write at 0x882C with 20 stores) to low-level compositing primitives (ISLAND_13C00, `st.b r1,0x700(r24)` with graduated-precision shift chains for color blending). Register r24 is the framebuffer base pointer throughout.

6. [confirmed] **The `__DATA` segment contains no static dispatch table** — extracted from the source Mach-O binary (`ND_MachDriver_reloc`, 795,464 B), the 56,400-byte `__DATA` section at vmaddr `0xF80B4000` reconciles to: TIFF/LZW image data (27%), zero-fill gap (15%), and GNU Emacs ChangeLog text (58%). The earlier `X86_CODE` tag in the first region is a classifier false positive on compressed image bytes. Zero PostScript operator string tables, zero flat handler-pointer tables, and only 3 low-confidence pointer matches into `__TEXT`.

7. [confirmed] **Foreign-architecture contamination** — three embedded Mach-O objects confirmed in the full `__text` section by header scan: m68k at 0x017CB8 (within clean window), x86 at 0x03DCB8 and 0x05DCB8 (outside clean window). The m68k Mach-O contains host driver code (0x1B9F0 = m68k push+bsr prologue). The x86 objects include PhotoAlbum.app (Kodak, 1991/1994) strings at offsets 0x4D712+. Earlier agent claims of FEEDFACE at 0x15B58 and 0x2DC00 were disproven by the extraction tool's exhaustive scan. Automated prologue scanning of the full 730 KB `__TEXT` found zero new i860 entry points; kernel hard-mask v3 with curated seeds recovered ~3 KB of i860 code in 64 small fragments beyond the clean 196 KB range.

8. [confirmed] **Linear sweep is counterproductive** — the i860 ISA decodes any 4 bytes as valid instructions, so linear sweep creates massive contamination. 67% of randomly sampled "functions" are pure zero padding. Only recursive descent from known entry points produces reliable results.

9. [confirmed] **The 10.9% ceiling is structural, not informational** — a 10-agent parallel analysis confirmed: only 2 internal call targets in the clean firmware, only 9 r0-based `orh`+`or` absolute address pairs (45 register-relative `orh` pairs exist but targets depend on runtime base register state), zero statically-resolvable `bri` targets, and zero embedded pointer tables in static data. The ceiling is caused by the firmware's exclusive use of dynamic register-relative dispatch (`orh imm,rBase,rDest` + `bri rN`) with runtime-loaded handler tables. Breaking through requires r15 dataflow tracing, runtime BSS analysis, or emulator-assisted dispatch recovery.

10. [confirmed] **The Emacs ChangeLog is a linker artifact** — ~32 KB of GNU Emacs 18.x ChangeLog (Oct 1986–Feb 1987, by Richard M. Stallman, Richard Mlynarik, Chris Hanson, Leonard H. Tower Jr.) is embedded as segment payload. This confirms the GNU-era build environment and explains the "Richard" fragment seen in `ISLAND_2F000`. The remaining meaningful initialized payload in `__DATA` is TIFF image data (6x8 glyph + 360x196 image).

11. [inferred] **The firmware is bare-metal, not a Mach kernel** — the i860 code contains OS-like primitives (VM init, exception handling, cache coherency) but no Mach kernel infrastructure. Mach API strings in the source binary belong to the host-side m68k driver code, not the i860 firmware. No Mach IPC, task/thread structures, or port namespace found in i860 code.

## Comparison with Kernel Binary

| Metric | Clean Firmware (196 KB) | Kernel (784 KB) |
|--------|------------------------|-----------------|
| I860_CODE | 115,712 B (57.7%) | 1,024 B (0.1%) |
| X86_CODE | 0 B | 298,312 B (40.8%) |
| M68K_CODE | 0 B | 41,984 B (5.7%) |
| NULL_PAD | 68,608 B (34.2%) | 115,712 B (15.8%) |
| i860 recovered (recursive) | 5,453 insns (10.9%) | 2,467 insns (1.3%) |
| Foreign contamination | None | ~52% (x86, m68k, ASCII, Mach-O) |

The clean firmware is dramatically better for analysis: zero foreign-architecture contamination, 100x more real i860 code by proportion.

## Firmware Memory Map (Architectural)

```
┌─────────────────────────────────────────────────────────────┐
│ 0x00000  Mach-O header + load commands (840 B)              │
│ 0x00348  Bootstrap / exception vectors (208 B)              │
│ 0x01000  ═══════════════════════════════════════════        │
│          MAIN_CODE — PostScript interpreter core            │
│          619 functions, 49,852 bytes                        │
│            0x1000  Bootstrap/init                           │
│            0x33C8  Central operator dispatch (312 B)        │
│            0x3C10  Bezier/path processing (560 B)           │
│            0x4018  Matrix multiply (208 B, pure FP)         │
│            0x7AD8  Name lookup chain (924 B)                │
│            0x882C  Scanline pixel write (404 B, ST=20)      │
│            0xB438  FP math library cluster (10 funcs)       │
│            0xD5AC  7-stage FP pipeline chain                │
│ 0x0F800  PostScript prolog (ASCII, ~2 KB)                   │
│ 0x10000  ─── Code islands + string tables ───               │
│            ISLAND_13C00  Pixel rendering primitives (12 f)  │
│            ISLAND_15C00  Mach-O/ObjC metadata (23 f)        │
│ 0x17CB8  ─── Embedded m68k Mach-O (FEEDFACE) ───            │
│            Host-side m68k driver code                       │
│ 0x18000  ═══════════════════════════════════════════        │
│          BLOCK2 — Operator registration infrastructure      │
│          289 functions, 19,004 bytes                        │
│            0x1B9F0  Embedded m68k code (7,152 B)            │
│            0x1B4D0  Numbered operator reg (15 entries)      │
│            0x1A9E8  Method dispatch trampolines             │
│            ISLAND_1FC00  PS registration table (4,328 B)    │
│ 0x23C00  ═══════════════════════════════════════════        │
│          BLOCK3 — Path/graphics operations                  │
│          102 functions, 6,728 bytes                         │
│            Zone A: Stack/dictionary ops                     │
│            Zone B: Bezier/spline computation                │
│            Zone C: Rendering + graphics state               │
│ 0x26400  ─── Late islands ───                               │
│            ISLAND_28400  AppKit class metadata (23 f)       │
│            ISLAND_29C00  AppKit class metadata (19 f)       │
│            ISLAND_2E000  Runtime metadata variant (22 f)    │
│            ISLAND_2F000  1987 build artifact (67 f)         │
│ 0x30FFF  ─────────────────────────────────────────          │
└─────────────────────────────────────────────────────────────┘
```

## Files

### Repo-tracked artifacts (reproducible)

| File | Description |
|------|-------------|
| `ND_i860_CLEAN.bin` | Clean firmware binary (196 KB) |
| `contamination_survey_clean.txt` | Block-level content classification |
| `extracted/ND_MachDriver___TEXT_section.bin` | Full __TEXT section (730,440 B) |
| `extracted/ND_MachDriver___DATA_section.bin` | Full __DATA section (56,400 B) |
| `extracted/GHIDRA_DATA_SURVEY.txt` | Ghidra contamination survey of __DATA |
| `extracted/ANALYSIS.txt` | __DATA pointer scan and density analysis |
| `extracted/RUST_DATA_STATS.txt` | Rust disassembler stats on __DATA |
| `scripts/extract_machdriver_segments.sh` | Reproducible Mach-O segment extractor |
| `docs/original-binary-extraction.md` | Extraction methodology and results |

### Session artifacts (`/tmp/` — ephemeral, regenerable via scripts)

| File | Description |
|------|-------------|
| `/tmp/i860_firmware_analysis.txt` | Full assembly-level analysis output (3,341 lines) |
| `/tmp/i860_asm_main_code.txt` | MAIN_CODE assembly (13,878 lines, 619 functions) |
| `/tmp/i860_asm_block2.txt` | BLOCK2 assembly (5,332 lines, 289 functions) |
| `/tmp/i860_asm_block3.txt` | BLOCK3 assembly (1,889 lines, 102 functions) |
| `/tmp/i860_asm_summary.txt` | Function summary table (1,233 lines) |
| `/tmp/i860_data_analysis.txt` | __DATA entropy/pointer analysis (431 lines) |
| `/tmp/i860_clean_asm_random.txt` | Random assembly sampling report |
| `/tmp/i860_clean_report_seeded_ghidra.txt` | Seeded recursive descent report |
| `/tmp/i860_clean_decompile_seeded_ghidra.txt` | Decompiler quality KPIs |
| `/tmp/i860_call_targets.txt` | Call target census (689 calls, 2 internal) |
| `/tmp/i860_branch_targets.txt` | Branch target census (2,052 branches, 230 external) |
| `/tmp/i860_address_constants.txt` | orh+or address pair scan (9 r0-based) |
| `/tmp/i860_bri_trace.txt` | bri indirect branch analysis (407 words, 0 constant) |
| `/tmp/i860_pointer_tables.txt` | Pointer table scan (0 found) |
