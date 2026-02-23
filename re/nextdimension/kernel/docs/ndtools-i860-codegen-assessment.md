# NDTools-4 i860 Codegen Assessment

## Scope

This note assesses how optimized the **compiler-generated** i860 code is in the
NeXT toolchain (`NDTools-4`, GCC 1.36 backend), and contrasts that with the
hand-tuned assembly used in the NeXTdimension rendering stack.

## Verdict

Code generation quality is **functionally solid but only moderately optimized**.
It is suitable for general kernel/server C code, but does not reach i860 peak
throughput for graphics hot paths. NeXT clearly relied on handwritten `.860.s`
kernels for high-performance routines.

## Evidence

### 1. Delay-slot optimization is local, not global pipeline scheduling

- Branch/call patterns default to explicit delay-slot NOPs in many cases:
  - `NDTools-4/gcc-1.36/config/i860.md` (`br ...;nop`, `bri ...;nop`,
    `call/calli ...;nop` around lines 2072, 2096, 2133, 2196).
- Delay-slot fill exists, but via narrow peepholes:
  - `NDTools-4/gcc-1.36/config/i860.md` (peepholes around lines
    2078-2090, 2098-2104, 2137-2166, 2200-2231, 2250-2256).
  - `NDTools-4/gcc-1.36/config/out-i860.c:1309` (`output_delayed_branch`).
- No evidence of machine-model scheduler constructs in the i860 MD file
  (for example no `define_function_unit` / `define_delay` blocks in
  `NDTools-4/gcc-1.36/config/i860.md`).

### 2. Backend comments show conservative heuristics

- `NDTools-4/gcc-1.36/config/out-i860.c` marks key selection logic as
  "Just experimenting" (for example lines 49 and 184).
- Delay-slot candidate selection explicitly avoids FP arithmetic because it
  "probably [takes] longer than the branch slot" (lines 290-292).
- Cost model is simple constant-cost heuristics, not deep i860 latency
  modeling (`NDTools-4/gcc-1.36/config/tm-i860.h:926-936`).

### 3. Chip stepping workarounds reduce optimization freedom

- For B0 steppings, backend reserves `r4` and injects extra instructions:
  - Fixed register note: `tm-i860.h` lines 141-142.
  - Opcode patch insertion: lines 1324-1337 (dummy store + NOP before several
    branch forms).

### 4. Build settings are conventional (`-O`), not aggressive modern tuning

- PSDriver common build flags use `-g -O`:
  - `NextDimension-21/PSDriver/Makefile.common:30`.

### 5. NeXT uses hand-written i860 assembly for hot paths

- There are 9 `.860.s` performance files in the tree (bitmap/server/device).
- These files explicitly exploit i860 features that the C backend generally
  does not synthesize well:
  - `bla` loops, `fst.d`, alignment-specific fast paths:
    `NextDimension-21/PSDriver/device/run32.860.s`.
  - Dual-instruction mode style scheduling (`d.fnop`, `d.faddp`, etc.):
    `NextDimension-21/PSDriver/bitmap/bm38sover.860.s`.
- Source history notes compiler workaround behavior:
  - `NextDimension-21/PSDriver/bitmap/mp12comp.c:19` ("code around gcc bug").

## RE Implications

1. Treat C-generated i860 code as reliable for control/data-flow recovery, but
   do not assume near-optimal pipeline packing.
2. Prioritize `.860.s` routines when reconstructing performance-critical
   behavior (compositing, mask/run/trap rasterization).
3. For emulator validation, include DIM behavior, delay slots, and `bla` loop
   semantics from handwritten kernels as first-class test material.

## Confidence

High. The conclusion is directly supported by backend source (`i860.md`,
`out-i860.c`, `tm-i860.h`) and by PSDriver handwritten kernel usage patterns.
