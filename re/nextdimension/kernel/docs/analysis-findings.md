# NeXTdimension i860 Kernel — Analysis Findings

## Binary

| Property | Value |
|----------|-------|
| File | `i860_kernel.bin` |
| Format | Mach-O (CPU type 15) |
| Size | 802,816 bytes (784 KB) |
| Architecture | i860:LE:32:XR (little-endian) |
| ABI | GCC/NeXTSTEP (r2=sp, r3=fp) |

## Memory Map

```
 F8000000 ┌─────────────────────────────────┐ ◄── entry
          │                                 │
          │         __text            r-x   │  730,440 B  (89.7%)
          │                                 │
          │   ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐   │
          │   ╎    2,467 instructions   ╎   │    9,868 B recovered
          │   ╎       58 functions      ╎   │  ~9,868 B i860 code (1.3%)
          │   ╎     1.3% coverage       ╎   │  ~721 KB contamination
          │   └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘   │
          │                                 │
 F80B2547 ├─────────────────────────────────┤
          │         __TEXT            r-x   │    6,840 B  (0.8%)
 F80B3FFF ├═════════════════════════════════╡
          │                                 │
          │         __data            rw-   │   56,400 B  (6.9%)
          │                                 │
 F80C1C4F ├─────────────────────────────────┤
          │         __DATA            rwx   │      176 B
 F80C1CFF ├─────────────────────────────────┤
          │         __bss             rw-   │      768 B
 F80C1FFF ├─────────────────────────────────┤
          │         __bss             rw-   │    1,984 B
 F80C27BF ├─────────────────────────────────┤
          │         __common          rw-   │    6,360 B  (0.8%)
 F80C4097 ├─────────────────────────────────┤
          │         __DATA            rwx   │    8,040 B  (1.0%)
 F80C5FFF └─────────────────────────────────┘
```

### Section Details

| Section | Start | End | Size | Perms | Content |
|---------|-------|-----|------|-------|---------|
| `__text` | F8000000 | F80B2547 | 730,440 | r-x | Mixed: ~1.3% i860 code, ~99% contamination (x86, m68k, ASCII, padding) |
| `__TEXT` | F80B2548 | F80B3FFF | 6,840 | r-x | Segment padding / alignment (not proven symbol+reloc content) |
| `__data` | F80B4000 | F80C1C4F | 56,400 | rw- | Initialized data (globals, vtables, strings) |
| `__DATA` | F80C1C50 | F80C1CFF | 176 | rwx | Small rwx — likely trampolines or dispatch stubs |
| `__bss` | F80C1D00 | F80C27BF | 2,752 | rw- | Uninitialized data (two segments) |
| `__common` | F80C27C0 | F80C4097 | 6,360 | rw- | Common symbols (tentative definitions) |
| `__DATA` | F80C4098 | F80C5FFF | 8,040 | rwx | Secondary rwx data — pure data (no code found) |

## Contamination Analysis

The __text section is overwhelmingly non-i860 content. A byte-level contamination survey (1 KB block classification) and cross-validation with the Rust i860 disassembler confirm:

### __text Content Breakdown

| Type | Size | % of __text | Description |
|------|------|-------------|-------------|
| X86_CODE | 298,312 | 40.8% | x86 object code (NeXTtv.app, drivers) |
| NULL_PAD | 115,712 | 15.8% | Zero-fill padding between objects |
| ASCII_TEXT | 108,544 | 14.9% | Strings, Spanish localization, Emacs changelog |
| X86_DATA | 71,680 | 9.8% | x86 initialized data segments |
| BIN_DATA | 54,272 | 7.4% | Unclassified binary data |
| M68K_CODE | 41,984 | 5.7% | m68k host driver code |
| M68K_DATA | 27,648 | 3.8% | m68k initialized data |
| I860_SPARSE | 8,192 | 1.1% | Blocks with some decoded i860 instructions |
| MACHO_X86 | 3,072 | 0.4% | Embedded Mach-O headers (x86 CPU type) |
| I860_CODE | 1,024 | 0.1% | Blocks with >25% decoded i860 instructions |

Only 526 i860 instructions were decoded by linear sweep across the entire __text section.

### Embedded Mach-O Objects

Three embedded Mach-O headers confirmed by hex dump:

| Address | Magic | CPU Type | Architecture |
|---------|-------|----------|-------------|
| F8017CB8 | `FEEDFACE` | 6 | m68k (host driver) |
| F803DCB8 | `CEFAEDFE` | 7 | i386 (NeXTtv.app or driver) |
| F805DCB8 | `CEFAEDFE` | 7 | i386 (second x86 object) |

The `...CB8` offsets (not page-aligned) reflect the Mach-O header + load command size offset from the 1 KB survey grid.

### Major Contamination Zones

| Range | Size | Dominant Content |
|-------|------|-----------------|
| F800FC00–F8017BFF | 32 KB | ASCII text (strings, localization) |
| F8018000–F80207FF | 34 KB | m68k code (host driver, starts after Mach-O header) |
| F8024800–F80377FF | 77 KB | Mixed x86 code/data |
| F8040400–F804BBFF | 46 KB | x86 code |
| F805F000–F8098FFF | 233 KB | x86 code/data (largest zone) |
| F80A3C00–F80AFBFF | 49 KB | x86 data, null padding |

Across these 6 zones (479,232 bytes, 65.6% of __text), the Rust CFG recovered only 79 unique instructions (0.07% density).

### Cross-Validation

| Method | Real i860 Found | Tool |
|--------|----------------|------|
| Byte heuristic survey | 9,216 B (1.3%) | Ghidra ContaminationSurvey.java |
| CFG recursive recovery (79 seeds) | 9,596 B (1.3%) | Rust i860 disassembler |
| CFG entry-only (no seeds) | 4,164 B (0.6%) | Rust i860 disassembler |

All three methods converge on ~1.3% real i860 code in __text.

## Analysis Results

### Summary — Latest (hard-mask v3, with pcode map)

| Metric | Value |
|--------|-------|
| Instructions decoded | 2,467 |
| Functions discovered | 58 |
| Code bytes | 9,868 (1.3% of __text) |
| Data bytes | 735,640 (in executable blocks) |
| Recovery map | `recovery_map_hardmask_pcode.json` |
| Allow ranges | 1 |
| Deny ranges | 43 |
| Curated seed defs | 309 |
| Curated seeds accepted | 151 |
| Missing delay-slot pcode errors | **0** (down from 19 in v2) |

### Summary — Earlier versions

| Version | Instructions | Functions | Code Bytes | Coverage | Seeds |
|---------|------------:|----------:|----------:|--------:|------:|
| v3 (hard-mask + pcode) | 2,467 | 58 | 9,868 | 1.3% | 309 defs, 151 accepted |
| v2 (hard-mask) | ~1,663 | ~64 | ~6,652 | 0.9% | 79 curated |
| Baseline (no map) | 735 | 8 | ~2,940 | 0.4% | entry only |

### Function Discovery Breakdown (v3)

| Strategy | Count | Notes |
|----------|-------|-------|
| Curated seeds (recovery map) | 151 | Hand-identified entry points (from 309 defs) |
| Prologue patterns | 2 | `addu -N,r2,r2` prologues |
| Pointer seeds | 1 | Data pointer into code |
| Post-return boundaries | 0 | No `bri r1` + nop patterns |
| Call targets | 0 | No direct `call` with in-range targets |
| Data pointers | 0 | No __data values pointing into recovered code |
| **Total new** | 67 | 12 pruned (bad start) → 58 surviving |

The near-zero automated discovery reflects the kernel's reliance on indirect calls (`calli` via register) and dispatch tables (`bri r8`) rather than direct `call` instructions.

## Loader Workarounds

### Missing Entry Point

Ghidra's Mach-O loader cannot parse the i860 LC_THREAD command (flavor `0x4`). Without this, there is no entry point, and auto-analysis discovers 0 functions.

**Workaround**: `I860Import.java` (preScript) sets the entry point at the start of the first executable block (`F8000000`) and uses recursive descent with iterative call/branch seeding for disassembly.

### Recovery Map

Because automated seed discovery is ineffective on this binary (contamination + indirect dispatch), a curated `recovery_map.json` provides:
- **Allow ranges**: address ranges known to contain i860 code
- **Deny ranges**: address ranges known to be contamination (suppresses false disassembly)
- **Curated seeds**: hand-identified function entry points

### Pcode Warnings

Recursive descent is much cleaner than linear sweep, but still produces `halt_baddata` warnings when control flow reaches data regions adjacent to code. With the recovery map's deny ranges, most contamination is avoided.

## Clean Firmware Comparison

The clean firmware extraction (`ND_i860_CLEAN.bin`, 200,704 bytes) provides a dramatically better analysis target:

| Metric | Kernel (784 KB) | Clean Firmware (196 KB) |
|--------|-----------------|------------------------|
| I860_CODE | 1,024 B (0.1%) | 115,712 B (57.7%) |
| X86_CODE | 298,312 B (40.8%) | 0 B (0%) |
| M68K_CODE | 41,984 B (5.7%) | 0 B (0%) |
| NULL_PAD | 115,712 B (15.8%) | 68,608 B (34.2%) |
| ASCII_TEXT | 108,544 B (14.9%) | 15,360 B (7.7%) |
| i860 decoded (linear) | 526 insns | 47,203 insns |

### Clean Firmware Recovery

| Tool | Mode | Instructions | Functions | Coverage |
|------|------|------------:|----------:|--------:|
| Rust disassembler | Recursive (seedless) | 1,041 | 1 | 2.1% |
| Rust disassembler | Recursive (seeded) | 5,491 | 16 | 10.9% |
| Ghidra headless | Seeded with Rust xrefs | 5,453 | 436 | 10.9% |

Coverage denominator: 50,176 instructions (200,704 bytes linear sweep).

Both tools converge at ~10.9% with seeds. Ghidra discovers 436 functions (vs Rust's 16) through multi-strategy function discovery (prologues, post-return boundaries, orphan code detection).

The 10.9% ceiling vs the 57.7% I860_CODE classification reflects the `bri r8` dispatch table problem: the firmware uses indirect jumps through register-loaded handler tables, and neither tool can follow the control flow without knowing the table contents.

### Clean Firmware Structure

The firmware is organized in distinct code blocks separated by null padding:
- **0x1000–0xF7FF** (59 KB contiguous) — bootstrap + graphics handlers
- **0x18000–0x1D3FF** (21.5 KB contiguous) — likely PostScript operators
- Scattered small code islands after 0x10000 — individual operators with null padding between them
- 15 KB ASCII text in 4 regions — string tables (error messages, operator names)
- Three embedded Mach-O objects: m68k at 0x017CB8 (FEEDFACE), x86 at 0x03DCB8 and 0x05DCB8 (CEFAEDFE) — linker artifacts, not i860 code

### Decompiler Quality (Clean Firmware)

Sample of 12 functions:

| KPI | Count | Scope |
|-----|------:|-------|
| Decompiled successfully | 12/12 | — |
| Timeouts | 0 | — |
| `halt_baddata()` | 26 | 12/12 functions |
| `halt_unimplemented()` | 0 | 0/12 functions |
| `unaff_*` variables | 64 | 9/12 functions |
| Unreachable block warnings | 6 | 2/12 functions |

- **`halt_baddata`**: Linear sweep forces decoding of data-as-code in null padding and ASCII regions (42% of image). These "instructions" produce garbage pcode that truncates control flow.
- **`halt_unimplemented: 0`**: All 172 SLEIGH instructions have working pcode semantics.
- **`unaff_*`**: Many firmware routines use non-standard register conventions (dispatch via `bri r8`, non-GCC callee-saved registers).

## Base Address

The kernel is loaded at `F8000000`, which matches the NeXTdimension board's memory-mapped region for kernel code. The Mach-O sections specify this base address, and Ghidra honors it during import.

## Key Conclusions

1. **The kernel binary is a fat container**, not a pure i860 image. It bundles m68k host driver code, x86 application objects (including PhotoAlbum.app/Kodak 1991), ASCII resources, and build artifacts (Emacs changelog) alongside ~1.3% genuine i860 code.
2. **Static analysis is severely limited** by indirect dispatch. The i860 firmware relies on `calli` (register indirect call) and `bri r8` (handler dispatch) rather than direct `call` instructions. Without dispatch table reconstruction, most code is unreachable to both Ghidra and the Rust disassembler.
3. **The clean firmware is the better target**. At 57.7% i860 code with zero foreign-architecture contamination, `ND_i860_VERIFIED_clean.bin` is far more amenable to analysis (10.9% recovery vs 1.3%).
4. **The Rust disassembler's Mach-O parser cannot handle this binary** — it fails with "Invalid Mach-O load command size", independently confirming the anomalous container structure.
5. **The firmware is bare-metal** — not a Mach kernel. OS-like primitives (VM init, exception handling, cache coherency) are present but Mach API strings belong to the host-side m68k driver code.
6. **No dispatch tables exist in `__DATA`** — the 56,400-byte section contains TIFF images, zero-fill BSS, and GNU Emacs ChangeLog linker padding. The 10.9% ceiling is structural (dynamic register-relative dispatch), not informational.
7. **Delay-slot pcode errors eliminated** — hard-mask v3 with pcode map produces zero missing-delay-slot pcode errors (down from 19 in v2), confirming the SLEIGH specification correctly handles all delay-slot variants encountered in real firmware.

## Open Questions

- ~~What is `__TEXT` (F80B2548–F80B3FFF, 6.8 KB)?~~ **Answered**: Segment padding/alignment, not proven C runtime or symbol/reloc content.
- The two `__DATA` rwx sections at F80C1C50 and F80C4098 — are the trampolines in the small one dynamically patched?
- ~~Can dispatch tables be reconstructed from the `__data` section?~~ **Answered**: No — `__DATA` contains TIFF images (27%), zero-fill BSS (15%), and GNU Emacs ChangeLog linker padding (58%). Zero dispatch tables found.
- ~~The clean firmware is 196 KB vs the 64 KB described in prior documentation?~~ **Answered**: Different binaries — 64 KB is the boot ROM (`ND_i860_CLEAN.bin` at 0xFFF00000), 196 KB is the DPS kernel (`ND_i860_VERIFIED_clean.bin` at 0xF8000000).
- **Next step**: r15-centric semantic lifting — base-register provenance tracing and `orh imm,r15,*` offset map to decode GState field layout and dispatch base origins.
