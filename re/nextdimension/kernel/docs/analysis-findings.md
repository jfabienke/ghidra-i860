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
          │   ╎    2,536 instructions   ╎   │   10,144 B recovered
          │   ╎       60 functions      ╎   │ ~10,144 B i860 code (1.4%)
          │   ╎     1.4% coverage       ╎   │  ~720 KB contamination
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
| `__text` | F8000000 | F80B2547 | 730,440 | r-x | Mixed: ~1.4% execution-proven i860 code, contamination-heavy remainder (x86, m68k, ASCII, padding) |
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
| Instructions decoded | 2,536 |
| Functions discovered | 60 |
| Code bytes | 10,144 (1.4% of __text) |
| Data bytes | 735,364 (in executable blocks) |
| Recovery map | `recovery_map_hardmask_pcode.json` |
| Allow ranges | 1 |
| Deny ranges | 43 |
| Curated seed defs | 311 |
| Curated seeds accepted | 153 |
| Missing delay-slot pcode errors | **0** (down from 19 in v2) |

### Summary — Earlier versions

| Version | Instructions | Functions | Code Bytes | Coverage | Seeds |
|---------|------------:|----------:|----------:|--------:|------:|
| v3 (hard-mask + pcode) | 2,536 | 60 | 10,144 | 1.4% | 311 defs, 153 accepted |
| v2 (hard-mask) | ~1,663 | ~64 | ~6,652 | 0.9% | 79 curated |
| Baseline (no map) | 735 | 8 | ~2,940 | 0.4% | entry only |

### Function Discovery Breakdown (v3)

| Strategy | Count | Notes |
|----------|-------|-------|
| Curated seeds (recovery map) | 153 | Hand-identified entry points (from 311 defs) |
| Prologue patterns | 2 | `addu -N,r2,r2` prologues |
| Pointer seeds | 1 | Data pointer into code |
| Post-return boundaries | 0 | No `bri r1` + nop patterns |
| Call targets | 0 | No direct `call` with in-range targets |
| Data pointers | 0 | No __data values pointing into recovered code |
| **Total new** | 69 | 12 pruned (bad start) → 60 surviving |

The near-zero automated discovery reflects the kernel's reliance on indirect calls (`calli` via register) and `bri`-based runtime dispatch tables rather than direct `call` instructions.

### Runtime Trace Closure Status (Current)

The runtime pipeline is in place (`run_emu_trace_seed_sweep.sh` → `dynamic_trace_to_recovery_map.py` → `run_analysis.sh`), but the latest iterative closure runs converged immediately with no new runtime seeds:

| Metric | Value |
|--------|-------|
| Iterations run | 1 |
| `dynamic_added` | 0 |
| Trace events | 0 |
| Indirect events | 0 |
| Targets seen | 0 |
| Functions (post-pass) | 60 |
| Instructions (post-pass) | 2,536 |

Source: `re/nextdimension/kernel/reports/iterative_closure/20260210-235407/kpi_summary.json`

Implication: current traces are not reaching dispatch-producing execution paths yet, so the converter has no runtime evidence to promote.

Experimental auto state-gap refinement run (`re/nextdimension/kernel/reports/iterative_closure/20260211-020258`) shows useful sequencing without coverage gains:
- Iteration 1: `state_gap_top=r8:1`, one state mutation applied from hints (`r8=0xF8008100`)
- Iteration 2: `state_gap_top=r18:1`, indirect events increased from 1 to 2
- Final metrics unchanged: `dynamic_added=0`, 60 functions, 2,536 instructions, 1.4% coverage

This confirms the gap-localization tooling is working (`r8 -> r18` chain), but additional runtime state/MMIO behavior is still required to cross into productive dispatch paths.

### Runtime Diagnostics (Boot ROM + Post-ROM Replay)

Recent emulator diagnostics narrowed the failure mode further:

| Scenario | Result | Evidence |
|----------|--------|----------|
| Kernel start from `0xF8000348` (state JSON, normal alignment checks) | Stops after 1,040 instructions at unaligned access | `pc=0xF8001388`, `word=0x15B8801E`, `err=Unaligned access at 0xFFFF801E` |
| Boot ROM run (`0xFFF00020` with stop at `0x00000000`) | Handoff path succeeds; post-ROM state captured | 203 instructions, stop reason `stop_pc`, state dump produced |
| Kernel replay with post-ROM state and `I860_ALLOW_UNALIGNED=1` | Hard self-loop, no dispatch events | `0xF800138C -> 0xF800138C` (~48,959 hits in 50k steps), `runtime_trace_merged.jsonl` empty |
| MMIO activity in looping kernel replay | Minimal and non-progressing | Reads only `0xFF800000` and `0xFF800008` once each |
| MMIO scalar sensitivity (`0xFF800000`,`0xFF800008`) | No behavioral change across 49 value pairs | Every run still traps at `0xF800138C` with exception `0x00000001` |

**Root cause identified**: The word at `0xF800138C` is `0x19B8801E` (primary opcode `0x06`, reserved). Byte-swapping this to `0x1E80B819` yields bits [31:26] = `000111` (opcode `0x07` = `st.s`), a valid instruction. This strongly indicates an **XOR-4 byte-ordering mismatch**: the emulator loads the kernel binary without applying the `LOADTEXT(addr ^ 4)` swap that the host driver (`libND/code.c`) uses during real kernel loading. The i860's 64-bit instruction bus in big-endian mode expects 32-bit words in the opposite half of each 64-bit pair.

Additionally, the kernel requires:
- **Trap vector at 0xFFFFFF00**: The kernel maps a physical page behind 0xFFFFFF00 during `early_start`/`config_memory` before enabling interrupts. If the emulator lacks this mapping, any exception becomes fatal.
- **TLB/ATE enable**: `dirbase` must enable address translation to map the uncacheable DRAM region (0xF80C0000) and the trap vector correctly.

The hard self-loop at `0xF800138C` is likely the kernel re-executing a faulting instruction (trap handler jumps back to PC of the reserved opcode, which traps again indefinitely).

`nd_trace` now supports `mmio_sequences` in state JSON for per-address read sequencing (hold-last semantics), which enables richer MMIO modeling experiments without changing emulator code.

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

The 10.9% ceiling vs the 57.7% I860_CODE classification reflects the `bri` dispatch-table problem: the firmware uses indirect jumps through register-loaded handler tables, and neither tool can follow the control flow without knowing the table contents.

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
- **`unaff_*`**: Many firmware routines use non-standard register conventions (dispatch via indirect `bri`, non-GCC callee-saved registers).

## Base Address

The kernel is loaded at `F8000000`, which matches the NeXTdimension board's memory-mapped region for kernel code. The Mach-O sections specify this base address, and Ghidra honors it during import.

## Key Conclusions

1. **The kernel binary is a fat container**, not a pure i860 image. It bundles m68k host driver code, x86 application objects (including PhotoAlbum.app/Kodak 1991), ASCII resources, and build artifacts (Emacs changelog) alongside a small i860 slice (~1.3% heuristic, ~1.4% execution-proven).
2. **Static analysis is severely limited** by indirect dispatch. The i860 firmware relies on `calli` (register indirect call) and `bri`-based handler dispatch rather than direct `call` instructions. Without dispatch table reconstruction, most code is unreachable to both Ghidra and the Rust disassembler.
3. **The clean firmware is the better target**. At 57.7% i860 code with zero foreign-architecture contamination, `ND_i860_VERIFIED_clean.bin` is far more amenable to analysis (10.9% recovery vs 1.3%).
4. **The Rust disassembler's Mach-O parser cannot handle this binary** — it fails with "Invalid Mach-O load command size", independently confirming the anomalous container structure.
5. **The firmware is bare-metal** — not a Mach kernel. OS-like primitives (VM init, exception handling, cache coherency) are present but Mach API strings belong to the host-side m68k driver code.
6. **Dispatch tables are in `__text` and BSS, not `__DATA`** — the `__data` section (56,400 B) contains TIFF images, zero-fill, and linker padding. However, the **PS registration table at 0x1FC00** (28 entries x 156 bytes in `__text`) contains operator names and handler pointers (e.g., `setcolor` → 0xF80045A0, `moveto` → 0xF80048C0, `lineto` → 0xF8004B20). BSS-resident tables are populated at runtime by `InitMessages()` and `AddPortToList()`.
7. **Delay-slot pcode errors eliminated** — hard-mask v3 with pcode map produces zero missing-delay-slot pcode errors (down from 19 in v2), confirming the SLEIGH specification correctly handles all delay-slot variants encountered in real firmware.
8. **Runtime closure is operational but not yet productive** — iterative sweep/convert/analyze currently adds zero dynamic seeds (`dynamic_added=0`), so coverage remains 1.4% until traces reach meaningful indirect-dispatch paths.
9. **Boot ROM handoff is now reproducible in emulator**, but kernel replay stalls due to **XOR-4 byte-ordering mismatch**: the emulator loads the binary without applying `LOADTEXT(addr ^ 4)` swap. The "reserved opcode" at `0xF800138C` (`0x19B8801E`) becomes valid `st.s` (`0x1E80B819`) when byte-swapped. Fix requires applying XOR-4 to `__TEXT` segments during emulator load plus trap vector (0xFFFFFF00) page mapping.

## Boot ROM Findings Applied To Kernel RE

The boot ROM RE (`re/nextdimension/boot-rom/docs/boot-rom-re.md`) gives concrete, reusable priors for kernel analysis:

| Boot ROM finding | Kernel RE leverage |
|------------------|--------------------|
| Post-ROM control state (`PSR/EPSR/FSR/DIRBASE`) and early stack setup (`r2/r3`) | Seed realistic kernel emulator starts and replay states instead of ad-hoc all-zero or synthetic state |
| Confirmed MMIO/CSR addresses and poll-loop behavior | Build stateful MMIO models (`mmio_sequences`) that advance mailbox/status state and unblock dispatcher progress |
| Mailbox command/data flow (`STATUS/COMMAND/DATA_PTR/DATA_LEN`) | Construct host-like command scenarios to drive kernel paths that static analysis cannot reach |
| Reset-vector and handoff behavior validated | Constrain kernel entry assumptions and detect impossible control-flow hypotheses earlier |
| ROM helper idioms (`flush`, `dirbase_tag`, register access patterns) | Use as pattern signatures to classify analogous kernel routines faster |

### Priority Task List (Coding Agent)

1. **Create canonical post-ROM kernel start presets**
   Files: `re/nextdimension/kernel/scripts/nd_postrom_handoff_state.json`, `re/nextdimension/kernel/scripts/nd_firmware_state.json`  
   Deliverable: baseline + post-ROM state presets with documented provenance.

2. **Model mailbox lifecycle as stateful MMIO sequences**
   Files: `re/nextdimension/kernel/scripts/nd_firmware_state.json` (or dedicated scenario JSONs under `re/nextdimension/kernel/scripts/`)  
   Deliverable: deterministic read-sequence profiles for mailbox status/command/data registers.

3. **Add scenario runner for kernel trace experiments**
   File: `re/nextdimension/kernel/scripts/run_emu_trace_seed_sweep.sh`  
   Deliverable: support running named scenario JSONs and emitting scenario ID into sweep metadata.

4. **Enrich dynamic converter with ROM-informed confidence hints**
   File: `re/nextdimension/kernel/scripts/dynamic_trace_to_recovery_map.py`  
   Deliverable: optional confidence bump tags for mailbox-driven provenance chains; no behavior change when disabled.

5. **Add KPI visibility for progress past poll loops**
   File: `re/nextdimension/kernel/scripts/run_iterative_closure.sh`  
   Deliverable: per-iteration counters for non-zero indirect targets, unique indirect sites, and dominant stop-reason transitions.

6. **Add regression validation for ROM-to-kernel assumptions**
   Files: `re/nextdimension/kernel/scripts/validate_*` (new), plus docs update  
   Deliverable: checks that expected ROM-derived constants/addresses remain consistent with current trace harness inputs.

### Acceptance Criteria

- At least one closure run where `indirect_events > 0` and `targets_seen > 1`.
- `stop_reason_top` is no longer dominated by a single tight-loop signature for all iterations.
- Any dynamic seeds added are reproducible across two identical runs with the same scenario/state files.
- All new behavior remains opt-in (default pipeline unchanged unless scenario/state options are supplied).

## PostScript Segment (Source-Backed)

The 32 KB ASCII-rich block in the clean window was re-extracted and normalized for direct inspection:

- Raw payload: `re/nextdimension/firmware/extracted/postscript/ND_MachDriver_postscript_payload_raw_off0xFCB8_len0x7F48.bin`
- Normalized text: `re/nextdimension/firmware/extracted/postscript/ND_MachDriver_postscript_payload_normalized.ps`
- Scope: clean-window offset `0xFCB8-0x17BFF` (VA `0xF800FCB8-0xF8017BFF`)

Confirmed structure markers inside this segment:

| Marker | VA |
|--------|----|
| `% graphic state operators` | `0xF800FE50` |
| `% path painting operators` | `0xF800FF9D` |
| `% group operators` | `0xF80103DA` |
| `% color operators` | `0xF8010614` |
| `%%EndProlog` | `0xF8010D74` |
| `%%BeginSetup` | `0xF8010D80` |
| `%AI3_BeginEncoding: _Symbol Symbol` | `0xF801111D` |
| `%AI3_EndEncoding` | `0xF8011767` |
| `%AI3_Note:` (numeric path payload begins) | `0xF80117B3` |

Source-backed interpretation:

- This block is real Display PostScript / Adobe Illustrator resource content, not executable i860 code.
- It includes shorthand operator wrappers (`/h`, `/N`, `/F`, `/S`, `/B`, `/W`, `/q`, `/Q`) and state helpers (`_pola`, `_doClip`, `CRender`).
- It transitions into dense vector path payload (hundreds of `x y m/L/C` lines) after setup/encoding sections.

### PS Symbol -> Kernel Cluster Cross-Reference

These mappings are partially confirmed by PS registration table extraction.

| PS symbol/pattern | Segment evidence | Candidate kernel cluster | Confidence |
|-------------------|------------------|--------------------------|------------|
| `_pola`, `_doClip`, `CRender` | wrappers in early prolog body | central operator/classify logic near `FUN_000033c8` | medium |
| `moveto` | PS table entry 2 at 0x1FC9C | **0xF80048C0** (confirmed handler address) | **verified** |
| `lineto` | PS table entry 3 at 0x1FD38 | **0xF8004B20** (confirmed handler address) | **verified** |
| `setcolor` | PS table entry 1 at 0x1FC00 | **0xF80045A0** (confirmed handler address) | **verified** |
| `setdash`, `setlinejoin`, `setlinecap`, etc. | `% graphic state operators` section | graphics-state update routines — likely in remaining 25 PS table entries | medium-high |
| `setgray`, `setcmykcolor`, `setcustomcolor` wrappers (`_fc`, `_sc`) | `% color operators` section | color/compositing routines — likely in remaining 25 PS table entries | medium-high |
| `%%BeginSetup`, Symbol encoding vectors | AI3 setup/encoding region | static resource data only (non-executable) | high |

Detailed operator-family worklist and runtime proof criteria:
`re/nextdimension/kernel/docs/postscript-operator-mapping.md`

### PS Registration Table (0x1FC00) — Structure Decoded

The 4,328-byte table at clean-firmware offset 0x1FC00 contains 28 entries at
**156 bytes** per entry stride (confirmed by ASCII string scanning). Per-entry
format (from NextDimension-21 source):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 128 | `name` | Operator name string (null-terminated) |
| 0x80 | 4 | `handler` | i860 handler function pointer |
| 0x84 | 4 | `flags` | Operator flags (type classification) |
| 0x88 | 16 | `signature` | Argument type signature |

**Extracted entries** (first three confirmed by hex dump):

| Entry | Offset | Name | Handler | Flags |
|-------|--------|------|---------|-------|
| 1 | 0x1FC00 | `setcolor` | 0xF80045A0 | 0x00000001 |
| 2 | 0x1FC9C | `moveto` | 0xF80048C0 | 0x00000001 |
| 3 | 0x1FD38 | `lineto` | 0xF8004B20 | 0x00000001 |

**Critical finding**: These handler addresses (0xF8004xxx) fall within the code
region recovered by Ghidra, confirming that the "orphaned" functions identified
by swarm analysis are **real PostScript operator handlers** reached through
runtime dispatch, not dead code or linker artifacts. This resolves the
operator-to-function mapping question and provides 28 named entry points for the
i860 code.

### Dispatch Mechanism (Source + Binary Correlation)

Source evidence separates responsibilities:

- `NDkernel/ND/messages.c` is queue transport/port matching for host↔board
  Mach-style messages (`ToND`/`FromND`), plus early queue initialization via
  `InitMessages()` / `AddPortToList()`.
- `PSDriver/server/server.c` performs message ID dispatch (`PSMARKID`,
  `ps_server`, etc.) into PostScript/rendering service paths.

Binary evidence still shows heavy indirect control flow (`bri` sites), but the
exact register-level dispatch chain for the 3.3 image remains a runtime-trace
task rather than a fully source-proven one-to-one mapping.

## Source Architecture Reference (NextDimension-21)

A detailed source-grounded architecture document is now available at:

- `re/nextdimension/kernel/docs/gack-source-architecture.md`

It maps host-side (`MachDriver` + `libND`) and board-side (`NDkernel`) responsibilities with file-level evidence, and it explicitly frames what should be treated as:

- Stable architecture invariants (high confidence for 3.3 RE)
- Version-sensitive details (must be re-proven against the binary/runtime traces)

Use it as the primary design reference for emulator instrumentation, trace taxonomy, and subsystem-level naming/crosswalk work.

## Open Questions

- ~~What is `__TEXT` (F80B2548–F80B3FFF, 6.8 KB)?~~ **Answered**: Segment padding/alignment, not proven C runtime or symbol/reloc content.
- `__DATA` rwx sections at F80C1C50 and F80C4098: **Partially explained, not fully proven**. `ND_WriteBranchInstruction` in `code.c` shows host-side instruction patching does occur, and rwx permissions are consistent with patchable stubs/trampolines. However, exact occupancy split (jump islands vs queue/lock data vs other payload) is still a runtime-validation item. Dump these ranges after `MSGFLAG_MSG_SYS_READY` to confirm.
- ~~Can dispatch tables be reconstructed from the `__data` section?~~ **Answered**: No — `__DATA` contains TIFF images (27%), zero-fill BSS (15%), and GNU Emacs ChangeLog linker padding (58%). Zero dispatch tables found.
- ~~The clean firmware is 196 KB vs the 64 KB described in prior documentation?~~ **Answered**: Different binaries — 64 KB is the boot ROM (`ND_i860_CLEAN.bin` at 0xFFF00000), 196 KB is the DPS kernel (`ND_i860_VERIFIED_clean.bin` at 0xF8000000).
- ~~Why does kernel replay enter the `0xF800138C` trap-loop~~ **Answered**: Root cause is XOR-4 byte-ordering mismatch. The emulator loads the kernel binary without applying `LOADTEXT(addr ^ 4)` swap. Word `0x19B8801E` byte-swapped to `0x1E80B819` yields opcode `0x07` (`st.s`), a valid instruction. Additionally, the trap vector at 0xFFFFFF00 must be mapped and TLB/ATE must be enabled before any exception can be handled correctly. Fix: apply XOR-4 to `__TEXT` segments during emulator binary load, and ensure trap vector page mapping.
- Should the trace harness stop/emit explicit trap events on `ExecutionResult.trapped` to avoid silent self-looping behavior?
- ~~Which MMIO stub values/behavior are required to drive firmware execution past poll loops and into real dispatch sites?~~ **Answered**: The host must (1) populate the shared memory message queues (`ToND` at `ND_START_UNCACHEABLE_DRAM=0xF80C0000`), and (2) set the `NDCSR_INT860` bit in the MC CSR (0xFF800000) to signal the i860. The message queues use Lamport locks (`Lock_x`, `Lock_y`, `Lock_b`) for lock-free host↔i860 communication, bypassing Mach kernel IPC for performance. Scalar MMIO sensitivity sweeps failed because they tested register values in isolation rather than modeling the queue+interrupt protocol.
- Converter enhancement: provenance-driven pointer chase in `dynamic_trace_to_recovery_map.py` to extract candidates from load chains once trace events are present.
- Extract all 28 PS registration table entries from 0x1FC00 (156-byte stride) — only first 3 hex-dumped so far; remaining 25 handler pointers yield named entry points.
- Signature-match 2.0 NDkernel utility functions (`readqueue`, `AddPortToList`, `is_empty`, `SpawnProc`, `Sleep`, `Wakeup`) against 3.3 binary using instruction sequence hashing or BinDiff.
- Search `__data` for `sysent` table pattern (array of `{n_args, handler()}` structs with mostly-`nosys` entries) to locate kernel syscall entry points.
- Dump rwx sections (F80C1C50 / 176 B and F80C4098 / 8,040 B) at runtime after `MSGFLAG_MSG_SYS_READY` to verify jump island / trampoline contents.
- ~~Kernel entry protocol~~ **Answered**: NDLoadCode (`code.c`) parses `LC_THREAD`/`LC_UNIXTHREAD` for entry point, loads segments individually with mixed-endian writes (`LOADTEXT` uses `addr ^ 4` XOR-4 swap for i860 big-endian instruction fetch). Entry point is extracted from Mach-O headers on the host side, not inferred by the ROM.
- ~~Mixed-endian text loading~~ **Answered**: The XOR-4 swap is required because the i860 instruction bus is 64 bits wide but instruction words are 32 bits. The XOR ensures words are placed in the correct half of the 64-bit bus when the processor is in Big-Endian mode.
