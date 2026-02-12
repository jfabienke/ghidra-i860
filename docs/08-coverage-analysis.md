# Byte-Coverage Analysis — ND_MachDriver_reloc

## Byte-Coverage Matrix (Original ND_MachDriver_reloc = 795,464 bytes)

| # | Region | Bytes | % Total | What we know | Open question |
|---|--------|------:|--------:|--------------|---------------|
| 1 | Mach-O header + load commands (pre-\_\_TEXT) | 840 | 0.11% | Fully parsed/accounted | None material |
| 2 | \_\_text section | 730,440 | 91.83% | 100% byte-typed (heuristic); embedded Mach-Os at 0x017CB8, 0x03DCB8, 0x05DCB8 | Which bytes are truly executable i860 code? (beyond current proven CFG islands) |
| 3 | \_\_TEXT tail (segment bytes outside \_\_text) | 6,840 | 0.86% | Accounted; currently looks foreign/non-i860 | Any meaningful i860 content here? |
| 4 | \_\_data section | 56,400 | 7.09% | Reconciled: TIFF/LZW + zero-fill + ChangeLog | No static dispatch table found; runtime only? |
| 5 | \_\_DATA tail (segment bytes outside \_\_data) | 944 | 0.12% | **CLOSED**: 176 B inter-section alignment padding + 768 B segment file padding in \_\_bss VA range; 100% GNU Emacs ChangeLog text; linker artifact | None — fully mapped |
| | **TOTAL** | **795,464** | **100.00%** | **Byte accounting complete** | — |

## \_\_text Heuristic Typing (730,440 bytes)

Classification, not proof of execution. Scoped to \_\_text section only; the raw contamination survey extends 7,016 bytes into \_\_TEXT tail and \_\_DATA regions (total 737,456), but only the 730,440 bytes within \_\_text section boundaries are included here.

**Why so little i860?** The full `\_\_text` section is a multi-architecture linker accident — NeXT's 1993–94 toolchain bundled m68k host driver code, x86 NeXTSTEP/Intel application objects, PostScript text, TIFF images, and the GNU Emacs ChangeLog alongside the actual i860 firmware, all within a single section. The i860 code is concentrated in the first ~200 KB (the "clean window"). When that window is analyzed in isolation, the breakdown is very different:

| Scope | i860 Code | % of Scope | Total |
|-------|----------:|-----------:|------:|
| Full \_\_text (below) | 1,024 B | 0.1% | 730,440 B |
| Clean window only | 115,712 B | 57.7% | 200,704 B |
| Execution-proven (CFG) | 10,144 B | 1.4% | 730,440 B |

The remaining ~530 KB (73% of \_\_text) is currently classified as foreign/non-executed under present evidence (see "What Is Still Open" item 1). Of the 116 KB heuristically classified as i860 in the clean window, only 10,144 bytes are execution-proven — the rest requires resolving 616 `bri rN` dynamic dispatch sites.

| Type | Bytes | % | Description |
|------|------:|--:|-------------|
| X86\_CODE | 298,312 | 40.8% | Two embedded x86/i386 Mach-O objects (CEFAEDFE little-endian) at 0x03DCB8 and 0x05DCB8. Executable code for NeXTSTEP/Intel applications — PhotoAlbum.app ("Copyright 1991, Eastman Kodak Company", built Fri Oct 21 1994) and likely NeXTtv.app video demo. NeXTSTEP/Intel transition linker artifact (1993–94). 100% dead code; never executed by i860. Heuristic over-matches compressed data in \_\_DATA (lesson #50) |
| NULL\_PAD | 115,712 | 15.8% | Zero-filled alignment gaps between embedded architecture blocks, linker page-boundary fill, inter-object padding. Concentrated in transition zones between x86/m68k objects and the sparse region (0xF8038000–0xF805B000) |
| ASCII\_TEXT | 108,544 | 14.9% | Multiple sources: (1) Display PostScript prolog with 26 Adobe Illustrator operator shortcuts at 0xF800F800 — functional, referenced by the PS interpreter; (2) PostScript coordinate data and diagnostic strings; (3) GNU Emacs 18.x ChangeLog (Oct 1986–Feb 1987, RMS/Mlynarik/Hanson/Tower) embedded as linker padding. Largest contiguous block: 32 KB at 0xF800FC00 |
| X86\_DATA | 71,680 | 9.8% | Initialized data sections of the embedded x86 Mach-O objects — constants, string tables, relocations. Interleaved with X86\_CODE blocks throughout 0xF8024000–0xF806B000 |
| BIN\_DATA | 54,272 | 7.4% | Unclassifiable binary: cannot be decoded as any recognized architecture. Includes mixed binary payloads and transition-zone fragments between classified regions. Scattered in small (1–2 KB) blocks across the full \_\_text range |
| M68K\_CODE | 41,984 | 5.7% | Host-side NeXTdimension driver from embedded m68k Mach-O (FEEDFACE big-endian, MH\_OBJECT, 3 load commands) at 0x017CB8. Concentrated in 0xF8018000–0xF8020800. Handles host↔i860 communication, DMA coordination, and command queueing via Mach IPC kernel ports. Confirmed m68k instruction patterns: `move.l` pushes, `bsr.l` calls |
| M68K\_DATA | 27,648 | 3.8% | Data sections of the embedded m68k host driver object — constants, string tables, initialized data. Interleaved with M68K\_CODE blocks in the 0xF8018000–0xF8023000 range |
| I860\_SPARSE | 8,192 | 1.1% | Blocks where some bytes decode as valid i860 instructions but without sufficient density or control-flow connectivity to classify as code. Likely foreign-architecture bytes that happen to decode validly — i860 ISA decodes any 4-byte sequence as a valid instruction (lesson #16). Eight scattered 1 KB blocks |
| MACHO\_X86 | 3,072 | 0.4% | Embedded Mach-O headers and load commands at three locations: m68k object header at 0x017CB8 (FEEDFACE), x86 object headers at 0x03DCB8 and 0x05DCB8 (CEFAEDFE). Label is generic despite including the m68k header |
| I860\_CODE | 1,024 | 0.1% | Single 1 KB block (0xF8008C00–0xF8008FFF) with high i860 instruction density (88 decoded instructions per 1,024 bytes) and valid control-flow patterns. Conservative heuristic — execution-proven i860 code is 10,144 bytes (see next section) |

## Execution-Proven i860 (Current Strict Harness)

- 10,144 bytes, 2,536 instructions, 60 functions
- 1.28% of full firmware, 1.39% of \_\_text
- Phase 2 added 0 new seeds (runtime-computed bri remains the blocker)

### Current Snapshot (As of February 10, 2026)

| Metric | Value | Source |
|--------|-------|--------|
| Execution-proven instructions | 2,536 | `re/nextdimension/kernel/reports/i860_kernel_report.txt` |
| Execution-proven functions | 60 | `re/nextdimension/kernel/reports/i860_kernel_report.txt` |
| Execution-proven code bytes | 10,144 | `re/nextdimension/kernel/reports/i860_kernel_report.txt` |
| Coverage | 1.4% | `re/nextdimension/kernel/reports/i860_kernel_report.txt` |
| Iterative closure (latest) | `dynamic_added=0` | `re/nextdimension/kernel/reports/iterative_closure/20260210-235407/kpi.csv` |
| Targets seen in latest closure pass | 0 | `re/nextdimension/kernel/reports/iterative_closure/20260210-235407/kpi.csv` |

## \_\_DATA Tail Provenance (944 bytes — CLOSED)

The \_\_DATA segment has 3 sections, not just \_\_data:

| Section | Type | VA | Size | File offset |
|---------|------|----|-----:|-------------|
| \_\_data | S\_REGULAR | 0xF80B4000 | 56,400 | 738120 |
| \_\_bss | S\_ZEROFILL | 0xF80C1D00 | 2,752 | 0 (no file backing) |
| \_\_common | S\_ZEROFILL | 0xF80C27C0 | 6,360 | 0 (no file backing) |

The 944-byte tail (segment-relative 0xDC50–0xDFFF) breaks down as:

| Range (seg-rel) | Bytes | Classification |
|-----------------|------:|----------------|
| 0xDC50–0xDCFF | 176 | Inter-section alignment padding: \_\_bss align=2^8=256 requires VA 0xF80C1D00; gap from \_\_data end |
| 0xDD00–0xDFFF | 768 | Segment file padding in \_\_bss VA range: segment filesize (0xE000) extends past \_\_data; \_\_bss is ZEROFILL so these file bytes are inert |

All 944 bytes are 100% printable ASCII: GNU Emacs ChangeLog entries (October 1986, Richard Mlynarik at MIT). The linker did not zero the gap, leaving stale object-file buffer content. At runtime, the \_\_bss portion (0xDD00–0xDFFF) is overwritten with zeros by the Mach-O loader.

**Conclusion**: No i860 code, no data structures, no dispatch tables. Pure linker/alignment artifact.

## What We Know Now

1. Byte accounting is airtight (100%).
2. \_\_DATA contains no static flat dispatch table (TIFF/LZW, zero-fill, ChangeLog).
3. Static cross-block BRI resolution hit the structural limit (no valid new targets).
4. \_\_DATA tail (944 B) fully mapped: alignment padding + segment file padding, all ChangeLog text.

## LLM Swarm Analysis (60 Promoted Functions)

A 4-stage LLM pipeline (intent claim → verification → contrarian challenge → synthesis) analyzed all 60 promoted functions using Claude via the Agent SDK Max backend.

### Pipeline

| Stage | Purpose | Model |
|-------|---------|-------|
| Intent | Classify function purpose, identify evidence | Claude (Max) |
| Verification | Cross-check claims against disassembly evidence | Claude (Max) |
| Contrarian | Challenge primary intent, propose alternatives | Claude (Max) |
| Synthesis | Group accepted functions into subsystems | Claude (Max) |

### Run 1 — Noisy Shards (Combined Prod + Retry)

Run on original shards containing 219 false `mmio_high_space` tags from an over-broad MMIO heuristic in ExportFactPack.java (scalar threshold matching instead of effective-address computation).

| Metric | Value |
|--------|-------|
| Functions analyzed | 60 (prod) + 35 (retry overlap) |
| Accepted | 32 (53%) |
| Revise | 22 (37%) |
| Reject | 6 (10%) |
| Subsystems identified | 0 |
| Total tokens | 1.67M |

Note: 32/22/6 is a combined baseline across two runs (prod 60 + retry 35 with overlapping function sets), not a single-pass metric.

### Run 2 — Cleaned Shards (Single Pass)

After removing all `mmio_high_space`, `mmio_low_space`, and `mmio_scalar_match` tags from shards and fixing ExportFactPack.java to compute effective addresses for MMIO tagging.

| Metric | Value |
|--------|-------|
| Functions analyzed | 60 |
| Accepted | 52 (87%) |
| Revise | 6 (10%) |
| Reject | 2 (3%) |
| Subsystems identified | 0 |
| Total tokens | 1.52M (1.13M in, 392K out) |
| Run ID | `3f574718` |

The +20 accept swing (53% → 87%) came entirely from input cleanup — no prompt changes. This confirms that noisy input context dominates LLM verdict quality (lesson #59).

### Key Findings

All findings below are **LLM-classified outcomes**, not ground truth. Confidence is capped by the structural limitations of the input (isolated functions with zero call-graph context). The 616 unresolved `bri` sites mean these functions could be reachable via runtime dispatch paths not yet proven.

1. **LLM-inferred: 50+/52 accepted functions classified as dead code or compiler artifacts**: zero callers in the promoted execution set, 70–95% of instructions write to hardwired-zero sink registers (r0, f0, f1), missing or invalid return mechanisms.
2. **LLM-inferred: zero subsystems identified**: no call graph edges connect the analyzed functions — all are isolated in the current promoted set.
3. **No known firmware patterns matched**: PostScript dispatch signatures (r15 GState, xorh 0x10c6 hash, 0xe827 classify), MMIO token reads (0x401C), and threaded interpreter chains were absent in the analyzed set.
4. **Supports static analysis ceiling hypothesis**: the 60 promoted functions are execution-proven but represent the discoverable fringe of the firmware. Real functional logic likely sits behind 616 unresolved `bri rN` dynamic dispatch sites that require emulation to resolve.
5. **MMIO tag quality is critical**: false MMIO tags caused the LLM to fabricate hardware-interaction narratives for functions that had no valid MMIO accesses, suppressing dead-code verdicts.

### Regression Check

`scripts/swarm/validate_factpack.py` validates factpack exports against:
- Banned broad MMIO tags (`mmio_high_space`, `mmio_low_space`, `mmio_scalar_match`)
- Non-memory instructions incorrectly tagged with MMIO labels
- Shard/manifest consistency

Run before every swarm invocation to prevent noisy-input regressions.

### Outputs

- Run 1 (noisy): `re/nextdimension/kernel/reports/factpack/swarm_prod_20260209/`
- Run 1 retry: `re/nextdimension/kernel/reports/factpack/swarm_retry_20260209/`
- **Run 2 (cleaned)**: `re/nextdimension/kernel/reports/factpack/swarm_run_20260210-080750/`
- Synthesis report: `re/nextdimension/kernel/reports/factpack/swarm_run_20260210-080750/synthesis.json`
- Claims database: `re/nextdimension/kernel/reports/factpack/swarm_run_20260210-080750/claims.db`

## What Is Still Open

1. True executable i860 extent inside \_\_text contamination-heavy regions.
2. Where/when dispatch targets are materialized at runtime (BSS/common/init path).
3. Operator-to-handler mapping for dynamic `bri rN` dispatch.
4. Precise role of embedded m68k/x86 payloads in final board runtime.
5. Register provenance tracking for bri/calli dispatch chains (implemented in emulator; next step: wire provenance parsing and pointer-chase confidence tiers into `dynamic_trace_to_recovery_map.py`).
6. MMIO stub values for firmware poll loops: mailbox signal (0x0200001C), interrupt status (0x020000C0), system control (0x02000100).

## Closing The Open Questions

### Emulation Pipeline (End-to-End Validated)

The runtime evidence pipeline is fully operational:

1. **Sweep**: `run_emu_trace_seed_sweep.sh` runs `nd_trace` per entry point with `I860_TRACE_JSONL`, producing per-entry JSONL trace files.
   The sweep CSV/manifest now captures `stop_reason` (`max_steps`, `trapped ...`, `execute_error ...`) for each entry to make failure mode triage machine-readable.
2. **Convert**: `dynamic_trace_to_recovery_map.py` scores candidate targets by hit count, unique source-site count, `calli` bonus, alignment, and executable range filter.
3. **Analyze**: `run_analysis.sh` accepts dynamic trace JSONL as 5th argument (or `DYNAMIC_TRACE_JSONL` env var), auto-merging runtime-discovered targets into the recovery map.
4. **Iterate**: `run_iterative_closure.sh` loops sweep → convert → analyze → compare until `dynamic_added == 0` or max iterations reached, tracking KPIs per iteration.

`run_iterative_closure.sh` now also supports optional auto state-gap refinement:
- `CLOSURE_AUTO_STATE_GAPS=1`
- `CLOSURE_STATE_HINTS_JSON=<path>`

In this mode, each iteration runs `generate_state_from_trace.py`, records `state_gap_top`, and can apply hint-driven state mutations before the next iteration.

State injection (`nd_firmware_state.json`) provides initial register values and MMIO stub return values. The sweep script passes this as the 7th parameter or `SWEEP_STATE_JSON` env var.

### Step 2 Provenance Status (Implemented)

Step 2 (register provenance tracking) is now implemented in the emulator runtime tracer:

- `ExecutionEngine` tracks per-register provenance tuples `(writer_pc, source_type, source_addr_or_reg)`.
- Instrumented handlers: `addu_imm`, `or_imm`, `orh`, and integer load forms (`ld.b`, `ld.s`, `ld.l`).
- `indirect_branch` trace events now include `provenance` with writer metadata and one-level backchain for ALU-derived values.

Current observed traces still frequently show `provenance: null` at `bri` sites because source registers remain zero on those paths. This indicates trace-depth/runtime-state limits rather than missing instrumentation. Next step is to consume these provenance fields in `dynamic_trace_to_recovery_map.py` for pointer-chase candidate extraction.

### Current Blockers

The pipeline works end-to-end but still produces `dynamic_added=0`. Current blockers are now better localized:

**1. Entry-path unaligned fault (baseline kernel start).** From `0xF8000348`, the trace advances ~1,040 instructions and stops at `0xF8001388` with `Unaligned access at 0xFFFF801E`.

**2. Trap-loop at `0xF800138C` (when unaligned is bypassed).** With `I860_ALLOW_UNALIGNED=1` and post-ROM handoff state replay, execution reaches a hot self-loop at `0xF800138C` (`~48,959` hits in 50k steps). The word there is `0x19B8801E` (primary opcode `0x06`, reserved in MAME decode table), so execution is entering a non-code/reserved-op region before dispatch-producing paths.

**3. MMIO model still too shallow for firmware progression.** In the above looping run, only two MMIO reads occur (`0xFF800000`, `0xFF800008`, once each). No mailbox/interrupt work-queue progression is observed, and no indirect branch events are emitted.

Targeted sensitivity sweep (49 combinations) over `0xFF800000`/`0xFF800008` stub values produced the same outcome in every case: trapped at `0xF800138C` (`0x19B8801E`, exception `0x1`). This suggests those two scalar MMIO values are not the primary gate for this path.

Observed with auto state-gap refinement (`20260211-020258`):
- Iteration 1: `state_gap_top=r8:1`, one hint-applied mutation (`r8=0xF8008100`)
- Iteration 2: `state_gap_top=r18:1`, events increased (`indirect_events: 1 -> 2`)
- Coverage and dynamic map unchanged (`dynamic_added=0`, 60 funcs, 2,536 insns)

Additional context:
- **Boot ROM handoff was reproduced.** Running ROM from `0xFFF00020` to stop-PC `0x00000000` completed in 203 instructions and dumped a reusable post-ROM state.
- **LC\_UNIXTHREAD zero-init remains correct.** Kernel register-zero startup is expected; ROM/boot path initialization is what must be modeled correctly.
- NDserver RE (host-side M68k driver) confirmed host control is IPC-driven; i860 firmware performs board-side MMIO sequencing.
- `nd_trace` now supports stateful MMIO read sequences via `mmio_sequences` in state JSON (per-address sequence, then hold-last), plus basic write-readback latching for MMIO writes.

| Rank | Blocker | Symptom | Primary owner | Next action |
|------|---------|---------|---------------|-------------|
| 1 | Entry-path unaligned fault | `0xF8000348 -> 0xF8001388` then execute error (`0xFFFF801E`) | Emulator (`i860-core`) | Fix effective-address/alignment behavior on this path (or model exact hardware semantics) |
| 2 | Trap-loop at `0xF800138C` | `0xF800138C -> 0xF800138C` back-edge dominates run | Emulator (`i860-core` + `nd_trace`) | Identify the control-flow/state path that falls into reserved-opcode region (opcode `0x06` is expected invalid) |
| 3 | MMIO progression absent | Only `0xFF800000`/`0xFF800008` reads; no mailbox-driven progress | Emulator MMIO model | Add stateful MMIO behavior for boot/kernel poll points beyond fixed scalar stubs |
| 4 | Dynamic `bri` targets unresolved | `dynamic_added=0` in closure loop | Converter + harness | Parse provenance chain and enable pointer-chase confidence tiers once traces include indirect events |

### Minimum Acceptance Criteria

- New dynamic seeds added to recovery map (non-zero `dynamic_added`).
- Increase in execution-proven instructions/functions without reopening deny-range contamination.
- At least one resolved operator-dispatch edge (`dispatch site -> concrete handler addr`) from runtime traces.
- Stable results across at least two independent emulator runs.

### Repro Commands

Single sweep (trace + conversion):

```bash
./re/nextdimension/kernel/scripts/run_emu_trace_seed_sweep.sh \
  re/nextdimension/kernel/i860_kernel.bin \
  0xF8000000 200000 \
  /tmp/i860_emu_trace_sweep \
  re/nextdimension/kernel/docs/recovery_map_hardmask_pcode.json \
  "" \
  re/nextdimension/kernel/scripts/nd_firmware_state.json
```

One-pass analysis with optional dynamic trace merge:

```bash
./re/nextdimension/kernel/scripts/run_analysis.sh \
  re/nextdimension/kernel/i860_kernel.bin \
  - \
  re/nextdimension/kernel/docs/recovery_map_hardmask_pcode.json \
  /tmp/factpack_out \
  /tmp/i860_emu_trace_sweep/runtime_trace_merged.jsonl
```

Iterative closure loop:

```bash
./re/nextdimension/kernel/scripts/run_iterative_closure.sh \
  re/nextdimension/kernel/i860_kernel.bin \
  re/nextdimension/kernel/docs/recovery_map_hardmask_pcode.json \
  re/nextdimension/kernel/scripts/nd_firmware_state.json \
  5
```

## Sources

- `re/nextdimension/firmware/extracted/BYTE_ACCOUNTING.txt` (canonical)
- `re/nextdimension/firmware/extracted/SEGMENTS.txt` (canonical)
- `re/nextdimension/firmware/extracted/EMBEDDED_MACHO_HEADERS.txt` (canonical)
- `re/nextdimension/kernel/reports/contamination_survey.txt`
- `re/nextdimension/kernel/reports/i860_kernel_report_hardmask_pcode_phase1_promoted.txt`
- `re/nextdimension/firmware/analysis/phase2/cross_block_results.json`
- `re/nextdimension/firmware/analysis/phase2/phase2_seeds.json`
- `re/nextdimension/firmware/analysis/provenance/data_tail_map.json`
- `re/nextdimension/kernel/reports/factpack/swarm_prod_20260209/claims.db` (Run 1)
- `re/nextdimension/kernel/reports/factpack/swarm_retry_20260209/synthesis.json` (Run 1 retry)
- `re/nextdimension/kernel/reports/factpack/swarm_run_20260210-080750/claims.db` (Run 2 — canonical)
- `re/nextdimension/kernel/reports/factpack/swarm_run_20260210-080750/synthesis.json` (Run 2 — canonical)
- `re/nextdimension/boot-rom/README.md` (boot ROM control-register/MMIO initialization context)
