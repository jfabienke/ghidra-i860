# Ghidra m68k Findings (2026-02-13)

## Scope

This note captures concrete findings from headless Ghidra m68k analysis of:

- NeXTSTEP 3.3 host executable `NDserver`
- OPENSTEP 4.2 host executable `m68k_exec_i860seg_5aa8000.bin`
- OPENSTEP 4.2 embedded m68k bundle `obj1_m68k_bundle_018000_60976.bin`

## Core Result

The OPENSTEP 4.2 host executable is very close to the 3.3 host executable in m68k behavior, while the embedded 4.2 m68k bundle carries the richer ND driver logic (`ND_Load_MachDriver`, `ND_MachDriver_reloc`, `ND_Port_check_in`, display path handlers).

For reverse engineering, this means the 4.2 bundle is the primary host-side target, not the thin top-level executable wrapper.

## Quantitative Snapshot

- 3.3 `NDserver`:
  - `function_total`: 88
  - `instruction_total`: 4939
  - `interesting_strings_total`: 62
- 4.2 host exec:
  - `function_total`: 66
  - `instruction_total`: 4490
  - `interesting_strings_total`: 56
- 4.2 embedded m68k bundle:
  - `function_total`: 190
  - `instruction_total`: 8050
  - `interesting_strings_total`: 32

Source reports:

- `re/nextdimension/ndserver_re/reports/ndserver_33_m68k_summary.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_exec_m68k_summary.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_m68k_summary.txt`

## Function-Level Anchors

### 3.3 vs 4.2 host executable

Top candidate functions align nearly 1:1 with small address drift:

- `FUN_0000399c` (3.3) <-> `FUN_0000398c` (4.2):
  port allocation/set registration and main receive/send loop.
- `FUN_00002dc6` (3.3) <-> `FUN_00002dae` (4.2):
  board discovery and boot/pager setup path (`ND_GetBoardList`, `ND_BootKernelFromSect`, `ND_SetPagerTask`).
- `FUN_00006474` (3.3) <-> `FUN_00006472` (4.2):
  `NDUX_Init` check-in helper path (`ND_Port_check_in`).

Source reports:

- `re/nextdimension/ndserver_re/reports/ndserver_33_interesting_decomp.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_exec_interesting_decomp.txt`

### 4.2 embedded m68k bundle

High-value recovered anchors:

- `FUN_7000210a`: top-level ND driver orchestrator (`ND_Load_MachDriver`, `ND_GetBoardList`, timeout/error handling)
- `FUN_7000998e`: kern_loader state machine for `/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc`
- `FUN_700025bc`: NDserver startup path and PostScript hook registration (`NDserver died on startup`)
- `FUN_70009d14`: `ND_Port_check_in()` helper
- `FUN_70003ba6` / `FUN_70003c9a`: `nd_start_video` flow
- `FUN_70004514`: `nd_resumerecording` flow
- `FUN_70005bf4`: CIE-table creation/error path

Source report:

- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_interesting_decomp.txt`

## Binary Delta: 3.3 vs 4.2 Host Executable

Comparison report:

- `re/nextdimension/ndserver_re/reports/ndserver_33_vs_42_exec_compare.md`
- `re/nextdimension/ndserver_re/reports/ndserver_33_vs_42_exec_compare.json`

Key deltas:

- file size delta: `+172,032` bytes (4.2 - 3.3)
- `__I860` segment growth matches this delta (`0xC4000` -> `0xEE000`)
- `__TEXT,__text` similarity ratio: `0.951945`
- only user-visible `__cstring` CLI delta detected:
  - 3.3: `Usage: %s [-s Slot]`
  - 4.2: `Usage: %s [-NDSlot Slot]`

## Pollution Comparison (i860 payload embedded foreign objects)

From extraction manifests:

- 3.3 i860 payload (`802,816` bytes):
  - foreign bytes: `246,468` (`30.7%`)
  - foreign object count: `3`
  - foreign types: `m68k object` + `i386 execute` x2
- 4.2 i860 payload (`974,848` bytes):
  - foreign bytes: `429,856` (`44.09%`)
  - foreign object count: `6`
  - foreign types: `m68k bundle` + `i386 execute` x2 + `sparc execute` x3

Source manifests:

- `re/nextdimension/ndserver_re/artifacts/extracted/nd33/i860_scan/manifest.json`
- `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_scan/manifest.json`

## Implication For RE Effort

- Yes: OPENSTEP 4.2 has the same embedded-foreign-object pattern as 3.3, and it is stronger by both absolute bytes and percentage.
- The 4.2 embedded m68k bundle at `0x18000` is the highest-value host driver target for naming and protocol recovery.
- The 4.2 top-level host executable should be treated as a close variant wrapper around the older 3.3 control flow.
