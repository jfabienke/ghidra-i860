# PostScript Operator -> i860 Handler Mapping

## Purpose
This document turns the extracted PostScript payload into a concrete reverse-engineering worklist for the GaCK i860 firmware.

Inputs:
- `re/nextdimension/firmware/extracted/postscript/ND_MachDriver_postscript_payload_normalized.ps`
- `re/nextdimension/firmware/docs/firmware-analysis.md`
- `re/nextdimension/kernel/docs/analysis-findings.md`

Scope:
- Hypothesis mapping only (static evidence + confidence).
- Runtime evidence requirements to prove or reject each mapping.

## Source-Backed Operator Catalog
Primary operator definitions are in the normalized PS payload:

| Family | Operators | PS lines |
|---|---|---|
| Path construction | `/m /l /c /v /y /h /N /n` | 2-47, 84-100 |
| Path painting | `/F /f /S /s /B /b /W` | 101-171 |
| Group/polarization | `/u /U /q /Q /*u /*U /D` | 182-208 |
| Placement/text wrapper | ``/` /~ /*`` | 172-179, 211-225 |
| Graphic-state | `/d /i /j /J /M /w` | 51-79 |
| Color | `/O /R /g /G /k /K /x /X` | 228-417 |
| Lock/annotation | `/A /annotatepage` | 420-431 |

Known helper symbols in this payload:
- `_doClip`, `CRender`, `_lp`, `_fc`, `_sc`, `_pf`, `_ps`, `_psf`, `_pjsf`, `_pss`, `_pjss`
- `_pola` is referenced and used for deferred rendering behavior.

## Mapping Hypotheses
Candidate i860 clusters come from current firmware analysis findings.

| PS family | Candidate i860 cluster(s) | Current evidence | Confidence | Runtime proof needed |
|---|---|---|---|---|
| Dispatch/core (`/N`, `_pola`, `CRender`, `_doClip`) | `0x33C8` central dispatch, `0x7AD8-0x7DC0` name lookup | type-mask logic (`and 0xe827`), hash/name chain, indirect dispatch patterns | Medium | Trace `bri` targets from dispatch entry and correlate with `_pola` state transitions |
| Path construction (`/m /l /c /v /h`) | `0x3C10` (Bezier), `0x80D4` (segment processing), `0x4650` (coord loop) | FP-heavy geometry kernels and path-like load/store patterns | Medium | For each operator token, observe entry handler and confirm geometry op sequence (`m/L/C` style control flow) |
| Paint (`/F /S /B /W`) | `0x8D10`, `0x882C`, `0x1C34` | fill/stroke-like data movement, MMIO-adjacent rendering primitives | Low-Medium | Demonstrate distinct handler targets for fill/stroke and clip-flag behavior (`_doClip`) |
| Graphics state (`/d /i /j /J /M /w /q /Q`) | `0x44C8` (gsave/grestore), `0x5510` (GState setter), nearby small control routines | direct GState flag patterns (`orh/xorh 0x6514`) | Medium | Show state mutation in the same register block prior to rendering (`_lp`, line style, join/cap/miter) |
| Color (`/g /G /k /K /x /X /O /R`) | `0x90A8` color fill/image, `0x882C` output path | color-heavy rendering and blend-like shift chains | Low-Medium | Validate separate grayscale/CMYK/custom-color paths via register/value traces |
| Text/placement (``/` /~ /*`` + `Tx/Tp/Tf`) | `BLOCK3` text-adjacent path island candidates | payload contains many text placement calls and Symbol encoding setup | Low | Identify handlers that process text placement commands and font-state changes |

## Priority Runtime Tasks
These tasks are ordered to maximize closure on ambiguous mappings.

1. Dispatch resolution first
- Entry points: `0xF80033C8`, `0xF8007AD8`
- Goal: recover non-zero indirect targets and cluster by recurrence.

2. Clip/deferred-render behavior
- Trigger `/N`, `/W`, `/F`, `/S`, `/B` sequences.
- Goal: verify `_doClip` and `CRender` semantics via handler divergence.

3. Geometry family separation
- Trigger `/m /l /c /v /h` patterns.
- Goal: prove which path kernels are shared vs operator-specific.

4. Color family separation
- Trigger `/g`, `/G`, `/k`, `/K`, `/x`, `/X` with distinct operands.
- Goal: confirm grayscale, CMYK, and custom-color handlers are distinct.

5. Text/placement linkage
- Trigger `/*` and placement wrappers.
- Goal: identify whether text path is active in GaCK runtime or dormant payload.

## Evidence Contract (Close Criteria)
A mapping is considered proven when all are true:
- One stable indirect-target cluster (same target seen across >=3 runs).
- A reproducible operator stimulus -> handler target relationship.
- Internal state side effects match PS semantics (clip flag, paint mode, color mode, or geometry progression).
- Repeatability across two identical runs with identical MMIO scenario.

## Current Blocking Risks
- Runtime still often halts or loops before productive dispatch (`0xF8001388/0xF800138C` path).
- MMIO behavior may be too shallow for mailbox-driven work progression.
- Some PS payload may be bundled resource content not exercised in normal firmware path.

