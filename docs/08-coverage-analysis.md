# Byte-Coverage Analysis — ND_MachDriver_reloc

## Byte-Coverage Matrix (Original ND_MachDriver_reloc = 795,464 bytes)

| # | Region | Bytes | % Total | What we know | Open question |
|---|--------|------:|--------:|--------------|---------------|
| 1 | Mach-O header + load commands (pre-\_\_TEXT) | 840 | 0.11% | Fully parsed/accounted | None material |
| 2 | \_\_text section | 730,440 | 91.83% | 100% byte-typed (heuristic); embedded Mach-Os at 0x017CB8, 0x03DCB8, 0x05DCB8 | Which bytes are truly executable i860 code? (beyond current proven CFG islands) |
| 3 | \_\_TEXT tail (segment bytes outside \_\_text) | 6,840 | 0.86% | Accounted; currently looks foreign/non-i860 | Any meaningful i860 content here? |
| 4 | \_\_data section | 56,400 | 7.09% | Reconciled: TIFF/LZW + zero-fill + ChangeLog | No static dispatch table found; runtime only? |
| 5 | \_\_DATA tail (segment bytes outside \_\_data) | 944 | 0.12% | Mostly ASCII (ChangeLog-like continuation) | Exact linker/section provenance |
| | **TOTAL** | **795,464** | **100.00%** | **Byte accounting complete** | — |

## \_\_text Heuristic Typing (730,440 bytes)

Classification, not proof of execution. Scoped to \_\_text section only; the raw contamination survey extends 7,016 bytes into \_\_TEXT tail and \_\_DATA regions (total 737,456), but only the 730,440 bytes within \_\_text section boundaries are included here.

| Type | Bytes | % |
|------|------:|--:|
| X86\_CODE | 298,312 | 40.8% |
| NULL\_PAD | 115,712 | 15.8% |
| ASCII\_TEXT | 108,544 | 14.9% |
| X86\_DATA | 71,680 | 9.8% |
| BIN\_DATA | 54,272 | 7.4% |
| M68K\_CODE | 41,984 | 5.7% |
| M68K\_DATA | 27,648 | 3.8% |
| I860\_SPARSE | 8,192 | 1.1% |
| MACHO\_X86 | 3,072 | 0.4% |
| I860\_CODE | 1,024 | 0.1% |

## Execution-Proven i860 (Current Strict Harness)

- 10,144 bytes, 2,536 instructions, 60 functions
- 1.28% of full firmware, 1.39% of \_\_text
- Phase 2 added 0 new seeds (runtime-computed bri remains the blocker)

## What We Know Now

1. Byte accounting is airtight (100%).
2. \_\_DATA contains no static flat dispatch table (TIFF/LZW, zero-fill, ChangeLog).
3. Static cross-block BRI resolution hit the structural limit (no valid new targets).

## What Is Still Open

1. True executable i860 extent inside \_\_text contamination-heavy regions.
2. Where/when dispatch targets are materialized at runtime (BSS/common/init path).
3. Operator-to-handler mapping for dynamic `bri rN` dispatch.
4. Precise role of embedded m68k/x86 payloads in final board runtime.

## Sources

- `re/nextdimension/firmware/extracted/BYTE_ACCOUNTING.txt` (canonical)
- `re/nextdimension/firmware/extracted/SEGMENTS.txt` (canonical)
- `re/nextdimension/firmware/extracted/EMBEDDED_MACHO_HEADERS.txt` (canonical)
- `re/nextdimension/kernel/reports/contamination_survey.txt`
- `re/nextdimension/kernel/reports/i860_kernel_report_hardmask_pcode_phase1_promoted.txt`
- `re/nextdimension/firmware/analysis/phase2/cross_block_results.json`
- `re/nextdimension/firmware/analysis/phase2/phase2_seeds.json`
