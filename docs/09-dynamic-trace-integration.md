# Dynamic Trace Integration (Emulator -> Ghidra Seeds)

This workflow converts runtime trace evidence (especially `bri/calli` targets) into curated seeds for `I860Analyze.java`.

## 1. Trace Schema (JSONL)

One JSON object per line. The converter is tolerant to field names; these are preferred:

### Indirect control-flow event (required for seed generation)

```json
{"event":"indirect_branch","kind":"bri","pc":"0xF8001234","target":"0xF8005678","src_reg":"r8","src_value":"0xF8005678","delay_slot_pc":"0xF8001238"}
```

Alternative accepted keys:
- `event|type|kind`: contains `indirect`, `bri`, or `calli`
- source PC: `pc|site_pc|instruction_pc|from|src`
- target PC: `target|target_pc|to|dst|branch_target`

### Memory / MMIO event (optional; reporting-only in v1)

```json
{"event":"mem_access","op":"write","pc":"0xF8002000","ea":"0x0200001C","width":1,"space":"mmio","base_reg":"r12","base_value":"0x01FFBFE4","disp":"0x401c"}
```

## 2. Convert Trace -> Recovery Map

```bash
python3 re/nextdimension/kernel/scripts/dynamic_trace_to_recovery_map.py \
  --trace /path/to/runtime_trace.jsonl \
  --base-map re/nextdimension/kernel/docs/recovery_map_hardmask_pcode.json \
  --out /tmp/i860_dynamic_recovery.json \
  --report /tmp/i860_dynamic_recovery.txt
```

Output is recovery-map JSON compatible with `I860Analyze.java`:
- preserves `allow_ranges` / `deny_ranges` from base map
- appends dynamic seeds with `addr` + `create_function`
- includes metadata (`dynamic_added`, thresholds, exec range)

## 3. Run Headless Analysis with Dynamic Seeds

`run_analysis.sh` now accepts an optional 5th argument (or env var):

```bash
./re/nextdimension/kernel/scripts/run_analysis.sh \
  re/nextdimension/kernel/i860_kernel.bin \
  /path/to/xrefs.json \
  re/nextdimension/kernel/docs/recovery_map_hardmask_pcode.json \
  re/nextdimension/kernel/reports/factpack/dyn_run \
  /path/to/runtime_trace.jsonl
```

Or:

```bash
DYNAMIC_TRACE_JSONL=/path/to/runtime_trace.jsonl \
./re/nextdimension/kernel/scripts/run_analysis.sh
```

The script generates `/tmp/i860_dynamic_recovery_<timestamp>.json` and uses it as the curated recovery map for import/analyze/export.

## 3a. One-Command Emulator Trace + Seed Pass

If the external emulator workspace is buildable, run:

```bash
./re/nextdimension/kernel/scripts/run_emu_trace_seed_pass.sh \
  re/nextdimension/kernel/i860_kernel.bin \
  0xF8000000 0xF8000000 200000
```

This script:

1. Runs the emulator trace runner (`i860-core/examples/nd_trace.rs`) with `I860_TRACE_JSONL`.
2. Converts runtime trace to `dynamic_recovery_map.json`.
3. Produces a text seed report for curation.

Current caveat: this wrapper performs a preflight check for a known external workspace issue (`emulator/i860-decoder/Cargo.toml` missing). Until that path is restored, emulator capture is blocked and only conversion/integration steps can run.

## 4. Current Scoring (v1)

`dynamic_trace_to_recovery_map.py` scores candidate targets by:
- hit count
- unique source-site count
- `calli` bonus over `bri`
- alignment + executable range filter

Defaults:
- `min_hits=1`
- `min_seed_score=50`
- `min_create_score=70`
- exec range: `0xF8000000 .. 0xF80B2547`

Tune as needed for trace quality/noise.
