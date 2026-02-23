# NDserver RE Analysis Workflow

## 1. Stage Inputs

Copy external binaries into `artifacts/incoming/<release>/`.

## 2. Extract Embedded Components

Run:

```bash
./scripts/extract_ndserver_components.sh <input_m68k_exec> <output_dir>
```

Outputs include:

- `i860_payload.bin` (when `__I860` exists)
- host and payload Mach-O scan manifests
- extracted embedded Mach-O object files
- SHA-256 manifest

## 3. Build Release Comparisons

Run:

```bash
python3 scripts/compare_ndserver.py \
  --a <nd33_m68k_exec> \
  --b <os42_m68k_exec> \
  --out-json <report.json> \
  --out-md <report.md>
```

Review:

- header/filetype changes
- segment/section size changes
- `__TEXT,__cstring` deltas
- per-section hash equality

## 4. Promote Findings

- Put stable conclusions in `docs/`.
- Keep run-specific outputs in `reports/`.
- Capture unresolved items as targeted next actions (function-level diff, IPC decode, loader path tests).

## 5. Ghidra m68k Pass (Headless)

Use explicit m68k mode to avoid auto-detection drift:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k \
  -import <m68k_macho.bin> \
  -processor 68000:BE:32:default \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportM68kSummary.java \
  "--out=re/nextdimension/ndserver_re/reports/<name>_m68k_summary.txt"
```

For targeted decomp around ND strings / loader paths:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k \
  -process <program_name> \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportM68kInterestingDecomp.java \
  "--out=re/nextdimension/ndserver_re/reports/<name>_interesting_decomp.txt" \
  "--max=12" \
  "--timeout=60"
```

Apply first-pass function names (4.2 bundle map):

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ApplyFunctionRenameMap.java \
  "--map=re/nextdimension/ndserver_re/docs/04-ndserver-42-bundle-rename-map.csv" \
  "--out=re/nextdimension/ndserver_re/reports/ndserver_42_bundle_rename_apply.txt"
```

Export IPC dispatch table and dispatcher evidence:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportNdserverIpcDispatch.java \
  "--out=re/nextdimension/ndserver_re/reports/ndserver_42_bundle_ipc_dispatch.txt" \
  "--func=0x700031b4" \
  "--table=0x7000c028" \
  "--limit=64"
```

Trace global references and decompile specific functions in a registration chain:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportGlobalRefMap.java \
  "--out=re/nextdimension/ndserver_re/reports/ndserver_42_bundle_global_refs.txt" \
  "--addr=0x7000c028,0x7000c03c,0x7000c06c,0x7000c0ac,0x7000c324"

/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportFunctionDecompByAddr.java \
  "--out=re/nextdimension/ndserver_re/reports/ndserver_42_bundle_registration_chain.txt" \
  "--func=0x700025bc,0x7000621e,0x700031b4,0x70002ea0,0x70006322,0x7000889e" \
  "--timeout=90"
```

## 6. Embedded-Object Growth Attribution (3.3 object vs 4.2 bundle)

Build a direct embedded-m68k comparison:

```bash
python3 re/nextdimension/ndserver_re/scripts/compare_ndserver.py \
  --a re/nextdimension/ndserver_re/artifacts/extracted/nd33/i860_scan/obj_02_off_018000_m68k_object_49860.bin \
  --b re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_scan/obj_02_off_018000_m68k_bundle_60976.bin \
  --out-json re/nextdimension/ndserver_re/reports/nd33_obj_vs_os42_bundle_compare.json \
  --out-md re/nextdimension/ndserver_re/reports/nd33_obj_vs_os42_bundle_compare.md
```

Dump full function inventories for both projects:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_nd33_obj \
  -process obj_02_off_018000_m68k_object_49860.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportFunctionMap.java \
  "--out=re/nextdimension/ndserver_re/reports/nd33_obj_function_map.tsv"

/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportFunctionMap.java \
  "--out=re/nextdimension/ndserver_re/reports/os42_bundle_function_map.tsv"
```

Scan decompiled output for specific message-id families:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_nd33_obj \
  -process obj_02_off_018000_m68k_object_49860.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ScanDecompForTokens.java \
  "--out=re/nextdimension/ndserver_re/reports/nd33_obj_token_scan_rpcids_precise.txt" \
  "--tokens== 0x6c;,= 0x6d;,= 0x6e;,= 0x6f;,= 0x70;,= 0x71;,= 0x72;,= 0x73;,= 0x74;,= 0x77;,= 0x88;,= 0x89;,== 0xec),== 0xed)" \
  "--timeout=40"

/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ScanDecompForTokens.java \
  "--out=re/nextdimension/ndserver_re/reports/os42_bundle_token_scan_rpcids_precise.txt" \
  "--tokens== 0x6c;,= 0x6d;,= 0x6e;,= 0x6f;,= 0x70;,= 0x71;,= 0x72;,= 0x73;,= 0x74;,= 0x77;,= 0x88;,= 0x89;,== 0xec),== 0xed)" \
  "--timeout=40"
```

Use targeted reference maps to validate whether newly observed wrappers/strings are active:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_ndserver_m68k_os42_bundle \
  -process obj1_m68k_bundle_018000_60976.bin \
  -noanalysis \
  -scriptPath re/nextdimension/ndserver_re/scripts \
  -postScript ExportGlobalRefMap.java \
  "--out=re/nextdimension/ndserver_re/reports/os42_rpc89_refs.txt" \
  "--addr=0x7000793c"
```
