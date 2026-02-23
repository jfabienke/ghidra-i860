# NeXTdimension NDserver RE

Host-side reverse engineering workspace for `NDserver` (m68k) across NeXTSTEP 3.3 and OPENSTEP 4.2.

## Scope

This sub-repo focuses on:

- m68k `NDserver` host daemon behavior and IPC protocol
- host-side kernel/firmware loading flow (`ND_Load_MachDriver` path)
- release-to-release diffs (3.3 vs 4.2)
- extraction of embedded Mach-O payloads needed for host analysis

This sub-repo does **not** store proprietary binary blobs in git.

## Quick Start

1. Place external binaries under `artifacts/incoming/`.

Example layout:

```text
artifacts/incoming/
  nd33/
    NDserver
  os42/
    m68k_exec_i860seg.bin
```

2. Extract host/i860 embedded components:

```bash
./scripts/extract_ndserver_components.sh \
  artifacts/incoming/nd33/NDserver \
  artifacts/extracted/nd33

./scripts/extract_ndserver_components.sh \
  artifacts/incoming/os42/m68k_exec_i860seg.bin \
  artifacts/extracted/os42
```

3. Compare two m68k host executables:

```bash
python3 scripts/compare_ndserver.py \
  --a artifacts/incoming/nd33/NDserver \
  --b artifacts/incoming/os42/m68k_exec_i860seg.bin \
  --out-json reports/ndserver_33_vs_42.json \
  --out-md reports/ndserver_33_vs_42.md
```

## Directory Structure

```text
ndserver_re/
├── README.md
├── docs/
│   ├── 01-scope-and-artifacts.md
│   ├── 02-analysis-workflow.md
│   ├── 03-ghidra-m68k-findings.md
│   ├── 04-ndserver-42-bundle-rename-map.csv
│   ├── 05-rename-and-ipc-dispatch.md
│   ├── 06-slot33-callback-trace.md
│   ├── 07-openstep42-ndserver-findings-and-memory-maps.md
│   └── 08-protocol-offload-and-code-growth-conclusion.md
├── scripts/
│   ├── ApplyFunctionRenameMap.java
│   ├── ExportFunctionMap.java
│   ├── ExportFunctionDecompByAddr.java
│   ├── ExportGlobalRefMap.java
│   ├── ExportM68kInterestingDecomp.java
│   ├── ExportM68kSummary.java
│   ├── ExportNdserverIpcDispatch.java
│   ├── ScanDecompForTokens.java
│   ├── extract_ndserver_components.sh
│   ├── macho_scan_extract.py
│   └── compare_ndserver.py
├── artifacts/
│   ├── incoming/          # external inputs (ignored)
│   └── extracted/         # generated extracts (ignored)
└── reports/               # generated reports (ignored)
```

## Notes

- Scripts are written to avoid machine-specific absolute paths.
- Keep evidence in `reports/` and promote stable conclusions into `docs/`.
- If a carved object is not a full executable (truncated tail), track that explicitly in report metadata.
