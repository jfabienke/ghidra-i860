# NeXTdimension i860 Kernel

Reverse engineering workspace for the NeXTdimension display board i860 kernel (`i860_kernel.bin`).

## Quick Start

```bash
./scripts/run_analysis.sh
```

This imports the kernel into Ghidra headless mode, runs `I860Import.java` as a preScript, runs auto-analysis, then runs `I860Analyze.java` as a postScript.

Optional inputs:

```bash
./scripts/run_analysis.sh [binary] [xrefs_json] [recovery_map_json]
```

- `xrefs_json`: Rust CFG/xref output (optional)
- `recovery_map_json`: allow/deny ranges + curated seeds (defaults to `docs/recovery_map.json`)

## Directory Structure

```text
kernel/
├── i860_kernel.bin              # 784 KB Mach-O binary
├── scripts/
│   ├── run_analysis.sh          # One-command headless pipeline
│   ├── I860Import.java          # preScript: entry + recursive seed disassembly
│   ├── I860Analyze.java         # postScript: worklist recovery + report
│   ├── FunctionConfidenceProfile.java  # per-function confidence scoring + exports
│   └── DecompileSample.java     # decompiler KPI sampling
├── docs/
│   ├── analysis-findings.md     # analysis notes and open issues
│   └── recovery_map.json        # curated ranges + function seeds
└── reports/
    ├── i860_kernel_report.txt   # latest analysis report
    └── headless.log             # full headless output
```

## Analysis Pipeline

```text
i860_kernel.bin
  -> I860Import.java (entry + recursive seeding)
  -> Ghidra auto-analysis
  -> I860Analyze.java (worklist + delay-slot closure + range-filtered seeds)
  -> reports/i860_kernel_report.txt
```

## Current Focus

- Improve CFG/xref recovery for indirect dispatch (`calli`, `bri`)
- Use curated seed/range maps to suppress known dead-space regions
- Track decompiler KPIs (`halt_baddata`, `unaff_*`, timeout rate) across runs

## Function Confidence Profiling

Generate function confidence outputs after analysis:

```bash
/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless \
  /tmp ghidra_i860_kernel \
  -process i860_kernel.bin \
  -noanalysis \
  -scriptPath ./scripts \
  -postScript FunctionConfidenceProfile.java /tmp
```

Outputs:

- `/tmp/function_confidence.csv`
- `/tmp/high_conf_functions.txt`
- `/tmp/suspect_functions.txt`
