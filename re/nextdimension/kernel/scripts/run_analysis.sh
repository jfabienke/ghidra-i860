#!/bin/bash
# One-command pipeline for NeXTdimension i860 kernel analysis.
# Usage: ./re/nextdimension/kernel/scripts/run_analysis.sh [binary] [xrefs_json] [recovery_map_json] [factpack_out_dir]
#
# Runs I860Import.java (preScript) + auto-analysis + I860Analyze.java (postScript),
# then exports swarm-ready fact-pack JSONL via ExportFactPack.java.

set -euo pipefail

GHIDRA_HOME=/opt/homebrew/Cellar/ghidra/12.0.2/libexec
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$KERNEL_DIR/reports"
BINARY="${1:-$KERNEL_DIR/i860_kernel.bin}"
XREFS_JSON="${2:-}"
RECOVERY_MAP_JSON="${3:-$KERNEL_DIR/docs/recovery_map.json}"
FACTPACK_OUT_DIR="${4:-}"
if [[ ! -f "$RECOVERY_MAP_JSON" ]]; then
    RECOVERY_MAP_JSON=""
fi
PHASE2_JSON="$KERNEL_DIR/../firmware/analysis/phase2/cross_block_results.json"
if [[ ! -f "$PHASE2_JSON" ]]; then
    PHASE2_JSON=""
fi
RUN_TS="$(date -u +%Y%m%d-%H%M%S)"
if [[ -z "$FACTPACK_OUT_DIR" ]]; then
    FACTPACK_OUT_DIR="$REPORT_DIR/factpack/$RUN_TS"
fi
mkdir -p "$REPORT_DIR" "$FACTPACK_OUT_DIR"

echo "=== NeXTdimension i860 Kernel Analysis ==="
echo "Binary:     $BINARY"
if [[ -n "$XREFS_JSON" ]]; then
    echo "Rust xrefs: $XREFS_JSON"
fi
if [[ -n "$RECOVERY_MAP_JSON" ]]; then
    echo "Recovery:   $RECOVERY_MAP_JSON"
fi
echo "Scripts:    $SCRIPT_DIR"
echo "Reports:    $REPORT_DIR"
echo "Fact pack:  $FACTPACK_OUT_DIR"
echo ""

# Clean previous project
rm -rf /tmp/ghidra_i860_kernel /tmp/ghidra_i860_kernel.rep /tmp/ghidra_i860_kernel.gpr

POST_ARGS=()
PRE_ARGS=()
if [[ -n "$XREFS_JSON" ]]; then
    POST_ARGS+=("$XREFS_JSON")
elif [[ -n "$RECOVERY_MAP_JSON" ]]; then
    POST_ARGS+=("-")
fi
if [[ -n "$RECOVERY_MAP_JSON" ]]; then
    POST_ARGS+=("$RECOVERY_MAP_JSON")
    PRE_ARGS+=("--seed-map=$RECOVERY_MAP_JSON")
fi

"$GHIDRA_HOME/support/analyzeHeadless" \
    /tmp ghidra_i860_kernel \
    -import "$BINARY" \
    -preScript "$SCRIPT_DIR/I860Import.java" "${PRE_ARGS[@]}" \
    -postScript "$SCRIPT_DIR/I860Analyze.java" "${POST_ARGS[@]}" \
    -postScript "$SCRIPT_DIR/ExportFactPack.java" \
        "--out=$FACTPACK_OUT_DIR" \
        "--seed-map=${RECOVERY_MAP_JSON:--}" \
        "--phase2=${PHASE2_JSON:--}" \
    -scriptPath "$SCRIPT_DIR" \
    2>&1 | tee "$REPORT_DIR/headless.log"

# Copy report from /tmp to reports dir
cp /tmp/i860_kernel_report.txt "$REPORT_DIR/i860_kernel_report.txt" 2>/dev/null || true

echo ""
echo "=== Done ==="
echo "Report:     $REPORT_DIR/i860_kernel_report.txt"
echo "Full log:   $REPORT_DIR/headless.log"
echo "Fact pack:  $FACTPACK_OUT_DIR"
