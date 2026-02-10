#!/bin/bash
# Capture runtime indirect-branch trace from emulator and convert to recovery-map seeds.
#
# Usage:
#   ./re/nextdimension/kernel/scripts/run_emu_trace_seed_pass.sh \
#     [binary] [base_addr] [entry_pc] [max_steps] [out_dir] [base_map_json]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$KERNEL_DIR/reports"

EMU_ROOT="${EMU_ROOT:-/Users/jvindahl/Development/nextdimension/emulator}"
BINARY="${1:-$KERNEL_DIR/i860_kernel.bin}"
BASE_ADDR="${2:-0xF8000000}"
ENTRY_PC="${3:-0xF8000000}"
MAX_STEPS="${4:-200000}"
OUT_DIR="${5:-$REPORT_DIR/dynamic_trace/$(date -u +%Y%m%d-%H%M%S)}"
BASE_MAP_JSON="${6:-$KERNEL_DIR/docs/recovery_map_hardmask_pcode.json}"

mkdir -p "$OUT_DIR"

TRACE_JSONL="$OUT_DIR/runtime_trace.jsonl"
TRACE_REPORT="$OUT_DIR/trace_seed_report.txt"
TRACE_MAP_JSON="$OUT_DIR/dynamic_recovery_map.json"
RUN_LOG="$OUT_DIR/nd_trace.log"

echo "=== Emulator Trace Seed Pass ==="
echo "Emulator:  $EMU_ROOT"
echo "Binary:    $BINARY"
echo "Base:      $BASE_ADDR"
echo "Entry:     $ENTRY_PC"
echo "Steps:     $MAX_STEPS"
echo "Out dir:   $OUT_DIR"
echo ""

if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: binary not found: $BINARY" >&2
  exit 1
fi
BINARY_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$BINARY")"

if [[ ! -d "$EMU_ROOT/i860-core" ]]; then
  echo "ERROR: i860-core crate not found under emulator root: $EMU_ROOT" >&2
  exit 1
fi

# Preflight for known workspace issue.
if [[ ! -f "$EMU_ROOT/i860-decoder/Cargo.toml" ]]; then
  echo "ERROR: missing workspace member: $EMU_ROOT/i860-decoder/Cargo.toml" >&2
  echo "The emulator workspace cannot build until this dependency path is restored." >&2
  exit 2
fi

if [[ ! -f "$EMU_ROOT/i860-core/examples/nd_trace.rs" ]]; then
  echo "ERROR: nd_trace example not found at $EMU_ROOT/i860-core/examples/nd_trace.rs" >&2
  exit 1
fi

if [[ ! -f "$BASE_MAP_JSON" ]]; then
  echo "ERROR: base recovery map not found: $BASE_MAP_JSON" >&2
  exit 1
fi
BASE_MAP_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$BASE_MAP_JSON")"

echo "Capturing runtime trace..."
(
  cd "$EMU_ROOT"
  I860_TRACE_JSONL="$TRACE_JSONL" \
    cargo run -p i860-core --example nd_trace -- \
      "$BINARY_ABS" "$BASE_ADDR" "$ENTRY_PC" "$MAX_STEPS"
) | tee "$RUN_LOG"

echo ""
echo "Converting trace to recovery map..."
python3 "$SCRIPT_DIR/dynamic_trace_to_recovery_map.py" \
  --trace "$TRACE_JSONL" \
  --base-map "$BASE_MAP_ABS" \
  --out "$TRACE_MAP_JSON" \
  --report "$TRACE_REPORT"

echo ""
echo "=== Done ==="
echo "Trace JSONL:  $TRACE_JSONL"
echo "Trace map:    $TRACE_MAP_JSON"
echo "Trace report: $TRACE_REPORT"
echo "Runner log:   $RUN_LOG"
echo ""
echo "Next:"
echo "  ./re/nextdimension/kernel/scripts/run_analysis.sh \\"
echo "    \"$BINARY\" - \"$TRACE_MAP_JSON\" \"$REPORT_DIR/factpack/emu_trace\" \"$TRACE_JSONL\""
