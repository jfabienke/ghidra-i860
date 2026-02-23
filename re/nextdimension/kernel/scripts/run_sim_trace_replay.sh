#!/bin/bash
# Replay runtime trace instruction words through i860-sim-rs.
#
# Usage:
#   ./re/nextdimension/kernel/scripts/run_sim_trace_replay.sh \
#     [trace_jsonl] [out_json] [max_instructions]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$KERNEL_DIR/reports"

EMU_ROOT="${EMU_ROOT:-/Users/jvindahl/Development/nextdimension/emulator}"
TRACE_JSONL="${1:-$REPORT_DIR/dynamic_trace/latest/runtime_trace.jsonl}"
OUT_JSON="${2:-$REPORT_DIR/sim_trace_replay_$(date -u +%Y%m%d-%H%M%S).json}"
MAX_INSTRUCTIONS="${3:-100000}"
SIM_REPLAY_DEDUP="${SIM_REPLAY_DEDUP:-1}"

if [[ ! -f "$TRACE_JSONL" ]]; then
  echo "ERROR: trace not found: $TRACE_JSONL" >&2
  exit 1
fi
if [[ ! -d "$EMU_ROOT/i860-sim-rs" ]]; then
  echo "ERROR: i860-sim-rs crate not found under emulator root: $EMU_ROOT" >&2
  exit 1
fi

TRACE_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$TRACE_JSONL")"
OUT_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUT_JSON")"
mkdir -p "$(dirname "$OUT_ABS")"

echo "=== Simulator Trace Replay ==="
echo "Emulator:         $EMU_ROOT"
echo "Trace:            $TRACE_ABS"
echo "Output:           $OUT_ABS"
echo "Max instructions: $MAX_INSTRUCTIONS"
echo "Dedup consecutive:$SIM_REPLAY_DEDUP"
echo ""

(
  cd "$EMU_ROOT"
  SIM_REPLAY_DEDUP="$SIM_REPLAY_DEDUP" \
    cargo run -p i860-sim-rs --example trace_replay -- \
      "$TRACE_ABS" "$OUT_ABS" "$MAX_INSTRUCTIONS"
)

echo ""
echo "=== Done ==="
echo "Report: $OUT_ABS"
