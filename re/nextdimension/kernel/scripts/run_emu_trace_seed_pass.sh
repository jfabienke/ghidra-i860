#!/bin/bash
# Capture runtime indirect-branch trace from emulator and convert to recovery-map seeds.
#
# Usage:
#   ./re/nextdimension/kernel/scripts/run_emu_trace_seed_pass.sh \
#     [binary] [base_addr] [entry_pc] [max_steps] [out_dir] [base_map_json] [state_json]

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
STATE_JSON="${7:-${SWEEP_STATE_JSON:-}}"
TRACE_MIN_HITS="${TRACE_MIN_HITS:-1}"
TRACE_MIN_SITES="${TRACE_MIN_SITES:-1}"
TRACE_MIN_SEED_SCORE="${TRACE_MIN_SEED_SCORE:-50}"
TRACE_MIN_CREATE_SCORE="${TRACE_MIN_CREATE_SCORE:-70}"
TRACE_ALLOW_SELF_LOOP_ONLY="${TRACE_ALLOW_SELF_LOOP_ONLY:-0}"
TRACE_DEDUP="${TRACE_DEDUP:-1}"
TRACE_MAX_EVENTS="${TRACE_MAX_EVENTS:-200000}"
TRACE_RESET_VECTOR_MODE="${TRACE_RESET_VECTOR_MODE:-0}"
TRACE_RESET_VECTOR_PC="${TRACE_RESET_VECTOR_PC:-0xFFF00000}"
TRACE_RESET_VECTOR_TARGET="${TRACE_RESET_VECTOR_TARGET:-}"
TRACE_TOP_HOTSPOTS="${TRACE_TOP_HOTSPOTS:-12}"

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
if [[ -n "$STATE_JSON" ]]; then
  echo "State:     $STATE_JSON"
fi
echo "Thresholds: hits>=$TRACE_MIN_HITS sites>=$TRACE_MIN_SITES seed>=$TRACE_MIN_SEED_SCORE create>=$TRACE_MIN_CREATE_SCORE self_loop_only=$TRACE_ALLOW_SELF_LOOP_ONLY"
echo "Trace opts: dedup=$TRACE_DEDUP max_events=$TRACE_MAX_EVENTS"
echo "Boot opts:  reset_mode=$TRACE_RESET_VECTOR_MODE reset_pc=$TRACE_RESET_VECTOR_PC reset_target=${TRACE_RESET_VECTOR_TARGET:-<entry>} hotspots=$TRACE_TOP_HOTSPOTS"
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

STATE_JSON_ABS=""
if [[ -n "$STATE_JSON" ]]; then
  if [[ ! -f "$STATE_JSON" ]]; then
    echo "ERROR: state json not found: $STATE_JSON" >&2
    exit 1
  fi
  STATE_JSON_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$STATE_JSON")"
fi

echo "Capturing runtime trace..."
(
  cd "$EMU_ROOT"
  TRACE_ENV=(I860_TRACE_JSONL="$TRACE_JSONL" I860_TRACE_DEDUP="$TRACE_DEDUP" I860_TRACE_MAX_EVENTS="$TRACE_MAX_EVENTS" I860_TRACE_TOP_HOTSPOTS="$TRACE_TOP_HOTSPOTS" I860_RESET_VECTOR_MODE="$TRACE_RESET_VECTOR_MODE" I860_RESET_VECTOR_PC="$TRACE_RESET_VECTOR_PC")
  if [[ -n "$TRACE_RESET_VECTOR_TARGET" ]]; then
    TRACE_ENV+=(I860_RESET_VECTOR_TARGET="$TRACE_RESET_VECTOR_TARGET")
  fi
  if [[ -n "$STATE_JSON_ABS" ]]; then
    env "${TRACE_ENV[@]}" \
      cargo run -p i860-core --example nd_trace -- \
        "$BINARY_ABS" "$BASE_ADDR" "$ENTRY_PC" "$MAX_STEPS" "$STATE_JSON_ABS"
  else
    env "${TRACE_ENV[@]}" \
      cargo run -p i860-core --example nd_trace -- \
        "$BINARY_ABS" "$BASE_ADDR" "$ENTRY_PC" "$MAX_STEPS"
  fi
) | tee "$RUN_LOG"

echo ""
echo "Converting trace to recovery map..."
ALLOW_SELF_LOOP_ARG=""
if [[ "$TRACE_ALLOW_SELF_LOOP_ONLY" == "1" || "$TRACE_ALLOW_SELF_LOOP_ONLY" == "true" || "$TRACE_ALLOW_SELF_LOOP_ONLY" == "TRUE" ]]; then
  ALLOW_SELF_LOOP_ARG="--allow-self-loop-only"
fi
python3 "$SCRIPT_DIR/dynamic_trace_to_recovery_map.py" \
  --trace "$TRACE_JSONL" \
  --base-map "$BASE_MAP_ABS" \
  --min-hits "$TRACE_MIN_HITS" \
  --min-sites "$TRACE_MIN_SITES" \
  --min-seed-score "$TRACE_MIN_SEED_SCORE" \
  --min-create-score "$TRACE_MIN_CREATE_SCORE" \
  $ALLOW_SELF_LOOP_ARG \
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
