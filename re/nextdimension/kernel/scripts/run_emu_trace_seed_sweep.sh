#!/bin/bash
# Multi-entry runtime trace sweep and dynamic seed generation.
#
# Usage:
#   ./re/nextdimension/kernel/scripts/run_emu_trace_seed_sweep.sh \
#     [binary] [base_addr] [max_steps_per_entry] [out_dir] [base_map_json] [entries_spec] [state_json]
#
# entries_spec:
#   - path to text file with one address per line (hex or decimal), or
#   - comma-separated list of addresses
#
# If entries_spec is omitted, entries are derived from the base map:
#   - bootstrap defaults: 0xF8000348, 0xF80014C4
#   - top create_function seeds from base map (bounded by SWEEP_MAX_ENTRIES, default 32)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$KERNEL_DIR/reports"

EMU_ROOT="${EMU_ROOT:-/Users/jvindahl/Development/nextdimension/emulator}"
BINARY="${1:-$KERNEL_DIR/i860_kernel.bin}"
BASE_ADDR="${2:-0xF8000000}"
MAX_STEPS="${3:-200000}"
OUT_DIR="${4:-$REPORT_DIR/dynamic_trace_sweep/$(date -u +%Y%m%d-%H%M%S)}"
BASE_MAP_JSON="${5:-$KERNEL_DIR/docs/recovery_map_hardmask_pcode.json}"
ENTRIES_SPEC="${6:-}"
STATE_JSON="${7:-${SWEEP_STATE_JSON:-}}"

SWEEP_MAX_ENTRIES="${SWEEP_MAX_ENTRIES:-32}"
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

mkdir -p "$OUT_DIR" "$OUT_DIR/traces" "$OUT_DIR/logs"

TRACE_REPORT="$OUT_DIR/trace_seed_report.txt"
TRACE_MAP_JSON="$OUT_DIR/dynamic_recovery_map.json"
SWEEP_REPORT="$OUT_DIR/sweep_report.txt"
MANIFEST_JSON="$OUT_DIR/sweep_manifest.json"
ENTRY_LIST_TXT="$OUT_DIR/entries.txt"
TRACE_MERGED_JSONL="$OUT_DIR/runtime_trace_merged.jsonl"

echo "=== Emulator Trace Seed Sweep ==="
echo "Emulator:    $EMU_ROOT"
echo "Binary:      $BINARY"
echo "Base:        $BASE_ADDR"
echo "Steps/entry: $MAX_STEPS"
if [[ -n "$STATE_JSON" ]]; then
  echo "State JSON:  $STATE_JSON"
fi
echo "Thresholds:  hits>=$TRACE_MIN_HITS sites>=$TRACE_MIN_SITES seed>=$TRACE_MIN_SEED_SCORE create>=$TRACE_MIN_CREATE_SCORE self_loop_only=$TRACE_ALLOW_SELF_LOOP_ONLY"
echo "Trace opts:  dedup=$TRACE_DEDUP max_events=$TRACE_MAX_EVENTS"
echo "Boot opts:   reset_mode=$TRACE_RESET_VECTOR_MODE reset_pc=$TRACE_RESET_VECTOR_PC reset_target=${TRACE_RESET_VECTOR_TARGET:-<entry>} hotspots=$TRACE_TOP_HOTSPOTS"
echo "Out dir:     $OUT_DIR"
echo ""

if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: binary not found: $BINARY" >&2
  exit 1
fi
BINARY_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$BINARY")"

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

if [[ ! -d "$EMU_ROOT/i860-core" ]]; then
  echo "ERROR: i860-core crate not found under emulator root: $EMU_ROOT" >&2
  exit 1
fi
if [[ ! -f "$EMU_ROOT/i860-decoder/Cargo.toml" ]]; then
  echo "ERROR: missing workspace member: $EMU_ROOT/i860-decoder/Cargo.toml" >&2
  exit 2
fi
if [[ ! -f "$EMU_ROOT/i860-core/examples/nd_trace.rs" ]]; then
  echo "ERROR: nd_trace example not found: $EMU_ROOT/i860-core/examples/nd_trace.rs" >&2
  exit 1
fi

echo "Resolving entry list..."
python3 - "$BASE_MAP_ABS" "$ENTRIES_SPEC" "$SWEEP_MAX_ENTRIES" > "$ENTRY_LIST_TXT" << 'PY'
import json
import os
import re
import sys

base_map = sys.argv[1]
entry_spec = sys.argv[2].strip()
max_entries = int(sys.argv[3])

def parse_num(tok):
    tok = tok.strip().replace("_", "")
    if not tok:
        return None
    try:
        if tok.lower().startswith("0x"):
            return int(tok, 16) & 0xFFFFFFFF
        return int(tok, 10) & 0xFFFFFFFF
    except ValueError:
        return None

entries = []
seen = set()

def add(v):
    if v is None:
        return
    if v in seen:
        return
    seen.add(v)
    entries.append(v)

if entry_spec:
    if os.path.isfile(entry_spec):
        for line in open(entry_spec, "r", encoding="utf-8"):
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            add(parse_num(s))
    else:
        for tok in entry_spec.split(","):
            add(parse_num(tok))
else:
    # Bootstrap defaults first.
    add(0xF8000348)
    add(0xF80014C4)

    with open(base_map, "r", encoding="utf-8") as f:
        data = json.load(f)
    seeds = data.get("seeds", [])
    # Prioritize create_function hints, preserve file order.
    for s in seeds:
        if len(entries) >= max_entries:
            break
        if not isinstance(s, dict):
            continue
        if not s.get("create_function", False):
            continue
        addr = parse_num(str(s.get("addr", "")))
        add(addr)

for e in entries:
    print(f"0x{e:08X}")
PY

ENTRY_COUNT="$(wc -l < "$ENTRY_LIST_TXT" | tr -d ' ')"
if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  echo "ERROR: no entry addresses resolved" >&2
  exit 1
fi

echo "Entries resolved: $ENTRY_COUNT"
sed -n '1,40p' "$ENTRY_LIST_TXT"
echo ""

echo "Building trace runner once..."
(
  cd "$EMU_ROOT"
  cargo build -p i860-core --example nd_trace >/dev/null
)
RUNNER="$EMU_ROOT/target/debug/examples/nd_trace"
if [[ ! -x "$RUNNER" ]]; then
  echo "ERROR: runner not found after build: $RUNNER" >&2
  exit 1
fi

echo "Running sweep..."
echo "entry,trace_file,log_file,lines,executed,final_pc,status,stop_reason" > "$OUT_DIR/sweep.csv"

TRACE_ARGS=()
TRACE_FILES=()
TOTAL_LINES=0
TOTAL_EXEC=0
RUN_OK=0
RUN_FAIL=0

while IFS= read -r ENTRY_PC; do
  [[ -z "$ENTRY_PC" ]] && continue
  ENTRY_TAG="${ENTRY_PC#0x}"
  TRACE_FILE="$OUT_DIR/traces/trace_${ENTRY_TAG}.jsonl"
  LOG_FILE="$OUT_DIR/logs/run_${ENTRY_TAG}.log"
  rm -f "$TRACE_FILE"

  set +e
  (
    cd "$EMU_ROOT"
    TRACE_ENV=(I860_TRACE_JSONL="$TRACE_FILE" I860_TRACE_DEDUP="$TRACE_DEDUP" I860_TRACE_MAX_EVENTS="$TRACE_MAX_EVENTS" I860_TRACE_TOP_HOTSPOTS="$TRACE_TOP_HOTSPOTS" I860_RESET_VECTOR_MODE="$TRACE_RESET_VECTOR_MODE" I860_RESET_VECTOR_PC="$TRACE_RESET_VECTOR_PC")
    if [[ -n "$TRACE_RESET_VECTOR_TARGET" ]]; then
      TRACE_ENV+=(I860_RESET_VECTOR_TARGET="$TRACE_RESET_VECTOR_TARGET")
    fi
    if [[ -n "$STATE_JSON_ABS" ]]; then
      env "${TRACE_ENV[@]}" \
        "$RUNNER" "$BINARY_ABS" "$BASE_ADDR" "$ENTRY_PC" "$MAX_STEPS" "$STATE_JSON_ABS"
    else
      env "${TRACE_ENV[@]}" \
        "$RUNNER" "$BINARY_ABS" "$BASE_ADDR" "$ENTRY_PC" "$MAX_STEPS"
    fi
  ) >"$LOG_FILE" 2>&1
  RC=$?
  set -e

  LINES=0
  if [[ -f "$TRACE_FILE" ]]; then
    LINES="$(wc -l < "$TRACE_FILE" | tr -d ' ')"
  fi
  EXEC="$(rg -o 'executed [0-9]+' "$LOG_FILE" | tail -1 | awk '{print $2}' || true)"
  FINAL_PC="$(rg -o 'final pc=0x[0-9A-Fa-f]+' "$LOG_FILE" | tail -1 | cut -d= -f2 || true)"
  STOP_REASON="$(sed -n 's/^nd_trace: stop reason=//p' "$LOG_FILE" | tail -1 || true)"
  EXEC="${EXEC:-0}"
  FINAL_PC="${FINAL_PC:-unknown}"
  STOP_REASON="${STOP_REASON:-unknown}"
  STOP_REASON_CSV="${STOP_REASON//\"/\"\"}"

  if [[ "$RC" -eq 0 ]]; then
    STATUS="ok"
    RUN_OK=$((RUN_OK + 1))
    TRACE_ARGS+=(--trace "$TRACE_FILE")
    TRACE_FILES+=("$TRACE_FILE")
  else
    STATUS="fail"
    RUN_FAIL=$((RUN_FAIL + 1))
  fi

  TOTAL_LINES=$((TOTAL_LINES + LINES))
  TOTAL_EXEC=$((TOTAL_EXEC + EXEC))
  echo "$ENTRY_PC,$TRACE_FILE,$LOG_FILE,$LINES,$EXEC,$FINAL_PC,$STATUS,\"$STOP_REASON_CSV\"" >> "$OUT_DIR/sweep.csv"
done < "$ENTRY_LIST_TXT"

if [[ "${#TRACE_ARGS[@]}" -eq 0 ]]; then
  echo "ERROR: no successful trace runs to convert" >&2
  exit 1
fi

# Merge per-entry traces for tools that accept one trace path.
: > "$TRACE_MERGED_JSONL"
for f in "${TRACE_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  cat "$f" >> "$TRACE_MERGED_JSONL"
done

python3 - "$OUT_DIR/sweep.csv" "$MANIFEST_JSON" << 'PY'
import csv
import json
import sys
rows = []
with open(sys.argv[1], newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        rows.append(r)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"runs": rows}, f, indent=2)
    f.write("\n")
PY

echo ""
echo "Converting combined traces to recovery map..."
ALLOW_SELF_LOOP_ARG=""
if [[ "$TRACE_ALLOW_SELF_LOOP_ONLY" == "1" || "$TRACE_ALLOW_SELF_LOOP_ONLY" == "true" || "$TRACE_ALLOW_SELF_LOOP_ONLY" == "TRUE" ]]; then
  ALLOW_SELF_LOOP_ARG="--allow-self-loop-only"
fi
python3 "$SCRIPT_DIR/dynamic_trace_to_recovery_map.py" \
  "${TRACE_ARGS[@]}" \
  --base-map "$BASE_MAP_ABS" \
  --min-hits "$TRACE_MIN_HITS" \
  --min-sites "$TRACE_MIN_SITES" \
  --min-seed-score "$TRACE_MIN_SEED_SCORE" \
  --min-create-score "$TRACE_MIN_CREATE_SCORE" \
  $ALLOW_SELF_LOOP_ARG \
  --out "$TRACE_MAP_JSON" \
  --report "$TRACE_REPORT"

{
  echo "=== Sweep Summary ==="
  echo "entries_total:        $ENTRY_COUNT"
  echo "runs_ok:             $RUN_OK"
  echo "runs_failed:         $RUN_FAIL"
  echo "total_trace_lines:   $TOTAL_LINES"
  echo "total_executed_insn: $TOTAL_EXEC"
  echo "trace_merged_jsonl:  $TRACE_MERGED_JSONL"
  echo "trace_map:           $TRACE_MAP_JSON"
  echo "trace_report:        $TRACE_REPORT"
  echo "manifest_json:       $MANIFEST_JSON"
  echo "sweep_csv:           $OUT_DIR/sweep.csv"
} | tee "$SWEEP_REPORT"

echo ""
echo "=== Done ==="
echo "Next:"
echo "  ./re/nextdimension/kernel/scripts/run_analysis.sh \\"
echo "    \"$BINARY\" - \"$TRACE_MAP_JSON\" \"$REPORT_DIR/factpack/emu_trace_sweep\" \"$TRACE_MERGED_JSONL\""
