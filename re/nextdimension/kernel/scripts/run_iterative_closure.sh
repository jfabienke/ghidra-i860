#!/bin/bash
# Iterative closure loop:
#   sweep traces -> convert to dynamic map -> run Ghidra analysis -> collect KPIs.
#
# Usage:
#   ./re/nextdimension/kernel/scripts/run_iterative_closure.sh \
#     <binary> <base_map_json> <state_json> [max_iters]
#
# Optional env knobs:
#   CLOSURE_AUTO_STATE_GAPS=1
#     If set, apply register/memory/MMIO hints between iterations using
#     generate_state_from_trace.py output + CLOSURE_STATE_HINTS_JSON.
#   CLOSURE_STATE_HINTS_JSON=<path>
#     JSON file with optional "registers", "memory_u32", "mmio_stubs" maps.
#   CLOSURE_STATE_GAP_MAX_REGS=<N>    (default: 2)
#   CLOSURE_STATE_GAP_FALLBACK=0|1    (default: 0)
#   CLOSURE_STATE_GAP_FILL=0x1        (default: 0x00000001)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$KERNEL_DIR/reports"

BINARY="${1:-$KERNEL_DIR/i860_kernel.bin}"
BASE_MAP="${2:-$KERNEL_DIR/docs/recovery_map_hardmask_pcode.json}"
STATE_JSON="${3:-$KERNEL_DIR/scripts/nd_firmware_state.json}"
MAX_ITERS="${4:-5}"

BASE_ADDR="${CLOSURE_BASE_ADDR:-0xF8000000}"
MAX_STEPS="${CLOSURE_MAX_STEPS:-200000}"
WORK_DIR="${CLOSURE_WORK_DIR:-$REPORT_DIR/iterative_closure/$(date -u +%Y%m%d-%H%M%S)}"
ENTRY_SPEC="${CLOSURE_ENTRY_SPEC:-}"
AUTO_STATE_GAPS="${CLOSURE_AUTO_STATE_GAPS:-0}"
STATE_HINTS_JSON="${CLOSURE_STATE_HINTS_JSON:-}"
STATE_GAP_MAX_REGS="${CLOSURE_STATE_GAP_MAX_REGS:-2}"
STATE_GAP_FALLBACK="${CLOSURE_STATE_GAP_FALLBACK:-0}"
STATE_GAP_FILL="${CLOSURE_STATE_GAP_FILL:-0x00000001}"

mkdir -p "$WORK_DIR"

if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: binary not found: $BINARY" >&2
  exit 1
fi
if [[ ! -f "$BASE_MAP" ]]; then
  echo "ERROR: base map not found: $BASE_MAP" >&2
  exit 1
fi
if [[ -n "$STATE_JSON" && ! -f "$STATE_JSON" ]]; then
  echo "ERROR: state json not found: $STATE_JSON" >&2
  exit 1
fi
if [[ -n "$STATE_HINTS_JSON" && ! -f "$STATE_HINTS_JSON" ]]; then
  echo "ERROR: state hints json not found: $STATE_HINTS_JSON" >&2
  exit 1
fi

KPI_CSV="$WORK_DIR/kpi.csv"
KPI_JSON="$WORK_DIR/kpi_summary.json"
RUN_LOG="$WORK_DIR/run.log"

echo "iteration,dynamic_added,targets_seen,trace_events,indirect_events,functions,instructions,code_bytes,coverage_pct,stop_reason_top,state_gap_top,state_mutations,state_json,map_path,trace_path,factpack_dir" > "$KPI_CSV"

CURRENT_MAP="$BASE_MAP"
CURRENT_STATE_JSON="$STATE_JSON"
CONVERGED=0

{
  echo "=== Iterative Closure ==="
  echo "Binary:      $BINARY"
  echo "Base map:    $BASE_MAP"
  echo "State json:  ${STATE_JSON:-<none>}"
  echo "Auto gaps:   $AUTO_STATE_GAPS"
  echo "Hints json:  ${STATE_HINTS_JSON:-<none>}"
  echo "Gap max reg: $STATE_GAP_MAX_REGS"
  echo "Gap fallback:${STATE_GAP_FALLBACK} (fill=${STATE_GAP_FILL})"
  echo "Iterations:  $MAX_ITERS"
  echo "Work dir:    $WORK_DIR"
  echo "Base addr:   $BASE_ADDR"
  echo "Max steps:   $MAX_STEPS"
  echo "Entry spec:  ${ENTRY_SPEC:-<auto>}"
  echo
} | tee -a "$RUN_LOG"

for i in $(seq 1 "$MAX_ITERS"); do
  ITER_DIR="$WORK_DIR/iter_${i}"
  SWEEP_DIR="$ITER_DIR/sweep"
  FACTPACK_DIR="$ITER_DIR/factpack"
  mkdir -p "$ITER_DIR"

  {
    echo "=== Iteration $i ==="
    echo "Input map: $CURRENT_MAP"
  } | tee -a "$RUN_LOG"

  if [[ -n "$ENTRY_SPEC" ]]; then
    "$SCRIPT_DIR/run_emu_trace_seed_sweep.sh" \
      "$BINARY" "$BASE_ADDR" "$MAX_STEPS" "$SWEEP_DIR" "$CURRENT_MAP" "$ENTRY_SPEC" "$CURRENT_STATE_JSON"
  else
    "$SCRIPT_DIR/run_emu_trace_seed_sweep.sh" \
      "$BINARY" "$BASE_ADDR" "$MAX_STEPS" "$SWEEP_DIR" "$CURRENT_MAP" "" "$CURRENT_STATE_JSON"
  fi

  DYNAMIC_MAP="$SWEEP_DIR/dynamic_recovery_map.json"
  TRACE_MERGED="$SWEEP_DIR/runtime_trace_merged.jsonl"
  STATE_GAP_JSON="$ITER_DIR/state_gap.json"
  STATE_GAP_TXT="$ITER_DIR/state_gap.txt"

  if [[ ! -f "$DYNAMIC_MAP" ]]; then
    echo "ERROR: missing dynamic map after sweep: $DYNAMIC_MAP" | tee -a "$RUN_LOG"
    exit 1
  fi
  if [[ ! -f "$TRACE_MERGED" ]]; then
    echo "ERROR: missing merged trace after sweep: $TRACE_MERGED" | tee -a "$RUN_LOG"
    exit 1
  fi

  python3 "$SCRIPT_DIR/generate_state_from_trace.py" \
    --trace "$TRACE_MERGED" \
    --out-json "$STATE_GAP_JSON" \
    --out-txt "$STATE_GAP_TXT" >/dev/null

  STATE_GAP_TOP="$(python3 - <<'PY' "$STATE_GAP_JSON"
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    j=json.load(f)
rows=j.get('register_seed_candidates',[])
if not rows:
    print('<none>')
else:
    r=rows[0]
    print(f"{r.get('reg','?')}:{int(r.get('zero_events',0))}")
PY
)"
  SWEEP_STOP_TOP="$(python3 - <<'PY' "$SWEEP_DIR/sweep.csv"
import csv,sys
from collections import Counter
p=sys.argv[1]
c=Counter()
with open(p,newline='',encoding='utf-8') as f:
    for r in csv.DictReader(f):
        s=(r.get('stop_reason') or '').strip()
        if s:
            c[s]+=1
if not c:
    print('<none>')
else:
    k,v=c.most_common(1)[0]
    print(f'{k}:{v}')
PY
)"
  STATE_MUTATIONS=0
  STATE_NEXT_JSON="$CURRENT_STATE_JSON"

  if [[ "$AUTO_STATE_GAPS" -eq 1 ]]; then
    STATE_NEXT_JSON="$ITER_DIR/state_next.json"
    STATE_MUTATIONS="$(python3 - <<'PY' \
      "$CURRENT_STATE_JSON" "$STATE_GAP_JSON" "$STATE_HINTS_JSON" "$STATE_NEXT_JSON" \
      "$STATE_GAP_MAX_REGS" "$STATE_GAP_FALLBACK" "$STATE_GAP_FILL"
import json, sys
from pathlib import Path

base_path = sys.argv[1]
gap_path = sys.argv[2]
hints_path = sys.argv[3]
out_path = sys.argv[4]
max_regs = max(0, int(sys.argv[5]))
fallback_enabled = int(sys.argv[6]) != 0
fill_text = sys.argv[7].strip()

def parse_u32(v):
    if isinstance(v, int):
        return v & 0xffffffff
    if isinstance(v, str):
        s = v.strip().lower().replace('_','')
        if s.startswith('0x'):
            return int(s, 16) & 0xffffffff
        return int(s, 10) & 0xffffffff
    raise ValueError(f"unsupported u32 value: {v!r}")

def fmt_u32(v):
    return f"0x{(v & 0xffffffff):08X}"

if base_path and Path(base_path).is_file():
    base = json.loads(Path(base_path).read_text(encoding='utf-8'))
else:
    base = {}
if not isinstance(base, dict):
    base = {}

base.setdefault("registers", {})
base.setdefault("memory_u32", {})
base.setdefault("mmio_stubs", {})

gaps = json.loads(Path(gap_path).read_text(encoding='utf-8'))
reg_candidates = gaps.get("register_seed_candidates", []) or []
reg_names = []
for row in reg_candidates:
    if not isinstance(row, dict):
        continue
    reg = row.get("reg")
    if isinstance(reg, str) and reg.startswith("r") and reg != "r0":
        reg_names.append(reg)
    if len(reg_names) >= max_regs:
        break

hints = {}
if hints_path and Path(hints_path).is_file():
    obj = json.loads(Path(hints_path).read_text(encoding='utf-8'))
    if isinstance(obj, dict):
        hints = obj

h_regs = hints.get("registers", {}) if isinstance(hints.get("registers"), dict) else {}
h_mem = hints.get("memory_u32", {}) if isinstance(hints.get("memory_u32"), dict) else {}
h_mmio = hints.get("mmio_stubs", {}) if isinstance(hints.get("mmio_stubs"), dict) else {}

fill_val = parse_u32(fill_text)
mutations = 0

for reg in reg_names:
    cur = base["registers"].get(reg)
    cur_u32 = None
    try:
        if cur is not None:
            cur_u32 = parse_u32(cur)
    except Exception:
        cur_u32 = None
    if cur_u32 not in (None, 0):
        continue
    if reg in h_regs:
        val = parse_u32(h_regs[reg])
        base["registers"][reg] = fmt_u32(val)
        mutations += 1
    elif fallback_enabled:
        base["registers"][reg] = fmt_u32(fill_val)
        mutations += 1

for k, v in h_mem.items():
    try:
        _ = parse_u32(k)
        val = parse_u32(v)
    except Exception:
        continue
    if base["memory_u32"].get(k) != fmt_u32(val):
        base["memory_u32"][k] = fmt_u32(val)
        mutations += 1

for k, v in h_mmio.items():
    try:
        _ = parse_u32(k)
        val = parse_u32(v)
    except Exception:
        continue
    if base["mmio_stubs"].get(k) != fmt_u32(val):
        base["mmio_stubs"][k] = fmt_u32(val)
        mutations += 1

Path(out_path).write_text(json.dumps(base, indent=2) + "\n", encoding='utf-8')
print(mutations)
PY
)"
    CURRENT_STATE_JSON="$STATE_NEXT_JSON"
  fi

  "$SCRIPT_DIR/run_analysis.sh" "$BINARY" - "$DYNAMIC_MAP" "$FACTPACK_DIR"

  REPORT_TXT="$REPORT_DIR/i860_kernel_report.txt"
  HEADLESS_LOG="$REPORT_DIR/headless.log"

  cp "$REPORT_TXT" "$ITER_DIR/i860_kernel_report.txt"
  cp "$HEADLESS_LOG" "$ITER_DIR/headless.log"

  DYNAMIC_ADDED="$(python3 - <<'PY' "$DYNAMIC_MAP"
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    j=json.load(f)
print(int(j.get('meta',{}).get('dynamic_added',0)))
PY
)"
  TARGETS_SEEN="$(python3 - <<'PY' "$DYNAMIC_MAP"
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    j=json.load(f)
m=j.get('meta',{})
print(int(m.get('targets_seen',0)))
PY
)"
  TRACE_EVENTS="$(python3 - <<'PY' "$DYNAMIC_MAP"
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    j=json.load(f)
m=j.get('meta',{})
print(int(m.get('events_total',0)))
PY
)"
  INDIRECT_EVENTS="$(python3 - <<'PY' "$DYNAMIC_MAP"
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    j=json.load(f)
m=j.get('meta',{})
print(int(m.get('indirect_events',0)))
PY
)"

  FUNCTIONS="$(rg -o '^Functions:\s+[0-9,]+' "$REPORT_TXT" | tail -1 | awk '{gsub(",","",$2); print $2}')"
  INSTRUCTIONS="$(rg -o '^Instructions:\s+[0-9,]+' "$REPORT_TXT" | tail -1 | awk '{gsub(",","",$2); print $2}')"
  CODE_BYTES="$(rg -o '^Code bytes:\s+[0-9,]+' "$REPORT_TXT" | tail -1 | awk '{gsub(",","",$3); print $3}')"
  COVERAGE="$(rg -o '^Coverage:\s+[0-9.]+%' "$REPORT_TXT" | tail -1 | awk '{print $2}' | tr -d '%')"

  FUNCTIONS="${FUNCTIONS:-0}"
  INSTRUCTIONS="${INSTRUCTIONS:-0}"
  CODE_BYTES="${CODE_BYTES:-0}"
  COVERAGE="${COVERAGE:-0}"

  echo "$i,$DYNAMIC_ADDED,$TARGETS_SEEN,$TRACE_EVENTS,$INDIRECT_EVENTS,$FUNCTIONS,$INSTRUCTIONS,$CODE_BYTES,$COVERAGE,$SWEEP_STOP_TOP,$STATE_GAP_TOP,$STATE_MUTATIONS,$STATE_NEXT_JSON,$DYNAMIC_MAP,$TRACE_MERGED,$FACTPACK_DIR" >> "$KPI_CSV"

  {
    echo "dynamic_added: $DYNAMIC_ADDED"
    echo "functions:     $FUNCTIONS"
    echo "instructions:  $INSTRUCTIONS"
    echo "coverage_pct:  $COVERAGE"
    echo "stop_reason:   $SWEEP_STOP_TOP"
    echo "state_gap_top: $STATE_GAP_TOP"
    echo "state_mutate:  $STATE_MUTATIONS"
    echo "state_json:    $STATE_NEXT_JSON"
    echo
  } | tee -a "$RUN_LOG"

  if [[ "$DYNAMIC_ADDED" -eq 0 ]]; then
    if [[ "$AUTO_STATE_GAPS" -eq 1 && "$STATE_MUTATIONS" -gt 0 ]]; then
      echo "dynamic_added=0 but applied state mutations ($STATE_MUTATIONS); continuing" | tee -a "$RUN_LOG"
      CURRENT_MAP="$DYNAMIC_MAP"
      continue
    else
      CONVERGED=1
      echo "Converged at iteration $i (dynamic_added=0)" | tee -a "$RUN_LOG"
      break
    fi
  fi

  CURRENT_MAP="$DYNAMIC_MAP"
done

python3 - <<'PY' "$KPI_CSV" "$KPI_JSON" "$CONVERGED"
import csv
import json
import sys

kpi_csv = sys.argv[1]
kpi_json = sys.argv[2]
converged = bool(int(sys.argv[3]))

rows = []
with open(kpi_csv, newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        rows.append(r)

summary = {
    'schema': 'iterative-closure-kpi-v1',
    'iterations': len(rows),
    'converged': converged,
    'rows': rows,
}

with open(kpi_json, 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
    f.write('\n')
PY

echo
if [[ "$CONVERGED" -eq 1 ]]; then
  echo "=== Iterative Closure Complete (converged) ==="
else
  echo "=== Iterative Closure Complete (max iterations reached) ==="
fi
echo "KPI CSV:     $KPI_CSV"
echo "KPI JSON:    $KPI_JSON"
echo "Work dir:    $WORK_DIR"
