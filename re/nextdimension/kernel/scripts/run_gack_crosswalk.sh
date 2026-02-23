#!/bin/bash
# GaCK source-to-binary crosswalk pipeline.
#
# Usage:
#   ./re/nextdimension/kernel/scripts/run_gack_crosswalk.sh \
#     [ndkernel_source] [binary] [factpack_dir] [out_dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$KERNEL_DIR/reports"

NDKERNEL_SOURCE="${1:-/Users/jvindahl/Development/re/NeXTDimension/NextDimension-21/NDkernel}"
BINARY="${2:-$KERNEL_DIR/i860_kernel.bin}"
FACTPACK_DIR="${3:-}"
OUT_DIR="${4:-$REPORT_DIR/crosswalk/$(date -u +%Y%m%d-%H%M%S)}"

MIN_SCORE="${CROSSWALK_MIN_SCORE:-24}"
MIN_CONFIDENCE="${CROSSWALK_MIN_CONFIDENCE:-60}"
TOP_K="${CROSSWALK_TOP_K:-8}"
SOURCE_VERSION="${CROSSWALK_SOURCE_VERSION:-NeXTSTEP-2.0}"
TARGET_VERSION="${CROSSWALK_TARGET_VERSION:-NeXTSTEP-3.3}"
ALLOW_COMPAT_LABELS="${CROSSWALK_ALLOW_COMPAT_LABELS:-0}"
COMPAT_LABEL_CLASS="${CROSSWALK_COMPAT_LABEL_CLASS:-strong_compat}"

mkdir -p "$OUT_DIR"

if [[ ! -d "$NDKERNEL_SOURCE" ]]; then
  echo "ERROR: NDkernel source dir not found: $NDKERNEL_SOURCE" >&2
  exit 1
fi
if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: binary not found: $BINARY" >&2
  exit 1
fi

if [[ -z "$FACTPACK_DIR" ]]; then
  if [[ -f "$REPORT_DIR/factpack/retagged/functions.jsonl" ]]; then
    FACTPACK_DIR="$REPORT_DIR/factpack/retagged"
  else
    FACTPACK_DIR="$(find "$REPORT_DIR/factpack" -maxdepth 1 -mindepth 1 -type d \
      -exec test -f '{}/functions.jsonl' ';' -print | sort | tail -n 1)"
  fi
fi

if [[ -z "$FACTPACK_DIR" || ! -f "$FACTPACK_DIR/functions.jsonl" ]]; then
  echo "ERROR: could not resolve factpack dir with functions.jsonl" >&2
  exit 1
fi

SOURCE_JSON="$OUT_DIR/source_functions.json"
BINARY_JSON="$OUT_DIR/binary_functions.json"
MATCH_JSON="$OUT_DIR/matches.json"
MATCH_CSV="$OUT_DIR/matches_ranked.csv"
LABEL_CSV="$OUT_DIR/ghidra_labels.csv"
LABEL_JSON="$OUT_DIR/ghidra_apply_crosswalk.json"
SUMMARY_TXT="$OUT_DIR/summary.txt"

{
  echo "=== GaCK Crosswalk ==="
  echo "ndkernel_source:  $NDKERNEL_SOURCE"
  echo "binary:           $BINARY"
  echo "factpack:         $FACTPACK_DIR"
  echo "out_dir:          $OUT_DIR"
  echo "min_score:        $MIN_SCORE"
  echo "min_confidence:   $MIN_CONFIDENCE"
  echo "top_k:            $TOP_K"
  echo "source_version:   $SOURCE_VERSION"
  echo "target_version:   $TARGET_VERSION"
  echo "allow_compat_lbl: $ALLOW_COMPAT_LABELS"
  echo "compat_lbl_class: $COMPAT_LABEL_CLASS"
  if [[ "$SOURCE_VERSION" != "$TARGET_VERSION" ]]; then
    echo "NOTE: compatibility mode active ($SOURCE_VERSION -> $TARGET_VERSION)."
    echo "      Labels are blocked unless CROSSWALK_ALLOW_COMPAT_LABELS=1."
  fi
  echo
} | tee "$SUMMARY_TXT"

python3 "$SCRIPT_DIR/extract_gack_source_facts.py" \
  --source-root "$NDKERNEL_SOURCE" \
  --source-version "$SOURCE_VERSION" \
  --out "$SOURCE_JSON" | tee -a "$SUMMARY_TXT"

python3 "$SCRIPT_DIR/extract_binary_facts.py" \
  --factpack "$FACTPACK_DIR" \
  --target-version "$TARGET_VERSION" \
  --out "$BINARY_JSON" | tee -a "$SUMMARY_TXT"

python3 "$SCRIPT_DIR/match_gack_to_binary.py" \
  --source "$SOURCE_JSON" \
  --binary "$BINARY_JSON" \
  --out-json "$MATCH_JSON" \
  --out-csv "$MATCH_CSV" \
  --min-score "$MIN_SCORE" \
  --top-k "$TOP_K" \
  --source-version "$SOURCE_VERSION" \
  --target-version "$TARGET_VERSION" | tee -a "$SUMMARY_TXT"

LABEL_ARGS=(
  --matches "$MATCH_JSON"
  --out-csv "$LABEL_CSV"
  --out-json "$LABEL_JSON"
  --min-confidence "$MIN_CONFIDENCE"
  --compat-class "$COMPAT_LABEL_CLASS"
)
if [[ "$ALLOW_COMPAT_LABELS" == "1" ]]; then
  LABEL_ARGS+=(--allow-compat-labels)
fi

python3 "$SCRIPT_DIR/generate_crosswalk_labels.py" \
  "${LABEL_ARGS[@]}" \
  | tee -a "$SUMMARY_TXT"

{
  echo
  echo "Artifacts:"
  echo "  $SOURCE_JSON"
  echo "  $BINARY_JSON"
  echo "  $MATCH_JSON"
  echo "  $MATCH_CSV"
  echo "  $LABEL_CSV"
  echo "  $LABEL_JSON"
} | tee -a "$SUMMARY_TXT"
