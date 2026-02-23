#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <input_m68k_exec> [output_dir]" >&2
  exit 1
fi

INPUT="$1"
OUTDIR="${2:-artifacts/extracted/run}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_PY="$SCRIPT_DIR/macho_scan_extract.py"

if [[ ! -f "$INPUT" ]]; then
  echo "input not found: $INPUT" >&2
  exit 1
fi

for tool in otool dd python3 shasum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

mkdir -p "$OUTDIR" "$OUTDIR/meta" "$OUTDIR/host_scan"

OTOOL_TXT="$OUTDIR/meta/otool_l.txt"
otool -l "$INPUT" > "$OTOOL_TXT"

INPUT_SIZE="$(stat -f%z "$INPUT" 2>/dev/null || stat -c%s "$INPUT")"
INPUT_SHA="$(shasum -a 256 "$INPUT" | awk '{print $1}')"

python3 "$SCAN_PY" "$INPUT" "$OUTDIR/host_scan" --primary-cpu 6

I860_SEG_LINE="$({
  awk '
    $1=="segname" && $2=="__I860" { hit=1; next }
    hit && $1=="vmaddr"  { vm=$2; next }
    hit && $1=="fileoff" { fo=$2; next }
    hit && $1=="filesize" { fs=$2; print vm, fo, fs; exit }
  ' "$OTOOL_TXT"
} || true)"

I860_PAYLOAD=""
if [[ -n "$I860_SEG_LINE" ]]; then
  read -r I860_VM I860_FILEOFF I860_FILESIZE <<<"$I860_SEG_LINE"

  if (( I860_FILESIZE > 0 )); then
    I860_PAYLOAD="$OUTDIR/i860_payload.bin"
    dd if="$INPUT" of="$I860_PAYLOAD" bs=1 skip=$((I860_FILEOFF)) count=$((I860_FILESIZE)) status=none
    mkdir -p "$OUTDIR/i860_scan"
    python3 "$SCAN_PY" "$I860_PAYLOAD" "$OUTDIR/i860_scan" --primary-cpu 15
  fi
fi

{
  echo "input: $INPUT"
  echo "input_size: $INPUT_SIZE"
  echo "input_sha256: $INPUT_SHA"
  echo ""
  if [[ -n "$I860_SEG_LINE" ]]; then
    echo "i860_segment_vmaddr: $I860_VM"
    echo "i860_segment_fileoff: $I860_FILEOFF"
    echo "i860_segment_filesize: $I860_FILESIZE"
    if [[ -n "$I860_PAYLOAD" ]]; then
      echo "i860_payload: $I860_PAYLOAD"
      echo "i860_payload_sha256: $(shasum -a 256 "$I860_PAYLOAD" | awk '{print $1}')"
    else
      echo "i860_payload: <not extracted>"
    fi
  else
    echo "i860_segment: <not present>"
  fi
} > "$OUTDIR/meta/extract_summary.txt"

SHAFILE="$OUTDIR/meta/sha256.txt"
{
  shasum -a 256 "$INPUT"
  if [[ -n "$I860_PAYLOAD" ]]; then
    shasum -a 256 "$I860_PAYLOAD"
  fi
} > "$SHAFILE"

echo "wrote: $OUTDIR/meta/extract_summary.txt"
echo "wrote: $OUTDIR/host_scan/manifest.json"
if [[ -f "$OUTDIR/i860_scan/manifest.json" ]]; then
  echo "wrote: $OUTDIR/i860_scan/manifest.json"
fi
