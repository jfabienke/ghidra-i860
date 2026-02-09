#!/usr/bin/env bash
set -euo pipefail

EXTRACTED_DIR="${1:-re/nextdimension/firmware/extracted}"
shift || true
DOCS=("$@")
if [[ ${#DOCS[@]} -eq 0 ]]; then
  DOCS=("re/nextdimension/firmware/docs/firmware-analysis.md")
fi

BYTE_ACCOUNTING="$EXTRACTED_DIR/BYTE_ACCOUNTING.txt"
EMBEDDED_HEADERS="$EXTRACTED_DIR/EMBEDDED_MACHO_HEADERS.txt"
SEGMENTS="$EXTRACTED_DIR/SEGMENTS.txt"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "Missing required file: $path"
}

require_file "$BYTE_ACCOUNTING"
require_file "$EMBEDDED_HEADERS"
require_file "$SEGMENTS"

# 1) Byte accounting must be complete.
grep -q "Byte accounting: OK (100% of bytes accounted for)" "$BYTE_ACCOUNTING" \
  || fail "Byte accounting is not OK in $BYTE_ACCOUNTING"

input_size="$(awk '/^Input size:/ {print $3; exit}' "$BYTE_ACCOUNTING")"
accounted_total="$(awk '/^Accounted total:/ {print $3; exit}' "$BYTE_ACCOUNTING")"
[[ -n "${input_size:-}" && -n "${accounted_total:-}" ]] \
  || fail "Could not parse input/accounted byte counts from $BYTE_ACCOUNTING"
[[ "$input_size" == "$accounted_total" ]] \
  || fail "Input size ($input_size) != accounted total ($accounted_total)"

# 2) Embedded Mach-O header inventory must match canonical scan output.
actual_headers="$(awk 'NR>1 && $1 ~ /^0x/ {printf "%s %s %s %s %s %s\n",$1,$2,$3,$4,$5,$6}' "$EMBEDDED_HEADERS")"
expected_headers="$(cat <<'EOF'
0x017CB8 0xF8017CB8 FEEDFACE 6 m68k no
0x03DCB8 0xF803DCB8 CEFAEDFE 7 x86 no
0x05DCB8 0xF805DCB8 CEFAEDFE 7 x86 no
EOF
)"
if [[ "$actual_headers" != "$expected_headers" ]]; then
  echo "Expected embedded header inventory:" >&2
  echo "$expected_headers" >&2
  echo "Actual embedded header inventory:" >&2
  echo "$actual_headers" >&2
  fail "Embedded Mach-O header inventory mismatch"
fi

# 3) Clean/post-clean split must exactly partition __text section.
text_size_hex="$(awk -F'size=' '/__text section:/ {split($2,a," "); print a[1]; exit}' "$SEGMENTS")"
clean_size_dec="$(awk '/^Clean window bytes:/ {print $4; exit}' "$SEGMENTS")"
post_size_dec="$(awk '/^Post-clean bytes:/ {print $3; exit}' "$SEGMENTS")"

[[ -n "${text_size_hex:-}" && -n "${clean_size_dec:-}" && -n "${post_size_dec:-}" ]] \
  || fail "Could not parse __text/clean/post sizes from $SEGMENTS"

text_size_dec=$((text_size_hex))
split_total=$((clean_size_dec + post_size_dec))
[[ "$split_total" -eq "$text_size_dec" ]] \
  || fail "Clean/post split mismatch: clean($clean_size_dec)+post($post_size_dec)!=$text_size_dec"

# 4) Optional doc-level sanity checks against known stale phrasing.
docs_checked=0
for doc in "${DOCS[@]}"; do
  if [[ ! -f "$doc" ]]; then
    echo "WARN: skipping missing doc: $doc" >&2
    continue
  fi

  grep -q "0x017CB8" "$doc" || fail "Doc missing canonical m68k header offset 0x017CB8: $doc"
  grep -q "0x03DCB8" "$doc" || fail "Doc missing canonical x86 header offset 0x03DCB8: $doc"
  grep -q "0x05DCB8" "$doc" || fail "Doc missing canonical x86 header offset 0x05DCB8: $doc"

  if grep -Eq "Embedded i386.*0x15B58.*0x2DC00|Embedded i386.*0x2DC00.*0x15B58" "$doc"; then
    fail "Doc contains stale embedded-i386 offset claim (0x15B58/0x2DC00): $doc"
  fi
  if grep -q "Embedded i386 contamination — identified, bounded, excluded (0x15B58, 0x2DC00)" "$doc"; then
    fail "Doc contains stale claim phrase (0x15B58/0x2DC00): $doc"
  fi

  docs_checked=$((docs_checked + 1))
done

echo "PASS: extraction ground truth validated"
echo "  input/accounted bytes: $input_size"
echo "  embedded headers: 3 (m68k@0x017CB8, x86@0x03DCB8, x86@0x05DCB8)"
echo "  __text split: clean=$clean_size_dec post-clean=$post_size_dec total=$text_size_dec"
echo "  docs checked: $docs_checked"
