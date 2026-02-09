#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-/Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/firmware/ND_MachDriver_reloc}"
OUTDIR="${2:-re/nextdimension/firmware/extracted}"
CLEAN_TEXT_BYTES="${3:-0x31000}" # default: 200,704 B window used by ND_i860_CLEAN.bin

if [[ ! -f "$INPUT" ]]; then
  echo "Input not found: $INPUT" >&2
  exit 1
fi

if ! command -v otool >/dev/null 2>&1; then
  echo "otool is required on macOS for Mach-O metadata parsing." >&2
  exit 1
fi

mkdir -p "$OUTDIR"

OTXT="$(mktemp)"
otool -lv "$INPUT" > "$OTXT"
INPUT_SIZE="$(stat -f%z "$INPUT")"

parse_segment() {
  local seg="$1"
  awk -v seg="$seg" '
    $1=="segname" && $2==seg { hit=1; next }
    hit && $1=="vmaddr" { vm=$2; next }
    hit && $1=="vmsize" { vs=$2; next }
    hit && $1=="fileoff" { fo=$2; next }
    hit && $1=="filesize" { fs=$2; print vm,vs,fo,fs; exit }
  ' "$OTXT"
}

parse_section() {
  local sec="$1"
  awk -v sec="$sec" '
    $1=="sectname" && $2==sec { hit=1; next }
    hit && $1=="segname" { sg=$2; next }
    hit && $1=="addr" { ad=$2; next }
    hit && $1=="size" { sz=$2; next }
    hit && $1=="offset" { of=$2; next }
    hit && $1=="align" { print sg,ad,sz,of; exit }
  ' "$OTXT"
}

read -r text_vm text_vs text_fo text_fs <<<"$(parse_segment __TEXT)"
read -r data_vm data_vs data_fo data_fs <<<"$(parse_segment __DATA)"

read -r text_sg text_sa text_ss text_so <<<"$(parse_section __text)"
read -r data_sg data_sa data_ss data_so <<<"$(parse_section __data)"

if [[ -z "${text_fo:-}" || -z "${data_fo:-}" || -z "${text_so:-}" || -z "${data_so:-}" ]]; then
  echo "Failed to parse Mach-O segments/sections from $INPUT" >&2
  rm -f "$OTXT"
  exit 1
fi

TEXT_SEG_OUT="$OUTDIR/ND_MachDriver___TEXT_segment.bin"
TEXT_SEC_OUT="$OUTDIR/ND_MachDriver___TEXT_section.bin"
DATA_SEG_OUT="$OUTDIR/ND_MachDriver___DATA_segment.bin"
DATA_SEC_OUT="$OUTDIR/ND_MachDriver___DATA_section.bin"
HEADER_OUT="$OUTDIR/ND_MachDriver_MachO_header.bin"
TEXT_CLEAN_OUT="$OUTDIR/ND_MachDriver___TEXT_clean_window.bin"
TEXT_POST_CLEAN_OUT="$OUTDIR/ND_MachDriver___TEXT_post_clean.bin"
EMBEDDED_MACHO_OUT="$OUTDIR/EMBEDDED_MACHO_HEADERS.txt"
BYTE_ACCOUNT_OUT="$OUTDIR/BYTE_ACCOUNTING.txt"

# shellcheck disable=SC2004

dd if="$INPUT" of="$HEADER_OUT" ibs=1 skip=0 count=$((text_fo)) status=none
# shellcheck disable=SC2004
dd if="$INPUT" of="$TEXT_SEG_OUT" ibs=1 skip=$((text_fo)) count=$((text_fs)) status=none
# shellcheck disable=SC2004
dd if="$INPUT" of="$TEXT_SEC_OUT" ibs=1 skip=$((text_so)) count=$((text_ss)) status=none
# shellcheck disable=SC2004
dd if="$INPUT" of="$DATA_SEG_OUT" ibs=1 skip=$((data_fo)) count=$((data_fs)) status=none
# shellcheck disable=SC2004
dd if="$INPUT" of="$DATA_SEC_OUT" ibs=1 skip=$((data_so)) count=$((data_ss)) status=none

TEXT_SEC_SIZE=$((text_ss))
REQUESTED_CLEAN_SIZE=$((CLEAN_TEXT_BYTES))
if (( REQUESTED_CLEAN_SIZE < 0 )); then
  REQUESTED_CLEAN_SIZE=0
fi
if (( REQUESTED_CLEAN_SIZE > TEXT_SEC_SIZE )); then
  CLEAN_SIZE=$TEXT_SEC_SIZE
else
  CLEAN_SIZE=$REQUESTED_CLEAN_SIZE
fi
POST_CLEAN_SIZE=$((TEXT_SEC_SIZE - CLEAN_SIZE))

dd if="$TEXT_SEC_OUT" of="$TEXT_CLEAN_OUT" ibs=1 skip=0 count=$CLEAN_SIZE status=none
if (( POST_CLEAN_SIZE > 0 )); then
  dd if="$TEXT_SEC_OUT" of="$TEXT_POST_CLEAN_OUT" ibs=1 skip=$CLEAN_SIZE count=$POST_CLEAN_SIZE status=none
else
  : > "$TEXT_POST_CLEAN_OUT"
fi

# Scan __TEXT section for embedded Mach-O headers (FEEDFACE/CEFAEDFE).
perl -e '
use strict;
use warnings;

my ($file, $base_hex, $out_file) = @ARGV;
open(my $fh, "<:raw", $file) or die "open $file: $!";
my $size = -s $fh;
my $data = "";
read($fh, $data, $size) == $size or die "read failed";
close($fh);

my $base = hex($base_hex);
my %cpu_name = (
  7  => "x86",
  6  => "m68k",
  15 => "i860",
);

open(my $out, ">", $out_file) or die "open $out_file: $!";
print $out "offset_file  vmaddr      magic      cpu_type  cpu_name  primary\n";

for (my $i = 0; $i + 28 <= length($data); $i += 4) {
  my $word = unpack("N", substr($data, $i, 4));
  next unless ($word == 0xFEEDFACE || $word == 0xCEFAEDFE);

  my $be = ($word == 0xFEEDFACE) ? 1 : 0;
  my $cpu = $be
    ? unpack("N", substr($data, $i + 4, 4))
    : unpack("V", substr($data, $i + 4, 4));

  my $magic = $be ? "FEEDFACE" : "CEFAEDFE";
  my $name = exists($cpu_name{$cpu}) ? $cpu_name{$cpu} : "unknown";
  my $primary = ($i == 0) ? "yes" : "no";

  printf $out "0x%06X     0x%08X  %-8s  %-8u  %-7s  %s\n",
      $i, ($base + $i), $magic, $cpu, $name, $primary;
}
close($out);
' "$TEXT_SEC_OUT" "$text_sa" "$EMBEDDED_MACHO_OUT"

TEXT_FO_DEC=$((text_fo))
TEXT_FS_DEC=$((text_fs))
DATA_FO_DEC=$((data_fo))
DATA_FS_DEC=$((data_fs))
TEXT_END_DEC=$((TEXT_FO_DEC + TEXT_FS_DEC))
DATA_END_DEC=$((DATA_FO_DEC + DATA_FS_DEC))
GAP_TEXT_TO_DATA=$((DATA_FO_DEC - TEXT_END_DEC))
TAIL_BYTES=$((INPUT_SIZE - DATA_END_DEC))
HEADER_BYTES=$TEXT_FO_DEC
ACCOUNTING_TOTAL=$((HEADER_BYTES + TEXT_FS_DEC + GAP_TEXT_TO_DATA + DATA_FS_DEC + TAIL_BYTES))

{
  echo "Input: $INPUT"
  echo "Input size: $INPUT_SIZE bytes"
  echo ""
  echo "Header bytes before __TEXT segment: $HEADER_BYTES"
  echo "__TEXT segment bytes: $TEXT_FS_DEC"
  echo "Gap bytes between __TEXT and __DATA file ranges: $GAP_TEXT_TO_DATA"
  echo "__DATA segment bytes: $DATA_FS_DEC"
  echo "Trailing bytes after __DATA segment: $TAIL_BYTES"
  echo "Accounted total: $ACCOUNTING_TOTAL"
  echo ""
  if (( ACCOUNTING_TOTAL == INPUT_SIZE )); then
    echo "Byte accounting: OK (100% of bytes accounted for)"
  else
    echo "Byte accounting: MISMATCH (check segment parsing)"
  fi
  echo ""
  echo "Clean window request: $CLEAN_TEXT_BYTES ($REQUESTED_CLEAN_SIZE bytes)"
  echo "Clean window extracted: $CLEAN_SIZE bytes"
  echo "Post-clean __TEXT remainder: $POST_CLEAN_SIZE bytes"
  echo ""
  echo "Notes:"
  echo "- __DATA extraction covers initialized data from file-backed __data only."
  echo "- Runtime BSS/common structures are zero-init and not present as initialized bytes."
  echo "- Clean-window extraction is a convenience slice and does NOT prove absence/presence of i860 code outside that window."
} > "$BYTE_ACCOUNT_OUT"

META="$OUTDIR/SEGMENTS.txt"
{
  echo "Input: $INPUT"
  echo "Input size: $INPUT_SIZE bytes"
  echo ""
  echo "__TEXT segment: vmaddr=$text_vm vmsize=$text_vs fileoff=$text_fo filesize=$text_fs"
  echo "__text section: seg=$text_sg addr=$text_sa size=$text_ss offset=$text_so"
  echo ""
  echo "__DATA segment: vmaddr=$data_vm vmsize=$data_vs fileoff=$data_fo filesize=$data_fs"
  echo "__data section: seg=$data_sg addr=$data_sa size=$data_ss offset=$data_so"
  echo ""
  echo "Clean window bytes: $CLEAN_SIZE (requested $REQUESTED_CLEAN_SIZE)"
  echo "Post-clean bytes: $POST_CLEAN_SIZE"
} > "$META"

shasum -a 256 \
  "$HEADER_OUT" \
  "$TEXT_SEG_OUT" \
  "$TEXT_SEC_OUT" \
  "$TEXT_CLEAN_OUT" \
  "$TEXT_POST_CLEAN_OUT" \
  "$DATA_SEG_OUT" \
  "$DATA_SEC_OUT" > "$OUTDIR/sha256.txt"

ls -lh \
  "$HEADER_OUT" \
  "$TEXT_SEG_OUT" \
  "$TEXT_SEC_OUT" \
  "$TEXT_CLEAN_OUT" \
  "$TEXT_POST_CLEAN_OUT" \
  "$DATA_SEG_OUT" \
  "$DATA_SEC_OUT"

echo ""
echo "Wrote metadata: $META"
echo "Wrote byte accounting: $BYTE_ACCOUNT_OUT"
echo "Wrote embedded Mach-O header inventory: $EMBEDDED_MACHO_OUT"
echo "Wrote checksums: $OUTDIR/sha256.txt"

rm -f "$OTXT"
