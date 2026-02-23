#!/bin/bash
# Disassemble m68k code from NDserver using rasm2
# Entry point: 0x00002d10
# Size: 18,664 bytes

INPUT="extracted/m68k_text.bin"
OUTPUT="disassembly/m68k_full.asm"
BASE_ADDR=0x00002d10

echo "# NDserver m68k Disassembly" > "$OUTPUT"
echo "# Entry Point: 0x$(printf '%08x' $BASE_ADDR)" >> "$OUTPUT"
echo "# Size: $(stat -f%z $INPUT) bytes" >> "$OUTPUT"
echo "# Disassembler: rasm2 (m68k.gnu)" >> "$OUTPUT"
echo "# Date: $(date)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Disassemble with rasm2
# -a: architecture
# -d: disassemble mode
# -B: binary input
# -f: input file
rasm2 -a m68k.gnu -d -B -f "$INPUT" >> "$OUTPUT"

echo ""
echo "Disassembly complete: $OUTPUT"
wc -l "$OUTPUT"
