# i860 Ghidra Scripts

General-purpose scripts for importing and analyzing i860 binaries in Ghidra.

## Scripts

### DisassembleAll.java

Linear sweep disassembly for **raw binary** imports. BinaryLoader creates byte data that blocks disassembly, so this script clears all existing data first, then disassembles at every 4-byte boundary. Exports results to `/tmp/ghidra_disasm.txt` (configurable via `-Dghidra.export.path=`).

Used for SLEIGH verification against the reference Rust disassembler.

### AnalysisStats.java

Standalone utility that prints analysis statistics: instruction count, function count, data items, and memory block layout. Useful for quick checks in the Ghidra GUI or headless mode.

## Target-Specific Scripts

Analysis scripts for specific binaries live alongside their targets in the `re/` tree:

- [`re/nextdimension/kernel/scripts/`](../re/nextdimension/kernel/scripts/) — NeXTdimension kernel analysis pipeline

## Delay Slot Pcode Warnings

Scripts that perform linear sweep produce `Pcode error ... Program does not contain referenced instruction` warnings. These are harmless — they occur when Ghidra's delay slot analysis references addresses that haven't been disassembled or fall in data regions. The instructions themselves decode correctly.
