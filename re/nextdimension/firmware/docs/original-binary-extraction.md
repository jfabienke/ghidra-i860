# ND_MachDriver_reloc Extraction and __DATA Survey

Source binary:
- `/Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/firmware/ND_MachDriver_reloc`
- Size: 795,464 bytes

## Reproducible extraction

Run:

```bash
re/nextdimension/firmware/scripts/extract_machdriver_segments.sh \
  /Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/firmware/ND_MachDriver_reloc \
  re/nextdimension/firmware/extracted
```

Optional third argument sets the "clean window" byte length extracted from the start of `__text`
(default `0x31000`, matching `ND_i860_CLEAN.bin`):

```bash
re/nextdimension/firmware/scripts/extract_machdriver_segments.sh \
  /Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/firmware/ND_MachDriver_reloc \
  re/nextdimension/firmware/extracted \
  0x31000
```

Extracted artifacts:
- `re/nextdimension/firmware/extracted/ND_MachDriver_MachO_header.bin` (840 B)
- `re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_section.bin` (730,440 B)
- `re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_segment.bin` (737,280 B)
- `re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_clean_window.bin` (default 200,704 B)
- `re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_post_clean.bin` (remaining `__text` bytes)
- `re/nextdimension/firmware/extracted/ND_MachDriver___DATA_section.bin` (56,400 B)
- `re/nextdimension/firmware/extracted/ND_MachDriver___DATA_segment.bin` (57,344 B)

Metadata and checksums:
- `re/nextdimension/firmware/extracted/SEGMENTS.txt`
- `re/nextdimension/firmware/extracted/BYTE_ACCOUNTING.txt`
- `re/nextdimension/firmware/extracted/EMBEDDED_MACHO_HEADERS.txt`
- `re/nextdimension/firmware/extracted/sha256.txt`
- `re/nextdimension/firmware/scripts/validate_extraction_ground_truth.sh` (consistency gate)

`BYTE_ACCOUNTING.txt` verifies full file coverage by extraction ranges:
`header + __TEXT segment + gap + __DATA segment + trailing == input size`.

`EMBEDDED_MACHO_HEADERS.txt` inventories nested Mach-O headers found in `__text`
(for this binary: m68k at `0x017CB8`, x86 at `0x03DCB8` and `0x05DCB8`).

Validate extracted ground truth:

```bash
re/nextdimension/firmware/scripts/validate_extraction_ground_truth.sh \
  re/nextdimension/firmware/extracted \
  re/nextdimension/firmware/docs/firmware-analysis.md
```

## What __DATA contains (Ghidra + Rust)

Ghidra headless contamination survey on `__data` (`base=0xF80B4000`) reports:
- `ASCII_TEXT`: 32,848 bytes (58.2%)
- `X86_CODE`: 12,288 bytes (21.8%)
- `NULL_PAD`: 7,168 bytes (12.7%)
- `X86_DATA`: 4,096 bytes (7.3%)
- `I860_CODE`: 0 bytes

Rust disassembler statistics on the same `__data` section show linear-sweep decode only (14,100 instructions), consistent with data-as-code contamination.

Key findings:
- Direct LE32 pointers from `__data` into i860 `__TEXT` are sparse (3 hits total).
- The expected `0xF80B7000` window is non-zero but does not present as a plain function-pointer table.
- A large ASCII changelog region starts at ~`0xF80B9CB8`.

Generated reports:
- `re/nextdimension/firmware/extracted/ANALYSIS.txt`
- `re/nextdimension/firmware/extracted/GHIDRA_DATA_SURVEY.txt`
- `re/nextdimension/firmware/extracted/RUST_DATA_STATS.txt`

## Implication

The missing-dispatch problem is not solved by simply extracting `__DATA`: the section is real and present, but it does not expose an obvious flat table of absolute i860 handler addresses. Next step is structure inference (packed/relative/hashed tables) in the `0xF80B7000` neighborhood rather than raw pointer scanning.

Important caveat:
- This extraction covers initialized file-backed data (`__data`), not runtime-built structures in `__bss`/`__common`.
- The clean-window split is a convenience baseline and does not imply that i860 code cannot exist outside that window.
