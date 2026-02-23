# Document Naming Convention

## Overview

This document describes the standardized naming convention for NeXTdimension firmware analysis documents.

**Effective Date**: 2025-11-10
**Convention Version**: 2.0

---

## Naming Pattern

```
<section>_<descriptive_name>.md
```

Where:
- `<section>`: Two-digit firmware section number(s), e.g., `01`, `02`, `03`, `01_02`
- `<descriptive_name>`: Lowercase with underscores, describes document purpose

---

## Section Mapping

| Section Code | Firmware File | Address Range | Size | Description |
|--------------|---------------|---------------|------|-------------|
| `01` | 01_bootstrap_graphics.bin | 0xF8000000 - 0xF8007FFF | 32 KB | Bootstrap Graphics HAL (includes sections 1+2) |
| `02` | 02_postscript_operators.bin | 0xF8008000 - 0xF800FFFF | 32 KB | PostScript Operators / Mach Services |
| `03` | 03_graphics_acceleration.bin | 0xF8010000 - 0xF802FFFF | 128 KB | Graphics Acceleration + Kernel Core |
| `04` | 04_vm.bin | 0xF8030000 - 0xF803FFFF | 64 KB | VM / Memory Management |
| `05` | (reserved) | 0xF8040000 - 0xF804FFFF | 64 KB | Handler Functions |
| `06` | (reserved) | 0xF8050000 - 0xF805FFFF | 64 KB | Graphics Primitives |
| `07` | (reserved) | 0xF8060000 - 0xF806FFFF | 64 KB | x86 Emulation Code |
| `08` | (reserved) | 0xF8070000 - 0xF807FFFF | 64 KB | Video Mode Configuration |
| `09` | (reserved) | 0xF8080000 - 0xF808FFFF | 64 KB | Utility Functions |
| `10` | (reserved) | 0xF8090000 - 0xF809FFFF | 64 KB | IPC / Communication |
| `11` | (reserved) | 0xF80A0000 - 0xF80AFFFF | 64 KB | Debug / Development |

**Note**: Section code `01` encompasses both the original SECTION1 and SECTION2 from the firmware, as they are combined in `01_bootstrap_graphics.bin`.

---

## Renamed Documents (2025-11-10)

### Bootstrap Graphics HAL (Section 01)

**Old Name** → **New Name**

```
SECTION1_2_ALGORITHM_VERIFICATION.md       → 01_bootstrap_algorithm_verification.md
SECTION1_2_ANALYSIS_COMPLETE.md            → 01_bootstrap_analysis_complete.md
SECTION1_2_ARCHITECTURE_GUIDE.md           → 01_bootstrap_architecture_guide.md
SECTION1_2_CONTROL_FLOW_TAXONOMY.md        → 01_bootstrap_control_flow_taxonomy.md
SECTION1_2_DATA_MOVEMENT_TAXONOMY.md       → 01_bootstrap_data_movement_taxonomy.md
SECTION1_2_DEEP_DIVE.md                    → 01_bootstrap_deep_dive.md
SECTION1_2_DEEP_DIVE_ALGORITHMS.md         → 01_bootstrap_deep_dive_algorithms.md
SECTION1_2_DETAILED_ANALYSIS.md            → 01_bootstrap_detailed_analysis.md
SECTION1_2_FUNCTIONAL_GROUPS.md            → 01_bootstrap_functional_groups.md
SECTION1_2_HARDWARE_SCAN.md                → 01_bootstrap_hardware_scan.md
SECTION1_2_PIXEL_OPS_TAXONOMY.md           → 01_bootstrap_pixel_ops_taxonomy.md
SECTION1_2_UTILITIES_TAXONOMY.md           → 01_bootstrap_utilities_taxonomy.md
```

**Note**: The old `SECTION1_2` prefix referred to the combined analysis of what was originally sections 1 and 2, now unified as section 01 (01_bootstrap_graphics.bin).

---

## Document Categories

Documents fall into several standard categories:

### Analysis Documents

- `*_detailed_analysis.md` - Comprehensive instruction-level analysis
- `*_deep_dive.md` - In-depth examination of specific features
- `*_hardware_scan.md` - Hardware operation (MMU, TLB, cache) analysis
- `*_algorithm_verification.md` - Verification of specific algorithms

### Architectural Documents

- `*_architecture_guide.md` - High-level architectural overview
- `*_functional_groups.md` - Grouping of related functions

### Taxonomy Documents

- `*_control_flow_taxonomy.md` - Classification of control flow patterns
- `*_data_movement_taxonomy.md` - Classification of data movement patterns
- `*_pixel_ops_taxonomy.md` - Classification of pixel operations
- `*_utilities_taxonomy.md` - Classification of utility functions

### Summary Documents

- `*_analysis_complete.md` - Marks completion of analysis phase
- `*_verification_card.md` - Quick reference verification checklist

---

## Cross-Section Documents

Some documents span multiple sections or cover cross-cutting concerns. These use descriptive names without section prefixes:

**Architecture & Design**:
- `FINAL_ARCHITECTURAL_REVELATION.md` - Master architectural synthesis
- `KERNEL_ARCHITECTURE_COMPLETE.md` - Complete kernel architecture
- `PROTECTION_VS_PREVENTION_DESIGN.md` - Protection model comparison

**Analysis Methodology**:
- `GACK_KERNEL_HARDWARE_SCAN.md` - Comparative hardware scan (all sections)
- `I860_CONTEXT_SWITCH_OPTIMIZATION_ANALYSIS.md` - Context switch optimization study
- `I860XP_MMU_FEATURES_ANALYSIS.md` - MMU feature comparison

**Protocol & Interface**:
- `HOST_I860_PROTOCOL_SPEC.md` - Host communication protocol
- `MAILBOX_PROTOCOL.md` - Mailbox interface specification
- `GACKLING_PROTOCOL_DESIGN.md` - GaCK protocol design

**Implementation Guides**:
- `GRAPHICS_ACCELERATION_GUIDE.md` - Graphics acceleration guide
- `GACKLING_IMPLEMENTATION_GUIDE.md` - GaCK implementation guide
- `VIDEO_MODE_IMPLEMENTATION_GUIDE.md` - Video mode configuration

**Reference**:
- `COMMAND_REFERENCE_CARDS.md` - Command quick reference
- `POSTSCRIPT_OPERATORS.md` - PostScript operator reference
- `NEXTDIMENSION_MEMORY_MAP_COMPLETE.md` - Complete memory map

---

## Future Sections

When analyzing additional firmware sections, follow this pattern:

### Example: Section 02 (PostScript Operators)

```
02_postscript_operators_analysis.md
02_postscript_command_reference.md
02_postscript_interpreter.md
```

### Example: Section 03 (Graphics Acceleration)

```
03_graphics_acceleration_analysis.md
03_graphics_primitive_implementation.md
03_graphics_kernel_core.md
```

### Example: Section 04 (VM / Memory Management)

```
04_vm_detailed_analysis.md
04_vm_page_table_walker.md
04_vm_tlb_management.md
04_vm_hardware_scan.md
```

---

## Guidelines

### DO

- ✓ Use two-digit section numbers with leading zero (01, 02, 03)
- ✓ Use lowercase with underscores for descriptive names
- ✓ Include section-specific context in name (bootstrap, mach, kernel, etc.)
- ✓ Use standard category suffixes (_analysis, _guide, _scan, etc.)
- ✓ Keep names concise but descriptive

### DON'T

- ✗ Use old SECTION1_2 format
- ✗ Use CamelCase or spaces in filenames
- ✗ Create ambiguous names without section context
- ✗ Use generic names like "analysis.md" or "notes.md"
- ✗ Mix old and new naming conventions

---

## Migration Checklist

When renaming documents:

- [ ] Update filename to new convention
- [ ] Update internal document references
- [ ] Update cross-references in other documents
- [ ] Update README or index if applicable
- [ ] Verify links still work
- [ ] Commit with clear message: "Rename: SECTION1_2_X → 01_02_Y"

---

## Examples of Good Names

```
✓ 01_02_bootstrap_hardware_scan.md
✓ 03_kernel_context_switch_analysis.md
✓ 06_graphics_primitive_implementation.md
✓ 10_ipc_mailbox_protocol.md
```

## Examples of Bad Names

```
✗ SECTION1_2_STUFF.md                    (old convention)
✗ analysis.md                            (no section context)
✗ Section-3-Analysis.md                  (inconsistent format)
✗ firmware_analysis_section_03.md        (wrong order)
```

---

## Document Version Control

### Version 1.0 (2024-2025)
- Original naming: `SECTION1_2_*`, `SECTION3_*`, etc.
- No standardized pattern
- Mixed conventions

### Version 2.0 (2025-11-10)
- Standardized naming: `01_02_*`, `03_*`, etc.
- Clear section mapping
- Consistent descriptive names
- This document created

---

## Quick Reference

**To find documents for a specific section**:
```bash
ls -1 03_*.md              # Section 3 documents
ls -1 01_02_*.md           # Bootstrap (sections 1+2)
ls -1 *_hardware_scan.md   # All hardware scan documents
```

**To rename a document**:
```bash
mv OLD_NAME.md XX_descriptive_name.md
git mv OLD_NAME.md XX_descriptive_name.md  # If tracked
```

---

**Document Version**: 1.0
**Last Updated**: 2025-11-10
**Author**: Documentation standardization
**Purpose**: Define and document naming convention for firmware analysis documents
