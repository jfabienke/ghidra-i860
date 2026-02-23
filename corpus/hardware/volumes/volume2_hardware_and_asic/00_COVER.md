---
title: "NeXT Hardware Architecture Reference"
subtitle: "Volume II: Hardware Components and ASIC Behavior"
author: "Reconstructed from ROM v3.3 Analysis"
date: "2025"
version: "1.0 Draft"
---

<!-- pagebreak -->

# NeXT Hardware Architecture Reference

## Volume II
## Hardware Components and ASIC Behavior

### Chip-Level and Register-Level Specification

---

**Reconstructed from NeXTcube ROM v3.3 Reverse Engineering**

**Confidence**: 95-100% (Verified from ROM behavior)

**Version**: 1.0 Draft

**Date**: 2025

---

### About This Volume

Volume II provides the detailed hardware manual — every register, every timing constraint, every undocumented quirk of NeXT hardware components. This is the register-level specification derived from ROM v3.3 behavior analysis with 95-100% confidence.

Unlike conventional chip datasheets, this volume documents **how NeXT actually uses these components**, including ASIC-specific behaviors not found in standard datasheets.

**Key Topics**:
- CPU subsystem (68030/68040 as used by NeXT)
- SCSI subsystem (NCR 53C90 with NeXTcube vs NeXTstation differences)
- Ethernet subsystem (AMD MACE with ASIC burial on NeXTcube)
- Graphics subsystem (VRAM, VDAC, planar layout)
- Audio subsystem (DMA quirks and timing)
- All other I/O devices

**Prerequisites**: Volume I recommended for architectural context

**Audience**:
- Emulator developers
- Hardware implementers
- FPGA developers
- Component-level researchers

**Companion Volumes**:
- Volume I: System Architecture
- Volume III: Firmware Behavior and Emulation Reference

---

### Critical Discoveries Documented Here

1. **NeXTcube SCSI**: Exactly 1 register write (0x88 to 0x02012000)
2. **NeXTstation SCSI**: 50+ register writes (full NCR initialization)
3. **SCSI DMA Registers**: Write-only config at 0x02020000/0x02020004
4. **Ethernet on NeXTcube**: Zero MACE accesses (completely ASIC-buried)
5. **Audio DMA**: One word ahead prefetch for cache coherency

---

### Copyright and License

This documentation is derived from clean-room reverse engineering of NeXTcube ROM v3.3 and public documentation. No NeXT proprietary materials were used in its creation.

**Status**: Public documentation for preservation and education

---

<!-- pagebreak -->
