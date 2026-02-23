# Abstract

Volume II presents the complete register-level specification of NeXT hardware components, reconstructed from NeXTcube ROM v3.3 reverse engineering with 95-100% confidence on documented behaviors.

This volume serves as the definitive hardware reference manual, documenting not just standard chip behaviors but the **NeXT-specific ASIC implementations** that make the hardware unique. Every register access, every timing constraint, and every undocumented quirk observed in the ROM is catalogued here.

The volume is organized into six major parts:

**Part 1: CPU Subsystem** documents the Motorola 68030 and 68040 as used by NeXT, including memory access timing, write buffer behavior, and exception semantics that NeXT firmware relies upon.

**Part 2: SCSI Subsystem** provides the critical distinction between NeXTcube (minimal NCR access via ASIC) and NeXTstation (full NCR access). This part resolves the mystery of why NeXTcube ROM writes exactly one SCSI register.

**Part 3: Ethernet Subsystem** documents the AMD MACE controller and its complete burial in the NeXTcube ASIC. Zero MACE register accesses occur on NeXTcube — all interaction is through two interface control registers.

**Part 4: Graphics Subsystem** details the video ASIC, VRAM architecture, planar memory layout, and VDAC behavior. Critical for understanding burst-aligned framebuffer access.

**Part 5: Audio Subsystem** documents the DAC/ADC architecture and the critical "one word ahead" DMA quirk that compensates for 68040 cache behavior.

**Part 6: Additional Devices** covers SCC (serial), keyboard/mouse controllers, real-time clock, and other peripherals.

Key register-level discoveries:

1. **SCSI Command Register Location**:
   - NeXTcube: 0x02012000 (offset +0x00 from base)
   - NeXTstation: 0x02114003 (offset +0x03 from base)

2. **SCSI DMA Registers** (NeXTcube only, write-only):
   - 0x02020000: DMA Mode (value: 0x08000000)
   - 0x02020004: DMA Enable (value: 0x80000000)

3. **Ethernet Interface Registers** (NeXTcube):
   - 0x02106002: Trigger (write 0xFF)
   - 0x02106005: Control 2 (board-specific: 0x00 or 0x80)

4. **Ethernet Descriptor Format**: 14 bytes (non-standard), 32 descriptors

5. **Audio DMA Pointer**: Writes to address+4 (one word ahead)

Every register is documented with:
- Absolute address
- Access type (R/W/RO/WO)
- Bit field definitions (where known)
- Observed values from ROM
- Confidence level
- Board-specific variations

**Confidence Levels**:
- Register existence: 100% (directly observed in ROM)
- Register values: 100% (captured from ROM execution)
- Bit field meanings: 70-100% (varies by register)
- Timing constraints: 85-95% (inferred from ROM behavior)

**Intended Audience**: Hardware implementers, emulator developers, FPGA designers, and anyone needing precise register-level specifications.

**Prerequisites**: Volume I recommended for understanding architectural context (ASIC-as-HAL, DMA architecture, interrupt routing).

**Length**: Approximately 250 pages

**Status**: Skeleton structure complete, content extraction in progress

---

**Keywords**: NeXT hardware, register map, SCSI NCR 53C90, AMD MACE, 68040, ASIC, hardware specification, device registers, ROM analysis
