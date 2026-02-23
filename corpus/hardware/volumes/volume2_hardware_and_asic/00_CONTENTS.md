# Volume II: Hardware Components and ASIC Behavior
## Table of Contents

---

## Front Matter

- [Cover](00_COVER.md)
- [Abstract](01_ABSTRACT.md)
- [Preface](02_PREFACE.md)
- [Table of Contents](00_CONTENTS.md) ← You are here
- [List of Figures](#list-of-figures)
- [List of Tables](#list-of-tables)
- [Register Map Quick Reference](#register-quick-reference)

---

## Part 1 — CPU Subsystem

### Chapter 1: 68030/68040 Memory Access Timing
- 1.1 Basic Bus Cycles
- 1.2 Burst Transfer Protocol
- 1.3 Cache Line Fills
- 1.4 MMIO Access Timing
- 1.5 NeXT-Specific Behaviors

### Chapter 2: Write Buffers and Read-Modify Cycles
- 2.1 Write Buffer Architecture
- 2.2 Write Posting
- 2.3 Read-Modify-Write Operations
- 2.4 Memory Ordering
- 2.5 DMA Implications

### Chapter 3: Exception Semantics NeXT Relied Upon
- 3.1 Bus Error Exceptions
- 3.2 Address Error Exceptions
- 3.3 Interrupt Exception Processing
- 3.4 Stack Frames
- 3.5 ROM Exception Handlers

---

## Part 2 — SCSI Subsystem (NCR 53C90 Family)

### Chapter 4: Historical NCR Architecture
- 4.1 NCR 53C90 Overview
- 4.2 Standard Register Map
- 4.3 Command Set
- 4.4 Phase State Machine
- 4.5 DMA Modes

### Chapter 5: NeXTstation — Direct Register Access
- 5.1 NCR Base Address (0x02114000)
- 5.2 Standard Register Layout
- 5.3 Command Register at +0x03
- 5.4 Full Initialization Sequence (50+ Accesses)
- 5.5 Verified Register Map

### Chapter 6: NeXTcube — ASIC-Mediated Register Access
- 6.1 NCR Base Address (0x02012000)
- 6.2 Non-Standard Register Layout
- 6.3 Command Register at +0x00
- 6.4 Minimal Initialization (1 Access: 0x88)
- 6.5 ASIC Abstraction Layer

### Chapter 7: Verified Register Maps (Corrected)
- 7.1 Complete NeXTcube SCSI Register Map
- 7.2 Complete NeXTstation SCSI Register Map
- 7.3 Register Address Comparison Table
- 7.4 Confidence Levels by Register

### Chapter 8: DMA-Based SCSI Architecture (Cube)
- 8.1 DMA Mode Register (0x02020000)
- 8.2 DMA Enable Register (0x02020004)
- 8.3 Write-Only Semantics
- 8.4 Bit Field Analysis
- 8.5 ASIC DMA State Machine

### Chapter 9: Differences in Probe Sequences (ROM)
- 9.1 NeXTcube SCSI Init (Function 0x0000ac8a)
- 9.2 NeXTstation SCSI Init
- 9.3 Register Access Patterns
- 9.4 Timing Differences

### Chapter 10: Error Handling and Phase Transition Notes
- 10.1 Phase Mismatch Handling
- 10.2 Selection Timeout
- 10.3 Parity Errors
- 10.4 ASIC Error Abstraction (Cube)

---

## Part 3 — Ethernet Subsystem (AMD 7990/Am79C940 "MACE")

### Chapter 11: AMD LANCE Lineage and MACE Enhancements
- 11.1 AMD LANCE (Am7990) History
- 11.2 MACE Design Evolution
- 11.3 NeXT-Specific Enhancements
- 11.4 Register Set Comparison

### Chapter 12: Why the ROM Never Touches MACE Registers Directly
- 12.1 NeXTcube ASIC Architecture
- 12.2 Complete MACE Burial
- 12.3 Zero Register Accesses (Verified)
- 12.4 Interface Controller Abstraction

### Chapter 13: Interface Control Registers (NeXTcube)
- 13.1 Trigger Register (0x02106002)
- 13.2 Control 2 Register (0x02106005)
- 13.3 Observed Values
- 13.4 Bit Field Analysis (70% confidence)

### Chapter 14: DMA Buffers, Packet Layout, and TX/RX Semantics
- 14.1 RX Buffer Base (0x03E00000)
- 14.2 TX Buffer Base (0x03F00000)
- 14.3 32 Descriptors × 8 KB Buffers
- 14.4 14-Byte Descriptor Format
- 14.5 Descriptor Fields

### Chapter 15: Auto-Detect Logic (AUI vs TP)
- 15.1 Physical Media Detection
- 15.2 ROM Configuration
- 15.3 Driver Behavior
- 15.4 Control 2 Role

### Chapter 16: Interrupt Behavior Reconstruction
- 16.1 RX Packet Arrival
- 16.2 TX Completion
- 16.3 Error Conditions
- 16.4 IPL6 Routing

---

## Part 4 — Graphics Subsystem

### Chapter 17: Video ASIC and VRAM Architecture
- 17.1 Video ASIC Overview
- 17.2 16 MB VRAM Layout
- 17.3 Memory Controller
- 17.4 Refresh Timing

### Chapter 18: Single-Planar and Burst-Aligned Framebuffers
- 18.1 Planar Memory Organization
- 18.2 2-bit Grayscale Mode
- 18.3 Burst Alignment Strategy
- 18.4 Performance Implications

### Chapter 19: VDAC Behavior (Brooktree / Custom Variants)
- 19.1 VDAC Overview
- 19.2 Color Palette
- 19.3 DAC Control Registers
- 19.4 Timing Generation

### Chapter 20: Memory-Mapped Rendering Rules
- 20.1 Framebuffer Access
- 20.2 Pixel Addressing
- 20.3 Cache Coherency
- 20.4 Dirty Tracking

### Chapter 21: Timing and Page-Flipping Semantics
- 21.1 Vertical Blanking Interval
- 21.2 Horizontal Timing
- 21.3 Page Flip Protocol
- 21.4 Tearing Prevention

---

## Part 5 — Audio Subsystem

### Chapter 22: 16-bit DAC/ADC Architecture
- 22.1 Audio Hardware Overview
- 22.2 Sample Rates
- 22.3 Bit Depth and Format
- 22.4 Channel Configuration

### Chapter 23: Out-of-Order DMA Quirk (Word-Ahead Prefetch)
- 23.1 The Discovery
- 23.2 Why: 68040 Write Buffer
- 23.3 Implementation: Address+4
- 23.4 Cache Coherency Fix

### Chapter 24: Buffer Semantics for Driver Compatibility
- 24.1 Ring Buffer Setup
- 24.2 Double Buffering
- 24.3 Interrupt Timing
- 24.4 Underrun/Overrun Handling

### Chapter 25: Interrupt Behavior
- 25.1 Buffer Half-Full Interrupt
- 25.2 Completion Interrupt
- 25.3 Error Interrupts
- 25.4 IPL6 Routing

### Chapter 26: Hardware Limitations and ROM Safeguards
- 26.1 Maximum Sample Rate
- 26.2 Buffer Size Constraints
- 26.3 ROM Validation
- 26.4 Error Recovery

---

## Part 6 — Timers, Serial, I/O, and Misc. Devices

### Chapter 27: SCC Behavior (Zilog Z8530)
- 27.1 SCC Overview
- 27.2 Register Map
- 27.3 Serial Port Configuration
- 27.4 Interrupt Generation (IPL2)

### Chapter 28: Keyboard/Mouse Microcontrollers
- 28.1 Keyboard Protocol
- 28.2 Mouse Protocol
- 28.3 Controller Registers
- 28.4 Interrupt Behavior

### Chapter 29: Floppy Controller Logic
- 29.1 Floppy Drive Support
- 29.2 Controller Registers
- 29.3 DMA Usage
- 29.4 Format Compatibility

### Chapter 30: Real-Time Clock Model
- 30.1 RTC Chip
- 30.2 Register Access
- 30.3 Battery Backup
- 30.4 Time-of-Day Keeping

### Chapter 31: Power, Thermal, and Reset Semantics
- 31.1 Power-On Reset Sequence
- 31.2 Reset Button Behavior
- 31.3 Thermal Monitoring
- 31.4 Power Management

---

## Appendices

### Appendix A: Complete Register Map
- A.1 NeXTcube Register Map (by address)
- A.2 NeXTstation Register Map (by address)
- A.3 Shared Registers
- A.4 Board-Specific Registers

### Appendix B: Register Access Patterns from ROM
- B.1 NeXTcube SCSI Init Sequence
- B.2 NeXTstation SCSI Init Sequence
- B.3 Ethernet Init Sequence
- B.4 Graphics Init Sequence

### Appendix C: Timing Diagrams
- C.1 SCSI Bus Phases
- C.2 Ethernet Frame Timing
- C.3 Audio Sample Timing
- C.4 Video Refresh Timing

### Appendix D: Descriptor Formats
- D.1 Ethernet Descriptor (14 bytes)
- D.2 SCSI DMA Descriptor (if applicable)
- D.3 Audio DMA Descriptor

### Appendix E: Bit Field Definitions
- E.1 SCSI DMA Mode Register
- E.2 SCSI DMA Enable Register
- E.3 Ethernet Control 2 Register
- E.4 Interrupt Status Register

### Appendix F: Confidence Levels by Component
- F.1 SCSI Registers (95-100%)
- F.2 Ethernet Registers (70-100%)
- F.3 DMA Registers (85%)
- F.4 Graphics Registers (90%)
- F.5 Audio Registers (95%)

---

## Index

(Alphabetical index to be generated)

---

**Volume II Status**: Skeleton structure complete ✅
**Next Step**: Content extraction from analysis documents
**Target Length**: ~250 pages

---

[Return to Master Index](../MASTER_INDEX.md)
