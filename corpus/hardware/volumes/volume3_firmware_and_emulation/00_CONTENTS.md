# Volume III: Firmware Behavior and Emulation Reference
## Table of Contents

---

## Front Matter

- [Cover](00_COVER.md)
- [Abstract](01_ABSTRACT.md)
- [Preface](02_PREFACE.md)
- [Table of Contents](00_CONTENTS.md) ← You are here
- [How to Use This Volume](#how-to-use-this-volume)
- [Test Suite Quick Start](#test-suite-quick-start)

---

## Part 1 — ROM Architecture Overview

### Chapter 1: Memory Layout and Entry Points
- 1.1 ROM Memory Map (128 KB)
- 1.2 Reset Vector and Entry Point
- 1.3 Exception Vector Table
- 1.4 Code Sections
- 1.5 Data Sections

### Chapter 2: Module Table, Driver Table, Device Registration
- 2.1 Module Structure
- 2.2 Driver Table Architecture
- 2.3 Device Registration Process
- 2.4 Probe Sequence

### Chapter 3: Cube vs Station ROM Differences
- 3.1 Conditional Compilation
- 3.2 Board-Specific Code Paths
- 3.3 Register Access Differences
- 3.4 Shared vs Separate Functions

### Chapter 4: Boot-Time Self-Tests and Hardware Init Ordering
- 4.1 Memory Tests
- 4.2 Cache Tests
- 4.3 Device Tests
- 4.4 Initialization Order

---

## Part 2 — ROM Hardware Behavior Reconstruction

### Chapter 5: SCSI Probe Loops (ID Enumeration)
- 5.1 SCSI Bus Reset
- 5.2 Target ID Iteration (0-6)
- 5.3 Selection Sequence
- 5.4 Timeout Handling
- 5.5 Device Registration

### Chapter 6: Network Initialization
- 6.1 Ethernet Address Retrieval
- 6.2 MAC Address Display
- 6.3 Media Selection (AUI vs TP)
- 6.4 Buffer Setup
- 6.5 Descriptor Initialization

### Chapter 7: DMA Configuration Sequences
- 7.1 NeXTcube DMA Init
- 7.2 NeXTstation DMA Init
- 7.3 Per-Channel Configuration
- 7.4 Buffer Allocation
- 7.5 Interrupt Enable

### Chapter 8: Interrupt Masking and Routing
- 8.1 Initial Interrupt Mask
- 8.2 Interrupt Handler Registration
- 8.3 NBIC Configuration
- 8.4 IPL Priority Setup

### Chapter 9: Board/Slot Space Usage
- 9.1 Slot Enumeration
- 9.2 Board Detection
- 9.3 Address Space Selection
- 9.4 Timeout Handling

### Chapter 10: Timing and Delay Mechanisms (Software-Based)
- 10.1 Software Delay Loops
- 10.2 Polling Intervals
- 10.3 Timeout Calculations
- 10.4 When Timing Matters

---

## Part 3 — Correct Emulation Behavior

### Chapter 11: What Must Behave Exactly Like Real Hardware
- 11.1 Board Config Byte (RAM+0x3a8)
- 11.2 SCSI Register Access Patterns
- 11.3 DMA Register Write-Only Semantics
- 11.4 Interrupt Priority Merging
- 11.5 Memory Map Layout

### Chapter 12: What Can Be Abstracted
- 12.1 ASIC Internal State
- 12.2 Timing Approximations
- 12.3 Device Emulation Shortcuts
- 12.4 Performance Optimizations

### Chapter 13: When Timing Matters (and When It Doesn't)
- 13.1 Critical Timing Paths
- 13.2 Non-Critical Paths
- 13.3 Acceptable Approximations
- 13.4 Timing Verification

### Chapter 14: Exception Semantics
- 14.1 Bus Error Generation
- 14.2 Address Error Conditions
- 14.3 Interrupt Processing
- 14.4 Missing Board Handling

---

## Part 4 — Emulator Implementation Guide

### Chapter 15: Global Memory Bus Model
- 15.1 Address Decode Implementation
- 15.2 Fast Path for RAM/ROM
- 15.3 Slow Path for MMIO
- 15.4 Endianness Handling

### Chapter 16: NBIC Bus Routing Model
- 16.1 Slot Space Decode
- 16.2 Board Space Decode
- 16.3 Timeout Implementation
- 16.4 Bus Error Generation

### Chapter 17: DMA Engine State Machines
- 17.1 Per-Channel State
- 17.2 FIFO Implementation
- 17.3 Ring Buffer Logic
- 17.4 Interrupt Generation

### Chapter 18: SCSI/NCR Minimal-Functional Model
- 18.1 NeXTcube Minimal Emulation
- 18.2 NeXTstation Full Emulation
- 18.3 Phase State Machine
- 18.4 DMA Integration

### Chapter 19: Ethernet/MACE Minimal-Functional Model
- 19.1 NeXTcube Interface Controller
- 19.2 Descriptor Processing
- 19.3 Packet Reception
- 19.4 Packet Transmission

### Chapter 20: Graphics and Audio Emulation Guidance
- 20.1 VRAM Access Emulation
- 20.2 Display Update
- 20.3 Audio DMA (Word-Ahead)
- 20.4 Performance Considerations

### Chapter 21: Interrupt Controller Simulation
- 21.1 Source Tracking
- 21.2 Priority Logic
- 21.3 Status Register Implementation
- 21.4 Acknowledgement Handling

---

## Part 5 — ROM Behavior Validation Suite

### Chapter 22: Test Categories

**22.1 Boot Banner Tests**
- 22.1.1 ROM Version Display
- 22.1.2 Hardware Detection Messages
- 22.1.3 Memory Size Report
- 22.1.4 Boot Device Selection

**22.2 Memory Tests**
- 22.2.1 DRAM Size Detection
- 22.2.2 Memory Pattern Tests
- 22.2.3 VRAM Tests
- 22.2.4 Cache Tests

**22.3 SCSI Tests**
- 22.3.1 Board Config Detection
- 22.3.2 NeXTcube Minimal Access (1 write)
- 22.3.3 NeXTstation Full Access (50+ writes)
- 22.3.4 DMA Register Tests (write-only)
- 22.3.5 Device Probe Tests

**22.4 Network Tests**
- 22.4.1 Ethernet Trigger Register
- 22.4.2 Control 2 Register (board-specific)
- 22.4.3 Zero MACE Access (NeXTcube)
- 22.4.4 Descriptor Ring Tests
- 22.4.5 Buffer Layout Tests

**22.5 DMA Tests**
- 22.5.1 Channel Allocation
- 22.5.2 FIFO Tests
- 22.5.3 Word-Pumped Transfer
- 22.5.4 Ring Buffer Wrap
- 22.5.5 Interrupt on Completion
- 22.5.6 Audio Word-Ahead Test

**22.6 NBIC Slot/Board Routing Tests**
- 22.6.1 Slot Space Decode
- 22.6.2 Board Space Decode
- 22.6.3 Timeout Generation
- 22.6.4 Bus Error Handling

### Chapter 23: Compliance Matrix
- 23.1 Required Behaviors
- 23.2 Optional Behaviors
- 23.3 Performance Requirements
- 23.4 Compatibility Levels

### Chapter 24: Automated Test Patterns
- 24.1 Test Framework Setup
- 24.2 Individual Test Descriptions (64+ tests)
- 24.3 Expected Results
- 24.4 Pass/Fail Criteria

### Chapter 25: Known ROM Bugs and Required Quirk Modes
- 25.1 ROM Bug Catalog
- 25.2 Workarounds
- 25.3 Quirk Mode Flags
- 25.4 Version Differences

---

## Part 6 — FPGA and Hardware Reimplementation Notes

### Chapter 26: Mapping ASIC Behavior to HDL
- 26.1 ASIC Functional Blocks
- 26.2 Verilog/VHDL Considerations
- 26.3 State Machine Translation
- 26.4 Interface Signals

### Chapter 27: Timing Closure Expectations
- 27.1 Clock Domain Crossing
- 27.2 Setup/Hold Times
- 27.3 Critical Paths
- 27.4 Timing Constraints File

### Chapter 28: Board-Space and Slot-Space Decode Logic
- 28.1 Combinatorial Logic
- 28.2 Address Comparators
- 28.3 Mux Selection
- 28.4 Timing Analysis

### Chapter 29: Reproducing NBIC Bus Error Timing
- 29.1 Timeout Counter
- 29.2 Bus Error Signal Generation
- 29.3 Handshake Protocol
- 29.4 Verification

### Chapter 30: DMA Alignment Rules in Hardware Implementations
- 30.1 Burst Alignment
- 30.2 Address Masking
- 30.3 FIFO Depth
- 30.4 Arbitration Logic

### Chapter 31: Recreating the Boot ROM Interface Requirements
- 31.1 ROM Timing Characteristics
- 31.2 Wait States
- 31.3 Cacheable Property
- 31.4 Read-Only Enforcement

---

## Appendices

### Appendix A: Complete Test Suite Source Code
- A.1 Test Framework (C)
- A.2 Board Config Tests
- A.3 SCSI Tests
- A.4 DMA Tests
- A.5 Ethernet Tests
- A.6 Interrupt Tests
- A.7 Memory Tests
- A.8 Boot Sequence Tests

### Appendix B: Test Data and Expected Results
- B.1 ROM Checksums
- B.2 Expected MMIO Access Patterns
- B.3 Expected Register Values
- B.4 Expected Timing Windows

### Appendix C: Emulator Debugging Checklist
- C.1 Initial Setup Verification
- C.2 Common Failure Modes
- C.3 Debug Tracing
- C.4 Comparison with Previous Emulator

### Appendix D: FPGA Resource Estimates
- D.1 Logic Element Count
- D.2 Memory Requirements
- D.3 Clock Domains
- D.4 I/O Pins

### Appendix E: Performance Benchmarks
- E.1 Memory Access Speed
- E.2 MMIO Access Speed
- E.3 DMA Transfer Speed
- E.4 Emulator vs Real Hardware

### Appendix F: ROM Function Reference
- F.1 Critical ROM Functions (with line numbers)
- F.2 Entry Points
- F.3 Jump Tables
- F.4 String Catalog

---

## Index

(Alphabetical index to be generated)

---

**Volume III Status**: Skeleton structure complete ✅
**Next Step**: Content extraction from test suite and emulator guide
**Target Length**: ~200 pages

---

[Return to Master Index](../MASTER_INDEX.md)
