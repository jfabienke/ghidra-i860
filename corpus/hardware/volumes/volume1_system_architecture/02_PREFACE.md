# Preface

## The Lost Architecture

When NeXT Computer shut down hardware manufacturing in 1993, much of the detailed technical knowledge of their hardware architecture vanished with it. While NeXTSTEP lived on (eventually becoming the foundation of macOS), the unique hardware designs that powered the original NeXT workstations became increasingly mysterious.

Unlike the well-documented systems from Sun Microsystems, Silicon Graphics, or DEC — which published comprehensive technical reference manuals — NeXT's hardware documentation was sparse and incomplete. The public documentation focused on software APIs and high-level concepts, while the detailed register maps, timing specifications, and hardware behaviors remained largely proprietary.

This presented a significant challenge for emulator developers and hardware preservationists. The Previous emulator (the most complete NeXT emulator) was developed through painstaking trial-and-error, hardware testing, and educated guesses. While remarkably successful at boot NeXTSTEP, the underlying "why" and "how" of many hardware behaviors remained unclear.

## The Discovery

This three-volume reference was born from a systematic reverse engineering effort of NeXTcube ROM v3.3 (Rev_3.3_v74.bin, 128 KB). Using proven firmware analysis techniques developed during the NeXTdimension i860 firmware project, we disassembled and analyzed every line of the ROM — 87,143 lines of 68040 assembly.

The goal was not just to understand the ROM firmware itself, but to reconstruct the hardware architecture from how the ROM uses it. By observing every MMIO access, every register write, every timing assumption, and every board-specific conditional, we could reverse-engineer the hardware specification that the ROM was written against.

What emerged was surprising: NeXT hardware was far more sophisticated — and far more unusual — than previously understood.

## The "Mainframe Techniques" Philosophy

Steve Jobs famously directed the NeXT hardware team to implement "mainframe techniques" in their workstation design. This wasn't mere marketing speak — it fundamentally shaped the architecture.

Rather than the register-based I/O typical of microcomputers (where the CPU directly writes configuration and command registers on peripheral chips), NeXT implemented a **channel-based I/O model** using custom ASICs as hardware abstraction layers.

In this model:
- The CPU primarily interacts with **DMA channels**, not device registers
- Custom ASICs handle the low-level device operations
- Hardware complexity is **hidden behind ASIC abstractions**
- Device initialization often involves a **single high-level command**, with the ASIC executing the full sequence

This is why the NeXTcube ROM writes exactly **one register** to the NCR 53C90 SCSI controller — the command register with value 0x88 (RESET | DMA). The ASIC then handles all FIFO operations, status checking, and state machine management that would normally require dozens of register accesses.

This is why the Ethernet subsystem on NeXTcube makes **zero accesses** to MACE registers — the entire MACE controller is buried in the ASIC, accessed only through two interface control registers.

This architectural choice has profound implications for emulation, hardware reimplementation, and understanding NeXT's design philosophy.

## What This Volume Covers

Volume I presents the **system-level architecture** — the foundations you need to understand before diving into the detailed component specifications in Volume II or the firmware behavior in Volume III.

We start with the design philosophy (Part 1), explaining why NeXT hardware works the way it does and how it differs from contemporary designs. This historical and conceptual foundation is crucial — without understanding the "mainframe techniques" approach, many hardware behaviors seem arbitrary or incomplete.

Part 2 presents the global memory architecture — the complete address space, including the critical distinction between "slot space" (0x0?xxxxxx) and "board space" (0x?xxxxxxx), burst-aligned memory regions, and cacheability rules.

Part 3 details the NBIC (NeXTbus Interface Controller) — the unsung hero of NeXT architecture. The NBIC implements address decoding, interrupt priority merging (many sources → IPL2/IPL6), bus arbitration, and timeout detection. Understanding the NBIC is key to understanding how the system actually works.

Part 4 explains the DMA architecture — NeXT's primary I/O abstraction. We document the 12-channel DMA engine, word-pumped ring buffers (not scatter-gather), descriptor formats, and the critical distinction between NeXTcube and NeXTstation DMA implementations.

Part 5 covers system timing, interrupts, and clocks — the temporal behavior of the system. This includes timer mechanisms, interrupt routing through the NBIC, and the timing constraints that matter for emulation (and those that don't).

## How This Work Was Done

This reference is based on **clean-room reverse engineering** of NeXTcube ROM v3.3:

1. **Disassembly**: Complete 68040 disassembly (87,143 lines, 7.2 MB)
2. **Function analysis**: Systematic analysis of critical ROM functions
3. **MMIO tracking**: Every memory-mapped I/O access catalogued
4. **Register tracing**: Following CPU registers (e.g., A0) through function execution
5. **Pattern analysis**: Identifying board-specific conditionals and hardware assumptions
6. **Cross-verification**: Comparing findings with Previous emulator source code

Every documented behavior is **graded by confidence**:
- **100%**: Directly observed in ROM, multiple confirmations
- **95%**: Directly observed, logical consistency
- **85%**: Circumstantial evidence, consistent patterns
- **70%**: Logical inference, needs hardware confirmation

The overall confidence level for this volume is **95-100%** on documented features.

No NeXT proprietary documentation was used in this analysis. All findings are derived from publicly available ROM images and the GPL-licensed Previous emulator source code.

## Who Should Read This Volume

This volume is for anyone who needs to understand NeXT hardware at the system level:

**Emulator developers** will find the architectural context necessary to understand why hardware behaves the way it does. Why does NeXTcube SCSI work so differently from NeXTstation? Why are there two different address spaces? Why do interrupts merge into IPL2 and IPL6? The answers are here.

**FPGA/hardware implementers** will find the system-level specifications needed to recreate NeXT hardware in modern silicon. The NBIC address decode logic, DMA timing requirements, and interrupt routing are all documented.

**Computer architecture researchers** will find a fascinating case study in alternative architectural approaches. NeXT's mainframe-inspired design offers lessons relevant to modern heterogeneous computing and hardware abstraction.

**Hardware historians** will find the missing technical documentation that explains how NeXT systems actually worked at the hardware level.

**Technical enthusiasts** will find clear explanations of a unique and sophisticated architecture, presented from first principles with no assumed NeXT knowledge.

## What You'll Need to Know

This volume assumes:
- Basic computer architecture concepts (memory maps, interrupts, DMA)
- Familiarity with hexadecimal notation
- General understanding of bus-based systems

You don't need:
- Prior NeXT hardware knowledge
- Assembly language expertise (though it helps for Volumes II and III)
- Electrical engineering background

The volume is designed to be read linearly, with each part building on previous ones. However, experienced readers can jump to areas of interest using the detailed cross-references.

## A Note on Confidence and Verification

Every piece of information in this reference is marked with its confidence level. We believe in being transparent about what we know with certainty, what we've inferred with high confidence, and what still needs hardware verification.

Where confidence is less than 100%, we explain:
- What evidence we have
- Why we believe it's correct
- What would be needed for 100% verification

Some areas (like SCSI DMA bit meanings) are at 85% confidence because we observe fixed values written to registers but lack hardware documentation on what each bit controls. We document the values, explain our reasoning about bit meanings, and mark it clearly as "inferred."

This transparency allows you to make informed decisions about what to trust completely and where to exercise additional caution.

## Acknowledgments

This work would not have been possible without:

**Previous emulator developers** — whose GPL source code provided invaluable cross-verification of ROM findings. The Previous emulator's ASIC implementations corroborate many of our discoveries.

**MAME NeXT driver contributors** — whose clean, well-documented code helped clarify ambiguous hardware behaviors.

**The 68kmla.org community** — for preserving NeXT knowledge, hardware, and software.

**Bitsavers.org archivists** — for preserving what public documentation exists.

**The NeXTdimension firmware project** — which developed the reverse engineering methodology applied here.

Special thanks to everyone working to preserve NeXT's legacy. Your efforts ensure this important piece of computing history isn't lost.

## How to Use This Volume

**If you're new to NeXT hardware**: Read Part 1 (Design Philosophy) first. It provides the conceptual framework that makes everything else make sense. Then read Part 2 (Memory Architecture) to understand the global address space. Parts 3-5 can be read as needed based on your interests.

**If you're implementing an emulator**: Read Parts 1-2 for context, then focus on Part 3 (NBIC), Part 4 (DMA), and Part 5 (Interrupts/Timing). You'll reference Volume II for detailed register specifications and Volume III for firmware behavior.

**If you're doing hardware reimplementation**: Read this volume completely — you need the full system context. Then work through Volume II for component details and Volume III Part 6 for FPGA-specific guidance.

**If you're researching computer architecture**: Part 1 (Design Philosophy) and Part 4 (DMA Architecture) are particularly interesting for understanding alternative approaches to I/O architecture.

## Looking Ahead

This is Volume I of three:

**Volume II: Hardware Components and ASIC Behavior** provides chip-level and register-level specifications for every subsystem (SCSI, Ethernet, graphics, audio, etc.).

**Volume III: Firmware Behavior and Emulation Reference** documents how the ROM uses the hardware and provides comprehensive test suites for validating implementations.

Together, these three volumes form the first complete technical specification of NeXT hardware — reconstructed from reverse engineering with 95-100% confidence and presented in the style of classic SGI, DEC, and Sun technical references.

## Contributing

This reference is a living document. If you have:
- Hardware documentation that improves confidence levels
- Real hardware test results that verify or correct our findings
- Additional ROM analysis that extends coverage
- FPGA implementation experiences that validate specifications

We welcome contributions. See the CONTRIBUTING section in the master index for guidelines.

---

**Let's begin the journey into NeXT's unique hardware architecture.**

— The NeXT Hardware Preservation Project
November 2025

<!-- pagebreak -->
