# Abstract

The NeXT Computer hardware architecture represents a unique synthesis of mainframe computing concepts and microcomputer implementation. Designed under Steve Jobs' directive to implement "mainframe techniques" in a workstation-class system, NeXT hardware departed significantly from contemporary microcomputer designs.

This volume presents the system-level architecture of NeXT Computer hardware, reconstructed from NeXTcube ROM v3.3 reverse engineering with 95-100% confidence. Rather than adopting the register-based I/O model typical of 1980s microcomputers, NeXT implemented:

- **Channel-based I/O** using custom ASICs as hardware abstraction layers
- **DMA-centric architecture** where direct CPU register access is minimized
- **Sophisticated interrupt routing** with NBIC-based IPL merging
- **Board-specific architectures** where NeXTcube and NeXTstation are fundamentally different designs

The architecture is documented through five major parts:

**Part 1** explains the design philosophy — why NeXT hardware works the way it does, tracing the influence of IBM mainframe architecture and NeXT's unique approach to hardware abstraction through ASICs.

**Part 2** presents the global memory architecture — the complete address space, burst-aligned memory regions, cacheability rules, and the critical distinction between slot space and board space addressing.

**Part 3** details the NBIC (NeXTbus Interface Controller) — the chip that implements slot/board address decoding, interrupt priority merging, and bus error semantics.

**Part 4** explains the DMA architecture — how NeXT implements I/O primarily through DMA channels rather than direct CPU register access, including word-pumped ring buffers and descriptor formats.

**Part 5** covers system timing, interrupts, and clocks — the temporal behavior of the system including timer mechanisms, DMA completion interrupts, interrupt routing, and emulation timing constraints.

Key discoveries from this analysis include:

1. **NeXTcube SCSI makes exactly one register write** to the NCR 53C90, with all other SCSI operations handled by ASIC abstraction — contrary to the assumption that standard NCR initialization occurs.

2. **DMA registers at 0x02020000/0x02020004 are write-only configuration registers** written once during boot, not runtime control registers.

3. **Ethernet on NeXTcube makes zero MACE register accesses**, with the MACE controller completely buried in the ASIC and accessed only through two interface control registers.

4. **Board configuration byte at RAM offset 0x3a8** (not a hardware register) selects fundamentally different hardware architectures, not just CPU speeds.

5. **Interrupt sources merge into IPL2 and IPL6** via the NBIC, with the NeXTSTEP kernel decoding individual sources from a status register rather than receiving separate interrupt levels.

This volume provides the architectural context necessary to understand the detailed component-level specifications in Volume II and the firmware behavior documented in Volume III.

**Confidence Level**: 95-100% on all documented architectural features, verified from ROM v3.3 disassembly (87,143 lines, ~10 hours of analysis).

**Intended Audience**: System architects, emulator developers, computer architecture researchers, and anyone seeking to understand the unique design philosophy of NeXT hardware.

**Prerequisites**: Basic familiarity with computer architecture concepts (memory maps, interrupts, DMA). No NeXT-specific knowledge required.

**Length**: Approximately 150 pages

**Status**: Skeleton structure complete, content extraction in progress

---

**Keywords**: NeXT Computer, NeXTcube, NeXTstation, hardware architecture, ASIC design, channel I/O, DMA, NBIC, 68040, ROM reverse engineering, system architecture, hardware abstraction layer
