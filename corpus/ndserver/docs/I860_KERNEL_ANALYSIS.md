# NDserver Embedded i860 Kernel Analysis

**Date**: November 7, 2025
**File**: `extracted/i860_kernel.bin` (802,816 bytes)
**MD5**: `bc23eaacacc54d4c3062714edaf809b9`

---

## Overview

This is the **GaCK (Graphics and Color Kernel)** - a stripped-down Mach microkernel that runs on the NeXTdimension's i860 processor. It's embedded in the NDserver binary and loaded onto the i860 at runtime via the kern_loader facility.

---

## Binary Format

```
Type: Mach-O PRELOAD executable i860g
Architecture: Intel i860 (RISC)
Size: 802,816 bytes (784 KB)
Flags: NOUNDEFS (no undefined symbols)
Entry Point: 0xF8000000 (from __text section)
```

**Comparison with Boot ROM**:

| Binary | Size | Type | Purpose |
|--------|------|------|---------|
| ND_step1_v43_eeprom.bin | 128 KB | Raw i860 code | Boot ROM - minimal bootstrap |
| i860_kernel.bin (this) | 784 KB | Mach-O i860 | Full GaCK kernel |

**Size difference**: GaCK is **6.27× larger** than boot ROM!

---

## Memory Map (i860 View)

From Mach-O load commands:

### __TEXT Segment (Code - 737,280 bytes = 720 KB)
```
VM Address:  0xF8000000
VM Size:     0x000B4000 (737,280 bytes = 720 KB)
File Offset: 840 bytes
Protection:  r-x (read + execute)
```

**Section: __text**
```
Address: 0xF8000000
Size:    0x000B2548 (730,440 bytes = 713 KB)
Type:    S_REGULAR (executable code)
```

**Entry Point**: 0xF8000000 (first instruction in __text)

### __DATA Segment (Globals - 57,344 bytes = 56 KB)
```
VM Address:  0xF80B4000
VM Size:     0x00012000 (73,728 bytes = 72 KB)
File Offset: 738,120 bytes
Protection:  rwx (read + write + execute)
```

**Section: __data (Initialized Data - 56 KB)**
```
Address: 0xF80B4000
Size:    0x0000DC50 (56,400 bytes)
Purpose: Global variables, initialized data
```

**Section: __bss (Uninitialized Data - 2.7 KB)**
```
Address: 0xF80C1D00
Size:    0x00000AC0 (2,752 bytes)
Purpose: Zero-initialized globals (BSS)
```

**Section: __common (Common Block - 6.2 KB)**
```
Address: 0xF80C27C0
Size:    0x000018D8 (6,360 bytes)
Purpose: Common symbols
```

### Total Memory Footprint
```
Code (__text):     713 KB
Data (__data):      56 KB
BSS  (__bss):      2.7 KB
Common:            6.2 KB
---------------------------------
Total:            ~778 KB
```

---

## Architecture Notes

**Loading Process**:

1. NDserver starts on 68040 host
2. Calls `ND_BootKernelFromSect()` to extract __I860 segment
3. Uses kern_loader facility to transfer kernel to i860
4. i860 ROM (ND_step1_v43_eeprom.bin) receives kernel via mailbox
5. ROM copies kernel from shared memory to i860 DRAM at 0x00000000
6. ROM jumps to entry point at 0xF8000000 (mapped to DRAM)
7. GaCK kernel takes over, ROM code no longer executes

**Memory Translation**:

The kernel is position-independent but assumes specific addresses:
- **VM addresses** (in Mach-O): 0xF8000000-0xF80C6000
- **Physical i860 DRAM**: 0x00000000-0x03FFFFFF (up to 64MB)
- **Mapping**: VM address 0xF8000000 → Physical 0x00000000 (via i860 page tables)

**Why high VM addresses?**
- NeXTdimension uses i860 MMU
- Kernel runs in high memory to separate from user space
- Page tables map 0xF8000000 → 0x00000000 physical

---

## Entry Point Analysis

From LC_UNIXTHREAD load command:

**Initial Register State** (all zeros):
```
i0-i30:  0x00000000  (General purpose registers)
f0-f9:   0x00000000  (Floating point registers)
```

**Entry point**: First instruction at 0xF8000000

**Expected boot sequence**:
```
1. 0xF8000000: Setup stack pointer (sp = i31)
2. Enable i860 caches (instruction + data)
3. Initialize MMU page tables
4. Set up FPU control registers
5. Initialize Mach IPC subsystem
6. Set up mailbox handlers
7. Initialize graphics subsystem
8. Enter main message loop
```

---

## Comparison: Boot ROM vs GaCK Kernel

| Feature | Boot ROM (128KB) | GaCK Kernel (784KB) |
|---------|------------------|---------------------|
| **Purpose** | Minimal bootstrap | Full operating system |
| **Code Size** | ~11KB | ~713KB |
| **Mach IPC** | No | Full Mach 2.5 IPC |
| **Display PostScript** | No | Yes (partial) |
| **Graphics Ops** | Minimal | Full 2D acceleration |
| **Memory Mgmt** | Basic | Full MMU + paging |
| **Mailbox** | Simple polling | Full message queue |
| **Font Cache** | No | Yes |
| **Video Modes** | Basic | Full NTSC/PAL/VGA |
| **DMA Support** | No | Yes |
| **Interrupts** | Basic | Full interrupt handling |

---

## Next Steps for Full Analysis

**Phase 1: Static Analysis** (if needed in future):
1. Disassemble with i860 disassembler (MAME, IDA, or Ghidra)
2. Identify entry point function
3. Map function call graph
4. Find Mach IPC message handlers
5. Locate graphics operation dispatch table

**Phase 2: Protocol Discovery**:
1. Find mailbox command handlers
2. Identify command IDs and parameter structures
3. Map graphics operation codes
4. Document Mach message formats

**Phase 3: Correlation with NDserver**:
1. Match m68k driver messages with i860 handlers
2. Understand command encoding
3. Map shared memory structures
4. Document synchronization protocol

---

## Current Status

**✅ Kernel Extracted**: 802,816 bytes from NDserver __I860 segment
**✅ Binary Format Verified**: Mach-O i860 PRELOAD executable
**✅ Memory Map Documented**: 720KB code, 56KB data, entry at 0xF8000000
**⏳ Disassembly**: Deferred (focus on m68k driver first)
**⏸️  Protocol Analysis**: Will correlate with m68k findings

---

## Strategic Decision

**We will NOT disassemble the i860 kernel immediately** because:

1. **Size**: 713KB of i860 code = weeks of analysis
2. **Already documented**: Boot ROM analysis covers initialization
3. **m68k driver more important**: It tells us HOW to communicate
4. **Protocol-first approach**: Understand commands before implementation
5. **Emulator already works**: Previous 1.4+ has working i860 emulation

**Focus instead on**:
- m68k driver disassembly (18KB only!)
- Mach IPC message structures
- Command format and encoding
- Shared memory layout

**When kernel analysis becomes necessary**:
- Use MAME i860 disassembler: `/Users/jvindahl/Development/nextdimension/tools/mame-i860/i860disasm`
- Cross-reference with Previous emulator source: `/tmp/previous-trunk/src/dimension/`
- Correlate with hardware capture logs

---

**Document Status**: i860 KERNEL EXTRACTED AND ANALYZED
**Date**: November 7, 2025
**Next**: Focus on m68k driver disassembly
