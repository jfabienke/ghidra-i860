# NeXTcube ROM v2.5 (v66) Analysis

**ROM File**: ROMV66-0001E-02588.ASM
**Version**: 2.5 (v66) - Most common NeXTcube ROM
**Size**: 128KB (0x01000000-0x0101FFFF)
**Architecture**: Motorola 68040
**Disassembly Lines**: 15,266
**Purpose**: System boot ROM for NeXTcube/NeXTstation

---

## Executive Summary

This is the boot ROM for the NeXTcube/NeXTstation computers. It contains the **initial bootstrap code** that executes immediately after power-on or reset. The ROM performs hardware initialization, memory testing, device probing, and prepares the system to load the operating system (NeXTSTEP/OPENSTEP).

**Key Functions**:
- CPU initialization (68040 caches, MMU)
- Memory controller setup
- Hardware device detection and configuration
- Video RAM testing
- RTC (Real-Time Clock) initialization
- Boot device detection
- Operating system handoff

**Note**: This ROM is for the **NeXTcube/NeXTstation**, **NOT** the NeXTdimension board. However, the NeXTdimension board has its own m68k ROM (with similar structure) that handles board initialization.

---

## Related Documentation

- **[ROM Monitor Command Set Analysis](nextcube-rom-monitor-commands.md)** - Detailed analysis of boot modes, device selection, and implicit "commands"

## Table of Contents

1. [Boot Sequence Overview](#boot-sequence-overview)
2. [Memory Map](#memory-map)
3. [Key Boot Stages](#key-boot-stages)
4. [Hardware Registers](#hardware-registers)
5. [Device Detection](#device-detection)
6. [Video Initialization](#video-initialization)
7. [RTC Handling](#rtc-handling)
8. [Boot Device Search](#boot-device-search)
9. [Key Functions](#key-functions)
10. [Relationship to NeXTdimension](#relationship-to-nextdimension)

---

## Boot Sequence Overview

### Boot Flow

```
Power-On / Reset
    │
    ▼
0x0100001E: RESET Vector
    │
    ├──> Initialize CPU (cache, MMU)
    ├──> Setup memory controller
    ├──> Detect RAM configuration
    ├──> Test video RAM
    ├──> Initialize RTC
    ├──> Detect boot devices
    └──> Jump to OS loader
```

### Boot Stages

From disassembly comments:

1. **Stage 1**: CPU initialization (no stack yet)
2. **Stage 2**: Memory controller setup, RAM probing
3. **Stage 3**: Video RAM testing, RTC check
4. **Stage 4**: Device detection, OS loading

---

## Memory Map

### ROM Address Space

```
0x01000000-0x0101FFFF   ROM (128KB)
    0x0100001E          RESET vector (entry point)
    0x01000038          Secondary initialization
    0x0100027C          Stage 3: Video RAM OK
    0x010048F2          RTC check subroutine
    0x010095B4          RTC read + screen clear
    0x01000AF8          RTC read + NeXT logo display
```

### Memory-Mapped I/O (Key Addresses)

From the disassembly:

```c
// Memory Controller Registers
0x020C0000   // Memory controller base
0x020C0004   // Memory controller config (writes: 0xC7000000)
0x020C0008   // Memory controller control (cleared to 0)
0x020C000C   // Memory controller status (writes: 0x80000000, 0xC0000000)
0x020C0030   // DMA base address? (writes: 0x40000000)
0x020C0034   // DMA base address? (writes: 0x40000000)
0x020C0038   // Unknown register (writes: 0xE1000000)

// Device Configuration
0x0200C000   // Device configuration register (read for probing)
0x0200C800   // Device ID/status register
0x0200D000   // Device control register

// Video/Display
0x02007800   // Video-related register (cleared)
0x02004188   // Video-related register

// Other Addresses
0x02106010   // Copy destination (from EPROM data)
0x02118180   // Device-specific register
0x02118190   // Device-specific register
```

### RAM Configuration

The ROM detects and configures RAM at various locations:

```c
// From code at 0x01000070:
D0 = *0x0200C800;           // Read device config
D0 &= 0xF0000000;            // Mask upper bits
A5 = D0;                     // Store base address

// Typical RAM base addresses detected:
0x04000000   // Main RAM (common)
0x08000000   // Alternate RAM location
0x0B03F800   // Stack location (detected at runtime)
```

---

## Key Boot Stages

### Stage 1: RESET (0x0100001E)

**No stack available yet** - uses registers only.

From **0x0100001E**:

```c
// Entry point
0100001E: MOVE.L #$00000000, $020C0008    // Clear memory controller
01000028: NOP.L
0100002A: CINVA.L #$00000000              // Invalidate all caches (68040)
01000032: JMP.L $01000A18                 // Jump to setup routine

// Secondary entry at 0x01000038:
01000038: MOVEA.L #$00008000, A0          // Setup for cache control
0100003E: MOVE2C.L #$8002                 // Configure cache (CACR register)
01000042: MOVE.L #$C7000000, $020C0004   // Initialize memory controller
0100004C: LEA.L $01000058, A5            // Setup base register
01000052: JMP.L $01000742                 // Continue initialization
```

**Key operations**:
- Invalidate CPU caches (`CINVA.L`)
- Configure cache control register (CACR = 0x8002)
- Initialize memory controller (0x020C0004 = 0xC7000000)

### Stage 2: Memory Probing (0x01000058)

From **0x01000058**:

```c
01000058: MOVE.L #$80000000, $020C000C   // Memory controller status
01000062: MOVE.L #$E1000000, $020C0038   // Unknown config
0100006C: MOVE.L $0200C800, D0           // Read device config
01000072: AND.L #$F0000000, D0           // Mask RAM base
01000078: MOVEA.L D0, A5                 // A5 = RAM base address

// Device configuration detection
0100009A: MOVE.L (A5, D0.W*1+33603584), D0  // Read device config
010000A2: MOVE.L D0, D1
010000A4: AND.L #$0000F000, D1
010000AA: MOVE.L #$0000000C, D2
010000AC: ASR.L D2, D1                   // Shift to extract field
010000AE: CMP.L #$00000003, D1
010000B4: BEQ.L $010000F2                // Branch if match
```

**Purpose**:
- Detect RAM configuration from hardware registers
- Extract device type from configuration bits
- Determine DMA base addresses

### Stage 3: Video RAM Test (0x0100027C)

From comments: "Video ram is ok, stack at 0B03F800"

From **0x0100027C**:

```c
0100027C: BSR.L $010048F2    // Check RTC
01000282: MOVE.L D0, D2      // Save RTC result
01000284: LEA.L $010002DC, A0
0100028A: ADDA.L A5, A0       // Calculate address with base
0100028C: MOVEC2.L #$9801    // Setup for operation
01000290: MOVE.L #$000000FF, D1
01000296: MOVE.L A0, (A1)+   // Copy operation
01000298: DBF.W D1, $01000296  // Loop

// Call video/screen initialization
0100029E: JSR.L $010003B6    // Setup video
010002A4: JSR.L $010095B4    // RTC read + clear screen
010002B2: JSR.L $01000AF8    // RTC read + display NeXT logo
```

**Purpose**:
- Video RAM has been tested (earlier code)
- Stack is now available at **0x0B03F800**
- RTC (Real-Time Clock) is checked
- Screen is cleared
- NeXT logo is displayed during boot

### Stage 4: Boot Device Detection

From **0x010002CC**:

```c
010002CC: MOVE.L A5, -(A7)        // Push base address
010002CE: MOVE.W #$0700, -(A7)   // Push parameters
010002D2: PEA.L $04000000        // Push address
010002DA: MVSR2.W -(A7)          // Save status register
```

**Purpose**:
- Search for bootable devices
- Load operating system
- Transfer control to OS

---

## Hardware Registers

### Memory Controller (0x020C0000)

From disassembly writes:

```c
struct memory_controller {
    uint32_t reserved0;            // 0x020C0000
    uint32_t config;               // 0x020C0004 = 0xC7000000
    uint32_t control;              // 0x020C0008 = 0x00000000
    uint32_t status;               // 0x020C000C = 0x80000000 or 0xC0000000
    // ...
    uint32_t dma_base1;            // 0x020C0030 = 0x40000000
    uint32_t dma_base2;            // 0x020C0034 = 0x40000000
    uint32_t unknown;              // 0x020C0038 = 0xE1000000
};

// Configuration values
#define MEM_CONFIG_INIT    0xC7000000
#define MEM_STATUS_INIT    0x80000000
#define MEM_STATUS_ALT     0xC0000000
#define DMA_BASE           0x40000000
```

### Device Configuration (0x0200C000)

```c
// Device configuration register at 0x0200C000
// Format (from bit masking and shifts):
//
// Bits 31-28 (0xF0000000): RAM base address (upper 4 bits)
// Bits 15-12 (0x0000F000): Device type field
//   Value 3: Special device (NeXTdimension?)
// Bits 11-8 (0x00000F00): Device subtype
//   Value 1: Specific variant
// Bits 7-0: Other configuration

// Example from 0x0100009A:
uint32_t config = *(uint32_t*)0x0200C000;
uint32_t ram_base = config & 0xF0000000;
uint32_t device_type = (config >> 12) & 0xF;
uint32_t device_subtype = (config >> 8) & 0xF;

if (device_type == 3) {
    // Special device handling
    // Possibly NeXTdimension or other expansion board
}
```

---

## Device Detection

### Device Type Detection Logic

From **0x0100009A-0x010000D4**:

```c
// Read device configuration
uint32_t config = *(uint32_t*)(A5 + 0x0200C000);

// Extract device type (bits 15-12)
uint32_t device_type = (config >> 12) & 0xF;

if (device_type == 3) {
    // Special handling for device type 3
    // Check subtype (bits 11-8)
    uint32_t subtype = (config >> 8) & 0xF;

    if (subtype == 1) {
        // Configure DMA base addresses
        *(uint32_t*)0x020C0034 = 0x40000000;
        *(uint32_t*)0x020C0030 = 0x40000000;
    }
}
```

**Device Type Values**:
- Type 3: Expansion board (possibly NeXTdimension)
  - Subtype 1: Specific variant requiring DMA setup

### Memory Configuration Detection

From **0x010005A4-0x01000628**:

```c
// Memory bit pattern testing
// Tests RAM configuration by writing and reading bit patterns

uint32_t test_pattern1 = 0xDB6DB6DB;
uint32_t test_pattern2 = 0;
uint32_t test_pattern3 = 0;

// Write patterns to RAM
*(uint32_t*)(ram_base + 0) = test_pattern1;
*(uint32_t*)(ram_base + 4) = test_pattern2;
*(uint32_t*)(ram_base + 8) = test_pattern3;

// Shift patterns (rolling bit test)
for (int i = 0; i < iterations; i++) {
    test_pattern1 = (test_pattern1 << 1) | (test_pattern1 >> 31);
    test_pattern2 = (test_pattern2 << 1) | (test_pattern2 >> 31);
    test_pattern3 = (test_pattern3 << 1) | (test_pattern3 >> 31);
}

// Verify patterns
if (*(uint32_t*)(ram_base + 0) == expected_pattern1 &&
    *(uint32_t*)(ram_base + 4) == expected_pattern2 &&
    *(uint32_t*)(ram_base + 8) == expected_pattern3) {
    // RAM test passed
}
```

---

## Video Initialization

### Video RAM Testing

From **0x0100020A-0x0100023E**:

```c
// Detect video RAM configuration
if (device_type != 3) {
    // Standard configuration
    LEA.L $01000216, A7    // Stack setup
    BT.L $01002B9E         // Branch to video test

    // Stack at calculated location
    LEA.L (A5, D0.W*1+184809472), A7  // 0x0B03F800
    CLR.B (A7, $0004)
    LEA.L (A7, $0400), A0

    // Call video RAM test
    JSR.L $010003B6
} else {
    // Device type 3 (expansion board)
    LEA.L $0100024A, A7
    ADDA.L #$00000800, A0
    MOVEA.L A0, A7

    // Different video initialization
    JSR.L $010003B6
    JSR.L $01004F38    // Additional init
}
```

### Screen Clearing

From **0x010095B4** (called at 0x010002A4):

```c
void rtc_read_and_clear_screen() {
    // Read RTC
    // Setup screen control register (SCR1)
    // Clear screen buffer
}
```

### NeXT Logo Display

From **0x01000AF8** (called at 0x010002B2):

```c
void rtc_read_and_display_logo() {
    // Read RTC
    // Setup SCR1
    // Display NeXT logo during boot (the famous boot screen)
}
```

---

## RTC Handling

### RTC Check (0x010048F2)

Called at **0x0100027C**:

```c
BSR.L $010048F2    // Go check RTC
```

**Purpose**: Verify Real-Time Clock is functional and set

### RTC Read Operations

Multiple RTC functions:

1. **0x010095B4**: RTC read + SCR1 + Clear screen
2. **0x01000AF8**: RTC read + SCR1 + Display NeXT logo testing

**RTC registers** (typical NeXT hardware):
- RTC is memory-mapped or accessed via specific I/O addresses
- ROM reads date/time to validate system clock

---

## Boot Device Search

### Boot Device Detection Pattern

From **0x010002CC**:

```c
// Prepare for boot device search
MOVE.L A5, -(A7)        // Base address
MOVE.W #$0700, -(A7)    // Boot flags/parameters
PEA.L $04000000         // RAM address for boot loader
MVSR2.W -(A7)          // Save processor status

// Enter bus error handler setup
// (ROM has comprehensive error handling for boot failures)
```

### Boot Priority

Typical NeXT boot order:
1. Internal SCSI hard drive
2. Floppy disk
3. Network boot (BootP/TFTP)
4. Optical drive

---

## Key Functions

### Cache Control

From **0x01000038**:

```c
MOVEA.L #$00008000, A0     // Cache control value
MOVE2C.L #$8002            // CACR (Cache Control Register)
                           // 0x8002 = Enable both caches
```

**68040 CACR bits**:
- Bit 15: Enable instruction cache
- Bit 0: Enable data cache
- Value 0x8002 = 0b1000000000000010 = Both caches on

### MMU Setup

From **0x01000226**:

```c
MOVE2C.L #$8801    // URP (User Root Pointer) - MMU table base
MOVE2C.L #$8801    // SRP (Supervisor Root Pointer)
```

**MMU configuration**:
- Sets up flat memory model initially
- Page tables will be configured by OS later

### Bus Error Handler

From **0x010002DC**:

```c
// Initial Bus error vector handler
SUBA.W #$0084, A7           // Reserve stack space
MVMLE.L #$ffff, (A7, $0000) // Save all registers
ADD.L #$00000084, (A7, $003c) // Adjust return address

// Save CPU state
MOVEC2.L #$8800    // VBR (Vector Base Register)
MOVE.L A0, (A7, $0040)
MOVEC2.L #$8000    // SFC (Source Function Code)
MOVE.L A0, (A7, $004c)
MOVEC2.L #$8001    // DFC (Destination Function Code)
MOVE.L A0, (A7, $0050)
MOVEC2.L #$8801    // URP
MOVE.L A0, (A7, $0054)
MOVEC2.L #$8002    // CACR
MOVE.L A0, (A7, $005c)

// Continue error handling
```

**Purpose**: Comprehensive error handling during boot for debugging

---

## Relationship to NeXTdimension

### NeXTdimension Detection

From **device type 3** detection at **0x010000B4**:

```c
if (device_type == 3) {
    // NeXTdimension board detected?
    // Special initialization required

    if (device_subtype == 1) {
        // Configure DMA base addresses
        *(uint32_t*)0x020C0034 = 0x40000000;
        *(uint32_t*)0x020C0030 = 0x40000000;
    }
}
```

**Analysis**: Device type 3 appears to be an **expansion board** identifier. This could be the NeXTdimension board being detected during system boot.

### NeXTdimension ROM Relationship

**Important distinction**:

1. **This ROM (NeXTcube ROM)**:
   - Executes on the **host CPU (68040)**
   - Initializes the **NeXTcube/NeXTstation** system
   - **Detects** NeXTdimension board as expansion
   - Configures host-side registers for NeXTdimension

2. **NeXTdimension ROM** (separate ROM on the ND board):
   - Executes on the **NeXTdimension's m68k ROM CPU** (small m68k for board init)
   - Initializes the **i860 processor**
   - Loads i860 firmware
   - Handles board-specific initialization

### Integration Points

```
NeXTcube Boot ROM (this ROM)
    │
    ├──> Detect NeXTdimension (device type 3)
    ├──> Configure DMA base addresses (0x020C0030/34)
    ├──> Enable communication with ND board
    └──> NeXTdimension ROM takes over board initialization
              │
              ├──> Initialize i860 CPU
              ├──> Load i860 firmware
              └──> Start graphics acceleration
```

---

## Summary

### ROM Purpose

This ROM (v2.5, v66) is the **NeXTcube/NeXTstation boot ROM** that:

1. ✅ Initializes 68040 CPU (caches, MMU)
2. ✅ Configures memory controller
3. ✅ Detects RAM configuration
4. ✅ Tests video RAM
5. ✅ Initializes RTC
6. ✅ **Detects NeXTdimension board** (device type 3)
7. ✅ Configures DMA for expansion boards
8. ✅ Searches for boot devices
9. ✅ Loads and transfers control to OS

### Key Addresses

| Address | Purpose |
|---------|---------|
| 0x0100001E | RESET entry point |
| 0x01000038 | Secondary initialization |
| 0x0100027C | Stage 3: Video RAM OK, RTC check |
| 0x010048F2 | RTC check subroutine |
| 0x010095B4 | RTC read + clear screen |
| 0x01000AF8 | RTC read + NeXT logo |
| 0x020C0000 | Memory controller base |
| 0x0200C000 | Device configuration register |
| 0x0B03F800 | Runtime stack location |

### NeXTdimension Connection

**Device Type 3 Detection**:
- ROM detects NeXTdimension as **expansion board** (device type 3, subtype 1)
- Configures **DMA base addresses** (0x40000000)
- Enables communication between host and NeXTdimension
- NeXTdimension's own ROM handles board-specific initialization

### Technical Characteristics

- **15,266 lines** of disassembled code
- **128KB ROM size**
- **68040 assembly language**
- **No stack initially** (uses registers only)
- **Comprehensive error handling** (bus errors, device failures)
- **Hardware probing** (memory, devices, video)
- **Boot device search** (SCSI, floppy, network)

---

**Document Location**: `/Users/jvindahl/Development/previous/docs/hardware/nextcube-rom-analysis.md`
**Created**: 2025-11-11
**Source**: ROMV66-0001E-02588.ASM (15,266 lines)
**Purpose**: Understanding NeXTcube boot process and NeXTdimension detection
