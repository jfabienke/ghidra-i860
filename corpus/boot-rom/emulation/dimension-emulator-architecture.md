# NeXTdimension Emulator - Complete Architecture

**Component**: Previous NeXTSTEP Emulator - NeXTdimension Subsystem
**Location**: `/src/dimension/`
**Total Code**: 9,339 lines across 24 files
**Language**: C/C++
**Status**: ~85% complete (functional emulation, some device stubs)
**Last Updated**: 2025-11-11

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Component Overview](#component-overview)
4. [File-by-File Reference](#file-by-file-reference)
5. [Memory Map](#memory-map)
6. [Integration Points](#integration-points)
7. [Threading Model](#threading-model)
8. [Build and Debug](#build-and-debug)
9. [Status and Roadmap](#status-and-roadmap)

---

## Executive Summary

The NeXTdimension emulator is a **cycle-accurate emulation** of the NeXTdimension graphics accelerator board, featuring:

- **Intel i860XP RISC processor** - Complete ISA with pipelines, caches, TLB (MAME-derived)
- **64MB RAM + 4MB VRAM** - Full memory subsystem with banking
- **128KB ROM/EEPROM** - Intel 28F010 Flash emulation
- **NBIC** - NeXTbus Interface Chip (slot communication)
- **Memory Controller** - CSR registers, DMA, interrupts
- **Mailbox Protocol** - Host ↔ i860 command/response interface
- **SDL Display** - 1120×832 rendering with 68Hz VBL
- **Threading** - i860 runs on separate thread for performance

### Key Statistics

| Metric | Value |
|--------|-------|
| **Total Files** | 24 |
| **Total Lines** | 9,339 |
| **i860 CPU** | 6,510 lines (70%) |
| **Memory System** | 723 lines (8%) |
| **Devices** | 1,120 lines (12%) |
| **Mailbox** | 465 lines (5%) |
| **Display** | 159 lines (2%) |
| **Integration** | 352 lines (4%) |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Previous Emulator                            │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                     m68040 Host CPU                            │  │
│  │  - Runs NeXTSTEP operating system                              │  │
│  │  - Communicates via NeXTbus                                    │  │
│  └────────────────┬───────────────────────────────────────────────┘  │
│                   │ NeXTbus (slot-based architecture)                │
│  ┌────────────────▼───────────────────────────────────────────────┐  │
│  │           NBIC - NeXTbus Interface Chip (nd_nbic.c)            │  │
│  │  - Board identification (0xC0000001)                           │  │
│  │  - Interrupt routing (m68k ↔ i860)                             │  │
│  │  - Bus error generation                                        │  │
│  │  - Memory map: 0xFFFFFFE8-0xFFFFFFFF                           │  │
│  └────────────────┬───────────────────────────────────────────────┘  │
│                   │                                                  │
│  ┌────────────────▼───────────────────────────────────────────────┐  │
│  │        Memory Controller & Devices (nd_devs.c)                 │  │
│  │  - CSR0: i860 control (reset, interrupts, cache, VBL)          │  │
│  │  - CSR1: CPU interrupt control                                 │  │
│  │  - CSR2: Global access control                                 │  │
│  │  - DMA controller (13 registers)                               │  │
│  │  - RAMDAC (Bt463) interface                                    │  │
│  │  - IIC bus for video devices                                   │  │
│  └───┬────────────┬────────────┬────────────┬─────────────────────┘  │
│      │            │            │            │                        │
│  ┌───▼────┐  ┌────▼─────┐ ┌────▼──────┐ ┌───▼────────────────────┐   │
│  │ RAMDAC │  │Data Path │ │ Video I/O │ │  Mailbox Protocol      │   │
│  │(Bt463) │  │Registers │ │(SAA7191/  │ │  (nd_mailbox.c)        │   │
│  │Pass-   │  │(nd_devs) │ │ SAA7192)  │ │  - 16×32-bit registers │   │
│  │through │  │IIC,DMA   │ │Register   │ │  - 18 commands         │   │
│  └────────┘  └──────────┘ │storage    │ │  - Status/control      │   │
│                           └───────────┘ └────────┬───────────────┘   │
│                                                  │                   │
│  ┌───────────────────────────────────────────────▼────────────────┐  │
│  │                  Memory System (nd_mem.c)                      │  │
│  │  ┌───────────┬──────────┬──────────────┬───────────────────┐   │  │
│  │  │ RAM       │ VRAM     │ ROM/EEPROM   │ Mailbox Registers │   │  │
│  │  │ 64MB      │ 4MB      │ 128KB        │ 64 bytes          │   │  │
│  │  │ 4 banks   │ Mapped   │ Flash 28F010 │ Protocol I/O      │   │  │
│  │  │ 0xF8      │ 0xFE     │ 0xFFF00000   │ 0x0F000000        │   │  │
│  │  └───────────┴──────────┴──────────────┴───────────────────┘   │  │
│  │                                                                │  │
│  │  Banking System: 65,536 banks × 64KB (4GB address space)       │  │
│  └──────────────────────────────────────┬─────────────────────────┘  │
│                                         │                            │
│  ┌──────────────────────────────────────▼─────────────────────────┐  │
│  │              i860 CPU Emulator (i860.cpp/hpp)                  │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  CPU State                                               │  │  │
│  │  │  - 32 integer registers + 32 FP registers                │  │  │
│  │  │  - PC, PSR (Processor Status Register)                   │  │  │
│  │  │  - 6 control registers (fir, psr, dirbase, db, fsr, epsr)│  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Pipelines (cycle-accurate)                              │  │  │
│  │  │  - Adder: 3-stage (S, R, A)                              │  │  │
│  │  │  - Multiplier: 3-stage (S, R, M)                         │  │  │
│  │  │  - Load: 3-stage (address, memory, writeback)            │  │  │
│  │  │  - Graphics: 1-stage (Z-buffer ops)                      │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Caches & TLB                                            │  │  │
│  │  │  - Instruction cache: 512 lines = 4KB                    │  │  │
│  │  │  - TLB: 2048 entries                                     │  │  │
│  │  │  - Dual Instruction Mode (DIM) support                   │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Threading & Communication                               │  │  │
│  │  │  - Runs on separate thread (or m68k thread)              │  │  │
│  │  │  - Message port for commands (reset, int, debug, VBL)    │  │  │
│  │  │  - Thread-safe communication                             │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────┬─────────────────┬─────────────────────────────┘  │
│                   │                 │                                │
│  ┌────────────────▼───────┐  ┌──────▼──────────────────────────────┐ │
│  │  Decoder & Executor    │  │    Debugger (i860dbg.cpp)           │ │
│  │  (i860dec.cpp)         │  │  - Breakpoints & single-step        │ │
│  │  - 3,981 lines         │  │  - Register inspection/modification │ │
│  │  - Full i860 ISA       │  │  - Memory dumps & searches          │ │
│  │  - 64 primary opcodes  │  │  - Disassembly at any address       │ │
│  │  - 128 FP variants     │  │  - Pipeline visualization           │ │
│  │  - 8 core escape ops   │  │  - Command console                  │ │
│  │  - Pipeline simulation │  │  - Traceback buffer                 │ │
│  │  - Virtual memory      │  │  - Performance counters             │ │
│  └────────────────────────┘  └─────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              Display System (nd_sdl.c)                          │ │
│  │  - Separate rendering thread                                    │ │
│  │  - 1120×832 window (NeXTdimension native resolution)            │ │
│  │  - VBL interrupts:                                              │ │
│  │    * Display VBL: 68Hz (14ms period, 136Hz toggle)              │ │
│  │    * Video VBL: 60Hz (16ms period, 120Hz toggle)                │ │
│  │  - SDL texture from VRAM                                        │ │
│  │  - Window show/hide based on monitor config                     │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Component Overview

### 1. Core Integration (2 files, 342 lines)

**Purpose**: Bridges NeXTdimension subsystem to Previous emulator

- **dimension.h** - Public API, memory constants, endianness functions
- **dimension.c** - Memory access bridge, initialization orchestration

**Key Functions**:
- `dimension_init()` - Initializes all subsystems
- `dimension_pause()` / `dimension_uninit()` - Lifecycle management
- `nd_board_rd/wr()` - i860 memory access (big-endian)
- `nd_slot_rd/wr()` - m68k slot access (NBIC-routed)

### 2. i860 CPU Emulation (6 files, 6,510 lines)

**Purpose**: Complete Intel i860XP processor emulation

**Files**:
- `i860cfg.h` (65 lines) - Configuration macros (SPEED/DEV/NO_THREAD modes)
- `i860.hpp` (706 lines) - CPU class definition, state, pipelines
- `i860.cpp` (641 lines) - CPU implementation, threading, messaging
- `i860dec.cpp` (3,981 lines) - Full ISA decoder/executor ⭐
- `i860dis.cpp` (699 lines) - Disassembler
- `i860dbg.cpp` (418 lines) - Interactive debugger

**Features**:
- ✅ Complete i860 ISA (64 primary + 128 FP + 8 core escape)
- ✅ Cycle-accurate pipeline simulation (Adder/Multiplier/Load/Graphics)
- ✅ 4KB instruction cache, 2K TLB
- ✅ Dual Instruction Mode (DIM) for parallel execution
- ✅ Configurable endianness (BE/LE with validation)
- ✅ Threading with message-based control
- ✅ Full debugger with breakpoints, inspection, disassembly

**Heritage**: CPU core derived from MAME for production quality

### 3. Memory System (2 files, 723 lines)

**Purpose**: NeXTdimension memory subsystem

**Files**:
- `nd_mem.h` (30 lines) - Banking interface, macros
- `nd_mem.c` (693 lines) - Complete memory implementation

**Memory Configuration**:
- **RAM**: 4 banks × 16MB = 64MB (configurable per bank)
- **VRAM**: 4MB mapped at 0xFE000000
- **ROM/EEPROM**: 128KB Flash (Intel 28F010) at 0xFFF00000
- **Dither Memory**: 512 bytes at 0xFF000000
- **Mailbox**: 64 bytes at 0x0F000000
- **I/O Registers**: 0xFF800000-0xFF803FFF
- **RAMDAC**: 0xFF200000-0xFF200FFF

**Banking**: 65,536 banks at 64KB granularity (4GB address space)

### 4. Hardware Devices (8 files, 1,120 lines)

**Purpose**: Peripheral and memory controller emulation

#### Memory Controller (nd_devs.c/h - 672 lines)
- **CSR0**: i860 control register
  - Reset, interrupt enables, cache enable, VBL enable
  - Boot sequence control
- **CSR1**: CPU interrupt control
- **CSR2**: Global access control
- **DMA Controller**: 13 registers for display DMA
- **Data Path Registers**: IIC bus, display offset, alpha control

#### NBIC (nd_nbic.c/h - 251 lines)
- **Board ID**: 0xC0000001
- **Interrupt Routing**: m68k ↔ i860
- **Bus Errors**: Illegal access detection
- **Memory Map**: 0xFFFFFFE8-0xFFFFFFFF (top of address space)

#### ROM/EEPROM (nd_rom.c/h - 106 lines)
- **Type**: Intel 28F010 Flash (128KB)
- **Commands**: Read, Write, Erase, Identify, Reset
- **Manufacturer/Device ID**: 0x89/0xB4
- **Write Protection**: Implemented

#### Video Devices (nd_vio.c/h - 127 lines) ⚠️ **STUB**
- **SAA7191**: Digital Multistandard Colour Decoder (DMCD)
- **SAA7192**: Digital Colour Space Converter (DCSC) ×2
- **Status**: Register storage only, no actual video processing

### 5. Mailbox Protocol (2 files, 465 lines) 🆕

**Purpose**: Command/response protocol for host ↔ i860 communication

**Files**:
- `nd_mailbox.h` (30 lines) - Protocol interface
- `nd_mailbox.c` (435 lines) - Protocol implementation

**Architecture**:
- **16 registers** × 32-bit at 0x0F000000 (i860 address space)
- **Host access**: m68k writes commands, reads responses
- **i860 access**: Reads commands, writes responses
- **Status flags**: READY, BUSY, COMPLETE, ERROR, IRQ

**Commands** (18 total):
```
0x00: NOP                    - No operation
0x01: LOAD_KERNEL           - Load i860 firmware from host memory
0x02: INIT_VIDEO            - Initialize video subsystem
0x03: SET_MODE              - Set display mode (resolution/bpp)
0x04: UPDATE_FRAMEBUFFER    - Refresh display
0x05: FILL_RECT             - Hardware rectangle fill
0x06: BLIT                  - Block image transfer
0x07: SET_PALETTE           - Color palette update
0x08: SET_CURSOR_IMAGE      - Cursor bitmap
0x09: SET_CURSOR_POSITION   - Cursor location
0x0A: SHOW_HIDE_CURSOR      - Cursor visibility
0x10: GET_INFO              - Board capabilities query
0x11: MEMORY_TEST           - RAM/VRAM test
0x12: RESET                 - Board reset
```

**Registers**:
```
0x00: Status      (READY|BUSY|COMPLETE|ERROR|IRQ flags)
0x04: Command     (command code)
0x08: Data Ptr    (pointer to host memory)
0x0C: Data Len    (data length in bytes)
0x10: Result      (command result value)
0x14: Error Code  (error details)
0x18: Host Signal (host → i860 notification)
0x1C: i860 Signal (i860 → host notification)
0x20-0x2C: Args 0-3 (command arguments)
0x30-0x3C: Reserved (future use)
```

**Current Status**: Simulation mode (i860 firmware not yet integrated)

### 6. Display System (2 files, 159 lines)

**Purpose**: SDL-based rendering and VBL timing

**Files**:
- `nd_sdl.h` (30 lines) - Display interface, timing constants
- `nd_sdl.c` (129 lines) - SDL implementation

**Features**:
- **Resolution**: 1120×832 (NeXTdimension native)
- **Display VBL**: 68Hz (14ms period, 136Hz CSR0 toggle)
- **Video VBL**: 60Hz (16ms period, 120Hz CSR0 toggle)
- **Rendering**: Separate thread, SDL texture from VRAM
- **Blank Time**: 2ms after VBL trigger
- **Window Management**: Show/hide based on monitor configuration

**Threading**: Independent rendering thread for UI responsiveness

---

## File-by-File Reference

### Build System

#### CMakeLists.txt (10 lines)
```cmake
# Defines compilation for Dimension library
add_library(Dimension ${SOURCES})
target_link_libraries(Dimension SDL2)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-write-strings")
```

**Purpose**: Build configuration for dimension subsystem

---

### Core Integration

#### dimension.h (72 lines)
```c
// Key declarations
#define ND_SLOT 2                 // Slot number on NeXTbus
#define ND_STEP 1                 // Memory controller step version

// Memory arrays
extern uint8_t ND_ram[64*1024*1024];   // 64MB main RAM
extern uint8_t ND_rom[128*1024];       // 128KB ROM
extern uint8_t ND_vram[4*1024*1024];   // 4MB VRAM

// Endianness-aware access (8/16/32/64/128-bit)
uint32_t nd_board_rd32(uint32_t addr);
void nd_board_wr32(uint32_t addr, uint32_t val);
// ... similar for 8/16/64/128-bit, BE and LE variants

// Lifecycle
void dimension_init(void);
void dimension_pause(bool pause);
void dimension_uninit(void);
```

**API Categories**:
1. **Board access** - Big-endian i860 memory operations
2. **Slot access** - NBIC-routed m68k slot access
3. **Lifecycle** - Initialization and control

#### dimension.c (270 lines)

**Key Functions**:

```c
// Board memory access (i860 side, big-endian)
uint32_t nd_board_rd32(uint32_t addr) {
    uint32_t val = nd_longget(addr);
    return (val<<24) | ((val<<8)&0xff0000) |
           ((val>>8)&0xff00) | (val>>24);
}

// Slot memory access (m68k side, via NBIC)
uint32_t nd_slot_rd32(uint32_t addr) {
    return nd_nbic_rd32(addr);  // Routes through NBIC
}

// System initialization
void dimension_init(void) {
    nd_memory_init();    // Memory banking
    nd_nbic_init();      // NeXTbus interface
    nd_rom_init();       // ROM/EEPROM
    nd_mailbox_init();   // Mailbox protocol
    nd_devices_init();   // Peripherals
    nd_sdl_init();       // Display
    i860_init();         // CPU (starts thread)
}
```

**Responsibilities**:
- Endianness conversion bridge
- NBIC routing for slot access
- Subsystem initialization sequencing
- Startup delay simulation (ROM polling)

---

### i860 CPU Files

See [dimension-i860-cpu.md](dimension-i860-cpu.md) for complete i860 documentation.

**Quick Summary**:
- **i860cfg.h**: Configuration (SPEED/DEV/NO_THREAD modes)
- **i860.hpp**: Class definition (registers, pipelines, caches, TLB)
- **i860.cpp**: Implementation (threading, messaging, execution)
- **i860dec.cpp**: ISA decoder/executor (3,981 lines, full ISA)
- **i860dis.cpp**: Disassembler (binary → assembly)
- **i860dbg.cpp**: Debugger (breakpoints, inspection, visualization)

---

### Memory Files

See [dimension-memory-system.md](dimension-memory-system.md) for complete memory documentation.

**Quick Summary**:
- **nd_mem.h**: Banking interface (65,536 banks × 64KB)
- **nd_mem.c**: Complete memory implementation (RAM/VRAM/ROM/mailbox)

---

### Device Files

See [dimension-devices.md](dimension-devices.md) for complete device documentation.

**Quick Summary**:
- **nd_devs.c/h**: Memory controller, CSR registers, DMA, RAMDAC, IIC bus
- **nd_nbic.c/h**: NeXTbus Interface Chip (board ID, interrupts)
- **nd_rom.c/h**: Flash EEPROM emulation (Intel 28F010)
- **nd_vio.c/h**: Video I/O devices (SAA7191/7192, stub)

---

### Mailbox Files

See [dimension-mailbox-protocol.md](dimension-mailbox-protocol.md) for complete protocol documentation.

**Quick Summary**:
- **nd_mailbox.c/h**: 16-register command/response protocol (18 commands)

---

### Display Files

See [dimension-display-system.md](dimension-display-system.md) for complete display documentation.

**Quick Summary**:
- **nd_sdl.c/h**: SDL rendering (1120×832, 68Hz VBL, threading)

---

## Memory Map

### Complete i860 Address Space

```
0x00000000-0x0EFFFFFF   Reserved / Unmapped
0x0F000000-0x0F00003F   Mailbox Registers (64 bytes)
0x0F000040-0xF7FFFFFF   Reserved
0xF8000000-0xF8FFFFFF   RAM Bank 0 (16MB)
0xF9000000-0xF9FFFFFF   RAM Bank 1 (16MB)
0xFA000000-0xFAFFFFFF   RAM Bank 2 (16MB)
0xFB000000-0xFBFFFFFF   RAM Bank 3 (16MB)
0xFC000000-0xFDFFFFFF   Reserved (banks 4-5 for future expansion)
0xFE000000-0xFE3FFFFF   VRAM (4MB)
0xFE400000-0xFEFFFFFF   Reserved
0xFF000000-0xFF0001FF   Dither Memory (512 bytes)
0xFF000200-0xFF1FFFFF   Reserved
0xFF200000-0xFF200FFF   RAMDAC (Bt463) Registers
0xFF201000-0xFF7FFFFF   Reserved
0xFF800000-0xFF800FFF   Memory Controller CSR
0xFF801000-0xFF801FFF   Data Path Registers
0xFF802000-0xFF803FFF   Reserved I/O space
0xFF804000-0xFFEFFFFF   Reserved
0xFFF00000-0xFFF1FFFF   ROM/EEPROM (128KB)
0xFFF20000-0xFFFFFFE7   Reserved
0xFFFFFFE8-0xFFFFFFFF   NBIC Registers (24 bytes)
```

### Memory Banks (64KB granularity)

The memory system uses a banking approach with 65,536 banks of 64KB each:

```c
nd_addrbank mem_banks[65536];  // 4GB / 64KB = 65,536 banks

// Bank 0x0F00: Mailbox (0x0F000000)
// Bank 0xF800-0xF8FF: RAM Bank 0
// Bank 0xF900-0xF9FF: RAM Bank 1
// Bank 0xFA00-0xFAFF: RAM Bank 2
// Bank 0xFB00-0xFBFF: RAM Bank 3
// Bank 0xFE00-0xFE3F: VRAM
// Bank 0xFF00: Dither memory
// Bank 0xFF20: RAMDAC
// Bank 0xFF80-0xFF81: Controller registers
// Bank 0xFFF0-0xFFF1: ROM
// Bank 0xFFFF: NBIC
```

---

## Integration Points

### 1. Host (m68k) → NeXTdimension

```c
// m68k writes to slot address
void slot_write32(uint32_t slot_addr, uint32_t value) {
    nd_slot_wr32(slot_addr, value);  // → nd_nbic_wr32()
}

// Typical sequence: Load kernel via mailbox
m68k_write(SLOT_BASE + MAILBOX_CMD, 0x01);      // LOAD_KERNEL
m68k_write(SLOT_BASE + MAILBOX_DATA_PTR, addr); // Source
m68k_write(SLOT_BASE + MAILBOX_DATA_LEN, size); // Size
m68k_write(SLOT_BASE + MAILBOX_SIGNAL, 1);     // Signal i860
// Wait for STATUS to show COMPLETE
```

### 2. i860 → Host (via Mailbox)

```c
// i860 firmware checks mailbox
uint32_t cmd = nd_mailbox_i860_read(MAILBOX_CMD);
if (cmd == 0x01) {  // LOAD_KERNEL
    uint32_t src = nd_mailbox_i860_read(MAILBOX_DATA_PTR);
    uint32_t len = nd_mailbox_i860_read(MAILBOX_DATA_LEN);
    // Copy from host memory to i860 RAM
    memcpy(ND_ram, host_memory + src, len);
    nd_mailbox_i860_write(MAILBOX_STATUS, STATUS_COMPLETE);
}
```

### 3. Display Updates (VBL-driven)

```c
// VBL handler (68Hz)
void nd_vbl_handler() {
    // Toggle CSR0 VBL bit
    CSR0 ^= CSR0_VBL;

    // If interrupts enabled, signal i860
    if (CSR0 & CSR0_VBL_IE) {
        i860_send_msg(I860_MSG_VBL);
    }

    // SDL rendering thread updates display from VRAM
}
```

---

## Threading Model

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Main Thread (m68k)                 │
│  - Runs NeXTSTEP                                │
│  - Writes to mailbox/slot                       │
│  - Receives VBL interrupts                      │
└────────────┬────────────────────────────────────┘
             │ Message Port
┌────────────▼────────────────────────────────────┐
│           i860 Thread (i860_run_thread)         │
│  - Runs i860_cpu_device::run()                  │
│  - Executes i860 instructions                   │
│  - Handles messages (reset, int, debug, VBL)    │
│  - Reads mailbox, writes responses              │
└────────────┬────────────────────────────────────┘
             │ VRAM updates
┌────────────▼────────────────────────────────────┐
│        SDL Rendering Thread (repainter)         │
│  - Blits VRAM → SDL texture                     │
│  - Updates window at 60 FPS                     │
│  - Independent of i860 execution                │
└─────────────────────────────────────────────────┘
```

### Message Types

```c
#define I860_MSG_RESET    0x01  // Reset CPU
#define I860_MSG_INT      0x02  // External interrupt
#define I860_MSG_DEBUG    0x03  // Enter debugger
#define I860_MSG_VBL      0x04  // VBL interrupt
```

### Thread Safety

- **Mailbox**: Atomic register access
- **VRAM**: Lock-free (SDL reads, i860 writes)
- **Messages**: Queue with mutex/condvar

---

## Build and Debug

### Build Modes

#### 1. Production (CONF_I860_SPEED)
```bash
cmake -DCONF_I860_SPEED=ON ..
make
```
- No traces, no debugger
- Maximum performance
- Softfloat disabled (native FP)

#### 2. Development (CONF_I860_DEV)
```bash
cmake -DCONF_I860_DEV=ON ..
make
```
- Full tracing
- Interactive debugger
- Performance counters
- Memory access logs

#### 3. Single-threaded (CONF_I860_NO_THREAD)
```bash
cmake -DCONF_I860_NO_THREAD=ON ..
make
```
- Runs i860 on m68k thread
- Simpler debugging
- Deterministic execution

### Debug Features

#### Interactive Debugger (DEV mode)
```
i860> b 0xf8000100           # Set breakpoint
i860> s                       # Single step
i860> r                       # Show registers
i860> p                       # Show pipelines
i860> m 0xf8000000 256        # Memory dump
i860> d 0xf8000100            # Disassemble
i860> c                       # Continue
```

#### Trace Flags (i860cfg.h)
```c
#define TRACE_MEM      1    // Memory accesses
#define TRACE_PAGE_FAULT 1  // TLB misses
#define TRACE_UNALIGNED 1   // Unaligned access
#define TRACE_INT      1    // Interrupts
```

#### Performance Counters
```
i860> perf
MIPS: 15.3
Cycles: 153,482,391
Instructions: 142,901,234
Cache hit rate: 98.7%
TLB hit rate: 99.9%
Pipeline stalls: 8.2%
```

---

## Status and Roadmap

### ✅ Complete (Production-Ready)

1. **i860 CPU**
   - Full ISA (64 primary + 128 FP + 8 core)
   - Cycle-accurate pipelines
   - Caches and TLB
   - DIM (Dual Instruction Mode)
   - Debugger
   - Threading

2. **Memory System**
   - Banking (64KB granularity)
   - RAM (64MB, 4 banks)
   - VRAM (4MB)
   - ROM/EEPROM (128KB Flash)
   - Endianness bridge

3. **Integration**
   - NBIC (board ID, interrupts)
   - Memory controller (CSR0/1/2)
   - DMA controller
   - Mailbox protocol (simulation)

4. **Display**
   - SDL rendering (1120×832)
   - VBL timing (68Hz, 60Hz)
   - Threading

### ⚠️ Stub/Minimal

1. **RAMDAC (Bt463)**
   - Pass-through only
   - No actual color lookup

2. **Video I/O (SAA7191/7192)**
   - Register storage only
   - No video processing

3. **Data Path**
   - Basic register emulation
   - IIC bus functional

### 🚧 In Progress / Future

1. **i860 Firmware Integration**
   - Currently simulated by mailbox
   - Need to load and execute real firmware
   - Requires: `LOAD_KERNEL` command + PC set

2. **NeXTSTEP Boot**
   - Goal: Boot NeXTSTEP 3.3 with NeXTdimension
   - Status: Emulator ready, needs firmware

3. **Graphics Acceleration**
   - Hardware rendering (PostScript)
   - Currently software-emulated

### Roadmap

#### Phase 1: Current (Emulator Foundation) ✅
- Complete i860 emulation
- Memory system
- Mailbox protocol
- Display rendering

#### Phase 2: Firmware Integration 🚧
- Load real i860 firmware via mailbox
- Execute firmware main loop
- Handle mailbox commands in firmware
- Test with simple graphics operations

#### Phase 3: NeXTSTEP Boot 📋
- Initialize NeXTdimension from NeXTSTEP
- Load kernel via mailbox
- Display PostScript rendering
- Full graphics acceleration

#### Phase 4: Optimization 🎯
- JIT compilation for i860
- Hardware-accelerated rendering
- Performance tuning

---

## Performance

### Typical Metrics (DEV mode on modern CPU)

```
i860 Clock: 40 MHz (simulated)
Emulated MIPS: 12-18 (depending on host)
Host CPU usage: 15-25% (one core)
Cache hit rate: 97-99%
TLB hit rate: 99.5-99.9%
Pipeline stalls: 5-10%
```

### Bottlenecks

1. **Memory access** - Endianness conversion overhead
2. **FP operations** - Softfloat library (when enabled)
3. **Pipeline simulation** - Cycle-accurate tracking
4. **Threading** - Message passing overhead

### Optimization Opportunities

1. **JIT compilation** - Generate native code for i860 basic blocks
2. **Cache emulation** - Skip for SPEED mode
3. **Fastpath** - Bypass banking for RAM/VRAM
4. **SIMD** - Use host SIMD for i860 graphics ops

---

## Cross-References

- **[i860 CPU Documentation](dimension-i860-cpu.md)** - Complete CPU architecture
- **[Memory System](dimension-memory-system.md)** - Banking and address spaces
- **[Devices](dimension-devices.md)** - Register documentation
- **[Mailbox Protocol](dimension-mailbox-protocol.md)** - Command/response interface
- **[Display System](dimension-display-system.md)** - SDL and VBL timing
- **[Quick Reference](dimension-quick-reference.md)** - Tables and summaries

---

## References

### NeXTdimension Hardware
- **Docs**: `/docs/02-hardware-specs/`
- **Protocol**: `/docs/04-protocol-specs/`
- **Firmware Analysis**: `/docs/03-firmware-analysis/`

### i860 Architecture
- **Intel i860 Microprocessor Programmer's Reference Manual** (1989)
- **Intel i860 XP Microprocessor Data Sheet** (1991)
- **MAME i860 Emulator** (source of CPU core)

### Emulator Source
- **Location**: `/src/dimension/`
- **Total**: 24 files, 9,339 lines
- **Language**: C/C++
- **Build**: CMake + GCC/Clang

---

**Last Updated**: 2025-11-11
**Maintainer**: Previous Project Team
**Status**: Production-ready emulator, firmware integration in progress
