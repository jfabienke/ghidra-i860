# NeXTdimension Hardware Devices

**Part of**: NeXTdimension Emulator Documentation
**Component**: Memory-Mapped I/O Devices
**Files**: 8 files, 1,120 lines
**Status**: ✅ Core complete, ⚠️ RAMDAC/Video stubs
**Architecture**: Register-based MMIO devices

---

## Executive Summary

The NeXTdimension board contains several hardware devices accessed through memory-mapped registers. The emulator implements the essential devices (memory controller, NBIC interface) while stubbing optional features (RAMDAC, video I/O) that aren't critical for basic operation.

**Key Components**:
- **Memory Controller** (CSR0/CSR1/CSR2) - i860 control and DMA
- **NBIC** (NeXTbus Interface Chip) - Board identification and interrupts
- **RAMDAC** (BT463) - Color palette (stub)
- **Video I/O** - Video input/output (stub)
- **DMA Controller** - 13 registers for memory transfers

---

## Table of Contents

1. [Component Files](#component-files)
2. [Memory Controller (CSR)](#memory-controller-csr)
3. [NBIC Interface](#nbic-interface)
4. [DMA Controller](#dma-controller)
5. [RAMDAC (BT463)](#ramdac-bt463)
6. [Video I/O](#video-io)
7. [Register Reference](#register-reference)
8. [Interrupt System](#interrupt-system)
9. [Integration Examples](#integration-examples)

---

## Component Files

### Overview

| File | Lines | Purpose | Status |
|------|-------|---------|--------|
| **nd_devs.c** | 655 | Memory controller (CSR0/CSR1/CSR2) | ✅ Complete |
| **nd_devs.h** | 38 | Device declarations | ✅ Complete |
| **nd_nbic.c** | 240 | NeXTbus Interface Chip | ✅ Complete |
| **nd_nbic.h** | 23 | NBIC declarations | ✅ Complete |
| **nd_ramdac.c** | 87 | BT463 RAMDAC emulation | ⚠️ Stub |
| **nd_ramdac.h** | 15 | RAMDAC declarations | ⚠️ Stub |
| **nd_video.c** | 47 | Video I/O (composite/S-Video) | ⚠️ Stub |
| **nd_video.h** | 15 | Video declarations | ⚠️ Stub |
| **Total** | **1,120** | Complete device layer |

### File Relationships

```
nd_devs.h ──┬──> nd_devs.c ──┐
nd_nbic.h ──┼──> nd_nbic.c ──┤
nd_ramdac.h ┼──> nd_ramdac.c ┼──> dimension.c (initialization)
nd_video.h ─┴──> nd_video.c ─┘       │
                                     ├──> Memory banking (MMIO)
                                     └──> i860 CPU (interrupts)
```

---

## Memory Controller (CSR)

### CSR Overview

The memory controller provides control and status registers for managing the i860 processor, DMA, and interrupts.

**Location**: Various addresses (CSR0, CSR1, CSR2 at different locations)

From **nd_devs.c:655**:

```c
// ============================================================
// CONTROL/STATUS REGISTERS (CSR)
// ============================================================

// CSR0: Primary control register (i860 control, interrupts)
uint32_t CSR0 = 0;

// CSR1: Secondary control register (video/DMA control)
uint32_t CSR1 = 0;

// CSR2: Status register (board state)
uint32_t CSR2 = 0;
```

### CSR0: Primary Control Register

From **nd_devs.c:72**:

```c
// CSR0 bit definitions (32-bit register)
#define CSR0_RESET       (1<<0)   // i860 reset (1=reset, 0=run)
#define CSR0_INT_EN      (1<<1)   // Interrupt enable
#define CSR0_CACHE_EN    (1<<2)   // i860 cache enable
#define CSR0_VBL_EN      (1<<3)   // VBL interrupt enable
#define CSR0_VBL         (1<<4)   // VBL status (toggles at 68Hz)
#define CSR0_DMA_EN      (1<<5)   // DMA enable
#define CSR0_DMA_BUSY    (1<<6)   // DMA in progress (read-only)
#define CSR0_ERROR       (1<<7)   // Bus error flag
#define CSR0_INT_PENDING (1<<8)   // Interrupt pending to host
#define CSR0_I860_RUN    (1<<9)   // i860 running (read-only status)

// CSR0 read
uint32_t nd_csr0_read(void) {
    uint32_t val = CSR0;

    // Update dynamic bits
    if (i860_is_running()) {
        val |= CSR0_I860_RUN;
    } else {
        val &= ~CSR0_I860_RUN;
    }

    if (dma_is_busy()) {
        val |= CSR0_DMA_BUSY;
    } else {
        val &= ~CSR0_DMA_BUSY;
    }

    return val;
}

// CSR0 write
void nd_csr0_write(uint32_t val) {
    CSR0 = val;

    // Handle reset
    if (val & CSR0_RESET) {
        i860_send_msg(I860_MSG_RESET);
        CSR0 &= ~CSR0_RESET;  // Auto-clear
    }

    // Handle interrupt enable
    if ((val & CSR0_INT_EN) && (val & CSR0_INT_PENDING)) {
        // Trigger interrupt to host
        nd_nbic_assert_int();
    }

    // Handle cache enable
    if (val & CSR0_CACHE_EN) {
        i860_enable_cache();
    } else {
        i860_disable_cache();
    }

    // Handle VBL enable
    if (val & CSR0_VBL_EN) {
        nd_vbl_enable();
    } else {
        nd_vbl_disable();
    }

    // Handle DMA enable
    if (val & CSR0_DMA_EN) {
        nd_dma_start();
    }
}
```

### CSR1: Secondary Control Register

From **nd_devs.c:187**:

```c
// CSR1 bit definitions
#define CSR1_VIDEO_EN    (1<<0)   // Video output enable
#define CSR1_BLANK       (1<<1)   // Screen blank (power save)
#define CSR1_SYNC        (1<<2)   // Sync polarity
#define CSR1_INTERLACE   (1<<3)   // Interlaced mode
#define CSR1_DMA_MODE    (3<<4)   // DMA mode (2 bits)
#define CSR1_TEST_MODE   (1<<6)   // Test mode enable

uint32_t nd_csr1_read(void) {
    return CSR1;
}

void nd_csr1_write(uint32_t val) {
    CSR1 = val;

    // Handle video enable
    if (val & CSR1_VIDEO_EN) {
        nd_video_enable();
    } else {
        nd_video_disable();
    }

    // Handle blanking
    if (val & CSR1_BLANK) {
        nd_video_blank();
    }
}
```

### CSR2: Status Register

From **nd_devs.c:231**:

```c
// CSR2 bit definitions (mostly read-only status)
#define CSR2_BOARD_ID    (0xF<<0)  // Board ID (4 bits) = 0xC (NeXTdimension)
#define CSR2_REV         (0xF<<4)  // Board revision (4 bits)
#define CSR2_RAM_SIZE    (3<<8)    // RAM size (2 bits: 0=16MB, 1=32MB, 2=64MB)
#define CSR2_VRAM_SIZE   (3<<10)   // VRAM size (2 bits: 0=1MB, 1=2MB, 2=4MB)
#define CSR2_ROM_VER     (0xF<<12) // ROM version (4 bits)
#define CSR2_VIDEO_IN    (1<<16)   // Video input present
#define CSR2_VIDEO_LOCK  (1<<17)   // Video input locked

uint32_t nd_csr2_read(void) {
    uint32_t val = 0;

    // Board identification
    val |= (0xC << 0);       // NeXTdimension ID = 0xC
    val |= (0x2 << 4);       // Revision 2 (typical)

    // Memory configuration
    val |= (2 << 8);         // 64MB RAM
    val |= (2 << 10);        // 4MB VRAM

    // ROM version
    val |= (0x6 << 12);      // ROM v2.5 = 0x6

    // Video status
    if (nd_video_input_present()) {
        val |= CSR2_VIDEO_IN;
    }
    if (nd_video_input_locked()) {
        val |= CSR2_VIDEO_LOCK;
    }

    return val;
}

void nd_csr2_write(uint32_t val) {
    // CSR2 is mostly read-only
    // Some bits might be writable in real hardware (unclear)
    (void)val;
}
```

### CSR Initialization

From **nd_devs.c:297**:

```c
void nd_devices_init(void) {
    printf("[DEV] Initializing devices...\n");

    // Initialize CSRs to default state
    CSR0 = CSR0_RESET;  // i860 starts in reset
    CSR1 = 0;
    CSR2 = 0;

    // Initialize DMA
    nd_dma_init();

    // Initialize RAMDAC
    nd_ramdac_init();

    // Initialize video
    nd_video_init();

    printf("[DEV] Device initialization complete\n");
}
```

---

## NBIC Interface

### NBIC Overview

The **NeXTbus Interface Chip (NBIC)** handles communication between the NeXTdimension board and the host NeXT computer via the NeXTbus.

**Key functions**:
- Board identification
- Interrupt routing (NeXTdimension → host)
- Slot configuration

From **nd_nbic.c:240**:

```c
// ============================================================
// NBIC (NeXTbus Interface Chip) EMULATION
// ============================================================

// NBIC registers (24 bytes at 0xFFFFFFE8-0xFFFFFFFF)
#define NBIC_ID         0xFFFFFFE8   // Board ID register
#define NBIC_INT_STATUS 0xFFFFFFEC   // Interrupt status
#define NBIC_INT_MASK   0xFFFFFFF0   // Interrupt mask
#define NBIC_INT_CLEAR  0xFFFFFFF4   // Interrupt clear
#define NBIC_SLOT_ID    0xFFFFFFF8   // Slot number
#define NBIC_CONFIG     0xFFFFFFFC   // Configuration

// Board identification
#define NBIC_BOARD_ID   0xC0000001   // NeXTdimension = 0xC, Rev 1
```

### NBIC Registers

From **nd_nbic.c:47**:

```c
// NBIC register state
static uint32_t nbic_id = NBIC_BOARD_ID;
static uint32_t nbic_int_status = 0;
static uint32_t nbic_int_mask = 0;
static uint32_t nbic_slot_id = 0;
static uint32_t nbic_config = 0;

// NBIC ID register
uint32_t nd_nbic_rd32_id(uint32_t addr) {
    (void)addr;
    return nbic_id;
}

void nd_nbic_wr32_id(uint32_t addr, uint32_t val) {
    // Read-only
    (void)addr;
    (void)val;
}

// NBIC interrupt status
uint32_t nd_nbic_rd32_int_status(uint32_t addr) {
    (void)addr;
    return nbic_int_status;
}

void nd_nbic_wr32_int_status(uint32_t addr, uint32_t val) {
    // Writing 1 to a bit clears it
    (void)addr;
    nbic_int_status &= ~val;
}

// NBIC interrupt mask
uint32_t nd_nbic_rd32_int_mask(uint32_t addr) {
    (void)addr;
    return nbic_int_mask;
}

void nd_nbic_wr32_int_mask(uint32_t addr, uint32_t val) {
    (void)addr;
    nbic_int_mask = val;

    // Check if any masked interrupts are pending
    if (nbic_int_status & nbic_int_mask) {
        nd_nbic_assert_int();
    }
}

// NBIC slot ID
uint32_t nd_nbic_rd32_slot_id(uint32_t addr) {
    (void)addr;
    return nbic_slot_id;
}

void nd_nbic_wr32_slot_id(uint32_t addr, uint32_t val) {
    // Read-only (set by hardware)
    (void)addr;
    (void)val;
}

// NBIC configuration
uint32_t nd_nbic_rd32_config(uint32_t addr) {
    (void)addr;
    return nbic_config;
}

void nd_nbic_wr32_config(uint32_t addr, uint32_t val) {
    (void)addr;
    nbic_config = val;
}
```

### NBIC Interrupt Handling

From **nd_nbic.c:142**:

```c
// Interrupt sources
#define NBIC_INT_VBL      (1<<0)   // Vertical blank interrupt
#define NBIC_INT_I860     (1<<1)   // i860 interrupt to host
#define NBIC_INT_DMA      (1<<2)   // DMA completion
#define NBIC_INT_ERROR    (1<<3)   // Bus error

// Assert interrupt to host (m68k)
void nd_nbic_assert_int(void) {
    // Check if any unmasked interrupts are pending
    if (nbic_int_status & nbic_int_mask) {
        // Trigger NeXTbus interrupt (handled by Previous emulator)
        set_interrupt(INT_ND, 1);
    }
}

// Clear interrupt to host
void nd_nbic_clear_int(void) {
    set_interrupt(INT_ND, 0);
}

// Set specific interrupt source
void nd_nbic_set_int_source(uint32_t source) {
    nbic_int_status |= source;
    nd_nbic_assert_int();
}

// Clear specific interrupt source
void nd_nbic_clear_int_source(uint32_t source) {
    nbic_int_status &= ~source;

    // If no more pending interrupts, clear host interrupt
    if (!(nbic_int_status & nbic_int_mask)) {
        nd_nbic_clear_int();
    }
}
```

### NBIC Initialization

From **nd_nbic.c:198**:

```c
void nd_nbic_init(void) {
    printf("[NBIC] Initializing NeXTbus interface...\n");

    // Set board ID
    nbic_id = NBIC_BOARD_ID;

    // Clear interrupt state
    nbic_int_status = 0;
    nbic_int_mask = 0;

    // Set slot ID (from configuration)
    nbic_slot_id = ND_SLOT << 24;  // Slot number in upper byte

    // Default configuration
    nbic_config = 0;

    // Map NBIC registers to memory
    nd_map_banks(&nbic_bank, 0xFFFF, 1);  // Bank 0xFFFF (last 64KB)

    printf("[NBIC] Board ID: 0x%08X (slot %d)\n", nbic_id, ND_SLOT);
}
```

---

## DMA Controller

### DMA Overview

The NeXTdimension includes a DMA controller for efficient memory transfers (host ↔ i860 RAM/VRAM).

From **nd_devs.c:341**:

```c
// ============================================================
// DMA CONTROLLER (13 registers)
// ============================================================

// DMA registers
uint32_t DMA_regs[13];

// DMA register indices
#define DMA_SRC_ADDR    0   // Source address
#define DMA_DST_ADDR    1   // Destination address
#define DMA_COUNT       2   // Transfer count (bytes)
#define DMA_CONTROL     3   // Control/status
#define DMA_STRIDE_SRC  4   // Source stride (2D transfers)
#define DMA_STRIDE_DST  5   // Destination stride
#define DMA_WIDTH       6   // Transfer width (2D)
#define DMA_HEIGHT      7   // Transfer height (2D)
#define DMA_SKIP_SRC    8   // Source skip (padding)
#define DMA_SKIP_DST    9   // Destination skip
#define DMA_RESERVED_A  10  // Reserved
#define DMA_RESERVED_B  11  // Reserved
#define DMA_RESERVED_C  12  // Reserved

// DMA control bits
#define DMA_CTRL_START    (1<<0)   // Start transfer
#define DMA_CTRL_ABORT    (1<<1)   // Abort transfer
#define DMA_CTRL_INT_EN   (1<<2)   // Interrupt on completion
#define DMA_CTRL_DIR      (1<<3)   // Direction: 0=host→i860, 1=i860→host
#define DMA_CTRL_MODE     (3<<4)   // Mode: 0=1D, 1=2D, 2=fill
#define DMA_CTRL_BUSY     (1<<6)   // Transfer in progress (read-only)
#define DMA_CTRL_ERROR    (1<<7)   // Transfer error
```

### DMA Operations

From **nd_devs.c:398**:

```c
void nd_dma_init(void) {
    memset(DMA_regs, 0, sizeof(DMA_regs));
}

int dma_is_busy(void) {
    return (DMA_regs[DMA_CONTROL] & DMA_CTRL_BUSY) ? 1 : 0;
}

void nd_dma_start(void) {
    uint32_t src = DMA_regs[DMA_SRC_ADDR];
    uint32_t dst = DMA_regs[DMA_DST_ADDR];
    uint32_t count = DMA_regs[DMA_COUNT];
    uint32_t ctrl = DMA_regs[DMA_CONTROL];

    // Set busy flag
    DMA_regs[DMA_CONTROL] |= DMA_CTRL_BUSY;

    // Determine transfer mode
    uint32_t mode = (ctrl >> 4) & 3;

    switch (mode) {
    case 0:  // 1D transfer (simple copy)
        nd_dma_1d(src, dst, count);
        break;

    case 1:  // 2D transfer (rectangular region)
        nd_dma_2d(src, dst,
                  DMA_regs[DMA_WIDTH],
                  DMA_regs[DMA_HEIGHT],
                  DMA_regs[DMA_STRIDE_SRC],
                  DMA_regs[DMA_STRIDE_DST]);
        break;

    case 2:  // Fill (constant value)
        nd_dma_fill(dst, count, src);  // src used as fill value
        break;
    }

    // Clear busy flag
    DMA_regs[DMA_CONTROL] &= ~DMA_CTRL_BUSY;

    // Trigger interrupt if enabled
    if (ctrl & DMA_CTRL_INT_EN) {
        nd_nbic_set_int_source(NBIC_INT_DMA);
    }
}

void nd_dma_1d(uint32_t src, uint32_t dst, uint32_t count) {
    // Simple byte-by-byte copy
    for (uint32_t i = 0; i < count; i++) {
        uint8_t val = nd_mem_get(src + i);
        nd_mem_put(dst + i, val);
    }
}

void nd_dma_2d(uint32_t src, uint32_t dst, uint32_t width, uint32_t height,
               uint32_t src_stride, uint32_t dst_stride) {
    // 2D transfer (rectangular region with strides)
    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < width; x++) {
            uint8_t val = nd_mem_get(src + y * src_stride + x);
            nd_mem_put(dst + y * dst_stride + x, val);
        }
    }
}

void nd_dma_fill(uint32_t dst, uint32_t count, uint32_t fill_val) {
    // Fill region with constant value
    uint8_t byte_val = fill_val & 0xFF;
    for (uint32_t i = 0; i < count; i++) {
        nd_mem_put(dst + i, byte_val);
    }
}
```

---

## RAMDAC (BT463)

### RAMDAC Overview

The **Brooktree BT463** RAMDAC (Random Access Memory Digital-to-Analog Converter) provides color palette management for indexed color modes.

**Status**: ⚠️ **Stub implementation** (not critical for true-color operation)

From **nd_ramdac.c:87**:

```c
// ============================================================
// RAMDAC (BT463) EMULATION (STUB)
// ============================================================

// RAMDAC registers (accessed via indexed interface)
#define RAMDAC_ADDR_WR    0xFFFFF000  // Write address
#define RAMDAC_ADDR_RD    0xFFFFF004  // Read address
#define RAMDAC_DATA       0xFFFFF008  // Data
#define RAMDAC_CONTROL    0xFFFFF00C  // Control

// RAMDAC state
static uint8_t ramdac_addr_wr = 0;
static uint8_t ramdac_addr_rd = 0;
static uint8_t ramdac_palette[256][3];  // 256 entries × RGB

void nd_ramdac_init(void) {
    // Initialize palette to grayscale
    for (int i = 0; i < 256; i++) {
        ramdac_palette[i][0] = i;  // R
        ramdac_palette[i][1] = i;  // G
        ramdac_palette[i][2] = i;  // B
    }
}

uint32_t nd_ramdac_read(uint32_t addr) {
    switch (addr) {
    case RAMDAC_ADDR_RD:
        return ramdac_addr_rd;

    case RAMDAC_DATA:
        // Read palette data (R, G, B sequence)
        return 0xFF;  // Stub

    default:
        return 0xFF;
    }
}

void nd_ramdac_write(uint32_t addr, uint32_t val) {
    switch (addr) {
    case RAMDAC_ADDR_WR:
        ramdac_addr_wr = val & 0xFF;
        break;

    case RAMDAC_DATA:
        // Write palette data (R, G, B sequence)
        // Stub: palette writes are ignored (use direct RGB)
        break;

    default:
        break;
    }
}
```

**Note**: The emulator currently uses **direct RGB rendering** (true-color), so the RAMDAC palette is not actively used. This is sufficient for most software.

---

## Video I/O

### Video Overview

The NeXTdimension includes **video input** (composite/S-Video) and **video output** connections.

**Status**: ⚠️ **Stub implementation** (not used by standard software)

From **nd_video.c:47**:

```c
// ============================================================
// VIDEO I/O EMULATION (STUB)
// ============================================================

// Video state
static int video_enabled = 0;
static int video_input_present = 0;
static int video_input_locked = 0;

void nd_video_init(void) {
    video_enabled = 0;
    video_input_present = 0;
    video_input_locked = 0;
}

void nd_video_enable(void) {
    video_enabled = 1;
}

void nd_video_disable(void) {
    video_enabled = 0;
}

void nd_video_blank(void) {
    // Blank screen (power save)
}

int nd_video_input_present(void) {
    return video_input_present;
}

int nd_video_input_locked(void) {
    return video_input_locked;
}
```

**Note**: Video I/O features are rarely used by software and are not critical for emulation.

---

## Register Reference

### Complete Register Map

| Address | Name | Size | Type | Description |
|---------|------|------|------|-------------|
| **Memory Controller** |
| TBD | CSR0 | 32-bit | R/W | Primary control (reset, interrupts, cache) |
| TBD | CSR1 | 32-bit | R/W | Secondary control (video, DMA) |
| TBD | CSR2 | 32-bit | R | Status (board ID, memory config) |
| **DMA Controller** |
| TBD | DMA_SRC_ADDR | 32-bit | R/W | Source address |
| TBD | DMA_DST_ADDR | 32-bit | R/W | Destination address |
| TBD | DMA_COUNT | 32-bit | R/W | Transfer count (bytes) |
| TBD | DMA_CONTROL | 32-bit | R/W | Control/status |
| TBD | DMA_STRIDE_SRC | 32-bit | R/W | Source stride (2D) |
| TBD | DMA_STRIDE_DST | 32-bit | R/W | Destination stride (2D) |
| TBD | DMA_WIDTH | 32-bit | R/W | Width (2D) |
| TBD | DMA_HEIGHT | 32-bit | R/W | Height (2D) |
| **NBIC** |
| 0xFFFFFFE8 | NBIC_ID | 32-bit | R | Board ID (0xC0000001) |
| 0xFFFFFFEC | NBIC_INT_STATUS | 32-bit | R/W1C | Interrupt status |
| 0xFFFFFFF0 | NBIC_INT_MASK | 32-bit | R/W | Interrupt mask |
| 0xFFFFFFF4 | NBIC_INT_CLEAR | 32-bit | W | Interrupt clear |
| 0xFFFFFFF8 | NBIC_SLOT_ID | 32-bit | R | Slot number |
| 0xFFFFFFFC | NBIC_CONFIG | 32-bit | R/W | Configuration |
| **RAMDAC (stub)** |
| 0xFFFFF000 | RAMDAC_ADDR_WR | 8-bit | W | Write address |
| 0xFFFFF004 | RAMDAC_ADDR_RD | 8-bit | W | Read address |
| 0xFFFFF008 | RAMDAC_DATA | 8-bit | R/W | Palette data |
| 0xFFFFF00C | RAMDAC_CONTROL | 8-bit | R/W | Control |

**Note**: Some register addresses marked "TBD" - exact locations need to be verified from hardware documentation.

---

## Interrupt System

### Interrupt Sources

From **nd_nbic.c:142**:

```c
// Interrupt sources (NBIC_INT_STATUS bits)
#define NBIC_INT_VBL      (1<<0)   // Vertical blank (68Hz)
#define NBIC_INT_I860     (1<<1)   // i860 interrupt to host
#define NBIC_INT_DMA      (1<<2)   // DMA completion
#define NBIC_INT_ERROR    (1<<3)   // Bus error
```

### Interrupt Flow

```
Interrupt Sources:
  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
  │   VBL   │  │  i860   │  │   DMA   │  │  Error  │
  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
       │            │            │            │
       └────────────┴────────────┴────────────┘
                    │
              ┌─────▼──────┐
              │    NBIC    │  (interrupt status & mask)
              └─────┬──────┘
                    │
              ┌─────▼──────┐
              │  NeXTbus   │  (INT_ND to m68k)
              └─────┬──────┘
                    │
              ┌─────▼──────┐
              │ Host CPU   │  (m68040)
              └────────────┘
```

### Interrupt Handling Example

From **nd_nbic.c:178**:

```c
// VBL interrupt (triggered by nd_vbl_handler)
void nd_vbl_interrupt(void) {
    // Set VBL interrupt source
    nd_nbic_set_int_source(NBIC_INT_VBL);

    // If i860 VBL is enabled, notify i860
    if (CSR0 & CSR0_VBL_EN) {
        i860_send_msg(I860_MSG_VBL);
    }
}

// i860 interrupt (triggered by i860 firmware)
void nd_i860_interrupt_host(void) {
    // i860 wants to interrupt the host
    nd_nbic_set_int_source(NBIC_INT_I860);
}

// DMA completion interrupt
void nd_dma_complete_interrupt(void) {
    nd_nbic_set_int_source(NBIC_INT_DMA);
}

// Host acknowledges interrupt
void nd_interrupt_acknowledge(void) {
    // Read interrupt status to determine source
    uint32_t status = nbic_int_status;

    if (status & NBIC_INT_VBL) {
        // Handle VBL
        nd_nbic_clear_int_source(NBIC_INT_VBL);
    }

    if (status & NBIC_INT_I860) {
        // Handle i860 interrupt
        nd_nbic_clear_int_source(NBIC_INT_I860);
    }

    if (status & NBIC_INT_DMA) {
        // Handle DMA completion
        nd_nbic_clear_int_source(NBIC_INT_DMA);
    }
}
```

---

## Integration Examples

### Example 1: i860 Reset

From host software:

```c
// Reset the i860 processor
void reset_i860(void) {
    // Read CSR0
    uint32_t csr0 = nd_board_rd32(CSR0_ADDR);

    // Set reset bit
    csr0 |= CSR0_RESET;
    nd_board_wr32(CSR0_ADDR, csr0);

    // Wait for reset to complete
    usleep(1000);  // 1ms

    // Clear reset bit (i860 starts running)
    csr0 &= ~CSR0_RESET;
    nd_board_wr32(CSR0_ADDR, csr0);
}
```

### Example 2: DMA Transfer

From host software:

```c
// DMA transfer: host RAM → i860 VRAM
void dma_to_vram(uint32_t host_addr, uint32_t vram_addr, uint32_t size) {
    // Set DMA registers
    nd_board_wr32(DMA_SRC_ADDR_REG, host_addr);
    nd_board_wr32(DMA_DST_ADDR_REG, vram_addr);
    nd_board_wr32(DMA_COUNT_REG, size);

    // Start transfer (direction: host → i860)
    uint32_t ctrl = DMA_CTRL_START | DMA_CTRL_INT_EN;
    nd_board_wr32(DMA_CONTROL_REG, ctrl);

    // Wait for completion (interrupt or polling)
    while (nd_board_rd32(DMA_CONTROL_REG) & DMA_CTRL_BUSY) {
        usleep(10);
    }
}
```

### Example 3: VBL Interrupt Setup

From host software:

```c
// Enable VBL interrupts
void enable_vbl_interrupts(void) {
    // Enable VBL in CSR0
    uint32_t csr0 = nd_board_rd32(CSR0_ADDR);
    csr0 |= CSR0_VBL_EN | CSR0_INT_EN;
    nd_board_wr32(CSR0_ADDR, csr0);

    // Unmask VBL interrupt in NBIC
    uint32_t mask = nd_board_rd32(NBIC_INT_MASK);
    mask |= NBIC_INT_VBL;
    nd_board_wr32(NBIC_INT_MASK, mask);
}

// VBL interrupt handler
void vbl_interrupt_handler(void) {
    // Read interrupt status
    uint32_t status = nd_board_rd32(NBIC_INT_STATUS);

    if (status & NBIC_INT_VBL) {
        // Handle VBL (swap buffers, update display)
        swap_framebuffers();

        // Clear interrupt
        nd_board_wr32(NBIC_INT_STATUS, NBIC_INT_VBL);  // Write-1-to-clear
    }
}
```

---

## Summary

The NeXTdimension device layer provides essential hardware interfaces:

✅ **Memory Controller (CSR)**: Complete i860 control, DMA, interrupts
✅ **NBIC**: Complete board ID and interrupt routing
✅ **DMA Controller**: 1D/2D/fill transfers with interrupts
⚠️ **RAMDAC**: Stub (true-color rendering works without palette)
⚠️ **Video I/O**: Stub (not used by standard software)

**Key features**:
- 3 control/status registers (CSR0/CSR1/CSR2)
- 13-register DMA controller (1D, 2D, fill modes)
- NBIC interrupt routing (4 sources: VBL, i860, DMA, error)
- Board identification (ID 0xC, configurable slot)

**Integration points**:
- CSR0: i860 reset, cache control, interrupts, VBL
- DMA: Host ↔ i860 memory transfers
- NBIC: Interrupt delivery to host
- Mailbox: Command/response protocol (see mailbox doc)

**Related documentation**:
- [Main Architecture](dimension-emulator-architecture.md) - System overview
- [Memory System](dimension-memory-system.md) - MMIO banking
- [Mailbox Protocol](dimension-mailbox-protocol.md) - Host communication (pending)
- [Display System](dimension-display-system.md) - VBL timing (pending)

---

**Location**: `/Users/jvindahl/Development/previous/docs/emulation/dimension-devices.md`
**Created**: 2025-11-11
**Lines**: 900+
