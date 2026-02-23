# NeXTdimension Emulator Quick Reference

**Part of**: NeXTdimension Emulator Documentation
**Purpose**: Fast lookup for common tasks and memory addresses
**Audience**: Developers working with the emulator

---

## Memory Map (i860 Address Space)

| Address Range | Size | Type | Purpose |
|---------------|------|------|---------|
| **0x0F000000-0x0F00003F** | 64B | MMIO | Mailbox registers (16×32-bit) |
| **0xF8000000-0xF8FFFFFF** | 16MB | RAM | RAM Bank 0 |
| **0xF9000000-0xF9FFFFFF** | 16MB | RAM | RAM Bank 1 |
| **0xFA000000-0xFAFFFFFF** | 16MB | RAM | RAM Bank 2 |
| **0xFB000000-0xFBFFFFFF** | 16MB | RAM | RAM Bank 3 |
| **0xFE000000-0xFE3FFFFF** | 4MB | RAM | VRAM (frame buffer) |
| **0xFFF00000-0xFFF1FFFF** | 128KB | ROM | Boot firmware |
| **0xFFF20000-0xFFF201FF** | 512B | RAM | Dither memory |
| **0xFFFFFFE8-0xFFFFFFFF** | 24B | MMIO | NBIC registers |

**Total mapped**: ~84MB of 4GB address space

---

## Register Quick Reference

### Mailbox Registers (0x0F000000)

| Offset | Name | R/W | Description |
|--------|------|-----|-------------|
| 0x00 | STATUS | R/W | Status flags (READY, BUSY, ERROR) |
| 0x04 | COMMAND | R/W | Command number (0-17) |
| 0x08 | DATA_PTR | R/W | Data pointer (address) |
| 0x0C | DATA_LEN | R/W | Data length (bytes) |
| 0x10 | PARAM0 | R/W | Parameter 0 |
| 0x14 | PARAM1 | R/W | Parameter 1 |
| 0x18 | PARAM2 | R/W | Parameter 2 |
| 0x1C | PARAM3 | R/W | Parameter 3 |
| 0x20 | RESULT0 | R/W | Result 0 |
| 0x24 | RESULT1 | R/W | Result 1 |
| 0x28 | RESULT2 | R/W | Result 2 |
| 0x2C | RESULT3 | R/W | Result 3 |

### CSR Registers

| Register | Type | Key Bits |
|----------|------|----------|
| **CSR0** | R/W | RESET(0), INT_EN(1), CACHE_EN(2), VBL_EN(3), VBL(4), DMA_EN(5), DMA_BUSY(6), ERROR(7), INT_PENDING(8), I860_RUN(9) |
| **CSR1** | R/W | VIDEO_EN(0), BLANK(1), SYNC(2), INTERLACE(3), DMA_MODE(4-5), TEST_MODE(6) |
| **CSR2** | R | BOARD_ID(0-3)=0xC, REV(4-7), RAM_SIZE(8-9)=2, VRAM_SIZE(10-11)=2, ROM_VER(12-15), VIDEO_IN(16), VIDEO_LOCK(17) |

### NBIC Registers (0xFFFFFFE8)

| Address | Name | R/W | Description |
|---------|------|-----|-------------|
| 0xFFFFFFE8 | NBIC_ID | R | Board ID (0xC0000001) |
| 0xFFFFFFEC | INT_STATUS | R/W1C | Interrupt status (VBL, i860, DMA, ERROR) |
| 0xFFFFFFF0 | INT_MASK | R/W | Interrupt mask |
| 0xFFFFFFF4 | INT_CLEAR | W | Interrupt clear |
| 0xFFFFFFF8 | SLOT_ID | R | Slot number |
| 0xFFFFFFFC | CONFIG | R/W | Configuration |

---

## Mailbox Command Reference

| Cmd | Name | Params | Results | Description |
|-----|------|--------|---------|-------------|
| 0x00 | NOP | - | - | No operation |
| 0x01 | LOAD_KERNEL | PTR, LEN, entry | - | Load i860 firmware |
| 0x02 | INIT_VIDEO | width, height | - | Initialize video |
| 0x03 | SET_MODE | mode | - | Set video mode |
| 0x04 | ALLOC_MEM | size | addr | Allocate memory |
| 0x05 | FREE_MEM | addr | - | Free memory |
| 0x06 | READ_MEM | addr, len | PTR | Read to host |
| 0x07 | WRITE_MEM | addr, PTR, LEN | - | Write from host |
| 0x08 | FILL_MEM | addr, len, val | - | Fill with value |
| 0x09 | COPY_MEM | src, dst, len | - | Copy within i860 |
| 0x0A | SYNC | - | - | Synchronize |
| 0x0B | GET_STATUS | - | status | Get i860 status |
| 0x0C | SET_PARAM | id, value | - | Set parameter |
| 0x0D | GET_PARAM | id | value | Get parameter |
| 0x0E | EXEC_CODE | addr | - | Execute code |
| 0x0F | INT_HOST | reason | - | Interrupt host |
| 0x10 | CLEAR_SCREEN | color | - | Clear screen |
| 0x11 | DRAW_RECT | x,y,w,h | - | Draw rectangle |

**Status Flags**:
- `STATUS_READY` = 0x00000001
- `STATUS_BUSY` = 0x00000002
- `STATUS_ERROR` = 0x00000004
- `STATUS_COMMAND_READY` = 0x00000008
- `STATUS_RESULT_READY` = 0x00000010

---

## i860 CPU Reference

### Register Set

**Integer Registers** (32 × 32-bit):
- `r0` = 0 (hardwired zero)
- `r1` = sp (stack pointer, by convention)
- `r2-r27` = general purpose
- `r28` = fp (frame pointer, by convention)
- `r29-r31` = temporaries

**Floating-Point Registers** (32 × 32-bit):
- `f0-f31` = single precision (32-bit)
- `f0:f1, f2:f3, ..., f30:f31` = double precision (64-bit pairs)

**Control Registers**:
- `PC` = Program counter
- `PSR` = Processor Status Register
- `DIRBASE` = Page directory base
- `FSR` = FP status register

### PSR Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | BR | Big-endian (1=big, 0=little) |
| 1 | BLA | Bus lock asserted |
| 2 | CC | Condition code |
| 3 | LCC | Loop condition code |
| 4 | IM | Interrupt mask |
| 5 | PIM | Previous interrupt mask |
| 6 | U | User mode (0=supervisor, 1=user) |
| 7 | PU | Previous user mode |
| 8 | IT | Instruction trap enable |
| 9 | IN | Interrupt pending |
| 10 | IAT | Instruction address trap |
| 11 | DAT | Data address trap |
| 12 | FTE | Floating trap enable |
| 13 | DS | Delayed switch |
| 14 | DIM | Dual Instruction Mode |
| 15 | KNF | Kill next FP instruction |

### Instruction Timing

| Instruction Type | Cycles | Pipeline | Notes |
|------------------|--------|----------|-------|
| Integer ALU | 1 | - | add, sub, and, or, xor, shifts |
| Integer mul | 3 | - | Unpipelined |
| Load | 3 | L | Pipelined (S, R, L stages) |
| Store | 1 | - | Write buffer |
| Branch | 1 | - | + pipeline flush |
| FP add | 3 | A | Pipelined (S, R, A stages) |
| FP mul | 3 | M | Pipelined (S, R, M stages) |
| FP div (single) | 16 | - | Unpipelined |
| FP div (double) | 20 | - | Unpipelined |
| Graphics (pixel) | 3 | G | pfadd, pfsub, pfmul |

---

## Display Reference

### Display Specifications

- **Resolution**: 1120×832 pixels
- **Pixel format**: ARGB8888 (32-bit per pixel)
- **Frame buffer size**: 3,727,360 bytes (~3.55MB)
- **VRAM total**: 4MB (450KB for offscreen buffers)
- **VBL frequency**: 68Hz (14.706ms period)
- **VBL bit toggle**: 136Hz (2× VBL frequency)
- **Rendering rate**: ~60 FPS (independent of VBL)

### Pixel Access

```c
// Calculate pixel address
uint32_t offset = (y * 1120 + x) * 4;
uint32_t* pixel = (uint32_t*)(ND_vram + offset);

// Set pixel (red)
*pixel = 0xFF0000FF;  // ARGB: Alpha=FF, R=00, G=00, B=FF

// Get pixel components
uint32_t color = *pixel;
uint8_t alpha = (color >> 24) & 0xFF;
uint8_t red   = (color >> 16) & 0xFF;
uint8_t green = (color >> 8) & 0xFF;
uint8_t blue  = color & 0xFF;
```

### VBL Synchronization

```c
// Wait for VBL (polling)
uint32_t last_vbl = CSR0 & CSR0_VBL;
while ((CSR0 & CSR0_VBL) == last_vbl) {
    // Wait for VBL bit toggle
}
// VBL occurred

// Enable VBL interrupts
CSR0 |= CSR0_VBL_EN | CSR0_INT_EN;
```

---

## Common Code Patterns

### Host → i860: Send Mailbox Command

```c
// Wait for mailbox ready
while (nd_mailbox_read(MBX_STATUS) & STATUS_BUSY) {
    usleep(10);
}

// Write parameters
nd_mailbox_write(MBX_PARAM0, param0);
nd_mailbox_write(MBX_PARAM1, param1);

// Write command
nd_mailbox_write(MBX_COMMAND, cmd);

// Notify i860
nd_mailbox_write(MBX_STATUS, STATUS_COMMAND_READY);

// Wait for completion
while (!(nd_mailbox_read(MBX_STATUS) & STATUS_READY)) {
    usleep(10);
}

// Check error
if (nd_mailbox_read(MBX_STATUS) & STATUS_ERROR) {
    fprintf(stderr, "Error: %u\n", nd_mailbox_read(MBX_RESULT0));
}
```

### i860: Poll Mailbox

```c
// Check for command
uint32_t status = *(volatile uint32_t*)(0x0F000000 + MBX_STATUS);
if (status & STATUS_COMMAND_READY) {
    // Set busy
    *(volatile uint32_t*)(0x0F000000 + MBX_STATUS) = STATUS_BUSY;

    // Read command
    uint32_t cmd = *(volatile uint32_t*)(0x0F000000 + MBX_COMMAND);

    // Execute command
    handle_command(cmd);

    // Set ready
    *(volatile uint32_t*)(0x0F000000 + MBX_STATUS) = STATUS_READY;
}
```

### i860: Memory Access (Big-Endian)

```c
// Read 32-bit word (big-endian)
uint32_t read32(uint32_t addr) {
    uint8_t b0 = *(volatile uint8_t*)(addr + 0);
    uint8_t b1 = *(volatile uint8_t*)(addr + 1);
    uint8_t b2 = *(volatile uint8_t*)(addr + 2);
    uint8_t b3 = *(volatile uint8_t*)(addr + 3);
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

// Write 32-bit word (big-endian)
void write32(uint32_t addr, uint32_t val) {
    *(volatile uint8_t*)(addr + 0) = (val >> 24) & 0xFF;
    *(volatile uint8_t*)(addr + 1) = (val >> 16) & 0xFF;
    *(volatile uint8_t*)(addr + 2) = (val >> 8) & 0xFF;
    *(volatile uint8_t*)(addr + 3) = val & 0xFF;
}
```

### DMA Transfer (1D)

```c
// Setup DMA registers
nd_board_wr32(DMA_SRC_ADDR_REG, src_addr);
nd_board_wr32(DMA_DST_ADDR_REG, dst_addr);
nd_board_wr32(DMA_COUNT_REG, byte_count);

// Start transfer
uint32_t ctrl = DMA_CTRL_START | DMA_CTRL_INT_EN;
nd_board_wr32(DMA_CONTROL_REG, ctrl);

// Wait for completion
while (nd_board_rd32(DMA_CONTROL_REG) & DMA_CTRL_BUSY) {
    usleep(10);
}
```

### Reset i860

```c
// Assert reset
uint32_t csr0 = nd_board_rd32(CSR0_ADDR);
csr0 |= CSR0_RESET;
nd_board_wr32(CSR0_ADDR, csr0);

// Wait 1ms
usleep(1000);

// Release reset
csr0 &= ~CSR0_RESET;
nd_board_wr32(CSR0_ADDR, csr0);
```

---

## File Reference

### Core Files

| File | Lines | Purpose |
|------|-------|---------|
| **dimension.c** | 270 | Main integration, initialization |
| **dimension.h** | 72 | Declarations, endianness functions |
| **i860.cpp** | 641 | i860 CPU core, threading |
| **i860dec.cpp** | 3,981 | ISA decoder (largest file) |
| **i860dbg.cpp** | 551 | Interactive debugger |
| **nd_mem.c** | 693 | Memory banking system |
| **nd_mailbox.c** | 435 | Mailbox protocol (NEW) |
| **nd_devs.c** | 655 | Memory controller (CSR) |
| **nd_nbic.c** | 240 | NBIC interface |
| **nd_sdl.c** | 129 | SDL display, VBL |

**Total**: 24 files, 9,339 lines

### Build Flags

From **i860cfg.h**:

```c
// Production mode (fast, no debug)
#define CONF_I860_SPEED

// Development mode (debug, trace)
#define CONF_I860_DEV

// Single-threaded mode (easier debugging)
#define CONF_I860_NO_THREAD
```

---

## Debugging Reference

### Debugger Commands

```
s              - Step one instruction
s <n>          - Step n instructions
c              - Continue execution
b <addr>       - Set breakpoint
d <addr>       - Delete breakpoint
l              - List breakpoints
r              - Show registers
m <addr> [n]   - Show memory
d <addr>       - Disassemble
q              - Quit debugger
h              - Help
```

### Trace Flags

```c
TRACE_INSN      = (1<<0)  // Instruction execution
TRACE_REGS      = (1<<1)  // Register changes
TRACE_MEM       = (1<<2)  // Memory access
TRACE_BRANCH    = (1<<3)  // Control flow
TRACE_PIPELINE  = (1<<4)  // Pipeline state
TRACE_FP        = (1<<5)  // FP operations
TRACE_CACHE     = (1<<6)  // Cache hits/misses
TRACE_TLB       = (1<<7)  // TLB lookups
TRACE_INT       = (1<<8)  // Interrupts
```

---

## Error Codes

### Mailbox Errors

| Code | Name | Description |
|------|------|-------------|
| 0 | ERROR_NONE | Success |
| 1 | ERROR_INVALID_CMD | Invalid command number |
| 2 | ERROR_INVALID_PARAM | Invalid parameter value |
| 3 | ERROR_MEM_ERROR | Memory access error |
| 4 | ERROR_TIMEOUT | Operation timeout |
| 5 | ERROR_BUSY | Mailbox busy |

---

## Constants

### Important Addresses

```c
#define ND_RAM_BASE     0xF8000000  // RAM start
#define ND_RAM_SIZE     (64*1024*1024)  // 64MB
#define ND_VRAM_BASE    0xFE000000  // VRAM start
#define ND_VRAM_SIZE    (4*1024*1024)  // 4MB
#define ND_ROM_BASE     0xFFF00000  // ROM start
#define ND_ROM_SIZE     (128*1024)  // 128KB
#define ND_MAILBOX_BASE 0x0F000000  // Mailbox
#define ND_NBIC_BASE    0xFFFFFFE8  // NBIC
```

### Display Constants

```c
#define DISPLAY_WIDTH   1120
#define DISPLAY_HEIGHT  832
#define BYTES_PER_PIXEL 4
#define VBL_FREQUENCY   68  // Hz
#define VBL_PERIOD_US   14706  // Microseconds
```

### Board Identification

```c
#define ND_BOARD_ID     0xC  // NeXTdimension = 0xC
#define ND_SLOT         2    // Typical slot number
#define NBIC_ID_VALUE   0xC0000001  // Board ID register
```

---

## Performance Reference

### Typical Performance

- **IPC (Instructions Per Cycle)**: 1.2-1.5 (typical code)
- **Best case IPC**: 2.0 (DIM mode, no hazards)
- **Worst case IPC**: 0.5 (pipeline stalls)
- **MIPS @ 40MHz**: 48-60 MIPS (typical)
- **Cache hit rate**: >90% (typical)
- **TLB hit rate**: >95% (typical)

---

## Status Overview

| Component | Status | Notes |
|-----------|--------|-------|
| i860 CPU | ✅ Complete | Full ISA, pipelines, cache, TLB |
| Memory System | ✅ Complete | 4GB address space, 84MB mapped |
| Mailbox Protocol | ✅ Complete | 18 commands, simulation mode |
| Display | ✅ Complete | SDL, 1120×832, VBL @ 68Hz |
| CSR Registers | ✅ Complete | i860 control, DMA, interrupts |
| NBIC | ✅ Complete | Board ID, interrupt routing |
| DMA | ✅ Complete | 1D/2D/fill transfers |
| RAMDAC | ⚠️ Stub | Not needed for true-color |
| Video I/O | ⚠️ Stub | Not used by standard software |

**Overall**: ~85% complete (functional, some device stubs)

---

## Related Documentation

- [Main Architecture](dimension-emulator-architecture.md) - Complete system overview
- [i860 CPU](dimension-i860-cpu.md) - CPU implementation details
- [Memory System](dimension-memory-system.md) - Banking and addressing
- [Devices](dimension-devices.md) - MMIO devices and registers
- [Mailbox Protocol](dimension-mailbox-protocol.md) - Host↔i860 communication
- [Display System](dimension-display-system.md) - SDL and VBL timing

---

**Location**: `/Users/jvindahl/Development/previous/docs/emulation/dimension-quick-reference.md`
**Created**: 2025-11-11
**Purpose**: Fast lookup for daily development
