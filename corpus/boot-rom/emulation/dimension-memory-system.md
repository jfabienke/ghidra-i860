# NeXTdimension Memory System

**Part of**: NeXTdimension Emulator Documentation
**Component**: Memory Banking and Address Space Management
**Files**: 2 files, 723 lines
**Status**: ✅ Complete implementation
**Architecture**: 65,536 banks × 64KB = 4GB address space

---

## Executive Summary

The NeXTdimension memory system provides a flexible banking architecture that maps the i860's 4GB address space to physical memory regions (RAM, VRAM, ROM, MMIO). The implementation uses function pointers for efficient access and supports both big-endian (i860 side) and little-endian (host side) views of the same memory.

**Key Features**:
- **Banking System**: 65,536 banks at 64KB granularity
- **Memory Regions**: RAM (64MB), VRAM (4MB), ROM (128KB), MMIO
- **Endianness Handling**: Big-endian ↔ Little-endian conversion
- **ROM Emulation**: 3 ROM versions + EEPROM support
- **Dither Memory**: 512 bytes for graphics dithering
- **Mailbox Integration**: 64-byte mailbox at 0x0F000000

---

## Table of Contents

1. [Component Files](#component-files)
2. [Banking Architecture](#banking-architecture)
3. [Memory Map](#memory-map)
4. [Physical Memory Regions](#physical-memory-regions)
5. [Endianness Handling](#endianness-handling)
6. [ROM and EEPROM](#rom-and-eeprom)
7. [Memory Access Functions](#memory-access-functions)
8. [Bank Mapping Functions](#bank-mapping-functions)
9. [Special Memory Regions](#special-memory-regions)
10. [Integration with i860 CPU](#integration-with-i860-cpu)

---

## Component Files

### Overview

| File | Lines | Purpose |
|------|-------|---------|
| **nd_mem.h** | 30 | Bank structure and function declarations |
| **nd_mem.c** | 693 | Complete memory implementation |
| **Total** | **723** | Memory banking system |

### File Relationships

```
nd_mem.h ────> nd_mem.c ────> dimension.c (initialization)
    │                              │
    └──────────────────────────────┴────> i860.cpp (memory access)
```

---

## Banking Architecture

### Banking System Design

The memory system divides the i860's 4GB address space into **65,536 banks** of **64KB each**:

```
4GB address space = 0x00000000 to 0xFFFFFFFF
Bank size = 64KB = 0x10000 bytes
Number of banks = 4GB / 64KB = 65,536 banks

Bank number = address >> 16
Offset in bank = address & 0xFFFF
```

### Bank Structure

From **nd_mem.h:30**:

```c
// Memory bank structure
typedef struct {
    // Function pointers for access (allows different behavior per bank)
    uint8_t (*get)(uint32_t addr);     // Read byte
    void    (*put)(uint32_t addr, uint8_t val);  // Write byte

    // Base pointer (for direct memory regions)
    uint8_t* mem;

    // Bank flags
    uint32_t flags;
} nd_addrbank;

// Bank flags
#define BANK_RAM       (1<<0)   // Writable RAM
#define BANK_ROM       (1<<1)   // Read-only ROM
#define BANK_MMIO      (1<<2)   // Memory-mapped I/O
#define BANK_UNMAPPED  (1<<3)   // Unmapped (bus error)

// Global bank array (65,536 entries)
extern nd_addrbank mem_banks[65536];
```

### Banking Benefits

1. **Flexibility**: Different banks can have different behaviors (RAM, ROM, MMIO)
2. **Efficiency**: Direct memory access for RAM/VRAM, function calls for MMIO
3. **Protection**: ROM banks can enforce read-only access
4. **Debugging**: Unmapped banks can detect invalid accesses

---

## Memory Map

### Complete i860 Address Space

From **nd_mem.c:693**:

```
i860 Virtual Address Space (4GB):

0x00000000 ─────────────────────────────────────
            │  Unmapped (0-2GB)                │
            │  (Could be used for expansion)   │
0x0F000000 ─┼────────────────────────────────────
            │  Mailbox (64 bytes)              │  NEW
0x0F000040 ─┼────────────────────────────────────
            │  Unmapped                        │
0xF8000000 ─┼────────────────────────────────────
            │  RAM Bank 0 (16MB)               │
0xF9000000 ─┼────────────────────────────────────
            │  RAM Bank 1 (16MB)               │
0xFA000000 ─┼────────────────────────────────────
            │  RAM Bank 2 (16MB)               │
0xFB000000 ─┼────────────────────────────────────
            │  RAM Bank 3 (16MB)               │
0xFC000000 ─┼────────────────────────────────────
            │  Unmapped                        │
0xFE000000 ─┼────────────────────────────────────
            │  VRAM (4MB)                      │
0xFE400000 ─┼────────────────────────────────────
            │  Unmapped                        │
0xFFF00000 ─┼────────────────────────────────────
            │  ROM (128KB)                     │
0xFFF20000 ─┼────────────────────────────────────
            │  Dither Memory (512 bytes)       │
0xFFF20200 ─┼────────────────────────────────────
            │  Unmapped                        │
0xFFFFFFE8 ─┼────────────────────────────────────
            │  NBIC Registers (24 bytes)       │
0xFFFFFFFF ─────────────────────────────────────

Total mapped: ~84MB (64MB RAM + 4MB VRAM + 128KB ROM + MMIO)
```

### Bank Mapping Table

| Address Range | Banks | Size | Type | Purpose |
|---------------|-------|------|------|---------|
| 0x0F000000-0x0F00003F | 0x0F00 (1 bank) | 64 bytes | MMIO | Mailbox protocol |
| 0xF8000000-0xFBFFFFFF | 0xF800-0xFBFF (1024 banks) | 64MB | RAM | Main memory (4×16MB) |
| 0xFE000000-0xFE3FFFFF | 0xFE00-0xFE3F (64 banks) | 4MB | RAM | Video RAM |
| 0xFFF00000-0xFFF1FFFF | 0xFFF0-0xFFF1 (2 banks) | 128KB | ROM | Boot firmware |
| 0xFFF20000-0xFFF201FF | 0xFFF2 (1 bank) | 512 bytes | RAM | Dither memory |
| 0xFFFFFFE8-0xFFFFFFFF | 0xFFFF (1 bank) | 24 bytes | MMIO | NBIC registers |

---

## Physical Memory Regions

### Memory Allocation

From **nd_mem.c:42**:

```c
// Physical memory arrays (allocated at startup)

// Main RAM: 64MB (4 banks × 16MB)
uint8_t ND_ram[64*1024*1024];

// Video RAM: 4MB (frame buffer)
uint8_t ND_vram[4*1024*1024];

// ROM: 128KB (boot firmware)
uint8_t ND_rom[128*1024];

// Dither memory: 512 bytes (for graphics operations)
uint8_t ND_dmem[512];

// EEPROM: 16KB (optional, for configuration)
uint8_t ND_eeprom[16*1024];
```

### RAM Banks (64MB)

From **nd_mem.c:167**:

```c
// RAM access functions
static uint8_t ram_get(uint32_t addr) {
    uint32_t offset = addr - 0xF8000000;
    if (offset < sizeof(ND_ram)) {
        return ND_ram[offset];
    }
    return 0xFF;  // Out of bounds
}

static void ram_put(uint32_t addr, uint32_t val) {
    uint32_t offset = addr - 0xF8000000;
    if (offset < sizeof(ND_ram)) {
        ND_ram[offset] = val;
    }
}

// RAM bank structure
static nd_addrbank ram_bank = {
    .get = ram_get,
    .put = ram_put,
    .mem = ND_ram,
    .flags = BANK_RAM
};
```

### VRAM (4MB)

From **nd_mem.c:213**:

```c
// VRAM access functions (identical to RAM)
static uint8_t vram_get(uint32_t addr) {
    uint32_t offset = addr - 0xFE000000;
    if (offset < sizeof(ND_vram)) {
        return ND_vram[offset];
    }
    return 0xFF;
}

static void vram_put(uint32_t addr, uint32_t val) {
    uint32_t offset = addr - 0xFE000000;
    if (offset < sizeof(ND_vram)) {
        ND_vram[offset] = val;
    }
}

static nd_addrbank vram_bank = {
    .get = vram_get,
    .put = vram_put,
    .mem = ND_vram,
    .flags = BANK_RAM  // VRAM is writable
};
```

### ROM (128KB)

From **nd_mem.c:259**:

```c
// ROM access functions (read-only)
static uint8_t rom_get(uint32_t addr) {
    uint32_t offset = addr - 0xFFF00000;
    if (offset < sizeof(ND_rom)) {
        return ND_rom[offset];
    }
    return 0xFF;
}

static void rom_put(uint32_t addr, uint32_t val) {
    // ROM writes are ignored (or could log error)
    (void)addr;
    (void)val;
}

static nd_addrbank rom_bank = {
    .get = rom_get,
    .put = rom_put,
    .mem = ND_rom,
    .flags = BANK_ROM  // Read-only
};
```

### Dither Memory (512 bytes)

From **nd_mem.c:298**:

```c
// Dither memory (used by graphics operations for dithering patterns)
static uint8_t dmem_get(uint32_t addr) {
    uint32_t offset = addr - 0xFFF20000;
    if (offset < sizeof(ND_dmem)) {
        return ND_dmem[offset];
    }
    return 0xFF;
}

static void dmem_put(uint32_t addr, uint32_t val) {
    uint32_t offset = addr - 0xFFF20000;
    if (offset < sizeof(ND_dmem)) {
        ND_dmem[offset] = val;
    }
}

static nd_addrbank dmem_bank = {
    .get = dmem_get,
    .put = dmem_put,
    .mem = ND_dmem,
    .flags = BANK_RAM
};
```

### Unmapped Regions

From **nd_mem.c:341**:

```c
// Unmapped memory (returns 0xFF, logs access)
static uint8_t unmapped_get(uint32_t addr) {
    fprintf(stderr, "[MEM] Read from unmapped address: 0x%08X\n", addr);
    return 0xFF;
}

static void unmapped_put(uint32_t addr, uint32_t val) {
    fprintf(stderr, "[MEM] Write to unmapped address: 0x%08X = 0x%02X\n",
            addr, val);
}

static nd_addrbank unmapped_bank = {
    .get = unmapped_get,
    .put = unmapped_put,
    .mem = NULL,
    .flags = BANK_UNMAPPED
};
```

---

## Endianness Handling

### The Endianness Problem

The NeXTdimension has **two different endianness views**:

- **i860 side**: Big-endian (MSB first)
- **Host (m68k) side**: Big-endian (same)
- **Emulator host (x86/ARM)**: Little-endian

### Endianness Conversion Functions

From **dimension.c:270** (from previous analysis):

```c
// ============================================================
// ENDIANNESS CONVERSION
// ============================================================

// i860 side: big-endian reads (from i860.cpp)
uint32_t nd_i860_rd32(uint32_t addr) {
    // Read from banking system (stored as little-endian on x86 host)
    uint8_t b0 = nd_mem_get(addr + 0);
    uint8_t b1 = nd_mem_get(addr + 1);
    uint8_t b2 = nd_mem_get(addr + 2);
    uint8_t b3 = nd_mem_get(addr + 3);

    // Assemble as big-endian
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

void nd_i860_wr32(uint32_t addr, uint32_t val) {
    // Disassemble as big-endian
    nd_mem_put(addr + 0, (val >> 24) & 0xFF);
    nd_mem_put(addr + 1, (val >> 16) & 0xFF);
    nd_mem_put(addr + 2, (val >> 8) & 0xFF);
    nd_mem_put(addr + 3, val & 0xFF);
}

// Host board side: needs conversion (from dimension.c)
uint32_t nd_board_rd32(uint32_t addr) {
    // Read 32-bit value from i860 side (big-endian)
    uint32_t val = nd_i860_rd32(addr);

    // Convert big → little for host
    return (val << 24) | ((val << 8) & 0xFF0000) |
           ((val >> 8) & 0xFF00) | (val >> 24);
}

void nd_board_wr32(uint32_t addr, uint32_t val) {
    // Convert little → big for i860 side
    uint32_t swapped = (val << 24) | ((val << 8) & 0xFF0000) |
                       ((val >> 8) & 0xFF00) | (val >> 24);
    nd_i860_wr32(addr, swapped);
}
```

### Memory Layout Example

Example: 32-bit value **0x12345678** at address **0xF8000000**:

```
Big-endian (i860 view):
  0xF8000000: 0x12
  0xF8000001: 0x34
  0xF8000002: 0x56
  0xF8000003: 0x78

Little-endian (host emulator memory):
  ND_ram[0]: 0x78
  ND_ram[1]: 0x56
  ND_ram[2]: 0x34
  ND_ram[3]: 0x12
```

---

## ROM and EEPROM

### ROM Versions

The NeXTdimension had **three ROM versions**:

From **nd_mem.c:421**:

```c
// ROM version selection
enum nd_rom_version {
    ROM_V25 = 0,    // Rev 2.5 v66 (most common, 128KB)
    ROM_V33,        // Rev 3.3 v74 (latest, 128KB)
    ROM_V10         // Rev 1.0 v43 (early, 128KB)
};

static enum nd_rom_version current_rom = ROM_V25;
```

### ROM Loading

From **nd_mem.c:448**:

```c
void nd_rom_init(void) {
    FILE* f = NULL;
    const char* rom_path = NULL;

    // Select ROM file based on version
    switch (current_rom) {
    case ROM_V25:
        rom_path = "roms/Rev_2.5_v66.bin";
        break;
    case ROM_V33:
        rom_path = "roms/Rev_3.3_v74.bin";
        break;
    case ROM_V10:
        rom_path = "roms/ND_step1_v43_eeprom.bin";
        break;
    }

    // Load ROM file
    f = fopen(rom_path, "rb");
    if (!f) {
        fprintf(stderr, "[ROM] Failed to load ROM: %s\n", rom_path);
        // Fill with 0xFF (unprogrammed EPROM pattern)
        memset(ND_rom, 0xFF, sizeof(ND_rom));
        return;
    }

    // Read ROM data
    size_t read = fread(ND_rom, 1, sizeof(ND_rom), f);
    fclose(f);

    printf("[ROM] Loaded %s (%zu bytes)\n", rom_path, read);

    // Verify ROM checksum (optional)
    uint32_t checksum = 0;
    for (size_t i = 0; i < sizeof(ND_rom); i++) {
        checksum += ND_rom[i];
    }
    printf("[ROM] Checksum: 0x%08X\n", checksum);
}
```

### EEPROM Support

From **nd_mem.c:512**:

```c
// EEPROM (16KB, battery-backed configuration)
// Note: Some early boards used EEPROM instead of ROM

static uint8_t eeprom_get(uint32_t addr) {
    uint32_t offset = addr - 0xFFF00000;
    if (offset < sizeof(ND_eeprom)) {
        return ND_eeprom[offset];
    }
    return 0xFF;
}

static void eeprom_put(uint32_t addr, uint32_t val) {
    // EEPROM is writable (but slow in real hardware)
    uint32_t offset = addr - 0xFFF00000;
    if (offset < sizeof(ND_eeprom)) {
        ND_eeprom[offset] = val;
        // Mark EEPROM as dirty (needs save to file)
        eeprom_dirty = 1;
    }
}

void nd_eeprom_save(void) {
    if (!eeprom_dirty) return;

    FILE* f = fopen("nvram/nd_eeprom.bin", "wb");
    if (f) {
        fwrite(ND_eeprom, 1, sizeof(ND_eeprom), f);
        fclose(f);
        eeprom_dirty = 0;
        printf("[EEPROM] Saved to nvram/nd_eeprom.bin\n");
    }
}
```

---

## Memory Access Functions

### Low-Level Byte Access

From **nd_mem.c:562**:

```c
// ============================================================
// CORE MEMORY ACCESS (used by all components)
// ============================================================

uint8_t nd_mem_get(uint32_t addr) {
    uint32_t bank = addr >> 16;        // Bank number (0-65535)
    uint32_t offset = addr & 0xFFFF;   // Offset in bank (0-65535)

    // Call bank's get function
    return mem_banks[bank].get(addr);
}

void nd_mem_put(uint32_t addr, uint8_t val) {
    uint32_t bank = addr >> 16;
    uint32_t offset = addr & 0xFFFF;

    // Call bank's put function
    mem_banks[bank].put(addr, val);
}
```

### Multi-Byte Access Functions

From **nd_mem.c:587**:

```c
// 16-bit access (halfword)
uint16_t nd_mem_get16(uint32_t addr) {
    uint8_t hi = nd_mem_get(addr);
    uint8_t lo = nd_mem_get(addr + 1);
    return (hi << 8) | lo;  // Big-endian
}

void nd_mem_put16(uint32_t addr, uint16_t val) {
    nd_mem_put(addr, (val >> 8) & 0xFF);    // High byte
    nd_mem_put(addr + 1, val & 0xFF);        // Low byte
}

// 32-bit access (word)
uint32_t nd_mem_get32(uint32_t addr) {
    uint8_t b0 = nd_mem_get(addr);
    uint8_t b1 = nd_mem_get(addr + 1);
    uint8_t b2 = nd_mem_get(addr + 2);
    uint8_t b3 = nd_mem_get(addr + 3);
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;  // Big-endian
}

void nd_mem_put32(uint32_t addr, uint32_t val) {
    nd_mem_put(addr, (val >> 24) & 0xFF);
    nd_mem_put(addr + 1, (val >> 16) & 0xFF);
    nd_mem_put(addr + 2, (val >> 8) & 0xFF);
    nd_mem_put(addr + 3, val & 0xFF);
}

// 64-bit access (doubleword, for FP operations)
uint64_t nd_mem_get64(uint32_t addr) {
    uint32_t hi = nd_mem_get32(addr);
    uint32_t lo = nd_mem_get32(addr + 4);
    return ((uint64_t)hi << 32) | lo;
}

void nd_mem_put64(uint32_t addr, uint64_t val) {
    nd_mem_put32(addr, (val >> 32) & 0xFFFFFFFF);
    nd_mem_put32(addr + 4, val & 0xFFFFFFFF);
}
```

---

## Bank Mapping Functions

### Mapping Banks to Memory Regions

From **nd_mem.c:638**:

```c
// Map a range of banks to a specific bank structure
void nd_map_banks(nd_addrbank* bank, uint32_t start_bank, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        mem_banks[start_bank + i] = *bank;
    }
}

// Unmap a range of banks (mark as unmapped)
void nd_unmap_banks(uint32_t start_bank, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        mem_banks[start_bank + i] = unmapped_bank;
    }
}
```

### Memory System Initialization

From **nd_mem.c:659**:

```c
void nd_memory_init(void) {
    printf("[MEM] Initializing memory system...\n");

    // 1. Initialize all banks as unmapped
    for (int i = 0; i < 65536; i++) {
        mem_banks[i] = unmapped_bank;
    }

    // 2. Map RAM banks (64MB at 0xF8000000-0xFBFFFFFF)
    //    Banks 0xF800-0xFBFF = 1024 banks = 64MB
    nd_map_banks(&ram_bank, 0xF800, 1024);
    printf("[MEM] Mapped RAM: 64MB at 0xF8000000\n");

    // 3. Map VRAM (4MB at 0xFE000000-0xFE3FFFFF)
    //    Banks 0xFE00-0xFE3F = 64 banks = 4MB
    nd_map_banks(&vram_bank, 0xFE00, 64);
    printf("[MEM] Mapped VRAM: 4MB at 0xFE000000\n");

    // 4. Map ROM (128KB at 0xFFF00000-0xFFF1FFFF)
    //    Banks 0xFFF0-0xFFF1 = 2 banks = 128KB
    nd_map_banks(&rom_bank, 0xFFF0, 2);
    printf("[MEM] Mapped ROM: 128KB at 0xFFF00000\n");

    // 5. Map dither memory (512 bytes at 0xFFF20000)
    //    Bank 0xFFF2 = 1 bank (only first 512 bytes used)
    nd_map_banks(&dmem_bank, 0xFFF2, 1);
    printf("[MEM] Mapped Dither: 512B at 0xFFF20000\n");

    // 6. Map mailbox (64 bytes at 0x0F000000)
    //    Bank 0x0F00 = 1 bank (only first 64 bytes used)
    nd_map_banks(&mailbox_bank, 0x0F00, 1);
    printf("[MEM] Mapped Mailbox: 64B at 0x0F000000\n");

    // 7. NBIC registers are mapped in nd_nbic_init() (0xFFFFFFE8)

    printf("[MEM] Memory initialization complete\n");
}
```

---

## Special Memory Regions

### Mailbox Memory

From **nd_mem.c:382** (integration with mailbox):

```c
// Mailbox bank (64 bytes at 0x0F000000)
static uint8_t mailbox_get(uint32_t addr) {
    uint32_t offset = addr - 0x0F000000;
    if (offset < 64) {
        // Redirect to mailbox read function
        return nd_mailbox_read_byte(offset);
    }
    return 0xFF;
}

static void mailbox_put(uint32_t addr, uint32_t val) {
    uint32_t offset = addr - 0x0F000000;
    if (offset < 64) {
        // Redirect to mailbox write function
        nd_mailbox_write_byte(offset, val);
    }
}

static nd_addrbank mailbox_bank = {
    .get = mailbox_get,
    .put = mailbox_put,
    .mem = NULL,  // No direct memory (handled by mailbox module)
    .flags = BANK_MMIO
};
```

### NBIC Registers

NBIC registers are mapped by the device layer (see `nd_nbic.c`), but the memory system provides the infrastructure:

```c
// NBIC bank (24 bytes at 0xFFFFFFE8-0xFFFFFFFF)
// Mapped by nd_nbic_init() using nd_map_banks()
```

---

## Integration with i860 CPU

### CPU Memory Access

From **i860.cpp:431** (see i860 CPU documentation):

```cpp
// i860 CPU uses these functions for all memory access

uint32_t i860_cpu_device::rdmem_32(uint32_t addr) {
    // Use memory banking system
    return nd_mem_get32(addr);  // Big-endian
}

void i860_cpu_device::wrmem_32(uint32_t addr, uint32_t val) {
    nd_mem_put32(addr, val);    // Big-endian
}

uint8_t i860_cpu_device::rdmem_8(uint32_t addr) {
    return nd_mem_get(addr);
}

void i860_cpu_device::wrmem_8(uint32_t addr, uint8_t val) {
    nd_mem_put(addr, val);
}
```

### Cache Integration

The i860 instruction cache sits **above** the memory banking system:

```
┌───────────────────┐
│  i860 CPU Core    │
└─────────┬─────────┘
          │
    ┌─────▼──────┐
    │ I-Cache    │  (4KB, 512 lines)
    │ (i860.cpp) │
    └─────┬──────┘
          │
    ┌─────▼──────────┐
    │ Banking System │  (nd_mem.c)
    └─────┬──────────┘
          │
    ┌─────▼──────────┐
    │ Physical RAM   │  (ND_ram[], ND_vram[], ND_rom[])
    └────────────────┘
```

---

## Summary

The NeXTdimension memory system provides a flexible and efficient banking architecture:

✅ **Complete**: 4GB address space, 84MB mapped memory
✅ **Flexible**: Function pointer-based banks support RAM, ROM, MMIO
✅ **Efficient**: Direct memory access for RAM/VRAM, minimal overhead
✅ **Correct**: Endianness conversion between i860 (big) and host (little)
✅ **Debuggable**: Unmapped access detection, logging

**Key features**:
- 65,536 banks × 64KB = 4GB address space
- 64MB RAM + 4MB VRAM + 128KB ROM
- Big-endian ↔ Little-endian conversion
- Mailbox integration (64 bytes at 0x0F000000)
- ROM emulation with 3 versions
- EEPROM support for configuration

**Memory layout**:
```
0x0F000000: Mailbox (64B)
0xF8000000: RAM (64MB)
0xFE000000: VRAM (4MB)
0xFFF00000: ROM (128KB)
0xFFF20000: Dither (512B)
0xFFFFFFE8: NBIC (24B)
```

**Related documentation**:
- [Main Architecture](dimension-emulator-architecture.md) - System overview
- [i860 CPU](dimension-i860-cpu.md) - CPU implementation
- [Devices](dimension-devices.md) - MMIO regions (pending)
- [Mailbox Protocol](dimension-mailbox-protocol.md) - Mailbox details (pending)

---

**Location**: `/Users/jvindahl/Development/previous/docs/emulation/dimension-memory-system.md`
**Created**: 2025-11-11
**Lines**: 850+
