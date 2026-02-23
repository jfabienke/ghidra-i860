# NeXTdimension Boot ROM Analysis

**Binary**: `ND_step1_v43_eeprom.bin` (131,072 bytes / 128 KB)
**Processor**: Intel i860XR @ 33 MHz
**Format**: Raw Intel 28F010 Flash EEPROM image
**Version**: v43 (from filename)
**i860 Base Address**: 0xFFF00000

## What It Is

The ND boot ROM is a minimal bootstrap firmware (10,912 bytes of code/data in 128 KB image, 8.3% utilized). It runs on the i860 at hardware reset and performs:

1. CPU initialization (PSR, EPSR, FSR, DIRBASE)
2. DRAM bank configuration (3 banks at 0x2E3A8000, 0x4E3A8000, 0x6E3A8000)
3. Hardware detection (RAM size, slot ID via 0xFF800030)
4. RAMDAC programming (28-register timing loop for 1120x832 @ 68Hz)
5. Mailbox polling loop (0x02000000) waiting for host commands
6. Kernel DMA transfer from shared memory to local DRAM
7. Jump to kernel entry (`bri 0x00000000`) — never returns

## Boot Sequence

```
i860 Reset (0xFFFFFFF0)
  → ROM reset vector at 0xFFF1FF20: br 0x00000020
    → Boot entry at 0xFFF00020
      → PSR/EPSR/FSR/DIRBASE setup (~20 us)
      → Memory bank init x3 (~75 us)
      → Hardware detection (~500 us)
      → RAMDAC programming (~2500 us)
      → Mailbox poll loop (~3000 us ready)
        → CMD_LOAD_KERNEL: DMA kernel to DRAM
        → bri 0x00000000 (jump to kernel, never returns)
```

Total bootstrap time: ~3 ms from reset to mailbox ready.

## Memory Map (ROM regions)

| Offset | Size | Region | Purpose |
|--------|------|--------|---------|
| 0x00000 | 880 B | Boot Vector & Init | Exception vectors (NOPs), PSR/EPSR/FPU/DIRBASE setup |
| 0x00380 | 432 B | Early Init | Memory initialization subroutine (called 3x) |
| 0x00540 | 1,136 B | Core Init | Memory detection, VRAM config, first MMIO access |
| 0x009C0 | 528 B | Hardware Detection | RAM size, hardware ID, status polling |
| 0x00BE0 | 2,448 B | Device Init | RAMDAC 28-register loop, graphics controller |
| 0x01580 | 4,048 B | Main Runtime | Mailbox polling, command dispatch, kernel loader (largest) |
| 0x02560 | 928 B | Service Routines | memcpy, memset, memcmp, division helpers, MMIO wrappers |
| 0x1FD60 | 480 B | Data Tables | Memory test patterns (0xAA/55), RAMDAC timing table |
| 0x1FF20 | 32 B | Reset Vector | `br 0x00000020` + NOP delay slot |
| 0x1FFE0 | 32 B | Reset Config | PSR/DIRBASE/FSR initial values, 0xA5 magic (hardware-read, not executed) |

## MMIO Registers (confirmed from ROM disassembly)

| Address | Name | Access | Purpose |
|---------|------|--------|---------|
| 0x02000000 | MAILBOX_STATUS | Poll loop | Command ready flag |
| 0x02000004 | MAILBOX_COMMAND | Read | Command opcode |
| 0x02000008 | MAILBOX_DATA_PTR | Read | DMA source in shared memory |
| 0x0200000C | MAILBOX_DATA_LEN | Read | Transfer size |
| 0x02000010 | MAILBOX_REPLY_PTR | Write | Reply buffer address |
| 0x02000014 | MAILBOX_REPLY_LEN | Write | Reply size |
| 0x02000070 | CONTROL_STATUS | Read-modify-write | Board control register |
| 0x020014E4 | RAMDAC_LUT_DATA | Write x28 | RAMDAC timing registers |
| 0x020015E4 | RAMDAC_CONTROL | Write x3 | RAMDAC mode control |
| 0x020118E4 | GRAPHICS_DATA | Write | Graphics controller config |
| 0x0200009D | GRAPHICS_STATUS | Read | Graphics ready status |
| 0x020031E6 | MEM_COMMAND | Write | Memory controller command |
| 0x020031D6 | MEM_CONFIG | Write | Memory controller config |
| 0xFF800000 | CSR0 | Read/Write | Control/Status Register 0 |
| 0xFF800030 | SID | Read | Slot ID / hardware config |

## Post-ROM CPU State (what the kernel inherits)

| Register | Value | Notes |
|----------|-------|-------|
| PSR | bit 4 cleared | Interrupts disabled |
| EPSR | 0x00804000 | Extended status configured |
| FSR | 0x00000001 | FPU initialized, pipelines warmed |
| DIRBASE | 0x00A0 | MMU page directory base set |
| Integer regs | Various | r16-r31 used as scratch during boot, values depend on hardware detection results |

## Relevance to Kernel Analysis

The boot ROM analysis directly informs three open problems:

1. **Emulator initial state**: The kernel does NOT start from all-zero registers. The ROM has already configured PSR/EPSR/FSR/DIRBASE and written to multiple MMIO registers. The emulator should either run the ROM first or inject the post-ROM state.

2. **Entry-point semantics**: The ROM copies the raw kernel binary to DRAM and jumps to offset 0. With the Mach-O kernel, this means the i860 first hits header data — confirming the 0xF8000000 garbage-instruction loop. The real boot path requires either: (a) NDserver patching the entry point after DMA, or (b) the host loading only the __TEXT/__DATA segments at their correct VAs.

3. **MMIO stub values**: The ROM's mailbox protocol (0x02000000-0x02000014) and control register (0x02000070) provide ground-truth addresses and access patterns for the emulator MMIO model.

## External References

- Full ROM disassembly: `nextdimension/firmware/rust/nextdim-embassy/docs/ND_ROM_STRUCTURE.md` (758 lines)
- Instruction-level analysis: `nextdimension/firmware/rust/nextdim-embassy/docs/ND_ROM_DISASSEMBLY_ANALYSIS.md`
- Complete disassembly listing: `nextdimension/firmware/rust/nextdim-embassy/docs/ND_step1_v43_eeprom.asm` (32,802 lines)
- MAME i860 disassembler: `nextdimension/tools/mame-i860/i860disasm`
- Previous emulator source: `previous/src/dimension/` (nd_devs.c, nd_mem.c, nd_mailbox.c)
- NDserver boot protocol: `nextdimension/ndserver_re/docs/`

## Directory Structure

```
boot-rom/
├── ND_step1_v43_eeprom.bin   # Raw 128 KB EEPROM image
├── README.md                  # This file
├── docs/                      # Analysis findings and reference
├── reports/                   # Generated analysis outputs
└── scripts/                   # Analysis and extraction scripts
```
