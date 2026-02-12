# NeXTdimension Boot ROM — Reverse Engineering Document

## 1. Binary Overview

| Field | Value |
|-------|-------|
| File | `ND_step1_v43_eeprom.bin` |
| Size | 131,072 bytes (128 KB) |
| Format | Raw Intel 28F010 Flash EEPROM image |
| Processor | Intel i860XR RISC @ 33 MHz |
| Version | v43 (from filename convention) |
| SHA-256 | `46dea61c6c5278ad324c7a804a792f163e79bdf5a2ecc3c02d058f2d1605cb92` |
| Code/data | 10,912 bytes (8.3% of image) |
| Zero-fill | 120,160 bytes (91.7%) |
| i860 base address | 0xFFF00000 |
| Reset vector | 0xFFF1FF20 → `br 0xFFF00020` |
| Disassembly tools | MAME i860 disassembler, Ghidra i860 SLEIGH module |

The ROM is a minimal first-stage bootloader. It initializes the i860 from cold
reset, configures memory and video hardware, then downloads the GaCK (Graphics
and Core Kernel) operating system from the host NeXTcube over the NuBus mailbox
interface. After DMA transfer, it jumps to DRAM and never returns.

---

## 2. i860 Address Space (from i860's perspective)

| Address Range | Size | Device | Notes |
|--------------|------|--------|-------|
| 0x00000000–0x03FFFFFF | 8–64 MB | DRAM | Main memory; kernel loaded here |
| 0x02000000–0x02000FFF | 4 KB | MMIO registers | Mailbox, DMA, video, interrupts, system control |
| 0x08000000–0x0BFFFFFF | 64 MB | Host window | Shared memory (NuBus DMA source) |
| 0x10000000–0x103FFFFF | 4 MB | VRAM | Framebuffer memory (single 1120x832x4 frame = 3.73 MB) |
| 0xF0000000–0xF0000FFF | 4 KB | Data path controller | CL550-related |
| 0xFF000000–0xFF0001FF | 512 B | Dither memory | Video dithering tables |
| 0xFF200000–0xFF200FFF | 4 KB | RAMDAC (Bt463) | 4-port interface: addr, palette, command, control |
| 0xFF400000–0xFF4001FF | 512 B | Unknown registers | MC step 1 (undocumented) |
| 0xFF800000–0xFF803FFF | 16 KB | I/O devices | Memory controller CSRs, board ID |
| 0xFFF00000–0xFFF1FFFF | 128 KB | Boot ROM (EEPROM) | This image |

**No serial UART is present on the NeXTdimension board.** The i860 has no
direct serial I/O path; all host communication goes through the mailbox
registers at 0x02000000.

---

## 3. ROM Code Layout

The ROM contains 9 code/data regions separated by zero-filled gaps:

```
0x00000 ──┬─────────────────────────────────────────┐
          │  Region 1: Boot Vector & Init           │  880 bytes
          │    Exception vectors (all NOPs)         │
          │    PSR/EPSR/FSR/DIRBASE setup           │
          │    FPU pipeline warmup                  │
          │    Stack pointer initialization         │
          │    3x memory bank init calls            │
          │    Hardware detection + paging enable   │
0x00370 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 16 bytes)            │
0x00380 ──┼─────────────────────────────────────────┤
          │  Region 2: Cache Flush / TLB Invalidate │  432 bytes
          │    Disable interrupts, save PSR/FSR     │
          │    Dual-mode cache flush (128 lines)    │
          │    FP pipeline load test via fld.d      │
          │    DIRBASE mode switching               │
          │    Called via bri (indirect return)     │
0x00530 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 16 bytes)            │
0x00540 ──┼─────────────────────────────────────────┤
          │  Region 3: Memory Test                  │ 1,136 bytes
          │    Write 4 patterns to 16-byte region   │
          │    Read-back verify, count mismatches   │
          │    Zero fill, return error count        │
0x009B0 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 16 bytes)            │
0x009C0 ──┼─────────────────────────────────────────┤
          │  Region 4: Hardware Detection           │  528 bytes
          │    RAM size detection                   │
          │    Board slot ID (0xFF800030)           │
          │    GState flag checks and init          │
0x00BD0 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 16 bytes)            │
0x00BE0 ──┼─────────────────────────────────────────┤
          │  Region 5: RAMDAC & Graphics Init       │ 2,448 bytes
          │    Clear 0xFF801000, 0xFF802000         │
          │    Bt463 direct register writes (12)    │
          │    Bt463 LUT loop (16 entries)          │
          │    Bt463 cursor loop (4 entries)        │
          │    Bt463 palette loop (512 entries)     │
          │    Total: 544 RAMDAC register writes    │
0x01570 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 16 bytes)            │
0x01580 ──┼─────────────────────────────────────────┤
          │  Region 6: Main Runtime        ★        │ 4,048 bytes
          │    Mailbox polling loop                 │
          │    Command dispatcher                   │
          │    Kernel loader (word-by-word DMA)     │
          │    Error recovery (3-level retry)       │
          │    bri to kernel entry (never returns)  │
0x02550 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 16 bytes)            │
0x02560 ──┼─────────────────────────────────────────┤
          │  Region 7: Service Routines             │  928 bytes
          │    memcpy, memset, memcmp               │
          │    Division helpers (no HW divide)      │
          │    MMIO read/write wrappers             │
0x02900 ──┼─────────────────────────────────────────┤
          │  (zero-filled, 119,904 bytes)           │
0x1FD60 ──┼─────────────────────────────────────────┤
          │  Region 8: Data Tables & Constants      │  480 bytes
          │    Memory test patterns (0xAA/0x55)     │
          │    RAMDAC timing table (28 x 4 bytes)   │
          │    Embedded reset vector at 0x1FF20     │
0x1FF40 ──┼─────────────────────────────────────────┤
          │  (zero-filled gap, 160 bytes)           │
0x1FFE0 ──┼─────────────────────────────────────────┤
          │  Region 9: Reset Config Data            │  32 bytes
          │    PSR/DIRBASE/FSR initial values       │
          │    0xA5 magic marker                    │
          │    NOT executable — read by HW at reset │
0x20000 ──┴─────────────────────────────────────────┘
```

---

## 4. Boot Sequence

### 4.1 Reset Entry

The i860 reset address is 0xFFFFFFF0. On the NeXTdimension board this maps to
ROM offset 0x1FFF0, which contains configuration data (not code). The actual
reset entry is at 0xFFF1FF20:

```asm
fff1ff20:  6bff803f  br   0xfff00020    ; Branch to boot entry
fff1ff24:  a0000000  shl  %r0,%r0,%r0   ; NOP (delay slot)
```

### 4.2 CPU Initialization (0xFFF00020–0xFFF00138)

Execution begins at 0xFFF00020 (falls through from exception vector NOP).

```asm
; 1. Disable interrupts
fff00028:  30300000  ld.c   %psr,%r16
fff0002c:  d6100010  andnot 0x10,%r16,%r16   ; Clear bit 4 (IM)
fff00030:  38208000  st.c   %r16,%psr

; 2. Configure EPSR
fff00044:  30b00000  ld.c   %epsr,%r16
fff00048:  ee100080  orh    0x80,%r16,%r16   ; Set bit 23 (BE)
fff0004c:  e6104000  or     0x4000,%r16,%r16 ; Set bit 14 (INT)
fff00050:  38a08000  st.c   %r16,%epsr       ; → EPSR = 0x00804000

; 3. Clear pending FP fault
fff00054:  30000000  ld.c   %fir,%r0         ; Read FIR, discard

; 4. Zero r15 (GState flags)
fff00058:  a0000000  shl    %r0,%r0,%r15

; 5. Set DIRBASE (cache config, no paging yet)
fff000c4:  e41000a0  or     0xa0,%r0,%r16    ; 0xA0 = CS8 on, ATE off
fff000e4:  38408000  st.c   %r16,%dirbase

; 6. Configure FSR (FP rounding mode)
fff00100:  ec100000  orh    0x0,%r0,%r16
fff00104:  e6100001  or     0x1,%r16,%r16
fff00108:  38808000  st.c   %r16,%fsr        ; → FSR = 0x00000001

; 7. Warm FP pipelines (textbook i860 init)
fff0010c:  48000403  r2apt.ss  %f0,%f0,%f0   ; Adder pipe
fff00110:  48000403  r2apt.ss  %f0,%f0,%f0
fff00114:  48000403  r2apt.ss  %f0,%f0,%f0
fff00118:  48000407  i2apt.ss  %f0,%f0,%f0   ; Multiplier pipe
fff0011c:  48000449  pfiadd.ss %f0,%f0,%f0   ; Pipelined FP add
fff00120:  48000449  pfiadd.ss %f0,%f0,%f0

; 8. Set up initial stack
fff00128:  ec10ff00  orh    0xff00,%r0,%r2   ; r2 = 0xFF000000
fff0012c:  e6100200  or     0x200,%r2,%r2    ; r2 = 0xFF000200
fff00130:  9442fff0  adds   -0x10,%r2,%r2    ; r2 = 0xFF0001F0 (SP)
fff00134:  94430008  adds   0x8,%r2,%r3      ; r3 = 0xFF0001F8 (FP)
```

### 4.3 Memory Bank Initialization (0xFFF0005C–0xFFF00088)

Three calls to the same subroutine entry at 0xFFF00380 (inside the function
labeled `FUN_fff0037c`) with different DRAM bank addresses:

| Call # | Parameter (r16) | Likely Purpose |
|--------|----------------|----------------|
| 1 | 0x2E3A8000 | DRAM bank 0 |
| 2 | 0x4E3A8000 | DRAM bank 1 |
| 3 | 0x6E3A8000 | DRAM bank 2 |

The subroutine (FUN_fff0037c / FUN_fff0048c) performs cache flush and TLB
invalidation: saves PSR/FSR/DIRBASE, disables interrupts, cycles through 128
cache lines using `flush` instructions with two different DIRBASE modes, then
restores state and returns via `bri %r27`.

### 4.4 Hardware Detection (0xFFF0008C–0xFFF000BC)

```asm
; Read board slot ID
fff0008c:  ec10ff80  orh    0xff80,%r0,%r16  ; r16 = 0xFF800000
fff00090:  16040031  ld.l   48(%r16),%r4     ; Read 0xFF800030 (SID register)
fff00094:  c484000f  and    0xf,%r4,%r4      ; Extract bits [3:0]
fff00098:  a484001c  shl    28,%r4,%r4       ; Shift to bits [31:28]

; Read/modify board control register
fff0009c:  ec05ff80  orh    0xff80,%r0,%r5
fff000a0:  14a60001  ld.l   0(%r5),%r6       ; Read 0xFF800000 (CSR0)
fff000a4:  e4d01000  or     0x1000,%r6,%r16  ; Set bit 12
fff000a8:  1ca08001  st.l   %r16,0(%r5)      ; Write back
```

Board ID bits [3:0] from the SID register determine RAM configuration. Bit 12
of CSR0 enables a memory region or feature gate.

### 4.5 RAMDAC Configuration (0xFFF00BE0–0xFFF01570)

The largest initialization section (2,448 bytes) programs the Brooktree Bt463
RAMDAC for 1120x832 @ 68.7 Hz, 32-bit RGBA output.

**Bt463 Interface** (4 byte-wide ports):

| Port | Address | Function |
|------|---------|----------|
| 0 | 0xFF200000 | Address register (write register index) |
| 1 | 0xFF200004 | Palette data (auto-increment) |
| 2 | 0xFF200008 | Command/overlay data |
| 3 | 0xFF20000C | Control register (direct access) |

**Programming protocol**: Each register write follows address → delay → data,
where the delay loop (~10 iterations, ~1 us at 33 MHz) satisfies the Bt463
minimum 100 ns timing between address and data writes.

**Write summary**:

| Phase | Address Range | Registers | Count | Content |
|-------|--------------|-----------|-------|---------|
| Pre-init | 0xFF801000, 0xFF802000 | Graphics controller | 2 | Clear (reset) |
| Direct | RAMDAC ports 0/1/2 | Command A/B, pixel mask, overlays | 12 | Mode/control |
| Loop 1 | Bt463 regs 0x0300–0x030F | Color lookup table | 16 | Default colors |
| Loop 2 | Bt463 regs 0x020C–0x020F | Cursor pattern | 4 | HW cursor shape |
| Loop 3 | Bt463 regs 0x0000–0x01FF | Palette/gamma | 512 | Full palette |
| **Total** | | | **544+2** | |

**Note**: Earlier analysis documents mention "28 iterations" — this refers to
only the table-driven timing parameter writes. The full RAMDAC init performs
544+ register writes.

**Video Timing** (from data table at 0xFFF1FDA0):

```
Horizontal: 1120 active + 32 front porch + 80 sync + 128 back porch = 1360 total
Vertical:    832 active +  3 front porch +  5 sync +  15 back porch =  855 total
Pixel clock: 1360 x 855 x 68.7 Hz ≈ 80 MHz
Color depth: 32-bit RGBA (8:8:8:8)
Frame buffer: 1120 x 832 x 4 = 3,727,360 bytes (~3.73 MB in 4 MB VRAM)
```

### 4.6 Main Loop and Kernel Loading (0xFFF01580–0xFFF02550)

The main runtime is the largest code region (4,048 bytes). After all
initialization, the i860 enters an infinite mailbox polling loop:

```
┌────────────────────────────────────┐
│  Pre-loader init calls (4x)        │
│  - FUN_fff00b78 (GState clear)     │
│  - FUN_fff01a98 (HW register)      │
│  - FUN_fff00b2c (stub)             │
│  - FUN_fff017f4 (table scan)       │
└──────────┬─────────────────────────┘
           ▼
┌────────────────────────────────────┐
│  Poll MAILBOX_STATUS (0x02000000)  │◄──┐
│  if CMD_READY bit clear: loop      │───┘
│  Read MAILBOX_COMMAND (0x02000004) │
│  Dispatch on command type          │
└──────────┬─────────────────────────┘
           ▼
┌────────────────────────────────────┐
│  CMD_LOAD_KERNEL handler:          │
│  1. Read DATA_PTR (0x02000008)     │
│  2. Read DATA_LEN (0x0200000C)     │
│  3. Word-by-word copy to DRAM      │
│     (manual DMA — no HW DMA)       │
│  4. Set CMD_COMPLETE in STATUS     │
│  5. bri %r24 → 0x00000000          │
│     (jump to kernel, never return) │
└────────────────────────────────────┘
```

**Critical detail**: The kernel loader uses a software DMA loop (word-by-word
`ld.l`/`st.l`), not hardware DMA. Transfer rate is limited by NuBus bandwidth
(~25 MB/s theoretical, ~10 MB/s practical). A 784 KB kernel takes approximately
80 ms to transfer.

**Error recovery**: The command dispatcher includes a 3-level retry mechanism
for failed operations.

### 4.7 Service Routines (0xFFF02560–0xFFF02900)

Utility functions called from the main loop:

| Function | Purpose | Notes |
|----------|---------|-------|
| memcpy | Block copy | Standard word-aligned loop |
| memset | Block fill | Zero or pattern fill |
| memcmp | Block compare | Returns difference count |
| Division helpers | Software divide | i860 has multiply but no divide |
| MMIO wrappers | Register I/O | Read-modify-write patterns |

---

## 5. Function Catalog

Ghidra analysis identified 30 functions. The table below includes corrected
descriptions from both the Opus 4.6 swarm analysis and cross-referencing with
the detailed ROM disassembly documents.

### 5.1 Substantive Functions

| Address | Name | Size | Description |
|---------|------|------|-------------|
| 0xFFF00020 | boot_entry | 464 B | Cold-start initialization: disable interrupts, configure PSR/EPSR/DIRBASE/FSR, warm FP pipelines, set up stack at 0xFF0001F0, call memory init 3x, call hardware detection, enable virtual addressing, return to virtual address 0xFFFE0204 |
| 0xFFF0037C | cache_flush_a | 116 B | TLB/cache invalidation pass A: save PSR/FSR/DIRBASE, disable interrupts, cycle 128 cache lines with `flush` instruction in two DIRBASE modes, return via `bri %r27`. Contains unresolved indirect return. |
| 0xFFF0048C | cache_flush_b | 156 B | TLB/cache invalidation pass B: similar to 0x37C but uses FP loads (`fld.d`) instead of flushes to test both sides of the i860 dual-execution pipeline. Sets DIRBASE bit 5 with 5 NOP delay for mode change. Contains unresolved indirect return. |
| 0xFFF00540 | mem_test | 160 B | Memory test: write 4 known patterns (0xFF, 0xAA, 0x55, 0x00) to a 16-byte region, read back and count mismatches, zero the region, return error count. |
| 0xFFF006C0 | table_init | 220 B | Initialize a 3-entry table structure by copying data blocks via two helper calls, writing status/flag words into each entry. Uses page-directory tag merge (calls FUN_fff0021c). |
| 0xFFF0079C | board_init | 524 B | Board/system initialization: sets up GState structure (r15), reads hardware configuration from MMIO registers (0xFF800000, 0xFF800030), initializes subsystems, calls memory and VRAM detection routines. |
| 0xFFF009C0 | hw_detect | 148 B | Hardware detection: checks GState flag, conditionally initializes subsystems, reads RAM sizing results, calls memory test with patterns. |
| 0xFFF00AB0 | checksum | 124 B | Compute byte-sum checksum over a region pointed to by r15, compare against stored expected value and a magic constant. Used for ROM integrity check. |
| 0xFFF00B78 | signal_notify | 88 B | Signal/notify: clear GState flag in r15 struct, call handler, write modified control/status register. Part of pre-loader init sequence. |
| 0xFFF00BE0 | ramdac_init | 120 B | System init sequence entry: clear graphics controller registers at 0xFF801000 and 0xFF802000, then call chain of 5 initialization subroutines for RAMDAC programming. |
| 0xFFF00CB8 | ramdac_program | 1,236 B | **Bt463 RAMDAC programming** (NOT a UART): 12 direct register writes + 3 table loops (16 LUT + 4 cursor + 512 palette) = 544 total writes. Each write uses address→delay→data protocol. Base address 0xFF200000. |
| 0xFFF013A4 | ramdac_reconfig | 316 B | **Bt463 RAMDAC reconfiguration** (NOT a UART): saves 0xFF802004, writes control bit, triple-phase sync poll on 0xFF800004 bit 0x100, then writes 3 register programming cycles to Bt463 ports. Tests bit 3 of readback, returns 0/1 success status. Restores saved register. |
| 0xFFF01580 | main_loop | 152 B | Multi-phase initialization entry point: calls chain of subsystem init functions checking return status after each. Transitions to mailbox polling when ready. |
| 0xFFF017F4 | table_scan | 476 B | Scan 3 array-of-structs (indexed via r15 table) across 2 iterations, zero-fill each with f0/f1 (FP zero registers), then verify written values. |
| 0xFFF01A98 | hw_reg_rw | 92 B | Call subroutine, then conditionally read and modify hardware register at 0xFF400004 (undocumented region). |
| 0xFFF0021C | dirbase_tag | 52 B | Merge 4-bit page-directory-base tag into bits [31:28] of r16: reads DIRBASE, checks ATE bit; if paging disabled, skip; if enabled, read 4-bit tag from 0xFF800031, mask r16 to 28 bits, merge tag. |
| 0xFFF00260 | get_int_level | 48 B | Read EPSR, extract 5-bit interrupt level field from bits [12:8], return in r16. |
| 0xFFF02560 | svc_wrapper | 48 B | Service routine wrapper: writes command byte 0x91 to hardware register at 0xFF000341 (dither memory region), then executes service function. |

### 5.2 Stub Functions (Ghidra boundary artifacts)

Ghidra's auto-analysis split several function epilogues as separate functions.
These are all single-instruction `adds 0x8,%r2,%r2` (stack deallocation) stubs
that are actually epilogues of the preceding function:

| Address | Parent Function | Instruction |
|---------|----------------|-------------|
| 0xFFF0001C | (vector 5 NOP) | `shl %r0,%r0,%r0` (NOP) |
| 0xFFF00250 | boot_entry epilogue | `shl %r0,%r0,%r0` (NOP stub) |
| 0xFFF00290 | get_int_level epilogue | `shr 8,%r16,%r16` |
| 0xFFF005E0 | mem_test epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF00A54 | hw_detect epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF00B2C | checksum epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF00C58 | ramdac_init epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF014E0 | ramdac_reconfig epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF01618 | main_loop epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF019D0 | table_scan epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF01B04 | hw_reg_rw epilogue | `adds 0x8,%r2,%r2` |
| 0xFFF02590 | svc_wrapper continuation | Service routine body |

These stubs inflated the function count from ~18 real functions to 30.

---

## 6. MMIO Register Map

All register addresses confirmed from ROM disassembly cross-referenced with
the Previous emulator source (`nd_devs.c`, `nd_mem.c`) and ROM analysis documents.

### 6.1 Mailbox Registers (0x02000000)

Host-i860 communication interface. All 32-bit aligned.

| Offset | Address | Name | R/W | Function |
|--------|---------|------|-----|----------|
| 0x000 | 0x02000000 | STATUS | RW | Command ready flag (poll target) |
| 0x004 | 0x02000004 | COMMAND | R | Command opcode from host |
| 0x008 | 0x02000008 | DATA_PTR | R | DMA source address in shared memory |
| 0x00C | 0x0200000C | DATA_LEN | R | Transfer size in bytes |
| 0x010 | 0x02000010 | RESULT | W | Return value to host |
| 0x014 | 0x02000014 | ERROR_CODE | W | Error status to host |
| 0x018 | 0x02000018 | HOST_SIGNAL | R | Signal from host |
| 0x01C | 0x0200001C | I860_SIGNAL | RW | Signal from i860 |

**Mailbox command codes** (from Previous emulator `nd_mailbox.c`):

| Code | Name | Description |
|------|------|-------------|
| 0x01 | LOAD_KERNEL | DMA kernel binary to DRAM, jump to entry |
| 0x07 | SET_PALETTE | Load RAMDAC palette colors |
| 0x0B | DPS_EXECUTE | Execute Display PostScript program |
| 0x0C | VIDEO_CAPTURE | Capture video frame |
| 0x10 | GET_INFO | Return board info |
| 0x11 | MEMORY_TEST | Run memory diagnostics |

**Note**: A previously circulated speculative header (`nextdimension.h`) had
different command code assignments (e.g. DPS_EXECUTE=0x01, SET_PALETTE=0x08).
The values above are from the actual Previous emulator implementation and should
be considered authoritative until verified against ROM disassembly of the
command dispatcher at 0xFFF01580.

### 6.2 Video/Graphics Registers

| Address | Name | R/W | Function |
|---------|------|-----|----------|
| 0x02000070 | CONTROL_STATUS | RW | Board control (read-modify-write with bit 12) |
| 0x020014E4 | RAMDAC_LUT_DATA | W | RAMDAC timing register writes |
| 0x020015E4 | RAMDAC_CONTROL | W | RAMDAC mode control |
| 0x020118E4 | GRAPHICS_DATA | W | Graphics controller configuration |
| 0x0200009D | GRAPHICS_STATUS | R | Graphics ready status |

### 6.3 Bt463 RAMDAC (0xFF200000)

Brooktree Bt463 168 MHz Triple DAC. Byte-wide port interface.

| Address | Port | Function |
|---------|------|----------|
| 0xFF200000 | ADDR | Write register index (auto-increments for sequential reads) |
| 0xFF200004 | PAL_DATA | Palette data read/write |
| 0xFF200008 | CMD | Command/overlay register data |
| 0xFF20000C | CTRL | Control register direct access |

### 6.4 Memory Controller (0xFF800000)

| Address | Name | R/W | Function |
|---------|------|-----|----------|
| 0xFF800000 | CSR0 | RW | Control/Status Register 0. Bit 12: memory region enable. |
| 0xFF800004 | CSR0+4 | R | Status register. Bit 8 (0x100): sync/ready signal, polled in triple-phase sequence during RAMDAC reconfig. |
| 0xFF800010 | CSR1 | RW | Control/Status Register 1 |
| 0xFF800020 | CSR2 | RW | Control/Status Register 2 |
| 0xFF800030 | SID | R | Slot ID / hardware config. Bits [3:0]: RAM size code. Bits [7:4]: feature flags. Shifted to bits [31:28] for DIRBASE page-directory-base tag. |

### 6.5 Graphics Controller

| Address | Name | R/W | Function |
|---------|------|-----|----------|
| 0xFF801000 | GFX_CTRL_0 | W | Graphics controller register 0 (cleared during init) |
| 0xFF802000 | GFX_CTRL_1 | W | Graphics controller register 1 (cleared during init) |
| 0xFF802004 | GFX_CTRL_1+4 | RW | Graphics control (saved/restored during RAMDAC reconfig) |

### 6.6 Other

| Address | Name | R/W | Function |
|---------|------|-----|----------|
| 0xFF000341 | DP_CSR+1 | W | DataPath Controller CSR (second byte, big-endian). `OFFSET_DP_CSR = 0x340` per `locore.s`. Writing 0x91 sets graphics data path control bits (video alpha / DMA enable). |
| 0xFF400004 | UNKNWN+4 | RW | Undocumented register. Conditionally read/modified by FUN_fff01a98. |

---

## 7. Data Structures

### 7.1 RAMDAC Timing Table (0xFFF1FDA0)

28 x 4-byte entries used by the table-driven RAMDAC configuration loop:

```
Offset  Value       Interpretation
0x00    0x00000000  Reserved
0x04    0x00000000  Reserved
0x08    0x00000000  Reserved
0x0C    0x00000000  Reserved
0x10    0x00000E80  Horizontal total (3712 clocks)
0x14    0x00003A00  Horizontal sync width
0x18    0x00000EBA  Horizontal back porch
0x1C    0x00000580  Vertical total
0x20    0x00000F80  Vertical sync width
0x24    0x00000040  Pixel clock divider
0x28    0x00000008  Bits per pixel control
0x2C    0x00001000  Memory address offset
0x30    0x00000000  Reserved
0x34    0x00000080  Sync polarity
...     ...         (remaining entries configure active area, blanking)
```

### 7.2 Memory Test Patterns (0xFFF1FD94)

```
0xFFFFFF00  — All-ones bitmask
0xAAAAAA00  — Alternating bits (0xAA pattern)
0x55555500  — Inverse alternating bits (0x55 pattern)
```

### 7.3 Reset Configuration Data (0xFFF1FFE0)

Not executable code. These values are read by i860 hardware during reset:

```
0xFFF1FFEC: 0xF0000000  — PSR initial value
0xFFF1FFF0: 0xFF00F500  — DIRBASE initial value
0xFFF1FFF4: 0x00080040  — FSR initial value
0xFFF1FFF8: 0xA5000000  — Magic marker (0xA5 = "alive")
0xFFF1FFFC: 0x000C0001  — Checksum or version ID
```

### 7.4 GState Structure (r15-relative)

The GState structure is a runtime data block addressed via r15. Fields
identified from ROM access patterns:

| Offset | Size | Access | Purpose |
|--------|------|--------|---------|
| +0 | 4 | RW | Status/flag word (checked and cleared by signal_notify) |
| +68 | 4 | R | Test address for FP cache validation (loaded by cache_flush_b) |
| +80 | 4 | W | Detected RAM size (written by hw_detect) |

---

## 8. Post-ROM CPU State

When the ROM finishes initialization and jumps to the kernel, the i860 is in
this state:

| Register | Value | How Set |
|----------|-------|---------|
| PSR | bit 4 clear | `andnot 0x10` — interrupts disabled |
| EPSR | 0x00804000 | `orh 0x80` + `or 0x4000` — bus error + int overflow trap |
| FSR | 0x00000001 | Explicit write — FP rounding mode configured |
| DIRBASE | 0x00A0 + ATE | Initially 0xA0 (cache only), then ATE enabled for paging |
| FIR | cleared | Read to r0 (discard) clears pending faults |
| r0 | 0 (hardwired) | Always zero |
| r1 | return addr | Last saved return address |
| r2 (SP) | 0xFF0001F0 | `orh 0xff00` + `or 0x200` + `adds -0x10` |
| r3 (FP) | 0xFF0001F8 | SP + 8 (GCC ABI) |
| r15 | 0 initially | `shl %r0,%r0,%r15` — GState flags, later overwritten |
| r16–r31 | various scratch | Used during boot, final values depend on HW detection |
| f0, f1 | 0.0 (hardwired) | Always zero |
| FP pipelines | drained | r2apt/i2apt/pfiadd warmup sequence |

**Key implication for kernel emulation**: An emulator cannot start the kernel
with all-zero registers. At minimum, PSR, EPSR, FSR, DIRBASE, r2 (SP), and r3
(FP) must be pre-initialized to post-ROM values.

---

## 9. Swarm Analysis Corrections

The Opus 4.6 LLM swarm (run `515c1f8e`) analyzed all 30 Ghidra functions.
Two significant misidentifications were found:

### 9.1 FUN_fff00cb8: "Serial UART init" → Bt463 RAMDAC programming

The swarm classified this as serial UART initialization because:
- Byte-wide writes (`st.b`) with 10-cycle delay loops resemble UART register programming
- The value 0x0D (decimal 13) was interpreted as ASCII carriage return
- Writes to offsets +0, +4, +8, +0xC looked like a 4-register UART

**Actual function**: Bt463 RAMDAC direct register programming. The value 0x0D
is register index 13 (a Bt463 control register). The delay loops satisfy the
Bt463 minimum timing requirement (100 ns between address and data writes).
The Previous emulator maps 0xFF200000 as the RAMDAC in `nd_devs.c`.

### 9.2 FUN_fff013a4: "Serial/UART device init" → Bt463 RAMDAC reconfiguration

Same root cause. This function reconfigures RAMDAC settings: saves a graphics
controller register, performs a triple-phase synchronization poll (waiting for
hardware timing edges), then writes three RAMDAC programming cycles and tests
the readback for success.

### 9.3 Overall Swarm Results

| Verdict | Count | Notes |
|---------|-------|-------|
| Accept | 1 | FUN_fff0001c (NOP padding — trivially correct) |
| Revise | 24 | 12 are boundary artifacts/stubs; 12 are substantive but need evidence refinement |
| Gate fail | 2 | FUN_fff0037c, FUN_fff0048c (unresolved-bri ceiling) |
| Schema fail | 2 | FUN_fff00290 (too few evidence entries), FUN_fff00cb8 (gate issue) |

The high revise rate (80%) is caused by two factors:
1. Ghidra splitting boundary artifacts/stubs as separate functions (12/30 are trivial or continuation artifacts)
2. The ROM's small size limits cross-reference evidence density

---

## 10. Call Graph

```
Reset Vector (0xFFF1FF20)
  └─► br 0xFFF00020
       └─► boot_entry (0xFFF00020)
            ├─► call cache_flush_a entry (0xFFF00380; function starts at 0xFFF0037C) — 3x with bank addresses
            │     └─► bri %r27 (return)
            ├─► call board_init (0xFFF0079C)
            │     ├─► call cache_flush_b (0xFFF0048C)
            │     ├─► call hw_detect (0xFFF009C0)
            │     │     └─► call mem_test (0xFFF00540)
            │     └─► return
            ├─► call dirbase_tag (0xFFF0021C)
            ├─► spin-wait on EPSR bit 17
            ├─► enable ATE in DIRBASE
            └─► ret to 0xFFFE0204 (virtual address)
                 └─► ramdac_init (0xFFF00BE0)
                      ├─► call stub (0xFFF00B30)
                      ├─► call ramdac_program (0xFFF00CB8)
                      │     └─► 544 Bt463 register writes
                      ├─► call ramdac_reconfig (0xFFF013A4)
                      └─► return
                           └─► main_loop (0xFFF01580)
                                ├─► call signal_notify (0xFFF00B78)
                                ├─► call hw_reg_rw (0xFFF01A98)
                                ├─► call table_scan (0xFFF017F4)
                                └─► mailbox_poll
                                     ├─► CMD_LOAD_KERNEL
                                     │     ├─► word-by-word DMA loop
                                     │     └─► bri %r24 → 0x00000000 (kernel)
                                     └─► other commands → loop
```

---

## 11. Open Questions

1. ~~**DRAM bank addresses**~~: **Answered**. The `FIX_ADDR` macro in
   `ND_rom.c` reveals that physical address lines A0 and A1 are mapped to A17
   and A18 as a hardware workaround for first-generation MC chips. This
   non-linear swizzling makes standard DRAM regions appear at fragmented,
   non-power-of-two addresses. The high nibble (0x2, 0x4, 0x6) is the NextBus
   Slot ID tag, so 0x2E3A8000/0x4E3A8000/0x6E3A8000 represent three banks
   differentiated by slot position.

2. ~~**SID register interpretation**~~: **Answered**. 0xFF800030 returns the
   4-bit NextBus slot ID. The value is shifted to bits [31:28] to uniquely tag
   the DIRBASE, ensuring every board in a multi-board system has a unique
   physical address space for its kernel and resources based on slot position.

3. ~~**0xFF000341 writes**~~: **Answered**. This address is in the DataPath
   Controller CSR block (`OFFSET_DP_CSR = 0x340` from `locore.s`; 0xFF000200
   is the top of Dither RAM). Writing 0x91 to 0xFF000341 (the second byte of
   the 32-bit CSR in big-endian mode) sets control bits for the graphics data
   path — likely video alpha or DMA enable.

4. **0xFF400004 access**: FUN_fff01a98 conditionally reads and modifies a
   register in the "unknown" MMIO range. What device lives at 0xFF400000?

5. ~~**Virtual entry point**~~: **Answered**. The ROM executes the
   transition from the instruction cache. It sets dirbase, then performs a `bri`
   (branch indirect). Since the code is already in the i-cache, the i860
   completes the jump to the new virtual address (0xFFFE0204) even as the MMU
   changes the underlying mapping. No explicit page table entry is needed for
   the transition itself — the cache carries execution across the ATE enable.

6. ~~**Kernel entry protocol**~~: **Answered**. The host-side `NDLoadCode`
   utility (`code.c`) parses the Mach-O `LC_THREAD` command to extract the
   entry point. Segments are loaded individually to their correct VAs using
   mixed-endian writes: `LOADTEXT(addr, data)` uses `addr ^ 4` (XOR-4 byte
   swap for i860 big-endian instruction fetch in little-endian data mode),
   while `LOADDATA(addr, data)` writes directly. The ROM does not strip
   headers — NDserver handles all Mach-O parsing on the host side.

7. ~~**GState structure**~~: **Answered**. In the boot ROM, r15 is explicitly
   reserved as a global pointer to `ROMGlobals` (per `NDrom.h`). In the
   kernel/DPS server, r15 expands to the Graphics State (GState) anchor:

   | Offset | Size | Field | Source |
   |--------|------|-------|--------|
   | +0 | 4 | Pointer to current Device structure | NDkernel source |
   | +68 | 4 | `MarkProcs` dispatch table pointer (MarkArgs/ImageArgs) | NDkernel source |
   | +80 | 4 | `ImageArgs->data` or pattern pointer | NDkernel source |

   The 25 `orh 0x6514,r15,r31` references in the kernel confirm r15 anchors
   all graphics state. Additional field offsets remain to be decoded for the
   3.3 binary.

8. **Command dispatch**: The ROM handles multiple mailbox commands beyond
   CMD_LOAD_KERNEL. Which other commands does it implement? Are graphics
   commands (DRAW_RECT, CLEAR_SCREEN, SET_PALETTE) handled in ROM or only
   by the kernel?

---

## 12. Tool Validation

### Ghidra i860 Module

The SLEIGH module correctly disassembles all ROM instructions:

- Control register ops: `ld.c`/`st.c` for psr, epsr, fsr, fir, dirbase
- FPU pipeline warmup: `r2apt.ss`, `i2apt.ss`, `pfiadd.ss`
- Cache management: `flush` with auto-increment
- Delay slot handling: correct for `call`, `br`, `bri`, `bc.t`, `bnc.t`, `bla`
- NOP recognition: `shl %r0,%r0,%r0` = 0xA0000000

30 functions identified, 1,149 instructions, 4,596 code bytes.

### MAME i860 Disassembler

Complete 32,802-line disassembly available. 100% mnemonic agreement with Ghidra
output on all code regions.

---

## References

| Resource | Location |
|----------|----------|
| ROM binary | `re/nextdimension/boot-rom/ND_step1_v43_eeprom.bin` |
| Ghidra disassembly | `re/nextdimension/boot-rom/reports/ghidra_disasm.txt` |
| Ghidra factpack | `re/nextdimension/boot-rom/reports/factpack/` |
| Swarm claims DB | `re/nextdimension/boot-rom/reports/factpack/swarm_opus_run/claims.db` |
| Import script | `re/nextdimension/boot-rom/scripts/BootRomImport.java` |
| ROM structure analysis | `nextdimension/firmware/rust/nextdim-embassy/docs/ND_ROM_STRUCTURE.md` |
| Instruction-level analysis | `nextdimension/firmware/rust/nextdim-embassy/docs/ND_ROM_DISASSEMBLY_ANALYSIS.md` |
| Detailed boot sequence | `nextdimension/firmware/rust/nextdim-embassy/docs/ROM_BOOT_SEQUENCE_DETAILED.md` |
| Complete disassembly listing | `nextdimension/firmware/rust/nextdim-embassy/docs/ND_step1_v43_eeprom.asm` |
| Previous emulator source | `previous/src/dimension/` (nd_devs.c, nd_mem.c, nd_mailbox.c) |
