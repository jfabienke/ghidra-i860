# Intel i860 Architecture Reference

*Comprehensive technical reference for Ghidra processor module development*

## 1. Architecture Overview

The Intel i860 (80860) is a 32/64-bit RISC microprocessor introduced by Intel in 1989. It was the world's first million-transistor chip, combining RISC integer and VLIW floating-point concepts in a single die.

**Key characteristics:**
- Load/store architecture (only load/store instructions access memory)
- Fixed 32-bit instruction width, 4-byte aligned
- Dual-instruction (VLIW-like) mode: one core + one FP instruction per cycle
- Up to three operations per clock (ALU + FP multiply + FP add/subtract)
- Program-accessible pipelines (compiler manages scheduling)
- Bi-endian (configurable little/big endian)
- 32-bit virtual and physical address space

**Two generations:**

| Feature | i860 XR (1989) | i860 XP (1991) |
|---------|----------------|----------------|
| Clock | 25/33/40 MHz | 40/50 MHz |
| Process | 1.0 um CMOS | 0.8 um CHMOS-V |
| Transistors | ~1 million | ~2.55 million |
| Peak MFLOPS (SP/DP) | 80/60 @ 40 MHz | 100/75 @ 50 MHz |
| I-Cache | 4 KB, 2-way | 16 KB, 4-way |
| D-Cache | 8 KB, 2-way | 16 KB, 4-way |
| Page sizes | 4 KB | 4 KB + 4 MB |
| Cache coherence | None | MESI protocol |
| Multiprocessor | Limited | Full bus snooping |

Both versions maintain **full binary compatibility** at the application instruction set level.

---

## 2. Register File

### 2.1 Integer Registers (32 x 32-bit)

| Register | Encoding | Purpose |
|----------|----------|---------|
| `r0` | 0 | Hardwired to zero (reads always return 0, writes discarded) |
| `r1` | 1 | Return address (link register, set by `call`/`calli`) |
| `r2` / `sp` | 2 | Stack pointer (by convention) |
| `r3` / `fp` | 3 | Frame pointer (by convention) |
| `r4`-`r15` | 4-15 | Callee-saved general purpose |
| `r16`-`r27` | 16-27 | Arguments / caller-saved (first 12 words of integer args) |
| `r28` | 28 | Frame pointer (SPEA ABI) / argument pointer (GCC ABI) |
| `r29` | 29 | Stack pointer (SPEA ABI) / static chain (GCC ABI) |
| `r30`-`r31` | 30-31 | Reserved / general purpose |

**Notes:**
- `r0` is architecturally hardwired to zero. Writing to `r0` is silently discarded.
- Two calling conventions exist in the wild: the GCC ABI (r2=sp, r3=fp) and the SPEA/APX2 ABI (r28=fp, r29=sp). See `05-binary-formats-and-platforms.md` for details.
- `r1` is implicitly written by `call` and `calli` instructions with the return address.

### 2.2 Floating-Point Registers (32 x 32-bit, aliased)

The 32 FP registers can be accessed in three configurations:

| Access Mode | Registers | Count | Alignment |
|-------------|-----------|-------|-----------|
| 32-bit single precision | `f0`-`f31` | 32 | Any |
| 64-bit double precision | `f0`,`f2`,`f4`,...,`f30` | 16 | Even-numbered |
| 128-bit quad / vector | `f0`,`f4`,`f8`,`f12`,`f16`,`f20`,`f24`,`f28` | 8 | Quad-aligned |

- `f0` and `f1` are hardwired to 0.0 (both single and double precision reads return zero).
- For double precision, the even-numbered register names the pair (e.g., `f2` means the 64-bit value in `f2:f3`).
- For 128-bit, the quad-aligned register names the group (e.g., `f4` means `f4:f5:f6:f7`).

**LLVM register class definitions** (from `I860RegisterInfo.td`):
```
GPR:        R0-R31 (R0 excluded from allocation)
GPRNoR0:    R1-R31
FPR:        F0-F31 (F0/F1 excluded from allocation)
FPRNoF0F1:  F2-F31
FPR64:      Even-numbered pairs (F2, F4, ..., F30)
VR64:       64-bit vector pairs for SIMD (F2F3, F4F5, ..., F30F31)
```

### 2.3 Special FP Registers

| Register | Size | Purpose |
|----------|------|---------|
| `KR` | 64-bit | Constant register for PFADD/PFSUB dual operations |
| `KI` | 64-bit | Constant register for PFMUL dual operations |
| `T` | 64-bit | Temporary register connecting multiplier to adder pipeline |
| `MERGE` | 64-bit | Graphics merge register for pixel operations |

These are not directly addressable by general instructions but are used implicitly by pipelined dual-operation floating-point instructions (PFAM, PFSM, PFMAM, PFMSM).

### 2.4 Control Registers (accessed via `ld.c`/`st.c`)

| Index (3-bit) | Register | Full Name |
|----------------|----------|-----------|
| 0 | `fir` | Fault Instruction Register |
| 1 | `psr` | Processor Status Register |
| 2 | `dirbase` | Directory Base Register |
| 3 | `db` | Data Breakpoint Register |
| 4 | `fsr` | Floating-Point Status Register |
| 5 | `epsr` | Extended Processor Status Register |
| 6 | (reserved) | |
| 7 | (reserved) | |

### 2.5 PSR (Processor Status Register) Bit Fields

| Bit(s) | Field | Description |
|--------|-------|-------------|
| 0 | BR | Branch flag |
| 1 | BW | Branch direction (taken/not taken) |
| 2 | CC | Condition Code (set by pfgt/pfle/pfeq comparisons) |
| 3 | LCC | Load Condition Code (used by `bla` loop instruction) |
| 4 | IM | Interrupt Mask |
| 5 | PIM | Previous Interrupt Mask |
| 6 | U | User mode |
| 7 | PU | Previous User mode |
| 8 | IT | Instruction Trap |
| 9 | IN | Interrupt pending |
| 10 | IAT | Instruction Access Trap |
| 11 | DAT | Data Access Trap |
| 12 | FT | Floating-Point Trap |
| 13 | DS | Delayed Switch (trap during DIM transition) |
| 14 | DIM | Dual Instruction Mode active |
| 15 | KNF | Kill Next Floating-point instruction |
| 17-21 | PM | Pixel Mask (5 bits, for `pst.d` pixel store) |
| 22-23 | PS | Pixel Size (00=8-bit, 01=16-bit, 10=32-bit) |
| 24-31 | SC | Shift Count (8 bits) |

### 2.6 EPSR (Extended Processor Status Register) Bit Fields

| Bit(s) | Field | Description |
|--------|-------|-------------|
| 0 | BE | Big Endian mode (0=little, 1=big) |
| 1 | OF | Integer Overflow Flag (set by adds/addu/subs/subu) |
| 2 | WP | Write Protect |
| 3 | INT | Interrupt pin state |
| 4-5 | DCS | Data Cache Size (read-only) |
| 6-7 | ICS | Instruction Cache Size (read-only) |
| 8 | PBM | Pipeline bypass mode |
| 9 | IL | Interlock |
| 16-23 | TYPE | Processor type ID |
| 24-31 | STEP | Stepping ID |

### 2.7 FSR (Floating-Point Status Register) Bit Fields

| Bit(s) | Field | Description |
|--------|-------|-------------|
| 0-1 | RM | Rounding Mode: 00=nearest, 01=down, 10=up, 11=truncate |
| 2 | TI | Trap on Inexact |
| 3 | SI | Sticky Inexact |
| 4 | FTE | Floating-point Trap Enable |
| 5 | SE | Source Exception |
| 6-8 | IRP/MRP/ARP | Result Precision for Integer/Multiply/Adder pipes |
| 9-14 | Trap flags | Various FP exception flags |
| 20 | LRP | Load Result Precision |

### 2.8 DIRBASE Register

| Bit(s) | Field | Description |
|--------|-------|-------------|
| 0 | ATE | Address Translation Enable |
| 1 | CS8 | Code size 8 |
| 4 | ITI | Invalidate TLB on write |
| 5 | BL | Bus Lock |
| 12-31 | DTB | Directory Table Base (page frame address) |

---

## 3. Thread State (from NeXTSTEP Mach headers)

The `i860_thread_state_regs` structure (532 bytes) represents a complete i860 context:

```c
struct i860_thread_state_regs {
    int     ireg[31];       // r1-r31 (r0 always zero, not saved)
    int     freg[30];       // f2-f31 (f0/f1 always zero, not saved)
    int     psr;            // Processor Status Register
    int     epsr;           // Extended PSR
    int     db;             // Data Breakpoint Register
    int     pc;             // Program Counter
    int     _padding_;
    /* FPU pipeline state */
    double  Mres3, Ares3;   // Pipeline stage 3
    double  Mres2, Ares2;   // Pipeline stage 2
    double  Mres1, Ares1;   // Pipeline stage 1
    double  Ires1;          // Integer result
    double  Lres3m, Lres2m, Lres1m;  // Load pipeline stages
    double  KR, KI, T;     // Special FP registers
    int     Fsr3, Fsr2, Fsr1;  // FSR pipeline snapshots
    int     Mergelo32;      // MERGE register low 32 bits
    int     Mergehi32;      // MERGE register high 32 bits
};
```

---

## 4. Addressing Modes

The i860 uses a **load/store architecture**. Only load and store instructions access memory.

| Mode | Syntax | Effective Address |
|------|--------|-------------------|
| Register + register | `ld.l rs1(rs2),rd` | EA = rs1 + rs2 |
| Register + displacement | `ld.l #imm16(rs2),rd` | EA = rs2 + sign_extend(imm16) |
| Register + register w/ autoincrement | `fld.d rs1(rs2)++,fd` | EA = rs1 + rs2; rs2 += size |
| Register + displacement w/ autoincrement | `fld.d #imm16(rs2)++,fd` | EA = rs2 + sext(imm16); rs2 = EA |
| PC-relative (branches) | `br target` | EA = PC + sign_extend(disp << 2) |
| 5-bit immediate (bte/btne) | `bte #imm5,rs2,target` | Compares zero-extended 5-bit imm vs rs2 |

**32-bit constant construction** (two instructions):
```asm
orh     ha%address, r0, r16    ; Load high 16 bits
or      lo%address, r16, r16   ; OR in low 16 bits
```

---

## 5. Endianness

- **Default**: Little-endian
- **Configurable** via `EPSR.BE` bit (bit 0):
  - BE = 0: Little-endian
  - BE = 1: Big-endian
- Instructions are always fetched in the same byte order regardless of data endianness

The Mach-O CPU subtype encodes endianness:
```c
#define CPU_SUBTYPE_LITTLE_ENDIAN  0
#define CPU_SUBTYPE_BIG_ENDIAN     1
```

---

## 6. Pipeline Architecture

The i860 has four independent execution pipelines:

| Pipeline | Stages | Operations |
|----------|--------|------------|
| Integer ALU | 4 (fetch, decode, execute, writeback) | Integer arithmetic, logic, shifts, address calc |
| FP Adder | 3 | FP add, subtract, comparisons, conversions |
| FP Multiplier | 2-3 | FP multiply, reciprocal, reciprocal sqrt |
| Graphics | 1 | 64-bit integer SIMD, pixel operations, Z-buffer |

### Dual-Instruction Mode

**Single-instruction mode** (default): One 32-bit instruction per cycle.

**Dual-instruction mode** (activated by D bit = bit 9 in FP instructions):
- Fetches 64-bit VLIW pairs: one core (integer) + one FP instruction
- Both execute simultaneously
- Can achieve 3 operations/clock: ALU + FP multiply + FP add
- `PSR.DIM` bit tracks current mode

The pipelines are **program-accessible** (VLIW-style):
- Compiler/programmer manages scheduling
- No hardware out-of-order execution
- Pipeline results exposed through KR, KI, T, MERGE registers

---

## 7. Branch Delay Slots

| Instruction | Delay Slot | Description |
|-------------|-----------|-------------|
| `br` | 0 | Unconditional branch |
| `call` | 0 | Call subroutine |
| `bc` | 0 | Branch if CC set (non-delayed) |
| `bc.t` | **1** | Branch if CC set (delayed) |
| `bnc` | 0 | Branch if CC clear (non-delayed) |
| `bnc.t` | **1** | Branch if CC clear (delayed) |
| `bte` | 0 | Branch if equal |
| `btne` | 0 | Branch if not equal |
| `bri` | 0 | Branch indirect |
| `bla` | **1** | Branch on LCC and Add (loop accelerator) |
| `calli` | 0 | Call indirect |

The `.t` suffix indicates a **delayed** branch: the instruction immediately following is executed before control transfers to the target.

---

## 8. Memory Model

- **32-bit virtual address space** (4 GB)
- Two-level page table (Intel 386/486 compatible)
- Page sizes: 4 KB (XR/XP), 4 MB (XP only)
- TLB: 64 entries, 4-way set-associative (+ 16 large-page entries on XP)
- Harvard cache: separate I-cache and D-cache
- 64-bit instruction bus, 128-bit data bus

---

## 9. Data Types

| Type | Size | Description |
|------|------|-------------|
| Byte | 8-bit | Signed/unsigned integer |
| Short | 16-bit | Signed/unsigned integer |
| Long/Word | 32-bit | Signed/unsigned integer |
| Single float | 32-bit | IEEE 754 |
| Double float | 64-bit | IEEE 754 |
| Pixel | 8/16/32-bit | Graphics pixel (PSR.PS selects size) |
| Quad/Vector | 128-bit | Four 32-bit or two 64-bit values |

---

## 10. References

- Intel *i860 64-Bit Microprocessor Programmer's Reference Manual*, May 1991 (Doc 240875-001)
  - PDF: `bitsavers.org/components/intel/i860/240875-001`
  - Local: `/Users/jvindahl/Development/nextdimension/docs/i860/reference/i860-reference.pdf`
- Intel *i860 XP Microprocessor Data Book*, May 1991 (Doc 240874-001)
- MAME i860 emulator: `mamedev/mame/src/devices/cpu/i860/`
- Local MAME port: `/Users/jvindahl/Development/nextdimension/tools/mame-i860/`
- Local LLVM backend: `/Users/jvindahl/Development/nextdimension/llvm-i860/`
- NeXTSTEP headers: `/Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/includes/I860_HEADERS_EXTRACTED.h`
