# Binary Formats, Platforms, and Calling Conventions

*Everything needed for loaders, relocation handlers, and compiler specs*

## 1. Platforms That Used the i860

| System | Manufacturer | i860 Variant | Use | Binary Format |
|--------|-------------|-------------|-----|---------------|
| NeXTdimension | NeXT | 33 MHz XR | Display board GPU | Mach-O |
| SPEA Fire / FirePro | SPEA | 33 MHz XR | PC graphics accelerator | COFF (0x0090) |
| iPSC/860 | Intel | XR | Supercomputer nodes | ELF / COFF |
| Paragon XP/S | Intel | XP | Massively parallel | ELF / COFF |
| FX/2800 | Alliant | XR | Parallel server | Unknown |
| Vistra 800 | Stardent | 40 MHz XR | Unix workstation | COFF / a.out |
| RealityEngine | SGI | XP | Geometry engine | Proprietary |

---

## 2. Mach-O Format (NeXTdimension)

### CPU Type and Subtype

```c
#define CPU_TYPE_I860               ((cpu_type_t) 7)  /* conflicts with I386! */
/* NeXT planned to change to 14, firmware uses 0x0F (15) in practice */

#define CPU_SUBTYPE_LITTLE_ENDIAN   ((cpu_subtype_t) 0)
#define CPU_SUBTYPE_BIG_ENDIAN      ((cpu_subtype_t) 1)
```

**Historical note**: CPU_TYPE_I860 was originally assigned value 7, which conflicted with CPU_TYPE_I386 (also 7). Internal NeXT memos (Mike Paquette, 10/16/90) planned to change it to 14, but the actual NeXTdimension firmware uses value 15 (0x0F) in Mach-O headers.

### Ghidra Mach-O Loader Integration

Ghidra's MachoLoader needs the i860 CPU type mapped to the Ghidra language ID. If the mapping is missing:
1. Ghidra may refuse to load or detect as "Raw Binary"
2. Patch: add CPU_TYPE_I860 constant and map to `i860:LE:32:XR`

### Relocation Types (from `mach-o/i860/reloc.h`)

```c
enum reloc_type_i860 {
    I860_RELOC_VANILLA,    // Standard 32-bit relocation
    I860_RELOC_PAIR,       // Follows HIGH or HIGHADJ (r_address has meaning)
    I860_RELOC_HIGH,       // High 16 bits in instruction; PAIR follows with low 16
    I860_RELOC_LOW0,       // Low 16 bits, no shift
    I860_RELOC_LOW1,       // Low 16 bits >> 1 (halfword aligned)
    I860_RELOC_LOW2,       // Low 16 bits >> 2 (word aligned)
    I860_RELOC_LOW3,       // Low 16 bits >> 3 (doubleword aligned)
    I860_RELOC_LOW4,       // Low 16 bits >> 4 (quad aligned)
    I860_RELOC_SPLIT0,     // Split across bits [20:14] and [10:0], no shift
    I860_RELOC_SPLIT1,     // Split >> 1
    I860_RELOC_SPLIT2,     // Split >> 2
    I860_RELOC_HIGHADJ,    // HIGH with sign-extension adjustment
    I860_RELOC_BRADDR,     // 26-bit PC-relative word displacement
    I860_RELOC_SECTDIFF    // Section difference (PAIR follows)
};
```

**Why so many relocation types**: The i860 has only 16-bit immediate fields but needs to load 32-bit addresses. Different instructions encode these bits in different positions and with different alignment requirements. The `HIGH`/`LOW` pair is for `orh`+`or` sequences. The `SPLIT` variants handle store instructions where the immediate is split across non-contiguous bit fields.

---

## 3. COFF Format (SPEA Fire / APX2 Toolchain)

### COFF Magic Number

```
i860 COFF Magic: 0x0090
```

### File Structure

```
COFF Header (20 bytes)
├── Magic: 0x0090
├── Num Sections
├── Timestamp
├── Symbol Table Offset
├── Num Symbols
├── Optional Header Size
└── Flags

Optional Header (28+ bytes)
├── Text Size, Data Size, BSS Size
├── Entry Point
├── Text Start, Data Start

Section Headers (40 bytes each)
├── Name (.text, .data, .bss)
├── Virtual/Physical Address
├── Size and Offsets
└── Relocation info
```

### Known COFF Binaries

| Binary | Size | Entry Point | Notes |
|--------|------|-------------|-------|
| BOOT.OUT | 13,786 B | 0x03fe3fe0 | SPEA Fire v1.45 |
| BOOT2.OUT | 27,800 B | 0x03fb0000 | SPEA Fire v1.50, 71 sections |

### COFF Relocation Types

```
i860 DIR32  - 32-bit direct
i860 IPAIR  - Instruction pair
i860 PAIR   - Data pair
i860 HIGH   - High 16 bits
i860 LOW0-4 - Low bits with alignment shifts
```

A Python COFF parser exists at `/Users/jvindahl/Development/spea-fire/analysis/parse_i860_coff.py`.

---

## 4. ELF Format

### ELF Machine Type

```c
EM_860 = 7    // Intel 80860 (from ELF specification)
```

Defined in Linux kernel headers (`include/uapi/linux/elf-em.h`) and LLVM (`llvm/include/llvm/BinaryFormat/ELF.h`).

GNU binutils produces ELF32 output for i860 via `as860` (GAS).

---

## 5. Calling Conventions

### GCC ABI (NeXTSTEP / Unix System V)

| Registers | Role | Saved By |
|-----------|------|----------|
| `r0` | Always zero | N/A |
| `r1` | Return address | Caller |
| `r2` (sp) | Stack pointer | Callee |
| `r3` (fp) | Frame pointer | Callee |
| `r4`-`r15` | General purpose | **Callee-saved** |
| `r16` | First integer arg / return value | Caller |
| `r17`-`r27` | Args 2-12 | Caller |
| `r28` | Argument pointer | Caller |
| `r29` | Static chain | Caller |
| `r30`-`r31` | General purpose | Caller |
| `f0`-`f1` | Always zero | N/A |
| `f2`-`f7` | General FP | **Callee-saved** |
| `f8`-`f15` | FP arguments (8 words) | Caller |
| `f16`-`f31` | General FP | Caller |

**Argument passing**: First 12 words of integer args in `r16`-`r27`. First 8 words of FP args in `f8`-`f15`. Overflow to stack.

**Return values**: Integer in `r16`. FP in FP register.

**Stack**: Grows downward. No push/pop instructions — explicit `addu`/`subu` on `sp`.

### SPEA / APX2 ABI (Alternate)

```asm
; Register conventions from SPEA APX2 assembler:
;   r0       = always zero
;   r1       = return address
;   r2-r3    = return values
;   r4-r11   = caller-saved (arguments)
;   r12-r15  = caller-saved (temporaries)
;   r16-r27  = callee-saved
;   r28      = frame pointer (fp)
;   r29      = stack pointer (sp)
;   r30-r31  = reserved
```

Note the difference: SPEA uses `r28`=fp, `r29`=sp, while GCC uses `r2`=sp, `r3`=fp.

### Stack Frame Pattern (from firmware analysis)

```asm
; Function entry
addu    -16, sp, sp         ; Allocate stack frame
st.l    r1, 0(sp)           ; Save return address

; Function body...

; Function exit
ld.l    0(sp), r1           ; Restore return address
addu    16, sp, sp          ; Deallocate frame
bri     r1                  ; Return (branch indirect through link register)
nop                         ; Delay slot (if applicable)
```

---

## 6. Memory Maps (Known Platforms)

### NeXTdimension Board

```
0x00000000 - 0x01FFFFFF  i860 DRAM (up to 32 MB)
0x02000000 - 0x020FFFFF  VRAM (1 MB framebuffer)
0x02100000 - 0x021FFFFF  Additional VRAM (if present)
0x0F000000 - 0x0F00FFFF  ROM (64 KB, i860 firmware)
0xFF800000 - 0xFF80FFFF  NeXTdimension control registers
```

### SPEA Fire Board

```
0x00200000                G364 VRAM (framebuffer, 2 MB)
0x03FB0000                i860 DRAM start (code/data)
0x03FC0000                Stack top
0xE0000000                Mailbox (host communication)
0xF0000000                ROM / trap handlers
```

---

## 7. i860 Code Recognition Patterns

When analyzing unknown binaries, these patterns identify i860 code:

| Feature | Pattern |
|---------|---------|
| Alignment | 4-byte aligned instructions (RISC) |
| No stack frames | No LINK/UNLK (m68k) or PUSH/POP (x86) |
| Load/store only | Only `ld`/`st` access memory |
| Returns | `bri %rN` (branch indirect), NOT `RTS` or `RET` |
| Register count | 32 integer (`r0`-`r31`) + 32 FP (`f0`-`f31`) |
| NOP encoding | 0xA0000000 (`shl r0,r0,r0`) |
| Address loading | `orh`/`or` pairs for 32-bit constants |

### Anti-patterns (NOT i860)

| Pattern | Architecture |
|---------|-------------|
| `4E 5E 4E 75 4E 56` repeating | M68k (UNLK+RTS+LINK) |
| `55 89 E5` / `C9 C3` | x86 (PUSH EBP+MOV EBP,ESP / LEAVE+RET) |

---

## 8. Assembler Syntax Notes

The GNU assembler and APX2 assembler use slightly different syntax:

| Feature | GNU/AT&T (GAS) | APX2/Intel |
|---------|----------------|------------|
| Register prefix | `%r0`, `%f0` | `r0`, `f0` |
| Immediate prefix | `$` or none | `#` or none |
| Default syntax | AT&T/SVR4 | Intel |
| Dual-mode block | N/A | `.dual` / `.enddual` |
| Section directives | `.text`, `.data`, `.bss` | `.text`, `.data`, `.bss` |
| Constant definition | `.equ NAME, VALUE` | `.equ NAME, VALUE` |

### Assembler Directives (from APX2 as860)

```asm
.text                    ; Code section
.data                    ; Data section
.bss                     ; Uninitialized data
.align N                 ; Alignment
.word VALUE              ; 32-bit constant
.long VALUE              ; 32-bit constant
.short VALUE             ; 16-bit constant
.byte VALUE              ; 8-bit constant
.double VALUE            ; 64-bit FP constant
.float VALUE             ; 32-bit FP constant
.extern SYMBOL           ; External symbol
.globl SYMBOL            ; Global symbol
.dual                    ; Begin dual-instruction mode block
.enddual                 ; End dual-instruction mode block
.equ NAME, VALUE         ; Constant definition
```

---

## Sources

- `/Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/includes/I860_HEADERS_EXTRACTED.h`
- `/Users/jvindahl/Development/spea-fire/analysis/parse_i860_coff.py`
- `/Users/jvindahl/Development/spea-fire/analysis/i860_dispatcher/dispatcher.asm`
- `/Users/jvindahl/Development/previous/reverse-engineering/03-firmware-analysis/code-patterns/I860_CODE_PATTERNS.md`
- `/Users/jvindahl/Development/previous/reverse-engineering/02-hardware-specs/NEXTDIMENSION_MEMORY_MAP_COMPLETE.md`
- GCC i860 backend (`config/i860/i860.h`)
- LLVM ELF.h (`EM_860 = 7`)
