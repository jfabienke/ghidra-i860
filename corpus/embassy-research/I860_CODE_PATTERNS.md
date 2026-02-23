# Intel i860 Code Pattern Recognition Guide
## Distinctive Patterns for Identifying i860 Code vs Other Architectures

**Purpose**: Quick reference for identifying genuine i860 code vs contamination (m68k, x86, data)
**Date**: 2025-11-05
**Based on**: Analysis of verified NeXTdimension GaCK kernel code

---

## Executive Summary

### Key i860 Characteristics

1. **4-byte aligned instructions** (RISC architecture)
2. **No stack frame instructions** (no LINK/UNLK like m68k, no PUSH/POP like x86)
3. **Load/Store architecture** (only ld/st access memory)
4. **Branch indirect returns** (bri %rN, not RTS or RET)
5. **32 general registers** (r0-r31) + 32 FP registers (f0-f31)

---

## 1. Function Boundaries

### i860 Function Pattern

**Entry** (no standard prologue):
```assembly
; No fixed pattern - may start with any instruction
; Common: Load parameters, initialize registers
fff01348:  ffff14ec  xorh    0x14ec,%r31,%r31
fff0134c:  ff94e600  ld.b    %r18(%r7),%r31
```

**Exit** (bri - branch indirect):
```assembly
; Return via branch indirect (NOT "RTS")
fff014c4:  4160401c  bri     %r8        ; Branch to address in r8
fff01510:  4070e427  bri     %r28       ; Branch to address in r28
fff01540:  4070f467  bri     %r30       ; Branch to address in r30
fff01a7c:  40004294  bri     %r8        ; Branch to address in r8
```

**Hex Patterns for bri**:
- `40 xx xx xx` or `43 xx xx xx` (bri instruction range)
- Last byte often `27`, `48`, `64`, `67`, `6c`, `6f`, `84`, `94` (register encoding)

### NOT i860: m68k Function Pattern

**m68k Entry/Exit** (distinct 6-byte sequence):
```
4E 5E 4E 75 4E 56  =  UNLK A6 + RTS + LINK A6,#xx
      ^^^^ ^^^^^
      UNLK  RTS
```

If you see `4E 5E 4E 75 4E 56` repeating → **m68k code, NOT i860**

### NOT i860: x86 Function Pattern

**x86 Entry/Exit**:
```
55        =  PUSH EBP      (function entry)
89 E5     =  MOV EBP, ESP  (stack frame setup)
C9        =  LEAVE         (function exit)
C3        =  RET           (return)
```

---

## 2. Memory Access (Load/Store)

### i860 Load Instructions

**Format**: `ld.{b|s|l|d|q} offset(%rN),%rM`

```assembly
fff08000:  01006314  ld.b      %r12(%r8),%r0      ; Load byte
fff08024:  15880058  ld.s      88(%r12),%r8       ; Load short (16-bit)
fff01350:  f815ec00  ld.b      %r2(%r7),%r24      ; Load byte
```

**Hex Patterns**:
- Bytes 2-3 often encode registers: `ec 00`, `e6 00`, `40 00`, `94 00`
- Common opcodes: `0x` `01`, `14`, `15`, `16`, `f8`, `ec`, `e6`

### i860 Store Instructions

**Format**: `st.{b|s|l|d|q} %rN,offset(%rM)`

```assembly
fff08014:  d08401c0  st.b      %r8,16412(%r8)     ; Store byte (debug trace)
fff0801c:  cf81fec0  st.b      %r3,-14356(%r7)    ; Store byte
fff08030:  cf852ee0  st.b      %r10,-15634(%r7)   ; Store byte
```

**Critical Pattern**: `st.b %r8,16412(%r8)` appears at every PostScript operator entry
- Hex: `d0 84 01 c0` or similar
- Used as debug trace marker
- Writes operator ID to memory address 0x0000401C + ID

### NOT i860: Direct Memory Access

x86 and m68k can directly manipulate memory:
```
; x86: MOV [address], value
; m68k: MOVE.L D0,(A0)
```

i860 **CANNOT** - must always use load/store with register base.

---

## 3. Arithmetic & Logical Operations

### i860 Arithmetic

```assembly
fff08008:  80042840  ixfr      %r8,%f0            ; Integer to FP register
fff0800c:  f0ff4294  xor       %r8,%r7,%r31       ; XOR operation
fff08020:  b91df117  shra      %r30,%r8,%r29      ; Shift right arithmetic
fff08048:  b11df017  shrd      %r30,%r8,%r29      ; Shift right double
```

**Common Patterns**:
- `adds`, `addu`, `subs`, `subu` (signed/unsigned)
- `and`, `or`, `xor`, `andnot`, `andh`, `xorh`
- `shl`, `shr`, `shra`, `shrd`
- Three-operand format: `op %rA,%rB,%rDest`

### Register Naming

**General Purpose**: `%r0` through `%r31`
- `%r0` = always zero (hardwired)
- `%r1` = link register (return address for calls)
- `%r2-%r31` = general use

**Floating Point**: `%f0` through `%f31`

**If you see**:
- `%eax`, `%ebx`, `%esp` → x86
- `D0`, `D1`, `A0`, `A6` → m68k
- `%r0` through `%r31` → i860 ✓

---

## 4. Branch Instructions

### i860 Branches

**Unconditional**:
```assembly
6d08401c  call      0x042121a0    ; Function call
6c04006c  call      0x00102570    ; Function call
4160401c  bri       %r8           ; Branch indirect (return)
```

**Conditional** (delayed branch - next instruction executes):
```assembly
fff01464:  btne  %r8,%r12,0x00000190   ; Branch if not equal
fff01468:  btne  8,%r12,0x00010194     ; Branch if not equal
fff0146c:  bte   %r8,%r12,0xfffe0198   ; Branch if equal
```

**Patterns**:
- `call` → `6c`, `6d`, `6e`, `6f` prefix
- `bri` → `40` or `43` prefix
- `bte`, `btne`, `bla`, `bc`, `bnc` → various conditional branches

### NOT i860: Other Architectures

**m68k**: `BRA`, `BEQ`, `BNE`, `BSR`, `JSR`, `RTS`
- Hex: `60 xx`, `66 xx`, `67 xx`, `61 xx`, `4E BA`, `4E 75`

**x86**: `JMP`, `JE`, `JNE`, `CALL`, `RET`
- Hex: `E9`, `74`, `75`, `E8`, `C3`

---

## 5. Hardware Register Access (NeXTdimension Specific)

### Common MMIO Addresses

If code accesses these addresses, likely i860:

```
0x02000000 - 0x0200FFFF  MMIO registers (mailbox, DMA, video)
0x10000000 - 0x103FFFFF  VRAM (4MB frame buffer)
0xFFF00000 - 0xFFFFFFFF  ROM space (boot ROM)
0xF8000000 - 0xF800FFFF  DRAM (where kernel loads)
```

**Example**:
```assembly
; Loading from mailbox
ld.l  0x02000000(%r0),%r8    ; Read mailbox status

; Writing to VRAM
st.l  %r5,0x10000000(%r10)   ; Write pixel to framebuffer
```

**Pattern**: Look for immediate values with `0x02`, `0x10`, `0xFF` high bytes.

---

## 6. Instruction Density & Entropy

### i860 Code Characteristics

**Entropy**: 7.2 - 7.8 bits/byte
- High entropy (appears random)
- Dense binary code

**Printable Ratio**: 20-40%
- Low printable characters
- If >60% printable → likely text/data, not code

**Null Bytes**: <10%
- RISC code has few zero bytes
- If >30% nulls → likely padding/data structures

**4-Byte Alignment**:
- All instructions are 4 bytes
- No instruction can span alignment boundary

---

## 7. Quick Identification Tests

### Test 1: Hex Pattern Scan (10 seconds)

```bash
# Look for m68k function boundaries
xxd file.bin | grep "4e 5e 4e 75 4e 56"
# If found → m68k, NOT i860

# Look for i860 bri (returns)
xxd file.bin | grep -E "40 [0-9a-f]{2} [0-9a-f]{2} (27|48|64|67|6c)"
# If found → likely i860
```

### Test 2: Disassembly Coherence (30 seconds)

```bash
# Disassemble as i860
/path/to/i860disasm -b 0xF8000000 file.bin | head -50

# Look for:
# ✓ Coherent instructions (ld.b, st.l, adds, bri)
# ✓ Valid register names (%r0-%r31)
# ✓ Reasonable branch targets
# ✗ Lots of ".long" directives (undecoded bytes)
# ✗ Nonsense mnemonics from ASCII text
```

### Test 3: Hardware Fingerprint (1 minute)

```python
with open('file.bin', 'rb') as f:
    data = f.read()

# Check for NeXTdimension MMIO patterns
mailbox = data.count(b'\x02\x00')      # 0x0200xxxx
vram = data.count(b'\x10\x00')         # 0x1000xxxx
ramdac = data.count(b'\xFF\x20')       # 0xFF20xxxx

if mailbox + vram + ramdac > 50:
    print("Likely i860 code (hardware access patterns)")
else:
    print("No hardware patterns - likely data or wrong arch")
```

### Test 4: Function Density (2 minutes)

```python
# Count i860 bri instructions (returns)
bri_patterns = [
    b'\x40\x00', b'\x40\x01', b'\x40\x07', b'\x43\x14'
    # ... (various bri encodings)
]

bri_count = sum(data.count(pattern) for pattern in bri_patterns)

# For i860 code:
# High density: 20-50 functions per 4KB
# Low density: 1-5 functions per 4KB (might be data)
# Zero: Definitely not i860 code
```

---

## 8. Comparison Table

```
┌─────────────────────┬──────────────┬──────────────┬──────────────┐
│ Feature             │ i860         │ m68k         │ x86          │
├─────────────────────┼──────────────┼──────────────┼──────────────┤
│ Instruction Size    │ 4 bytes      │ 2-10 bytes   │ 1-15 bytes   │
│ Alignment           │ 4-byte       │ 2-byte       │ 1-byte       │
│ Function Entry      │ Varies       │ LINK A6      │ PUSH EBP     │
│ Function Exit       │ bri %rN      │ UNLK/RTS     │ LEAVE/RET    │
│ Register Names      │ %r0-%r31     │ D0-D7/A0-A7  │ EAX/EBX/etc  │
│ Memory Access       │ ld/st only   │ MOVE direct  │ MOV direct   │
│ Return Pattern      │ 40/43 xx xx  │ 4E 75        │ C3           │
│ Prologue/Epilogue   │ None fixed   │ 4E56/4E5E    │ 55 89 E5     │
│ Function Boundary   │ bri detect   │ UNLK+RTS+LINK│ RET detect   │
└─────────────────────┴──────────────┴──────────────┴──────────────┘
```

---

## 9. Real-World Examples from GaCK Kernel

### Verified i860 Code (Section 3 - PostScript Operators)

```assembly
fff08014:  d08401c0  st.b      %r8,16412(%r8)   ; Debug trace marker
fff08018:  80043940  ixfr      %r8,%f0          ; Transfer to FP reg
fff0801c:  cf81fec0  st.b      %r3,-14356(%r7)  ; Store to memory
fff08020:  b91df117  shra      %r30,%r8,%r29    ; Shift operation
fff08024:  15880058  ld.s      88(%r12),%r8     ; Load from offset
```

**Characteristics**:
- All 4-byte aligned
- Register names %r8, %r3, %r7, %r29, %r12, %f0
- Load/store pattern (ld.s, st.b)
- Arithmetic operations (shra, ixfr)
- Coherent when disassembled

### Verified m68k Code (Section 4/5 - Host Driver)

```
Hex:     4E 5E 4E 75 4E 56 00 00 2F 2E 00 08 61 FF
Disasm:  UNLK A6
         RTS
         LINK A6,#0
         MOVE.L 8(A6),-(A7)
         BSR.L func
```

**Characteristics**:
- Variable-length instructions
- Pattern `4E 5E 4E 75 4E 56` repeats every 50-200 bytes
- Register names D0-D7, A0-A7
- Stack operations (LINK, UNLK, MOVE to stack)

### PostScript Text (Section 4 - Contamination)

```
Hex:     09 5F 64 6F 43 6C 69 70 20 31 20 65 71 20 0A
ASCII:   ._doClip 1 eq \n
```

**Characteristics**:
- 89-98% printable ASCII characters
- Human-readable text
- Low entropy (5.5-6.5 bits/byte)
- Disassembles to nonsense in any architecture

---

## 10. Decision Tree

```
Is the code i860?

START
  │
  ├─→ Contains "4E 5E 4E 75 4E 56" pattern?
  │   YES → m68k code (NOT i860) ✗
  │   NO  → Continue
  │
  ├─→ Printable characters > 60%?
  │   YES → Text data (NOT i860) ✗
  │   NO  → Continue
  │
  ├─→ Disassembles coherently as i860?
  │   NO  → NOT i860 ✗
  │   YES → Continue
  │
  ├─→ Contains bri instructions (40/43 xx xx)?
  │   NO  → Probably NOT i860 ⚠
  │   YES → Continue
  │
  ├─→ Contains hardware MMIO patterns (0x02xx, 0x10xx)?
  │   NO  → Might be generic code ⚠
  │   YES → Continue
  │
  ├─→ 4-byte aligned throughout?
  │   NO  → NOT i860 ✗
  │   YES → Continue
  │
  └─→ LIKELY i860 CODE ✓
```

---

## 11. Common False Positives

### Random Data Can Look Like i860

**Problem**: Any 4-byte aligned data can decode as "valid" i860 instructions.

**Solution**: Look for coherence:
- Do branch targets make sense?
- Are there function boundaries (bri)?
- Does it access hardware registers?
- Is entropy in the 7.2-7.8 range?

### ASCII Text Decodes as "Instructions"

**Example**:
```
ASCII:    "pliC"
Hex:      70 69 6C 43
i860:     bc 0x01a5b114  (nonsense branch target)
```

**Solution**: Check printable ratio. If >60%, it's text.

---

## 12. Tools & Commands

### Extract and Disassemble

```bash
# Extract region from binary
dd if=firmware.bin of=section.bin bs=1 skip=OFFSET count=SIZE

# Disassemble with correct base address
/path/to/mame-i860/i860disasm -b 0xF8000000 section.bin > output.asm

# Count function boundaries (bri instructions)
grep -c "bri" output.asm
```

### Pattern Search

```bash
# Search for m68k patterns
xxd firmware.bin | grep "4e 5e 4e 75 4e 56"

# Search for i860 bri patterns
xxd firmware.bin | grep -E "40 [0-9a-f]{2} [0-9a-f]{2}"

# Extract strings (if many found, likely not code)
strings -n 10 firmware.bin | wc -l
```

### Python Analysis

```python
import struct

with open('firmware.bin', 'rb') as f:
    data = f.read()

# Check 4-byte alignment
for offset in range(0, len(data)-4, 4):
    instr = struct.unpack('>I', data[offset:offset+4])[0]

    # Check if bri instruction (simplified)
    opcode = (instr >> 26) & 0x3F
    if opcode == 0x10:  # bri opcode (simplified)
        print(f"bri at offset {offset:08X}")
```

---

## Summary Checklist

To confirm i860 code, verify:

- [ ] 4-byte aligned instructions
- [ ] Contains bri (branch indirect) for returns
- [ ] Register names %r0-%r31 and %f0-%f31
- [ ] Load/store architecture (ld.b, st.l, etc.)
- [ ] NO m68k patterns (4E 5E 4E 75 4E 56)
- [ ] NO x86 patterns (55 89 E5 / C3)
- [ ] Printable ratio < 50%
- [ ] Entropy 7.0-7.8 bits/byte
- [ ] Disassembles coherently
- [ ] May access 0x02000000, 0x10000000 (NeXTdimension hardware)

**If all checks pass → Genuine i860 code ✓**

---

**Document Status**: Complete
**Last Updated**: 2025-11-05
**Based On**: NeXTdimension GaCK kernel analysis (Sections 1-3 verified i860 code)
**Tool**: MAME i860 disassembler
