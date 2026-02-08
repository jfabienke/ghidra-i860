# Intel i860 Instruction Encoding Reference

*Complete opcode maps and bit-level encoding for Ghidra SLEIGH development*

## 1. Instruction Word Structure

All instructions are **32 bits wide**, aligned on 4-byte boundaries.

Primary opcode: **bits [31:26]** (6 bits, 64 entries).

### Register Field Positions (all 5 bits)

| Field | Bits | Extraction | Used For |
|-------|------|------------|----------|
| src1 / fsrc1 | [15:11] | `(insn >> 11) & 0x1f` | Source register 1 |
| dest / fdest | [20:16] | `(insn >> 16) & 0x1f` | Destination register |
| src2 / fsrc2 | [25:21] | `(insn >> 21) & 0x1f` | Source register 2 |
| creg | [23:21] | `(insn >> 21) & 0x7` | Control register (3 bits only) |

Integer and FP instructions use the **same bit positions**. The register file accessed is determined by the opcode.

---

## 2. Instruction Format Types

### Format A: Register-Register-Register (int_12d / flop_12d)

```
 31    26 25  21 20  16 15  11 10        0
+--------+------+------+------+-----------+
| opcode | src2 | dest | src1 |  varies   |
+--------+------+------+------+-----------+
   6 bits  5 bits 5 bits 5 bits   11 bits
```

Used by: `addu`, `subu`, `adds`, `subs`, `shl`, `shr`, `shra`, `shrd`, `and`, `or`, `xor`, `andnot`, `trap`, and all FP register operations.

### Format B: Immediate-Register-Register (int_i2d)

```
 31    26 25  21 20  16 15                0
+--------+------+------+------------------+
| opcode | src2 | dest |    imm16         |
+--------+------+------+------------------+
   6 bits  5 bits 5 bits     16 bits
```

Used by: immediate variants of ALU ops (`addu #imm`), `andh`, `orh`, `xorh`, `andnot #imm`, `andnoth`.

**Encoding convention**: Even opcodes = register-register, odd opcodes = immediate form.

### Format C: Long Branch (int_L) — 26-bit displacement

```
 31    26 25                              0
+--------+--------------------------------+
| opcode |       lbroff (26 bits)         |
+--------+--------------------------------+
   6 bits            26 bits
```

Target = PC + sign_extend(lbroff << 2)

Used by: `br`, `call`, `bc`, `bc.t`, `bnc`, `bnc.t`

### Format D: Short Branch with Registers (int_12S)

```
 31    26 25  21 20  16 15  11 10        0
+--------+------+------+------+-----------+
| opcode | src2 |sbroff| src1 |  sbroff   |
|        |      | (hi) |      |   (lo)    |
+--------+------+------+------+-----------+
```

The 16-bit branch offset is **split**: high 5 bits in [20:16], low 11 bits in [10:0].
Reconstruction: `split_imm16 = ((insn >> 5) & 0xf800) | (insn & 0x07ff)`

Used by: `bte`, `btne`, `bla`

### Format E: Short Branch with Immediate (int_i2S)

Same as Format D but src1 field [15:11] is a 5-bit zero-extended immediate.

Used by: `bte #imm5`, `btne #imm5`

### Format F: Load/Store Integer

```
 31    26 25  21 20  16 15                0
+--------+------+------+------------------+
| opcode | src2 | dest |  imm16 / src1    |
+--------+------+------+------------------+
```

- **Bit 26** (within opcode) selects addressing mode:
  - 0 = register+register: `EA = src1 + src2`
  - 1 = displacement+register: `EA = sext(imm16) + src2`
- **Bits 28 and 0** encode operand size:
  - `size_table[((insn >> 27) & 2) | (insn & 1)]` = {1, 1, 2, 4} bytes

### Format G: Load/Store Floating-Point

```
 31    26 25  21 20  16 15  11 10        0
+--------+------+------+------+-----------+
| opcode | src2 | dest | src1 |   flags   |
+--------+------+------+------+-----------+
```

- **Bit 26**: reg+reg vs displacement+reg addressing
- **Bits [2:1]**: operand size: `{8, 4, 16, 4}` bytes
- **Bit 0**: auto-increment flag (`++`)

### Format H: Floating-Point Operations (primary opcode 0x12)

```
 31    26 25  21 20  16 15  11 10  9  8  7 6       0
+--------+------+------+------+---+--+--+--+--------+
|  0x12  | fsrc2| fdest| fsrc1| P | D| S| R| FP_op  |
+--------+------+------+------+---+--+--+--+--------+
   6 bits  5 bits 5 bits 5 bits  1  1  1  1  7 bits
```

| Bit | Name | Meaning |
|-----|------|---------|
| 10 | P | Pipelined (1 = pipelined operation, prefix `p`) |
| 9 | D | Dual-instruction mode transition (prefix `d.`) |
| 8 | S | Source precision (0=single, 1=double) |
| 7 | R | Result precision (0=single, 1=double) |

Precision suffixes from S,R bits:
| S | R | Suffix |
|---|---|--------|
| 0 | 0 | `.ss` |
| 0 | 1 | `.sd` |
| 1 | 0 | `.ds` |
| 1 | 1 | `.dd` |

### Format I: Core Escape (primary opcode 0x13)

Uses bits [2:0] to select from 8 sub-operations.

### Format J: Control Register (ld.c / st.c)

Uses 3-bit creg field at bits [23:21] to select from 8 control registers.

---

## 3. Primary Opcode Map (bits [31:26])

| Hex | Binary | Instruction | Format | Notes |
|-----|--------|-------------|--------|-------|
| 0x00 | 000000 | `ld.b` (reg+reg) | F | Load byte, reg addressing |
| 0x01 | 000001 | `ld.b` (disp+reg) | F | Load byte, displacement |
| 0x02 | 000010 | `ixfr` | A | Integer-to-FP register transfer |
| 0x03 | 000011 | `st.b` | F | Store byte |
| 0x04 | 000100 | `ld.{s,l}` (reg+reg) | F | Load short/long, reg (bit 0 selects) |
| 0x05 | 000101 | `ld.{s,l}` (disp+reg) | F | Load short/long, displacement |
| 0x06 | 000110 | (reserved) | — | |
| 0x07 | 000111 | `st.{s,l}` | F | Store short/long |
| 0x08 | 001000 | `fld.{l,d,q}` (reg+reg) | G | FP load, reg addressing |
| 0x09 | 001001 | `fld.{l,d,q}` (disp+reg) | G | FP load, displacement |
| 0x0A | 001010 | `fst.{l,d,q}` (reg+reg) | G | FP store, reg addressing |
| 0x0B | 001011 | `fst.{l,d,q}` (disp+reg) | G | FP store, displacement |
| 0x0C | 001100 | `ld.c` | J | Load control register |
| 0x0D | 001101 | `flush` | — | Cache line flush |
| 0x0E | 001110 | `st.c` | J | Store to control register |
| 0x0F | 001111 | `pst.d` | G | Pixel store double |
| 0x10 | 010000 | `bri` | A | Branch indirect |
| 0x11 | 010001 | `trap` | A | Software trap |
| 0x12 | 010010 | **FP escape** | H | 128-entry FP sub-table |
| 0x13 | 010011 | **Core escape** | I | 8-entry core sub-table |
| 0x14 | 010100 | `btne` (reg) | D | Branch if not equal (register) |
| 0x15 | 010101 | `btne` (imm5) | E | Branch if not equal (immediate) |
| 0x16 | 010110 | `bte` (reg) | D | Branch if equal (register) |
| 0x17 | 010111 | `bte` (imm5) | E | Branch if equal (immediate) |
| 0x18 | 011000 | `pfld.{l,d,q}` (reg+reg) | G | Pipelined FP load |
| 0x19 | 011001 | `pfld.{l,d,q}` (disp+reg) | G | Pipelined FP load |
| 0x1A | 011010 | `br` | C | Unconditional branch (26-bit) |
| 0x1B | 011011 | `call` | C | Call subroutine (26-bit) |
| 0x1C | 011100 | `bc` | C | Branch if CC set |
| 0x1D | 011101 | `bc.t` | C | Branch if CC set (delayed) |
| 0x1E | 011110 | `bnc` | C | Branch if CC clear |
| 0x1F | 011111 | `bnc.t` | C | Branch if CC clear (delayed) |
| 0x20 | 100000 | `addu` (reg) | A | Add unsigned, reg-reg |
| 0x21 | 100001 | `addu` (imm) | B | Add unsigned, immediate |
| 0x22 | 100010 | `subu` (reg) | A | Subtract unsigned, reg-reg |
| 0x23 | 100011 | `subu` (imm) | B | Subtract unsigned, immediate |
| 0x24 | 100100 | `adds` (reg) | A | Add signed, reg-reg |
| 0x25 | 100101 | `adds` (imm) | B | Add signed, immediate |
| 0x26 | 100110 | `subs` (reg) | A | Subtract signed, reg-reg |
| 0x27 | 100111 | `subs` (imm) | B | Subtract signed, immediate |
| 0x28 | 101000 | `shl` (reg) | A | Shift left |
| 0x29 | 101001 | `shl` (imm) | B | Shift left immediate |
| 0x2A | 101010 | `shr` (reg) | A | Shift right logical |
| 0x2B | 101011 | `shr` (imm) | B | Shift right logical immediate |
| 0x2C | 101100 | `shrd` | A | Shift right double |
| 0x2D | 101101 | `bla` | D | Branch on LCC and Add (delayed) |
| 0x2E | 101110 | `shra` (reg) | A | Shift right arithmetic |
| 0x2F | 101111 | `shra` (imm) | B | Shift right arithmetic immediate |
| 0x30 | 110000 | `and` (reg) | A | Bitwise AND |
| 0x31 | 110001 | `and` (imm) | B | Bitwise AND immediate |
| 0x32 | 110010 | (reserved) | — | |
| 0x33 | 110011 | `andh` | B | AND high 16 bits |
| 0x34 | 110100 | `andnot` (reg) | A | AND NOT |
| 0x35 | 110101 | `andnot` (imm) | B | AND NOT immediate |
| 0x36 | 110110 | (reserved) | — | |
| 0x37 | 110111 | `andnoth` | B | AND NOT high 16 bits |
| 0x38 | 111000 | `or` (reg) | A | Bitwise OR |
| 0x39 | 111001 | `or` (imm) | B | Bitwise OR immediate |
| 0x3A | 111010 | (reserved) | — | |
| 0x3B | 111011 | `orh` | B | OR high 16 bits |
| 0x3C | 111100 | `xor` (reg) | A | Bitwise XOR |
| 0x3D | 111101 | `xor` (imm) | B | Bitwise XOR immediate |
| 0x3E | 111110 | (reserved) | — | |
| 0x3F | 111111 | `xorh` | B | XOR high 16 bits |

---

## 4. Floating-Point Sub-Opcode Map (bits [6:0] when primary = 0x12)

### Multiply Unit Operations

| FP Op | Hex | Instruction | Description |
|-------|-----|-------------|-------------|
| 0x20 | 20 | `fmul.xx` | FP multiply |
| 0x21 | 21 | `fmlow.dd` | Multiply low (double only) |
| 0x22 | 22 | `frcp.xx` | Reciprocal approximation |
| 0x23 | 23 | `frsqr.xx` | Reciprocal square root |
| 0x24 | 24 | `pfmul3.dd` | 3-stage pipelined multiply (XP only) |

### Adder Unit Operations

| FP Op | Hex | Instruction | Description |
|-------|-----|-------------|-------------|
| 0x30 | 30 | `fadd.xx` | FP add |
| 0x31 | 31 | `fsub.xx` | FP subtract |
| 0x32 | 32 | `fix.xx` | Float to integer conversion |
| 0x33 | 33 | `famov.xx` | FP move via adder pipeline |
| 0x34 | 34 | `pfgt.xx` / `fgt.xx` | Greater-than comparison |
| 0x35 | 35 | `pfle.xx` / `fle.xx` | Less-or-equal comparison |
| 0x3A | 3A | `ftrunc.xx` | Truncate to integer |
| 0x35 | 35 | `pfeq.xx` / `feq.xx` | Equality comparison |

### Transfer Operations

| FP Op | Hex | Instruction | Description |
|-------|-----|-------------|-------------|
| 0x40 | 40 | `fxfr` | FP-to-integer register transfer |

### FP Integer Operations (Graphics)

| FP Op | Hex | Instruction | Description |
|-------|-----|-------------|-------------|
| 0x49 | 49 | `fiadd.xx` | Integer add on FP bit patterns |
| 0x4D | 4D | `fisub.xx` | Integer subtract on FP bit patterns |

### Graphics Operations

| FP Op | Hex | Instruction | Description |
|-------|-----|-------------|-------------|
| 0x50 | 50 | `faddp` | Pixel add with merge |
| 0x51 | 51 | `faddz` | FP add with Z-buffer check |
| 0x57 | 57 | `fzchkl` | Z-check lower |
| 0x5A | 5A | `form.dd` | Graphics OR merge |
| 0x5F | 5F | `fzchks` | Z-check stencil |

### Dual-Operation Instructions (FP ops 0x00-0x1F)

These simultaneously issue to both multiplier and adder pipelines:

| Range | Family | Description |
|-------|--------|-------------|
| 0x00-0x0F | PFAM/PFMAM | Pipelined FP add+multiply (16 DPC variants) |
| 0x10-0x1F | PFSM/PFMSM | Pipelined FP subtract+multiply (16 DPC variants) |

Each variant encodes a **Data Path Control (DPC)** code in the lower 4 bits, selecting from 16 possible routing configurations through KR, KI, T registers.

---

## 5. Core Escape Sub-Opcode Map (bits [2:0] when primary = 0x13)

| Code | Instruction | Description |
|------|-------------|-------------|
| 0x01 | `lock` | Bus lock |
| 0x02 | `calli` | Call indirect (via register) |
| 0x04 | `intovr` | Integer overflow trap |
| 0x07 | `unlock` | Bus unlock |

### i860XP Additional Core Escapes

| Code | Instruction | Description |
|------|-------------|-------------|
| 0x08 | `ldio` | Load I/O |
| 0x09 | `stio` | Store I/O |
| 0x0A | `ldint` | Load interrupt vector |
| 0x0B | `scyc` | Special cycles broadcast |

---

## 6. Pseudo-Instructions

| Pseudo | Actual Encoding | Machine Word |
|--------|----------------|--------------|
| `nop` | `shl r0,r0,r0` | 0xA0000000 |
| `fnop` | FP no-op | 0xB0000000 |
| `mov src,dst` | `or src,r0,dst` | Uses OR encoding |
| `fmov.xx fsrc,fdst` | `famov fsrc,fdst` | Uses famov encoding |
| `ret` | `bri r1` | Branch indirect via link register |

---

## 7. Key Encoding Constants

From GNU binutils / Apple cctools:

```
OP_PREFIX_MASK       = 0xFC000000   // bits [31:26]
PREFIX_FPU           = 0x48000000   // opcode 0x12
OP_FNOP              = 0xB0000000
OP_NOP               = 0xA0000000
DUAL_INSN_MODE_BIT   = 0x00000200   // bit 9 in FP instructions
LOGOP_MASK           = 0xC0000000
```

---

## 8. Sources

- `/Users/jvindahl/Development/nextdimension/data/i860/i860-encodings.json` — Complete JSON encoding database
- `/Users/jvindahl/Development/nextdimension/data/i860/i860-opcodes.txt` — Opcode quick reference
- `/Users/jvindahl/Development/nextdimension/tools/mame-i860/i860dec.hxx` — MAME decoder (3500+ lines)
- `/Users/jvindahl/Development/nextdimension/tools/mame-i860/i860dis.cpp` — MAME disassembler
- `/Users/jvindahl/Development/nextdimension/i860-disassembler/src/opcode_table.rs` — Rust opcode table
- Apple cctools `i860-opcode.h`
- GNU binutils `include/opcode/i860.h`
- Intel i860 Programmer's Reference Manual, Appendix B
