# Intel i860 Instruction Set — Complete Inventory

*Every instruction in the ISA, categorized and annotated for implementation tracking*

## Summary

| Category | Count | Priority |
|----------|-------|----------|
| Integer ALU | 30 | Phase 1 |
| Shift Operations | 7 | Phase 1 |
| Memory Operations | 29 | Phase 1 |
| Control Flow | 14 | Phase 1 |
| Floating-Point | 45 | Phase 3 |
| Graphics Operations | 7 | Phase 5 |
| System Operations | 8 | Phase 2 |
| Dual Operations | 22 | Phase 5 |
| i860XP-Specific | 10 | Phase 5 |
| **Total** | **~172** | |

---

## 1. Integer ALU Operations (30)

### Basic Arithmetic (16)

| # | Instruction | Opcode | Format | Description |
|---|-------------|--------|--------|-------------|
| 1 | `adds` (reg) | 0x24 | A | Signed add, sets EPSR.OF |
| 2 | `adds` (imm) | 0x25 | B | Signed add immediate |
| 3 | `addu` (reg) | 0x20 | A | Unsigned add |
| 4 | `addu` (imm) | 0x21 | B | Unsigned add immediate |
| 5 | `subs` (reg) | 0x26 | A | Signed subtract, sets EPSR.OF |
| 6 | `subs` (imm) | 0x27 | B | Signed subtract immediate |
| 7 | `subu` (reg) | 0x22 | A | Unsigned subtract |
| 8 | `subu` (imm) | 0x23 | B | Unsigned subtract immediate |

### Logical Operations (14)

| # | Instruction | Opcode | Format | Description |
|---|-------------|--------|--------|-------------|
| 9 | `and` (reg) | 0x30 | A | Bitwise AND |
| 10 | `and` (imm) | 0x31 | B | AND immediate |
| 11 | `andh` | 0x33 | B | AND high 16 bits (imm << 16) |
| 12 | `andnot` (reg) | 0x34 | A | AND NOT |
| 13 | `andnot` (imm) | 0x35 | B | AND NOT immediate |
| 14 | `andnoth` | 0x37 | B | AND NOT high 16 bits |
| 15 | `or` (reg) | 0x38 | A | Bitwise OR |
| 16 | `or` (imm) | 0x39 | B | OR immediate |
| 17 | `orh` | 0x3B | B | OR high 16 bits (imm << 16) |
| 18 | `xor` (reg) | 0x3C | A | Bitwise XOR |
| 19 | `xor` (imm) | 0x3D | B | XOR immediate |
| 20 | `xorh` | 0x3F | B | XOR high 16 bits |

### Pseudo-ops

| # | Pseudo | Expansion |
|---|--------|-----------|
| 21 | `nop` | `shl r0,r0,r0` (0xA0000000) |
| 22 | `mov rs,rd` | `or rs,r0,rd` |

## 2. Shift Operations (7)

| # | Instruction | Opcode | Format | Description |
|---|-------------|--------|--------|-------------|
| 23 | `shl` (reg) | 0x28 | A | Shift left |
| 24 | `shl` (imm) | 0x29 | B | Shift left immediate |
| 25 | `shr` (reg) | 0x2A | A | Logical shift right |
| 26 | `shr` (imm) | 0x2B | B | Logical shift right immediate |
| 27 | `shra` (reg) | 0x2E | A | Arithmetic shift right |
| 28 | `shra` (imm) | 0x2F | B | Arithmetic shift right immediate |
| 29 | `shrd` | 0x2C | A | Shift right double (64-bit) |

## 3. Memory Operations (29)

### Integer Load/Store (12)

| # | Instruction | Opcode | Description |
|---|-------------|--------|-------------|
| 30 | `ld.b` (reg) | 0x00 | Load byte, register addressing |
| 31 | `ld.b` (imm) | 0x01 | Load byte, displacement |
| 32 | `ld.s` (reg) | 0x04 | Load short, register addressing |
| 33 | `ld.s` (imm) | 0x05 | Load short, displacement |
| 34 | `ld.l` (reg) | 0x04 | Load long, register addressing |
| 35 | `ld.l` (imm) | 0x05 | Load long, displacement |
| 36 | `st.b` | 0x03 | Store byte |
| 37 | `st.s` | 0x07 | Store short |
| 38 | `st.l` | 0x07 | Store long |
| 39 | `ld.c` | 0x0C | Load control register |
| 40 | `st.c` | 0x0E | Store control register |
| 41 | `flush` | 0x0D | Cache flush |

### FP Load/Store (11)

| # | Instruction | Opcode | Description |
|---|-------------|--------|-------------|
| 42 | `fld.l` (reg) | 0x08 | FP load single, register |
| 43 | `fld.l` (imm) | 0x09 | FP load single, displacement |
| 44 | `fld.d` (reg) | 0x08 | FP load double, register |
| 45 | `fld.d` (imm) | 0x09 | FP load double, displacement |
| 46 | `fld.q` (reg) | 0x08 | FP load quad, register |
| 47 | `fld.q` (imm) | 0x09 | FP load quad, displacement |
| 48 | `fst.l` (reg) | 0x0A | FP store single, register |
| 49 | `fst.l` (imm) | 0x0B | FP store single, displacement |
| 50 | `fst.d` (reg) | 0x0A | FP store double, register |
| 51 | `fst.d` (imm) | 0x0B | FP store double, displacement |
| 52 | `fst.q` (reg) | 0x0A | FP store quad |

### Pipelined FP Load (3) + Pixel Store (1) + XP I/O (6)

| # | Instruction | Opcode | Description |
|---|-------------|--------|-------------|
| 53 | `pfld.l` | 0x18/0x19 | Pipelined FP load single |
| 54 | `pfld.d` | 0x18/0x19 | Pipelined FP load double |
| 55 | `pfld.q` | 0x18/0x19 | Pipelined FP load quad (XP) |
| 56 | `pst.d` | 0x0F | Pixel store double |
| 57-62 | `ldio/stio.{b,s,l}` | escape | XP I/O operations |

## 4. Control Flow (14)

| # | Instruction | Opcode | Delay? | Description |
|---|-------------|--------|--------|-------------|
| 63 | `br` | 0x1A | No | Unconditional branch |
| 64 | `call` | 0x1B | No | Call (saves to r1) |
| 65 | `bc` | 0x1C | No | Branch if CC set |
| 66 | `bc.t` | 0x1D | **Yes** | Branch if CC set, delayed |
| 67 | `bnc` | 0x1E | No | Branch if CC clear |
| 68 | `bnc.t` | 0x1F | **Yes** | Branch if CC clear, delayed |
| 69 | `bte` (reg) | 0x16 | No | Branch if equal |
| 70 | `bte` (imm5) | 0x17 | No | Branch if equal, immediate |
| 71 | `btne` (reg) | 0x14 | No | Branch if not equal |
| 72 | `btne` (imm5) | 0x15 | No | Branch if not equal, imm |
| 73 | `bla` | 0x2D | **Yes** | Branch on LCC and Add |
| 74 | `bri` | 0x10 | No | Branch indirect |
| 75 | `calli` | escape 0x02 | No | Call indirect |
| 76 | `trap` | 0x11 | No | Software trap |

## 5. Floating-Point (45)

### Basic FP (10 with precision variants)

| # | Instruction | FP Op | Description |
|---|-------------|-------|-------------|
| 77-79 | `fadd.{ss,sd,dd}` | 0x30 | FP add |
| 80-82 | `fsub.{ss,sd,dd}` | 0x31 | FP subtract |
| 83-86 | `fmul.{ss,sd,ds,dd}` | 0x20 | FP multiply |

### Pipelined FP (9)

| # | Instruction | FP Op | Description |
|---|-------------|-------|-------------|
| 87-89 | `pfadd.{ss,sd,dd}` | 0x30+P | Pipelined FP add |
| 90-92 | `pfsub.{ss,sd,dd}` | 0x31+P | Pipelined FP subtract |
| 93-95 | `pfmul.{ss,sd,dd}` | 0x20+P | Pipelined FP multiply |

### Special FP (11)

| # | Instruction | FP Op | Description |
|---|-------------|-------|-------------|
| 96-98 | `frcp.{ss,sd,dd}` | 0x22 | Reciprocal |
| 99-101 | `frsqr.{ss,sd,dd}` | 0x23 | Reciprocal sqrt |
| 102-104 | `fix.{ss,sd,dd}` | 0x32 | Float to int |
| 105-107 | `ftrunc.{ss,sd,dd}` | 0x3A | Truncate |
| 108-111 | `famov.{ss,sd,ds,dd}` | 0x33 | FP move |
| 112 | `fxfr` | 0x40 | FP-to-integer transfer |
| 113 | `ixfr` | 0x02 (primary) | Integer-to-FP transfer |

### FP Integer (2)

| # | Instruction | FP Op | Description |
|---|-------------|-------|-------------|
| 114-115 | `fiadd.{ss,dd}` | 0x49 | Integer add on FP bits |
| 116-117 | `fisub.{ss,dd}` | 0x4D | Integer subtract on FP bits |

### FP Comparisons (6)

| # | Instruction | FP Op | Description |
|---|-------------|-------|-------------|
| 118-119 | `pfgt.{ss,dd}` | 0x34 | Greater than (sets CC) |
| 120-121 | `pfle.{ss,dd}` | 0x35 | Less or equal (sets CC) |
| 122-123 | `pfeq.{ss,dd}` | 0x35 | Equal (sets CC) |

### FP Pseudo-ops

| # | Pseudo | Expansion |
|---|--------|-----------|
| 124 | `fnop` | 0xB0000000 |
| 125 | `fmov.xx` | `famov` |

## 6. Graphics Operations (7)

| # | Instruction | FP Op | Description |
|---|-------------|-------|-------------|
| 126 | `faddp` | 0x50 | Pixel add with merge |
| 127 | `faddz` | 0x51 | FP add with Z-buffer |
| 128 | `fzchkl` | 0x57 | Z-check lower |
| 129 | `fzchks` | 0x5F | Z-check stencil |
| 130 | `pfzchkl` | 0x57+P | Pipelined Z-check lower |
| 131 | `pfzchks` | 0x5F+P | Pipelined Z-check stencil |
| 132 | `form.dd` | 0x5A | Graphics OR merge |

## 7. System Operations (8)

| # | Instruction | Encoding | Description |
|---|-------------|----------|-------------|
| 133 | `trap` | 0x11 | Software trap |
| 134 | `intovr` | escape 0x04 | Integer overflow trap |
| 135 | `flush` | 0x0D | Cache flush |
| 136 | `lock` | escape 0x01 | Bus lock |
| 137 | `unlock` | escape 0x07 | Bus unlock |
| 138 | `ld.c` | 0x0C | Load control register |
| 139 | `st.c` | 0x0E | Store control register |
| 140 | `fmlow.dd` | 0x21 | Multiply low double |

## 8. Dual Operations (22)

| # | Family | DPC Variants | Description |
|---|--------|-------------|-------------|
| 141-156 | `pfam.{dpc}` | 16 | Pipelined FP add and multiply |
| 157-172 | `pfsm.{dpc}` | 16 | Pipelined FP subtract and multiply |
| 173-187 | `pfmam.{dpc}` | 15 | Pipelined FP multiply and add |
| 188-202 | `pfmsm.{dpc}` | 15 | Pipelined FP multiply and subtract |

DPC codes: r2p1, r2pt, r2ap1, r2apt, i2p1, i2pt, i2ap1, i2apt, rat1p2, m12apm, ra1p2, m12ttpa, iat1p2, m12tpm, ia1p2, m12tpa

## 9. i860XP-Specific (10)

| # | Instruction | Description |
|---|-------------|-------------|
| 203 | `ldio.b` | Load I/O byte |
| 204 | `ldio.s` | Load I/O short |
| 205 | `ldio.l` | Load I/O long |
| 206 | `stio.b` | Store I/O byte |
| 207 | `stio.s` | Store I/O short |
| 208 | `stio.l` | Store I/O long |
| 209 | `ldint` | Load interrupt vector |
| 210 | `scyc` | Special cycles broadcast |
| 211 | `pfld.q` (pipelined) | Pipelined FP load quad 128-bit |
| 212 | `pfmul3.dd` | 3-stage pipelined multiply |

---

## Sources

- Emulator instruction status: `/Users/jvindahl/Development/nextdimension/emulator/i860-core/docs/i860-instruction-status.md`
- MAME decoder: `/Users/jvindahl/Development/nextdimension/tools/mame-i860/i860dec.hxx`
- Encoding database: `/Users/jvindahl/Development/nextdimension/data/i860/i860-encodings.json`
- Intel i860 Programmer's Reference Manual, Appendix A
