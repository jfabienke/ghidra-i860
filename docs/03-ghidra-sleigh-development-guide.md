# Ghidra SLEIGH Development Guide for Intel i860

*Patterns, strategies, and practical guidance for implementing the i860 processor module*

## 1. Required Files

| File | Purpose |
|------|---------|
| `i860.slaspec` | Top-level SLEIGH spec (or `i860_le.slaspec` / `i860_be.slaspec` for bi-endian) |
| `i860.sinc` | Shared definitions (registers, tokens, core instructions) |
| `i860_fpu.sinc` | Floating-point instruction definitions |
| `i860.ldefs` | Language definitions XML (registers module with Ghidra) |
| `i860.pspec` | Processor specification XML (program counter, register groups) |
| `i860.cspec` | Compiler specification XML (calling conventions, stack) |
| `i860.opinion` | Loader hints (can be empty initially) |

### Extension Directory Structure

```
ghidra-i860/
├── data/
│   └── languages/
│       ├── i860.ldefs
│       ├── i860.pspec
│       ├── i860.cspec
│       ├── i860.opinion
│       ├── i860_le.slaspec       # Little-endian entry point
│       ├── i860_be.slaspec       # Big-endian entry point
│       ├── i860.sinc             # Core definitions + integer instructions
│       └── i860_fpu.sinc         # Floating-point instructions
├── src/main/java/                # Java sources (loader patches if needed)
├── extension.properties
└── Module.manifest
```

---

## 2. Core SLEIGH Definitions

### 2.1 Top-Level slaspec (i860_le.slaspec)

```sleigh
@define ENDIAN "little"
@define ADDRSIZE "4"
@include "i860.sinc"
@include "i860_fpu.sinc"
```

### 2.2 Address Spaces

```sleigh
define endian=$(ENDIAN);
define alignment=4;

define space ram      type=ram_space      size=$(ADDRSIZE) default;
define space register type=register_space size=4;
```

### 2.3 Register Definitions

```sleigh
# Integer registers (32 x 32-bit)
define register offset=0x0000 size=4 [
    r0  r1  r2  r3  r4  r5  r6  r7
    r8  r9  r10 r11 r12 r13 r14 r15
    r16 r17 r18 r19 r20 r21 r22 r23
    r24 r25 r26 r27 r28 r29 r30 r31
];

# Program counter
define register offset=0x0100 size=4 [ PC ];

# Control registers
define register offset=0x0200 size=4 [
    fir psr dirbase db fsr epsr
];

# 32 single-precision (32-bit) FP registers
define register offset=0x1000 size=4 [
    f0  f1  f2  f3  f4  f5  f6  f7
    f8  f9  f10 f11 f12 f13 f14 f15
    f16 f17 f18 f19 f20 f21 f22 f23
    f24 f25 f26 f27 f28 f29 f30 f31
];

# 16 double-precision (64-bit) FP registers (overlapping pairs)
define register offset=0x1000 size=8 [
    fd0  _  fd2  _  fd4  _  fd6  _
    fd8  _  fd10 _  fd12 _  fd14 _
    fd16 _  fd18 _  fd20 _  fd22 _
    fd24 _  fd26 _  fd28 _  fd30 _
];
# NOTE: The _ placeholders skip the odd slots. An alternative
# approach uses explicit byte offsets or defines a separate set.

# Special FP registers (64-bit)
define register offset=0x2000 size=8 [
    KR KI T MERGE
];

# Context register for DIM tracking
define register offset=0x3000 size=4 [ contextreg ];
define context contextreg
    DIM_MODE = (0,0) noflow
;
```

**Key insight from SPARC**: Use overlapping register definitions at the same offset for single/double/quad views. SPARC does exactly this pattern.

### 2.4 Token Definition

```sleigh
define token instr(32)
    # Primary opcode
    op          = (26,31)

    # Register fields
    rs2         = (21,25)        # source register 2
    rd          = (16,20)        # destination register
    rs1         = (11,15)        # source register 1

    # FP register fields (same bit positions, different attach)
    fsrc2       = (21,25)
    fdest       = (16,20)
    fsrc1       = (11,15)

    # Control register field
    creg        = (21,23)        # 3-bit control register selector

    # Immediate fields
    imm16       = (0,15)
    simm16      = (0,15) signed
    imm26       = (0,25)
    simm26      = (0,25) signed
    imm5        = (11,15)        # 5-bit immediate for bte/btne

    # FP control bits
    fp_p        = (10,10)        # Pipelined flag
    fp_d        = (9,9)          # Dual-instruction mode bit
    fp_s        = (8,8)          # Source precision
    fp_r        = (7,7)          # Result precision
    fp_op       = (0,6)          # 7-bit FP sub-opcode

    # Split branch offset fields
    sbroff_hi   = (16,20)
    sbroff_lo   = (0,10)

    # Core escape sub-opcode
    esc_op      = (0,2)

    # Load/store size bits
    ls_bit0     = (0,0)
    ls_bit28    = (28,28)

    # FP load/store flags
    fls_size    = (1,2)          # FP operand size selector
    fls_auto    = (0,0)          # Auto-increment flag
;
```

### 2.5 Attach Variables

```sleigh
attach variables [ rs1 rs2 rd ] [
    r0  r1  r2  r3  r4  r5  r6  r7
    r8  r9  r10 r11 r12 r13 r14 r15
    r16 r17 r18 r19 r20 r21 r22 r23
    r24 r25 r26 r27 r28 r29 r30 r31
];

attach variables [ fsrc1 fsrc2 fdest ] [
    f0  f1  f2  f3  f4  f5  f6  f7
    f8  f9  f10 f11 f12 f13 f14 f15
    f16 f17 f18 f19 f20 f21 f22 f23
    f24 f25 f26 f27 f28 f29 f30 f31
];
```

---

## 3. Instruction Patterns

### 3.1 Integer ALU (register form)

```sleigh
:addu rs1, rs2, rd  is  op=0x20 & rs1 & rs2 & rd {
    rd = rs1 + rs2;
}

:subu rs1, rs2, rd  is  op=0x22 & rs1 & rs2 & rd {
    rd = rs1 - rs2;
}

:adds rs1, rs2, rd  is  op=0x24 & rs1 & rs2 & rd {
    rd = rs1 + rs2;
    # TODO: set EPSR.OF on signed overflow
}
```

### 3.2 Integer ALU (immediate form)

```sleigh
:addu simm16, rs2, rd  is  op=0x21 & simm16 & rs2 & rd {
    rd = rs2 + simm16;
}
```

### 3.3 Logical with High Immediate

```sleigh
:orh imm16, rs2, rd  is  op=0x3B & imm16 & rs2 & rd {
    rd = rs2 | (imm16 << 16);
}
```

### 3.4 r0 Hardwired to Zero

Use a sub-table to force zero for r0 reads (MIPS pattern):

```sleigh
RSsrc1: rs1  is  rs1               { export rs1; }
RSsrc1: rs1  is  rs1 & rs1=0       { export 0:4; }
```

### 3.5 Branch Instructions

```sleigh
# Unconditional branch (no delay slot)
:br target  is  op=0x1A & simm26 [ target = inst_start + (simm26 << 2); ] {
    goto target;
}

# Call (saves return address in r1)
:call target  is  op=0x1B & simm26 [ target = inst_start + (simm26 << 2); ] {
    r1 = inst_next;
    call target;
}

# Branch if CC set (non-delayed)
:bc target  is  op=0x1C & simm26 [ target = inst_start + (simm26 << 2); ] {
    if (psr[2,1] != 0) goto target;  # CC bit is PSR bit 2
}

# Branch if CC set (delayed - has delay slot)
:bc.t target  is  op=0x1D & simm26 [ target = inst_start + (simm26 << 2); ] {
    local cond:1 = (psr[2,1] != 0);
    delayslot(1);
    if (cond) goto target;
}
```

### 3.6 Delay Slot Pattern (from MIPS/SPARC)

Critical: compute condition/target BEFORE `delayslot(1)`, then branch AFTER.

```sleigh
:bnc.t target  is  op=0x1F & simm26 [ target = inst_start + (simm26 << 2); ] {
    local cond:1 = (psr[2,1] == 0);
    delayslot(1);
    if (cond) goto target;
}

:bla rs1, rs2, target  is  op=0x2D & rs1 & rs2 & sbroff_hi & sbroff_lo
    [ target = inst_start + (((sbroff_hi << 11) | sbroff_lo) << 2); ] {
    local cond:1 = (psr[3,1] != 0);   # LCC bit
    rs2 = rs1 + rs2;                    # Add operation
    # Update LCC based on result
    delayslot(1);
    if (cond) goto target;
}
```

### 3.7 Branch Indirect / Call Indirect

```sleigh
:bri rs1  is  op=0x10 & rs1 {
    local target = rs1;
    goto [target];
}

# Return pseudo-instruction
:ret  is  op=0x10 & rs1=1 {
    return [r1];
}
```

---

## 4. Floating-Point Instructions

### 4.1 Basic FP Operations

```sleigh
# FP add single precision
:fadd.ss fsrc1, fsrc2, fdest  is  op=0x12 & fp_op=0x30 & fp_s=0 & fp_r=0 & fp_p=0 & fsrc1 & fsrc2 & fdest {
    fdest = fsrc1 f+ fsrc2;
}

# FP multiply double precision (uses overlapping 64-bit registers)
:fmul.dd fsrc1, fsrc2, fdest  is  op=0x12 & fp_op=0x20 & fp_s=1 & fp_r=1 & fp_p=0 & fsrc1 & fsrc2 & fdest {
    # Need to reference 64-bit register aliases here
    local a:8 = fsrc1;   # 64-bit read
    local b:8 = fsrc2;
    fdest = a f* b;
}
```

### 4.2 Pipelined FP (immediate-result semantics)

For Ghidra, model pipelined operations with immediate results (correct for data flow, ignores timing):

```sleigh
:pfadd.ss fsrc1, fsrc2, fdest  is  op=0x12 & fp_op=0x30 & fp_p=1 & fp_s=0 & fp_r=0 & fsrc1 & fsrc2 & fdest {
    fdest = fsrc1 f+ fsrc2;
}
```

### 4.3 FP Comparisons (set CC flag in PSR)

```sleigh
:pfgt.ss fsrc1, fsrc2, fdest  is  op=0x12 & fp_op=0x34 & fp_s=0 & fp_r=0 & fsrc1 & fsrc2 & fdest {
    local cond:1 = (fsrc1 f> fsrc2);
    # Set CC bit in PSR
    psr = (psr & 0xFFFFFFFB) | (zext(cond) << 2);
}
```

### 4.4 Operations Without Direct P-Code Equivalent

```sleigh
define pcodeop CacheFlush;
define pcodeop BusLock;
define pcodeop BusUnlock;
define pcodeop IntegerOverflowTrap;
define pcodeop DualModeBegin;
define pcodeop DualModeEnd;
define pcodeop PixelStore;
define pcodeop ZBufferCheck;

:flush rs1  is  op=0x0D & rs1 {
    CacheFlush(rs1);
}

:lock  is  op=0x13 & esc_op=0x01 {
    BusLock();
}
```

---

## 5. Dual-Instruction Mode Strategy

### Recommended Approach: Sequential with Context Variable

DIM does not affect program correctness, only performance. Model as sequential:

1. When D bit (bit 9) is set in an FP instruction, note the mode transition
2. Disassemble subsequent instructions as normal 32-bit words
3. The decompiler will correctly track data flow

```sleigh
# DIM transition tracking (optional, for annotation)
:d.fadd.ss fsrc1, fsrc2, fdest  is  op=0x12 & fp_op=0x30 & fp_d=1 & fp_s=0 & fp_r=0 & fsrc1 & fsrc2 & fdest
    [ DIM_MODE=1; globalset(inst_next, DIM_MODE); ] {
    fdest = fsrc1 f+ fsrc2;
}
```

This is acceptable because parallel execution does not change the semantics that matter for reverse engineering.

---

## 6. XML Configuration Files

### 6.1 Language Definition (i860.ldefs)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="i860"
           endian="little"
           size="32"
           variant="XR"
           version="1.0"
           slafile="i860_le.sla"
           processorspec="i860.pspec"
           id="i860:LE:32:XR">
    <description>Intel i860 XR Little Endian</description>
    <compiler name="default" spec="i860.cspec" id="default"/>
  </language>
  <language processor="i860"
           endian="big"
           size="32"
           variant="XR"
           version="1.0"
           slafile="i860_be.sla"
           processorspec="i860.pspec"
           id="i860:BE:32:XR">
    <description>Intel i860 XR Big Endian</description>
    <compiler name="default" spec="i860.cspec" id="default"/>
  </language>
</language_definitions>
```

### 6.2 Processor Spec (i860.pspec)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
  <programcounter register="PC"/>
  <register_data>
    <register name="r0" group="General" hidden="true"/>
    <register name="r1" group="General"/>
    <register name="r2" group="General"/>
    <register name="psr" group="Control"/>
    <register name="epsr" group="Control"/>
    <register name="fsr" group="Control"/>
    <register name="fir" group="Control"/>
    <register name="dirbase" group="Control"/>
    <register name="db" group="Control"/>
    <register name="contextreg" hidden="true"/>
  </register_data>
</processor_spec>
```

### 6.3 Compiler Spec (i860.cspec)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
  <data_organization>
    <integer_size value="4"/>
    <pointer_size value="4"/>
    <float_size value="4"/>
    <double_size value="8"/>
  </data_organization>
  <global>
    <range space="ram"/>
  </global>
  <stackpointer register="r2" space="ram" growth="negative"/>
  <default_proto>
    <prototype name="default" extrapop="0" stackshift="0">
      <input>
        <pentry minsize="1" maxsize="4"><register name="r16"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r17"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r18"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r19"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r20"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r21"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r22"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r23"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r24"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r25"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r26"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="r27"/></pentry>
      </input>
      <output>
        <pentry minsize="1" maxsize="4"><register name="r16"/></pentry>
      </output>
      <unaffected>
        <register name="r2"/>
        <register name="r3"/>
        <register name="r4"/>
        <register name="r5"/>
        <register name="r6"/>
        <register name="r7"/>
        <register name="r8"/>
        <register name="r9"/>
        <register name="r10"/>
        <register name="r11"/>
        <register name="r12"/>
        <register name="r13"/>
        <register name="r14"/>
        <register name="r15"/>
      </unaffected>
    </prototype>
  </default_proto>
</compiler_spec>
```

---

## 7. Implementation Order

### Phase 1: Minimal Disassembly
1. Token and register definitions
2. Integer ALU (adds, addu, subs, subu, and, or, xor, shifts)
3. Load/store (ld.b, ld.s, ld.l, st.b, st.s, st.l)
4. Branches (br, call, bc, bnc, bc.t, bnc.t, bri, calli)
5. `orh`/`or` pair for 32-bit constant loading
6. Pseudo-ops (nop, mov, ret)

### Phase 2: Control Flow Correctness
7. Delay slot handling (bc.t, bnc.t, bla)
8. bte/btne conditional branches
9. Split branch offset reconstruction
10. ld.c/st.c control register access

### Phase 3: Floating-Point Disassembly
11. Basic FP ops (fadd, fsub, fmul with all precision variants)
12. FP load/store (fld.l, fld.d, fld.q, fst.l, fst.d)
13. FP specials (frcp, frsqr, fix, ftrunc, famov, fxfr, ixfr)
14. FP comparisons (pfgt, pfle, pfeq)

### Phase 4: P-Code Semantics for Decompiler
15. Integer ALU p-code semantics
16. Load/store p-code (address calculation)
17. Branch semantics (condition evaluation)
18. FP p-code (f+, f-, f*, conversions)
19. Calling convention tuning (cspec)

### Phase 5: Advanced Features
20. Pipelined FP operations
21. Auto-increment addressing modes
22. Graphics operations (faddp, faddz, fzchkl, form, pst.d)
23. Dual-operation instructions (PFAM, PFSM, PFMAM, PFMSM)
24. XP-specific instructions (ldio, stio, ldint, scyc, pfmul3)

---

## 8. Regression Testing Strategy

Use the existing Rust disassembler to generate golden output:

```bash
# Generate golden listing from known firmware
i860-disassembler --format json --show-addresses ND_i860_CLEAN.bin > golden.json

# Compare Ghidra output against golden listing
```

The Rust disassembler at `/Users/jvindahl/Development/nextdimension/i860-disassembler/` achieves 99.93% match against MAME and covers ~99% of the ISA.

---

## 9. Key Pitfalls

1. **Even/odd opcode convention**: Register vs. immediate forms differ by LSB of 6-bit opcode
2. **Split branch offsets**: bte/btne/bla use non-contiguous offset fields
3. **FP register aliasing**: Must handle 32/64/128-bit views at same register space offset
4. **r0/f0/f1 hardwired zero**: Decompiler needs to know these always read zero
5. **Two calling conventions**: GCC ABI vs SPEA ABI use different SP/FP register assignments
6. **Delay slots only on `.t` branches and `bla`**: Other branches have no delay slot

---

## 10. References

- Ghidra SLEIGH Language Reference: `ghidra.re/ghidra_docs/languages/html/sleigh.html`
- Ghidra Toy processor: `Ghidra/Processors/Toy/data/languages/`
- Ghidra SPARC processor: `Ghidra/Processors/Sparc/data/languages/` (closest architecture pattern)
- Ghidra MIPS processor: `Ghidra/Processors/MIPS/data/languages/` (delay slot patterns)
