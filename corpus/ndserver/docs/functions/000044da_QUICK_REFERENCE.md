# FUN_000044da - Quick Reference Card

## Function Identity
- **Address**: 0x000044da
- **Size**: 280 bytes (70 instructions)
- **Type**: PostScript Graphics Operator Handler
- **Operator Code**: 0x6d (ASCII 'm')
- **Likely Operation**: PostScript moveto/graphics transformation

## Function Signature
```c
int PSGraphicsOperator_Phase1(
    int operand_count,      // 8(A6)
    int context1,           // 12(A6)
    int context2,           // 16(A6)
    int context3,           // 20(A6)
    void* output_ptr1,      // 24(A6) → A3
    void* output_ptr2       // 28(A6) → A4
);
// Returns: D0 = error code (0=success, negative=error)
```

## Execution Overview

| Phase | Actions | Key Instructions |
|-------|---------|------------------|
| **Setup** | Frame setup, register save | link.w A6,-0x30; movem.l save |
| **Init** | Load globals, set constants | move.l from 0x7ae8-0x7af0 |
| **Build** | Create packet in buffer | bsr.l 0x050029c0 (packet builder) |
| **Validate** | Check type & format | cmpi.l #0xd1, buffer[0x14] |
| **Extract** | Copy results to outputs | move.l buffer[0x24],(A3) |
| **Return** | Cleanup and exit | movem.l restore; unlk A6; rts |

## Stack Frame Layout

```
+0x1c: arg5_output2 ← A4
+0x18: arg4_output1 ← A3
+0x14: arg3_context3
+0x10: arg2_context2
+0x0c: arg1_context1
+0x08: arg0_operand_count
+0x04: return address
─────────────────────────
 0x00: saved A6
-0x04: save_arg3
-0x08: global_7af0
-0x0c: save_arg2
-0x10: global_7aec
-0x14: save_arg1
-0x18: global_7ae8
-0x1c: operator_code(0x6d)
-0x20: lib_result
-0x24: lib_result_save
-0x28: size_0x100
-0x2c: buffer_size
-0x2d: flag_byte
-0x30: packet_buffer[48]
```

## Key Register Usage

| Register | Purpose | Status |
|----------|---------|--------|
| D0 | Return value | Final return to caller |
| D1 | Compare constant | 0x30, 0x20, 1 |
| D2 | Packet result | Work register |
| A2 | Buffer pointer | Points to -0x30(A6) |
| A3 | Output1 pointer | From arg4 |
| A4 | Output2 pointer | From arg5 |
| A6 | Frame pointer | Set by link.w |

## PostScript Packet Structure (48 bytes)

```
Offset   Bytes  Purpose
0x00-03   4     Packet header
0x04-07   4     Size field (0x30 or 0x20)
0x08-0b   4     Reserved
0x0c-0f   4     Reserved
0x10-13   4     Reserved
0x14-17   4     Type ID (must be 0xd1 ✓)
─────────────────────────────
0x18-1b   4     Validation1 (== global[0x7af4])
0x1c-1f   4     Return value / result
0x20-23   4     Validation2 (== global[0x7af8])
0x24-27   4     Output_value1 → *A3
0x28-2b   4     Validation3 (== global[0x7afc])
0x2c-2f   4     Output_value2 → *A4
```

## Error Codes

| Code | Hex | Meaning |
|------|-----|---------|
| 0 | 0x00 | Success |
| -300 | -0x12c | Validation failed (global mismatch) |
| -301 | -0x12d | Invalid packet type (not 0xd1) |
| -202 | -0xca | Special error (triggers handler 0x0500295a) |
| Other | varies | OS/library error |

## Control Flow Summary

```
1. Setup frame & registers
2. Load globals (0x7ae8-0x7af0)
3. Call 0x05002960 (OS init) → D0
4. Build packet via 0x050029c0 → D2
   ├─ If D2 == 0: continue
   ├─ If D2 == -0xca: call 0x0500295a, return
   └─ Else: return D2 (error)
5. Validate packet type
   └─ If buffer[0x14] != 0xd1: return -0x12d
6. Validate size/type byte
   └─ If (D2!=0x30 && D2!=0x20) || D0!=1: return -0x12c
7. Conditional extraction:
   ├─ Path A: D2==0x30 && D0==1
   │  ├─ Validate globals
   │  ├─ If buffer[0x1c]!=0: return buffer[0x1c]
   │  └─ Else: extract outputs
   └─ Path B: D2==0x20 && D0==1 && buffer[0x1c]!=0
      └─ Validate globals, return buffer[0x1c]
8. Return D0 (success code or error)
```

## Library Function Calls

| Address | Called At | Purpose |
|---------|-----------|---------|
| 0x05002960 | 0x4530 | Graphics context init |
| 0x050029c0 | 0x454a | PostScript packet builder |
| 0x0500295a | 0x4560 | Error handler (if D2==-0xca) |

## Security Assessment

| Aspect | Status | Notes |
|--------|--------|-------|
| **Buffer Overflow** | ✅ Safe | Fixed 48-byte buffer, no user input |
| **Null Pointer** | ✅ Safe | Validated before dereference |
| **Out of Bounds** | ✅ Safe | Fixed offsets, no indexing |
| **Use After Free** | ✅ Safe | Stack variables only |
| **Format String** | ✅ Safe | No string operations |

## Instruction Statistics

| Category | Count | Details |
|----------|-------|---------|
| Data Transfer | 32 | move.l, movea.l, moveq, lea |
| Arithmetic/Logical | 12 | cmp.l, tst.l, clr.l |
| Branch | 18 | bsr.l, beq.b, bne.b, bra.b |
| Special | 8 | link.w, unlk, movem.l, bfextu, rts |
| **Total** | **70** | 280 bytes |

## Known Callers

**None found in disassembly** - Likely called via:
- Function pointer table (operator dispatch)
- Operator code 0x6d lookup
- Dynamic dispatch by PostScript server

## Similar Functions

- **FUN_000045f2** (operator 0x6e): Same pattern, 280 bytes
- **FUN_00004822** (referenced in similar operators)
- **FUN_0000493a** (referenced in similar operators)

All PostScript operators follow this structure.

## Analysis Completeness

| Section | Status | Coverage |
|---------|--------|----------|
| Disassembly | ✅ Complete | All 70 instructions annotated |
| Register Usage | ✅ Complete | All registers documented |
| Stack Frame | ✅ Complete | Layout mapped |
| Data Structures | ✅ Complete | Packet & local vars |
| Control Flow | ✅ Complete | All paths traced |
| Error Handling | ✅ Complete | All codes documented |
| Hardware Access | ✅ Complete | None (indirect via library) |
| Call Graph | ⚠️ Partial | Callers unknown (likely dispatch) |
| Operator Identity | ⚠️ Probable | Code 0x6d → moveto likely |

## Confidence Levels

- **Purpose**: MEDIUM-HIGH (PostScript operator confirmed)
- **Structure**: HIGH (Layout clear and logical)
- **Errors**: HIGH (Codes consistent and well-defined)
- **Caller**: MEDIUM (Dispatch-driven, not visible)
- **Operator**: MEDIUM (0x6d suggests moveto, not confirmed)

---

**Document Version**: 1.0
**Analysis Date**: November 9, 2025
**Tool**: Ghidra 11.2.1 / m68k disassembly
**Total Analysis**: 1,672 lines (comprehensive guide)
**Quick Reference**: This document
