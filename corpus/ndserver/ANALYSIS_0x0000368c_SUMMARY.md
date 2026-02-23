# Function Analysis Summary: FUN_0000368c

**Address**: 0x0000368c (13964 decimal)
**Size**: 38 bytes (10 instructions)
**Date**: November 8, 2025
**Tool**: Ghidra 11.2.1 (m68k disassembly)
**Binary**: NDserver (Mach-O m68k executable)
**Priority**: HIGH
**Category**: Callback/Wrapper Function

---

## Quick Facts

| Property | Value |
|----------|-------|
| **Address** | 0x0000368c |
| **Decimal** | 13964 |
| **Size** | 38 bytes |
| **Instructions** | 10 |
| **Type** | Callback Wrapper / Adapter |
| **Complexity** | Low |
| **Hardware Access** | None |
| **Called By** | FUN_00006156 (1 caller) |
| **Calls** | 2 library functions |
| **Frame Size** | 0 bytes (no locals) |
| **Register Usage** | D0 only |

---

## Function Overview

**FUN_0000368c** is a **callback wrapper/adapter function** that implements a two-stage processing pipeline:

```
INPUT:  5 parameters from caller
        ↓
STAGE 1: Call 0x0500315e (string/data conversion)
        ↓
STAGE 2: Call 0x050032c6 (validation/processing)
        with result from Stage 1 + original context
        ↓
OUTPUT: Final result in D0
```

---

## What It Does (Step by Step)

1. **Accept 5 parameters** from caller
2. **Ignore arg1** (first parameter is not used)
3. **Push arg2-arg5** to stack
4. **Call 0x0500315e** (library function, likely string conversion)
   - Takes arg2-arg5 as input
   - Returns converted value in D0
5. **Push converted result** to stack
6. **Call 0x050032c6** (library function, validation callback)
   - Takes converted value (D0) as arg1
   - Takes original arg2-arg5 as context
   - Returns validation result in D0
7. **Return D0** to caller
8. **Unwind stack** and return

---

## Code Disassembly (Annotated)

```asm
0x0000368c:  link.w     A6,0x0                  ; Setup frame (no locals)
0x00003690:  move.l     (0x18,A6),-(SP)         ; Push arg5
0x00003694:  move.l     (0x14,A6),-(SP)         ; Push arg4
0x00003698:  move.l     (0x10,A6),-(SP)         ; Push arg3
0x0000369c:  move.l     (0xc,A6),-(SP)          ; Push arg2
0x000036a0:  bsr.l      0x0500315e              ; CALL conversion function
0x000036a6:  move.l     D0,-(SP)                ; Push result
0x000036a8:  bsr.l      0x050032c6              ; CALL validation function
0x000036ae:  unlk       A6                      ; Unwind frame
0x000036b0:  rts                                ; Return
```

---

## Calling Context

**Called by**: `FUN_00006156` at offset `0x000061d0`

**Calling code**:
```asm
0x000061bc:  move.l     (0x34,A0),-(SP)        ; Push arg5
0x000061c0:  move.l     (0x2c,A0),-(SP)        ; Push arg4
0x000061c4:  move.l     (0x24,A0),-(SP)        ; Push arg3
0x000061c8:  move.l     (0x1c,A0),-(SP)        ; Push arg2
0x000061cc:  move.l     (0xc,A0),-(SP)         ; Push arg1
0x000061d0:  bsr.l      0x0000368c             ; CALL FUN_0000368c
0x000061d6:  move.l     D0,(0x1c,A2)           ; Store result in structure
0x000061da:  tst.l      (0x1c,A2)              ; Test if zero
0x000061de:  bne.b      0x000061ec             ; Branch if error (non-zero)
```

**After return**:
- Result is stored in structure at A2 (offset 0x1C)
- Tested for zero/non-zero (zero = success, non-zero = error)

---

## Library Functions

### 0x0500315e (Conversion Function)

| Property | Value |
|----------|-------|
| **Address** | 0x0500315e |
| **Type** | Library/system function |
| **Frequency** | 15 calls total (very common) |
| **Likely Purpose** | String-to-integer conversion (atoi, strtol) |
| **Input** | arg2-arg5 (string + parameters) |
| **Output** | D0 (converted value) |
| **Preserves** | A2-A7, D2-D7 (standard ABI) |

### 0x050032c6 (Validation Function)

| Property | Value |
|----------|-------|
| **Address** | 0x050032c6 |
| **Type** | Library/system function |
| **Frequency** | 1 call only (unique to this context) |
| **Likely Purpose** | Validation/processing callback |
| **Input** | D0 (converted value) + arg2-arg5 (context) |
| **Output** | D0 (validation result) |
| **Preserves** | A2-A7, D2-D7 (standard ABI) |

---

## Stack Frame Diagram

### At Entry
```
SP+0x00 = Return address (to FUN_00006156)
SP+0x04 = arg1 (NOT USED)
SP+0x08 = arg2
SP+0x0C = arg3
SP+0x10 = arg4
SP+0x14 = arg5

After LINK.W A6,0x0:
A6+0x08 = Return address
A6+0x0C = arg2
A6+0x10 = arg3
A6+0x14 = arg4
A6+0x18 = arg5
```

### Before First Library Call
```
SP → arg5
SP+0x04 → arg4
SP+0x08 → arg3
SP+0x0C → arg2
SP+0x10 → (saved A6)
SP+0x14 → Return PC
```

### Before Second Library Call
```
SP → D0 (result from first call)
SP+0x04 → arg5 (still on stack)
SP+0x08 → arg4
SP+0x0C → arg3
SP+0x10 → arg2
```

---

## Analysis Details

### Hardware Access
✅ **NONE** - This is pure software

- No addresses in NeXT hardware range (0x02000000-0x02FFFFFF)
- No NeXTdimension MMIO access (0xF8000000-0xFFFFFFFF)
- No register operations beyond CPU registers

### Memory Access
- Stack operations only (argument passing)
- Library functions may dereference pointers (arg2-arg5)
- No direct global variable access in this function

### Register Usage
| Register | Usage |
|----------|-------|
| **A6** | Frame pointer (standard) |
| **A7 (SP)** | Stack pointer (standard) |
| **D0** | Return value flow (arg1 to 0x050032c6, then output) |
| **D1-D7** | Unused (untouched) |
| **A0-A5** | Unused (untouched) |

### Control Flow
- **Linear**: No branches or jumps (other than function calls)
- **Deterministic**: Same execution path every time
- **No loops**: Single pass through all instructions

---

## Design Pattern: Adapter/Bridge

This function implements the **Adapter Pattern**:

```
Goal: Combine two operations atomically
   1. Convert input data
   2. Validate converted result

Standard flow would be:
   caller → convert → [intermediate result]
   caller → validate → [final result]

Adapter approach:
   caller → [adapter] → convert → validate → [final result]

Benefits:
   - Atomicity (conversion and validation happen together)
   - Simplified caller interface (single call vs two)
   - Consistent error handling (single return code)
```

---

## Key Observations

### arg1 is Ignored
- First parameter (arg1) is **completely bypassed**
- Not pushed to stack
- Not passed to either library function
- Suggests: arg1 was in original design but not needed here
- Or: arg1 is kept for API compatibility

### Two-Stage Processing
- 0x0500315e converts/processes raw input (arg2-arg5)
- 0x050032c6 validates result using original context (arg2-arg5)
- This chaining is automatic and hidden from caller

### Callback Infrastructure
- 0x050032c6 is **only called once** (unique to this context)
- Suggests it's a **callback** specific to this validation scenario
- FUN_0000368c is the **dispatcher** for this callback

---

## Comparison: Similar Functions

**FUN_0000366e** (predecessor, offset 0x0000366e):
- Also takes parameters
- Also calls 0x0500315e
- But calls 0x050032ba (different validator)
- Suggests **templated pattern**: conversion + variable validators

---

## Confidence Levels

| Aspect | Confidence | Evidence |
|--------|------------|----------|
| **Disassembly Accuracy** | ✅ HIGH | Clear instructions, no ambiguity |
| **Function Flow** | ✅ HIGH | Linear execution, straightforward |
| **Calling Context** | ✅ HIGH | Clear caller at FUN_00006156 |
| **Purpose (Adapter)** | ⚠️ MEDIUM | Pattern clear, exact purpose inferred |
| **Library Functions** | ⚠️ MEDIUM | Usage patterns suggest types, not confirmed |
| **Data Types** | ❓ LOW | Parameters inferred but not verified |
| **Error Codes** | ❓ LOW | Return value semantics not explicit |

---

## Unknowns & Questions

1. **Why is arg1 unused?**
   - Is it deprecated? Reserved? Required by caller?
   - What was it originally for?

2. **What is 0x0500315e really doing?**
   - Is it definitely atoi? Or something else?
   - Why is it called "string/data conversion"?

3. **What is 0x050032c6?**
   - Why is it only called here?
   - What makes it specific to this validation?
   - What error codes does it return?

4. **What are arg2-arg5 in real context?**
   - From FUN_00006156: offsets 0x0C, 0x1C, 0x24, 0x2C, 0x34 in structure at A0
   - What structure is this? Board info? Device config?

5. **How to interpret return value?**
   - Caller checks for zero/non-zero
   - Zero = success or error?
   - What error codes exist?

---

## Files Generated

### 1. Comprehensive Analysis Document
📄 **`0x0000368c_COMPREHENSIVE_ANALYSIS.md`**
- 18-section deep analysis
- Full parameter documentation
- Library function behavior
- Design patterns
- Recommended next steps

### 2. Annotated Disassembly
📄 **`0x0000368c_FUN_0000368c.asm`**
- Complete disassembly with detailed comments
- Stack frame diagrams
- Instruction-by-instruction analysis
- Calling context explanation
- Summary of execution flow

### 3. This Summary Document
📄 **`ANALYSIS_0x0000368c_SUMMARY.md`**
- Quick reference
- High-level overview
- Key facts and observations
- Confidence assessment
- Next steps

---

## Next Analysis Steps

### Immediate (Easy)
1. ✅ Read comprehensive analysis document
2. ✅ Review annotated disassembly
3. Search for 0x0500315e in other binaries/documentation
4. Look for 0x050032c6 references (should be unique)

### Short-term (Medium)
5. Analyze FUN_00006156 to understand calling context
6. Map structure at A0 (offsets 0x0C, 0x1C, 0x24, 0x2C, 0x34)
7. Compare with FUN_0000366e (similar pattern)
8. Search codebase for error code definitions

### Long-term (Advanced)
9. Use Mach debugger to trace real execution
10. Set breakpoint at 0x0000368c
11. Inspect parameter values at runtime
12. Monitor return values and error conditions
13. Cross-reference with NeXTSTEP documentation

---

## Summary

**FUN_0000368c** is a **callback wrapper** that chains two library functions:

1. **Stage 1**: Convert input data (0x0500315e)
2. **Stage 2**: Validate/process result (0x050032c6)

The function is simple (38 bytes, 10 instructions), hardware-independent, and serves as an adapter between two related library functions. It's part of a larger board initialization system in NDserver.

**Key Purpose**: Encapsulates a conversion + validation sequence as an atomic operation for board configuration.

**Complexity**: Very Low (linear code, no branches, simple parameter passing)

**Understanding**: Good for mechanics, moderate for purpose, needs work on exact data types and error semantics.

---

*Analysis completed: November 8, 2025*
*Analyst: Claude Code with Ghidra 11.2.1*
*Confidence: HIGH for mechanics, MEDIUM for purpose*

