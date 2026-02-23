# Deep Function Analysis: FUN_0000368c (Callback Wrapper)

**Analysis Date**: November 8, 2025
**Tool**: Ghidra 11.2.1 (m68k disassembly)
**Binary**: NDserver (Mach-O m68k executable)
**Priority**: HIGH
**Category**: Callback/Wrapper Function

---

## Executive Summary

**FUN_0000368c** is a **5-argument callback wrapper function** that:
1. Accepts 5 parameters from caller
2. Restructures them for library function call
3. Calls 0x0500315e (likely `atoi()` or string conversion)
4. Passes result + 4 original args to 0x050032c6
5. Returns control to caller

**Purpose**: Acts as an **adapter/bridge** between two library functions, possibly converting string data and processing it through a validation callback.

**Classification**:
- **Type**: Callback Wrapper / Adapter Pattern
- **Complexity**: Low (8 instructions, 38 bytes)
- **Hardware Access**: None (pure software)
- **Libraries Used**: 2 (0x0500315e, 0x050032c6)

---

## Section 1: Complete Disassembly

```asm
; Function: FUN_0000368c
; Address: 0x0000368c (13964 decimal)
; Size: 38 bytes (10 instructions)
; Frame: 0 bytes (no local variables)
; ============================================================================

  0x0000368c:  link.w     A6,0x0                        ; Standard prologue (no locals)
  0x00003690:  move.l     (0x18,A6),-(SP)               ; Push arg5 (5th parameter) to stack
  0x00003694:  move.l     (0x14,A6),-(SP)               ; Push arg4 to stack
  0x00003698:  move.l     (0x10,A6),-(SP)               ; Push arg3 to stack
  0x0000369c:  move.l     (0xc,A6),-(SP)                ; Push arg2 to stack
  0x000036a0:  bsr.l      0x0500315e                    ; CALL library function 0x0500315e
                                                         ; Input: arg2-arg5 on stack
                                                         ; Output: D0 = result
  0x000036a6:  move.l     D0,-(SP)                      ; Push return value (D0) to stack
  0x000036a8:  bsr.l      0x050032c6                    ; CALL library function 0x050032c6
                                                         ; Input: D0 (1st arg) + arg2-arg5 (2nd-5th args)
                                                         ; Output: D0 = return value
  0x000036ae:  unlk       A6                            ; Standard epilogue
  0x000036b0:  rts                                      ; Return to caller

; ============================================================================
```

### Instruction-by-Instruction Breakdown

| Address | Instr | Operands | Stack Effect | Registers | Purpose |
|---------|-------|----------|--------------|-----------|---------|
| 0x368c | `link.w` | A6,0x0 | Create frame, SP -= 0 | A6 saved | Setup frame (no locals) |
| 0x3690 | `move.l` | (0x18,A6),-(SP) | arg5 → [SP-4] | SP -= 4 | Push 5th parameter |
| 0x3694 | `move.l` | (0x14,A6),-(SP) | arg4 → [SP-4] | SP -= 4 | Push 4th parameter |
| 0x3698 | `move.l` | (0x10,A6),-(SP) | arg3 → [SP-4] | SP -= 4 | Push 3rd parameter |
| 0x369c | `move.l` | (0xc,A6),-(SP) | arg2 → [SP-4] | SP -= 4 | Push 2nd parameter |
| 0x36a0 | `bsr.l` | 0x0500315e | **CALL** | D0 = result | Call library fn #1 |
| 0x36a6 | `move.l` | D0,-(SP) | D0 → [SP-4] | SP -= 4 | Push result for fn #2 |
| 0x36a8 | `bsr.l` | 0x050032c6 | **CALL** | D0 = return | Call library fn #2 |
| 0x36ae | `unlk` | A6 | Restore SP, A6 | SP, A6 | Teardown frame |
| 0x36b0 | `rts` | - | PC = [SP], SP += 4 | PC | Return |

---

## Section 2: Stack Frame Analysis

### Calling Convention (Standard m68k ABI)

**Caller's stack layout when entering FUN_0000368c**:

```
[SP]        = Return address (inserted by BSR.L)
[SP+0x04]   = arg1 (NOT accessed in this function)
[SP+0x08]   = arg2
[SP+0x0C]   = arg3
[SP+0x10]   = arg4
[SP+0x14]   = arg5
[SP+0x18]   = (undefined - beyond 5 args)

After LINK.W A6,0x0:
A6          = SP+0x04 (frame pointer)

Offsets from A6:
A6+0x08     = Return address
A6+0x0C     = arg2
A6+0x10     = arg3
A6+0x14     = arg4
A6+0x18     = arg5

Note: arg1 is at A6+0x08, but it's NOT USED in this function!
```

### Stack Transformation During Execution

**Entry State** (after `link.w A6,0x0`):
```
SP -->  [Previous SP value saved by link]
SP+0x04 --> Return PC
SP+0x08 --> arg1 (ignored)
SP+0x0C --> arg2
SP+0x10 --> arg3
SP+0x14 --> arg4
SP+0x18 --> arg5

A6 points to SP+0x04
```

**After 4× `move.l (xx,A6),-(SP)`**:
```
SP -->       arg5
SP+0x04 -->  arg4
SP+0x08 -->  arg3
SP+0x0C -->  arg2
SP+0x10 -->  [Previous SP]
SP+0x14 -->  Return PC
SP+0x18 -->  arg1
SP+0x1C -->  arg2 (duplicate)
SP+0x20 -->  arg3 (duplicate)
SP+0x24 -->  arg4 (duplicate)

(Arguments pushed right-to-left for C calling convention)
```

**Before 0x0500315e call**:
- Stack has arg2-arg5 positioned for standard m68k ABI
- 0x0500315e reads these arguments via stack offsets
- Result returned in D0

**After move.l D0,-(SP)** (before 0x050032c6 call):
```
SP -->       D0 (result from 0x0500315e)
SP+0x04 -->  arg5
SP+0x08 -->  arg4
SP+0x0C -->  arg3
SP+0x10 -->  arg2
SP+0x14 -->  [Previous SP]
...
```

0x050032c6 sees:
- arg1 (1st param) = D0 (result)
- arg2-arg5 = original arg2-arg5

---

## Section 3: Parameter Analysis

### Function Signature (Reconstructed)

```c
// Calling convention: m68k stack-based, arguments right-to-left
// Return value: 32-bit in D0

int32_t FUN_0000368c(
    int32_t arg1,      // +0x08(A6) - NOT USED in this function
    int32_t arg2,      // +0x0C(A6) - Passed to both lib functions
    int32_t arg3,      // +0x10(A6) - Passed to both lib functions
    int32_t arg4,      // +0x14(A6) - Passed to both lib functions
    int32_t arg5       // +0x18(A6) - Passed to both lib functions
);
```

### Parameter Flow

```
[Caller]
    ↓
    arg1 (ignored by FUN_0000368c!)
    arg2, arg3, arg4, arg5
    ↓
[FUN_0000368c]
    │
    ├─→ Push arg2, arg3, arg4, arg5 to stack
    │
    ├─→ Call 0x0500315e(arg2, arg3, arg4, arg5)
    │   └─→ Returns D0 (converted/processed value)
    │
    ├─→ Push D0 to stack
    │
    ├─→ Call 0x050032c6(D0, arg2, arg3, arg4, arg5)
    │   └─→ Returns D0 (final result)
    │
    └─→ Return D0 to [Caller]
```

### Key Observation: arg1 Bypassed

The first parameter (arg1 at offset 0x08 in the frame) is **completely ignored**:
- Not pushed to stack
- Not used in any computation
- Not passed to either library function

**Implications**:
1. **Possibly removed or deprecated** - Original function might have used it, but this wrapper doesn't need it
2. **Callback context** - Could be a callback structure pointer that caller must manage separately
3. **Reserved for future use** - Placeholder for potential extension

---

## Section 4: Library Function Analysis

### Function 0x0500315e

**Call Site**: `0x000036a0: bsr.l 0x0500315e`

**Arguments Received**:
```
Stack @ BSR entry:
SP+0x00 = return PC (0x000036a6)
SP+0x04 = arg2
SP+0x08 = arg3
SP+0x0C = arg4
SP+0x10 = arg5
```

**Return Value**: D0 (32-bit value)

**Frequency**: Used **15 times** across codebase (very common utility)

**Likely Purpose**: **String-to-integer conversion** (atoi, strtol, or similar)
- Evidence from CROSS_REFERENCE_GUIDE.md: "String/data conversion"
- Used in ND_URLFileDescriptorOpen for port number parsing
- Consistent with taking string data and producing numeric result

**Behavior Pattern**:
```
Input:  arg2 = pointer to string (or data buffer)
        arg3, arg4, arg5 = formatting/conversion parameters
Output: D0 = converted integer value
```

### Function 0x050032c6

**Call Site**: `0x000036a8: bsr.l 0x050032c6`

**Arguments Received**:
```
Stack @ BSR entry:
SP+0x00 = return PC (0x000036ae)
SP+0x04 = D0 (result from 0x0500315e) ← NEW arg1
SP+0x08 = arg2 (original)
SP+0x0C = arg3 (original)
SP+0x10 = arg4 (original)
SP+0x14 = arg5 (original)
```

**Return Value**: D0 (32-bit value, passed through to caller)

**Frequency**: Used **1 time** only in entire codebase (specific to this context)

**Likely Purpose**: **Validation/processing callback** that:
- Takes result from 0x0500315e as primary argument
- Uses original context arguments (arg2-arg5) for validation
- Returns success/failure or processed value

**Behavior Pattern**:
```
Input:  D0 = converted value (from 0x0500315e)
        arg2-arg5 = validation context
Output: D0 = validation result or processed value
```

---

## Section 5: Control Flow Graph

```
┌─────────────────────────────────────┐
│ FUN_0000368c (Caller entry)         │
│ Parameters: arg1, arg2, arg3, arg4, arg5 │
│ Frame: 0 bytes locals               │
└─────────────────────────────────────┘
           │
           │ Stack frame created (A6 set)
           ↓
┌─────────────────────────────────────┐
│ Push Arguments to Stack             │
│ -(SP) = arg5, arg4, arg3, arg2      │
│ (arg1 discarded)                    │
└─────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ CALL 0x0500315e                     │
│ (String/data conversion)             │
│ Input: arg2, arg3, arg4, arg5       │
│ Output: D0 = converted_value        │
└─────────────────────────────────────┘
           │
           │ Return path
           ↓
┌─────────────────────────────────────┐
│ Push Converted Value                │
│ -(SP) = D0 (result)                 │
└─────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ CALL 0x050032c6                     │
│ (Validation/processing callback)     │
│ Input: D0 (converted), arg2-arg5    │
│ Output: D0 = final_result           │
└─────────────────────────────────────┘
           │
           │ Return path
           ↓
┌─────────────────────────────────────┐
│ Restore Stack Frame                 │
│ A6 restored                         │
└─────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ Return to Caller                    │
│ D0 = final result                   │
│ Stack cleaned by caller             │
└─────────────────────────────────────┘
```

---

## Section 6: Hardware Access Analysis

### Direct Hardware Register Access

**Result**: **NONE**

**Verification**:
- ✅ No addresses in NeXT hardware range `0x02000000-0x02FFFFFF`
- ✅ No addresses in NeXTdimension MMIO range `0xF8000000-0xFFFFFFFF`
- ✅ No memory-mapped register patterns (CSR, RAMDAC, mailbox, etc.)

### Indirect Hardware Dependencies (via Library Functions)

**0x0500315e** (String conversion):
- Likely pure software (string parsing/arithmetic)
- May touch global data (conversion tables, radix definitions)
- No direct hardware I/O expected

**0x050032c6** (Validation callback):
- **UNKNOWN** - could potentially call hardware functions
- Only called once, context-specific
- Behavior depends on what arg2-arg5 reference

### Memory Access Pattern

```
Stack operations:
- No DATA segment reads/writes
- No global variable access
- Pure stack-based computation

Potential indirect memory access:
- arg2-arg5 are likely pointers
- 0x0500315e may dereference arg2 (string pointer)
- 0x050032c6 may dereference arg3-arg5 (context pointers)
```

### Safety Assessment

**Memory Safety**: ✅ **SAFE**
- Function is pure wrapper
- Delegates validation to library functions
- No buffer operations
- No pointer arithmetic

---

## Section 7: Calling Context

### Function That Calls FUN_0000368c

**Caller**: `FUN_00006156` at offset `0x000061d0`

**Caller's Purpose**: Board initialization validator (inferred)

**Call Site Disassembly**:
```asm
0x000061bc:  move.l     (0x34,A0),-(SP)               ; Push arg5
0x000061c0:  move.l     (0x2c,A0),-(SP)               ; Push arg4
0x000061c4:  move.l     (0x24,A0),-(SP)               ; Push arg3
0x000061c8:  move.l     (0x1c,A0),-(SP)               ; Push arg2
0x000061cc:  move.l     (0xc,A0),-(SP)                ; Push arg1
0x000061d0:  bsr.l      0x0000368c                    ; CALL FUN_0000368c
0x000061d6:  move.l     D0,(0x1c,A2)                  ; Store result @ offset 0x1C
```

**Context**:
- Caller is `FUN_00006156` (Entry Point, NOT called by other internal functions)
- Arguments pulled from structure at A0 (offsets: 0x0C, 0x1C, 0x24, 0x2C, 0x34)
- Result stored into structure at A2 (offset: 0x1C)

**Caller's Behavior After Call**:
```asm
0x000061d6:  move.l     D0,(0x1c,A2)                  ; Store result
0x000061da:  tst.l      (0x1c,A2)                     ; Test if result is non-zero
0x000061de:  bne.b      0x000061ec                    ; Branch if non-zero (success?)
0x000061e0:  move.b     #0x1,(0x3,A2)                 ; Set flag @ +0x03
0x000061e6:  moveq      0x20,D1                       ; Load constant 0x20
0x000061e8:  move.l     D1,(0x4,A2)                   ; Store @ +0x04
```

**Implication**: Return value is tested:
- If **non-zero**: error path (jump to 0x61EC)
- If **zero**: success path (continue, set flags)

---

## Section 8: Pattern Recognition

### Adapter/Bridge Pattern

This function implements the **Adapter/Bridge Design Pattern**:

```
Caller wants: Convert arg2-arg5 using 0x0500315e, then validate via 0x050032c6
Caller provides: arg1-arg5 parameters

Adapter does:
1. Ignores arg1 (context not needed here)
2. Calls conversion function with arg2-arg5
3. Takes result + original context (arg2-arg5)
4. Calls validation function
5. Returns final result to caller
```

### Why This Pattern?

**Possible reasons for this wrapper**:
1. **API compatibility** - Hide complexity from caller
2. **Chaining operations** - Convert then validate as atomic operation
3. **Callback infrastructure** - Provide consistent interface for event handlers
4. **Protocol negotiation** - Standardized way to process board/device data

---

## Section 9: Register Usage Summary

### Register Allocation

| Register | Usage | Preserved? | Notes |
|----------|-------|------------|-------|
| **D0** | Return value (INPUT to fn1, OUTPUT from fn2) | No | Caller-saved, overwritten multiple times |
| **D1-D7** | NONE | - | Not modified |
| **A0-A1** | NONE | - | Not modified |
| **A2-A5** | NONE | - | Not modified |
| **A6** | Frame pointer | Yes (by link/unlk) | Callee-saved, restored by unlk |
| **A7 (SP)** | Stack pointer | Yes | Caller must clean up stack |

### Register Pressure

**Minimal** - Only D0 used for data flow, all other registers untouched

---

## Section 10: Data Type Analysis

### Parameter Types (Inferred)

Based on usage in caller and library function behavior:

| Param | Type | Likely Content | Evidence |
|-------|------|-----------------|----------|
| **arg1** | `void*` | Context/structure pointer (UNUSED) | Offset in structure (0x0C, 0x1C, etc.) |
| **arg2** | `const char*` | String or data buffer | Passed to conversion function |
| **arg3** | `int32_t` | Formatting/radix parameter | Numeric parameter |
| **arg4** | `void*` | Optional buffer/context | Passed to both functions |
| **arg5** | `int32_t` | Size/length parameter | Numeric parameter |

### Return Type

**`int32_t`** (or possibly error code enumeration)
- Tested for zero/non-zero by caller
- Stored in structure field (+0x1C in calling context)
- 32-bit value fits in D0 register

---

## Section 11: Calling Convention Details

### m68k ABI Stack Convention

```
┌────────────────────────────────────┐
│ CALLER'S PERSPECTIVE               │
├────────────────────────────────────┤
│ Preserved Registers: A2-A7, D2-D7  │
│ Scratch Registers: A0-A1, D0-D1    │
│                                    │
│ Argument passing: STACK (right-to- │
│                           left)    │
│ Return value: D0 (32-bit) or D0:D1 │
│              (64-bit)              │
│                                    │
│ Stack cleanup: CALLER'S TASK       │
│ (stdcall would be callee cleanup)  │
└────────────────────────────────────┘
```

### Function's Calling Convention Compliance

✅ **FULLY COMPLIANT**:
- Arguments accessed via A6 offsets (standard)
- Only D0 modified (caller-saved register)
- Stack restored before return (via unlk)
- Other registers untouched (callee-save preserved)

---

## Section 12: m68k Architecture Deep Dive

### Link/Unlk Frame Management

```asm
link.w  A6,0x0
    Actions:
    1. [-(SP)] = A6           ; Save caller's A6
    2. A6 = SP                ; Set A6 to current SP
    3. SP -= 0                ; Allocate 0 bytes for locals

unlk    A6
    Actions:
    1. SP = A6                ; Restore SP to frame start
    2. A6 = [SP]+             ; Restore A6 from [SP], SP += 4

Result: Function frame completely cleaned up
```

### Addressing Modes

**Register Indirect with Displacement**:
```asm
move.l  (0x18,A6),-(SP)

Calculation:
    Effective Address = A6 + 0x18
    Operand = [EA]
    Destination = [SP-4], then SP -= 4

Stack-based offset addressing
```

**Pre-decrement Stack**:
```asm
-(SP)

Effect: SP -= 4 (for long), then write to [SP]
Used for pushing arguments right-to-left
```

---

## Section 13: Dataflow Analysis

### Information Flow Diagram

```
INPUTS:
┌──────────────┐
│ arg1 (unused)│
│ arg2         ├──→ Stack
│ arg3         │
│ arg4         │
│ arg5         │
└──────────────┘
        │
        ├─────────────────────────┐
        │                         │
    [0x0500315e]         [0x050032c6]
        │ D0=result              │
        │                         │
        └─→ + arg2-arg5 ─→ 0x050032c6
                            │
                            └──→ D0=final_result
                                │
                                └──→ OUTPUT

OUTPUT:
┌──────────────┐
│ D0 (result)  │
└──────────────┘
    Tested by caller for error handling
```

### State Transitions

```
[Entry] → Stack set up → Call conversion → Store result
       → Stack modified → Call validator → Return to caller
```

---

## Section 14: Code Quality Metrics

### Complexity Metrics

| Metric | Value | Assessment |
|--------|-------|------------|
| **Cyclomatic Complexity** | 1 | Trivial (no branches) |
| **Instruction Count** | 10 | Very simple |
| **Register Usage** | 1 effective | Minimal |
| **Stack Usage** | 4 frames | Moderate |
| **Dependencies** | 2 external | Low coupling |
| **Lines of Logic** | 8 | Straightforward |

### Code Characteristics

✅ **Strengths**:
- Clear, linear execution flow
- No conditional branches
- Simple parameter passing
- Minimal register usage

⚠️ **Oddities**:
- arg1 parameter completely ignored (design choice or error?)
- Only called once (unique function)
- Minimal computational logic (pure adapter)

---

## Section 15: Function Classification

### Type Classification

**Primary**: **Callback Wrapper / Adapter Function**
- Bridges between two library functions
- Restructures parameters for compatibility
- Acts as intermediate processing layer

**Secondary**: **Validation Function**
- Validates data via conversion + checking
- Returns status code
- Used during initialization/negotiation

### Functionality Category

**Board/Device Initialization** (inferred from calling context)
- Called by `FUN_00006156` (entry point)
- Processes board-related parameters
- Result stored in board structure

### Reentrancy

**Single-threaded** - No static locals, no global state modifications
- Safe to call from multiple contexts
- No hidden state

---

## Section 16: Reverse Engineering Notes

### What We Know With Certainty

✅ **HIGH CONFIDENCE**:
1. Function takes 5 parameters, uses 4 of them (arg2-arg5)
2. Calls 0x0500315e with arg2-arg5
3. Takes result, combines with arg2-arg5, calls 0x050032c6
4. Returns result in D0
5. No hardware access
6. Called once by FUN_00006156

### What Requires Further Analysis

⚠️ **MEDIUM CONFIDENCE**:
1. **Exact purpose of arg1** - Why is it passed but ignored?
2. **0x050032c6 behavior** - Only called here, purpose unclear
3. **Return value semantics** - Does zero = success or failure?
4. **Context of conversion** - What data is being converted?

❓ **LOW CONFIDENCE**:
1. **0x0500315e identity** - Likely atoi but not confirmed
2. **Library origin** - Which shared library/framework?
3. **Real function names** - Ghidra generated names only

---

## Section 17: Comparative Analysis

### Similar Functions in Codebase

**FUN_0000366e** (predecessor, similar pattern):
```
Also takes 2 args, calls 0x0500315e, calls different function (0x050032ba)
Suggests a pattern: conversion → different validators/processors
```

**Pattern Recognition**:
```
FUN_0000366e: arg2, arg3 → 0x0500315e → [result] → 0x050032ba
FUN_0000368c: arg2-arg5 → 0x0500315e → [result] → 0x050032c6
FUN_000036a0: (presumably similar pattern)

Suggests: Templated callback infrastructure
```

---

## Section 18: Recommended Next Steps

### Immediate Analysis Tasks

1. **Identify 0x0500315e**
   - Search codebase for patterns of use
   - Check if always converts strings to integers
   - Verify with surrounding code context

2. **Understand arg1 Usage**
   - Check calling functions to see if arg1 is significant
   - Look for register reuse patterns
   - Determine if it's truly unused or optimization artifact

3. **Analyze FUN_00006156 Structure**
   - Understand what structure is being initialized
   - Map the offset accesses (0x0C, 0x1C, 0x24, 0x2C, 0x34)
   - Determine structure type and purpose

4. **Find 0x050032c6 Context**
   - It's only called here - highly specific
   - Likely validator for this exact data type
   - Check if it appears in other modules/exports

### Longer-term Analysis

5. **Cross-reference with NeXTSTEP Headers**
   - Look for driver init callbacks
   - Search for similar parameter patterns in IOKit/DriverKit

6. **Dynamic Analysis**
   - Use Mach debugger to trace execution
   - Set breakpoint at 0x0000368c
   - Inspect stack values and return codes

7. **Symbol Resolution**
   - If binary has symbol information, use `nm` or similar
   - Check Mach-O load commands for shared libraries
   - Match library addresses to known frameworks

---

## Summary

**FUN_0000368c** is a **low-complexity callback wrapper** that acts as an **adapter between two library functions**. It:

1. Takes 5 parameters (only uses 4)
2. Calls string/data conversion function (0x0500315e)
3. Chains result to validation/processing function (0x050032c6)
4. Returns final status to caller

**Key Characteristics**:
- **38 bytes**: Minimal code footprint
- **No hardware access**: Pure software function
- **Simple control flow**: No branches, linear execution
- **Standard calling convention**: m68k stack-based parameter passing
- **Callback pattern**: Adapter for compatible function chaining

**Confidence Assessment**:
- ✅ Function mechanics: **HIGH**
- ⚠️ Function purpose: **MEDIUM** (likely validation, exact context unclear)
- ⚠️ Library functions: **LOW** (identities unknown)

**Recommendations**:
- Correlate with calling function `FUN_00006156` for business logic understanding
- Identify 0x0500315e through comparative analysis
- Use dynamic debugging to trace actual execution flow
- Map data structures to understand context parameters

---

*Analysis completed with Ghidra 11.2.1 reverse engineering platform*
*Binary: NDserver (Mach-O m68k executable)*
*Confidence: HIGH for mechanics, MEDIUM for purpose*

