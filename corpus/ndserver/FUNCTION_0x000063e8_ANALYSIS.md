# Function Analysis: 0x000063e8 - Hardware Access Callback Wrapper

**Function Address:** 0x000063e8
**Decimal Address:** 25,576
**Size:** 44 bytes
**Type:** Non-thunk function
**Calling Convention:** Motorola 68000 Stack-based (6-word parameter passing)
**Source:** Ghidra export from NeXTdimension firmware analysis

---

## 1. FUNCTION SIGNATURE & NAMING CONVENTION

```
void FUN_000063e8(void *handle, uint32_t param1, uint32_t param2)
```

**Inferred Signature:**
- **Return Type:** `void` (registers not preserved for return value)
- **Parameters:**
  - `A6 + 0x08` = `void *handle` (passed via A6 offset)
  - `A6 + 0x10` = `uint32_t param1` (long word, low-order parameter)
  - `A6 + 0x14` = `uint32_t param2` (long word, high-order parameter)
- **Preserved Registers:** A2, A6
- **Modified Registers:** A2 (restored), D0, D1, SP

---

## 2. RAW DISASSEMBLY

```assembly
; Address: 0x000063e8
; Size: 44 bytes
; ============================================================================

  0x000063e8:  link.w     A6,0x0                        ; Stack frame setup
  0x000063ec:  move.l     A2,-(SP)                      ; Save A2 (work register)
  0x000063ee:  movea.l    (0xc,A6),A2                   ; A2 = param3/handle (A6+12)
  0x000063f2:  move.l     (0x14,A6),-(SP)               ; Push param2 (A6+20)
  0x000063f6:  move.l     (0x10,A6),-(SP)               ; Push param1 (A6+16)
  0x000063fa:  bsr.l      0x0500222e                    ; Call external handler @ 0x0500222e
  0x00006400:  moveq      -0x1,D1                       ; D1 = -1 (error sentinel)
  0x00006402:  cmp.l      D0,D1                         ; Compare D0 with -1
  0x00006404:  bne.b      0x0000640c                    ; Skip error handler if D0 != -1
  0x00006406:  move.l     (0x040105b0).l,(A2)           ; Write error code to handle: *(A2) = error_value
  0x0000640c:  movea.l    (-0x4,A6),A2                  ; Restore A2 from stack
  0x00006410:  unlk       A6                            ; Unlink stack frame
  0x00006412:  rts                                      ; Return to caller
```

**Byte Breakdown:**
- `0x000063e8 - 0x000063ec`: Stack frame initialization (4 bytes)
- `0x000063ec - 0x000063f6`: Parameter setup & A2 register save/load (10 bytes)
- `0x000063f6 - 0x00006402`: Parameter passing to external function (12 bytes)
- `0x00006402 - 0x00006406`: Error return code check (4 bytes)
- `0x00006406 - 0x0000640c`: Error handling (6 bytes)
- `0x0000640c - 0x00006412`: Stack frame cleanup (8 bytes)

---

## 3. CALLING CONTEXT & CALLERS

### Calling Function:
**Address:** 0x00006ac2 (FUN_00006ac2)
**Size:** 186 bytes
**Relationship:** Indirect caller - prepares parameters and dispatches to 0x000063e8

**Call Instruction at 0x00006ac2:**
```assembly
; Within FUN_00006ac2, at address ~0x6abc:
bsr.l      0x000063e8        ; Call this wrapper function
```

### Call Stack Context:
1. Caller function (FUN_00006ac2) prepares:
   - A2 register with result/error handle pointer
   - Two parameters (param1, param2) on stack
2. Calls 0x000063e8 with `bsr.l` (Branch to Subroutine, Long)
3. Wrapper 0x000063e8:
   - Moves handle to A2
   - Pushes param1 and param2
   - Calls external handler at 0x0500222e
4. On return from 0x0500222e:
   - Checks return code in D0
   - If D0 == -1 (error), writes error code to handle pointer

---

## 4. STACK LAYOUT & PARAMETER PASSING

### Stack Frame Structure (in effect during function):
```
        [Higher memory]
SP+28:  [Return address from caller]      (RTS target)
SP+24:  [Previous A6 (link A6)]           (From LINK instruction)
SP+20:  [A2 saved value]                  (From MOVE.L A2,-(SP))
SP+16:  [param2 value]                    (From MOVE.L (0x14,A6),-(SP))
SP+12:  [param1 value]                    (From MOVE.L (0x10,A6),-(SP))
SP+8:   [Return address to 0x0500222e]    (BSR.L target)
        [Lower memory - SP]
```

### Parameter Offsets (relative to A6):
- `(0x08,A6)` = Return address from immediate caller (not used)
- `(0x0C,A6)` = Third parameter (handle/output pointer)
- `(0x10,A6)` = First parameter (param1)
- `(0x14,A6)` = Second parameter (param2)

**Note:** Offset differences of 4 bytes indicate 32-bit long word parameters.

---

## 5. CONTROL FLOW ANALYSIS

### Execution Path (Normal Case):
```
Entry (0x63e8)
    ↓
LINK.W A6, #0          Setup stack frame
    ↓
MOVE.L A2, -(SP)       Save A2 register
    ↓
MOVEA.L (0xC,A6), A2   Load handle into A2
    ↓
MOVE.L (0x14,A6), -(SP) Push param2
MOVE.L (0x10,A6), -(SP) Push param1
    ↓
BSR.L 0x0500222E       Call external handler
    ↓
D0 contains return code
    ↓
IF (D0 == -1):         Check for error code
    MOVE.L (0x040105b0).l, (A2)   [ERROR PATH] Write error value via handle
ELSE:                  [SUCCESS PATH]
    (Skip error write)
    ↓
MOVEA.L (-0x4,A6), A2  Restore A2
UNLK A6                Cleanup stack frame
RTS                    Return to caller
```

### Branch Condition:
- **Condition:** `D0 ≠ -1` (not equal to -1)
- **True branch (bne.b 0x0000640c):** Skip error handler, go to cleanup
- **False branch:** Fall through to error handler at 0x00006406

---

## 6. INSTRUCTION BREAKDOWN

| Offset | Instruction | Operation | Notes |
|--------|-------------|-----------|-------|
| +0x00 | `LINK.W A6, #0` | Create stack frame | No local variables |
| +0x04 | `MOVE.L A2, -(SP)` | Push A2 for preservation | Pre-decrement addressing |
| +0x06 | `MOVEA.L (0xC,A6), A2` | Load parameter 3 into A2 | Handle/output pointer |
| +0x0A | `MOVE.L (0x14,A6), -(SP)` | Push parameter 2 | High-order parameter |
| +0x0E | `MOVE.L (0x10,A6), -(SP)` | Push parameter 1 | Low-order parameter |
| +0x12 | `BSR.L 0x0500222E` | Call external function | 32-bit branch |
| +0x16 | `MOVEQ #-1, D1` | Load -1 into D1 (immediate) | Quick load (-1 = 0xFFFFFFFF) |
| +0x18 | `CMP.L D0, D1` | Compare D0 with -1 | Sets condition codes |
| +0x1A | `BNE.B 0x0000640C` | Branch if not equal | 8-bit offset (+8 bytes) |
| +0x1C | `MOVE.L (0x040105b0).l, (A2)` | Write error to handle | Long absolute addressing |
| +0x22 | `MOVEA.L (-0x4,A6), A2` | Restore A2 from stack | Restore saved value |
| +0x26 | `UNLK A6` | Unlink stack frame | Restore A6 and SP |
| +0x28 | `RTS` | Return from subroutine | Pop return address to PC |

---

## 7. DATA FLOW ANALYSIS

### Input Data Flow:
```
Caller Function (FUN_00006ac2)
    │
    ├─→ A6 + 0x0C: Handle pointer (output buffer address)
    │              Type: Address of uint32_t
    │              Usage: Result/error storage
    │
    ├─→ A6 + 0x10: Parameter 1 (passed to external)
    │              Type: uint32_t (likely config/flags)
    │              Usage: First argument to 0x0500222E
    │
    └─→ A6 + 0x14: Parameter 2 (passed to external)
                   Type: uint32_t (likely data/address)
                   Usage: Second argument to 0x0500222E

    External Handler at 0x0500222E
    │
    └─→ Returns in D0
         Value: uint32_t (return code or -1 for error)
```

### Output Data Flow:
```
D0 Register (from 0x0500222E)
    │
    ├─ Success (D0 ≠ -1):
    │  Function exits normally, no write to handle
    │
    └─ Error (D0 == -1):
       A2 (loaded from A6+0x0C) = points to output location
       │
       └─→ Write Memory Address (0x040105b0) to location (A2)
           This stores a global error code in the caller's buffer
```

### Error Handling:
- **Error Sentinel:** -1 (0xFFFFFFFF in two's complement)
- **Error Action:** Write from global location `0x040105b0` to output handle
- **Rationale:** -1 return from external indicates error; wrapper stores error details

---

## 8. REGISTER USAGE

### Register Usage Summary:

| Register | Usage | Preserved? | Notes |
|----------|-------|-----------|-------|
| **A2** | Work register (handle pointer) | Yes (saved/restored) | Holds output pointer during error write |
| **A6** | Stack frame pointer | Yes | Set by LINK, restored by UNLK |
| **SP** | Stack pointer | Auto | Modified by PUSH/POP operations |
| **D0** | Return value from external | No | Checked for error condition (-1) |
| **D1** | Error sentinel (-1) | No | Temporary comparison value |
| **A0-A1, A3-A5** | Not used | - | Caller-preserved convention |
| **D2-D7** | Not used | - | Caller-preserved convention |

### Register Pressure:
- **High-use registers:** A6 (frame pointer), A2 (parameter pointer), SP (stack)
- **Minimal register usage** suggests function is a simple pass-through wrapper
- **Single-use comparison register (D1)** with immediate load suggests tight code

---

## 9. MEMORY ADDRESSING MODES

### Addressing Modes Used:

1. **Displacement Indirect with Register (Address Register Indirect):**
   ```
   (0x0C, A6)    ; A6 + 0x0C → parameter from stack frame
   (0x10, A6)    ; A6 + 0x10 → parameter from stack frame
   (0x14, A6)    ; A6 + 0x14 → parameter from stack frame
   (-0x4, A6)    ; A6 - 0x4 → restore A2 from link frame
   (A2)          ; Address register indirect → write via pointer
   ```

2. **Pre-Decrement Stack Addressing:**
   ```
   -(SP)         ; Push operation: decrement SP then write
   ```

3. **Long Absolute Addressing:**
   ```
   (0x040105b0).l  ; 32-bit absolute address (global/static data)
   ```

### Memory Access Summary:
- **Reads:** 4 parameters (3 from stack frame, 1 from global)
- **Writes:** 1 error code (via A2 pointer) when error occurs
- **Access Pattern:** Linear, no complex indexing

---

## 10. ASSEMBLY IDIOMS & PATTERNS

### Pattern Recognition:

**Error-Checking Wrapper Pattern:**
```assembly
; Step 1: Save context and parameter setup
LINK.W A6, #0              ; Standard prologue
MOVE.L A2, -(SP)           ; Save work register
MOVEA.L (0xC, A6), A2      ; Load output handle

; Step 2: Delegate to external function
MOVE.L params, -(SP)       ; Push parameters (2x)
BSR.L external_handler     ; Call external function

; Step 3: Check return status
MOVEQ #-1, D1              ; Load error sentinel
CMP.L D0, D1               ; Compare result with sentinel
BNE.B skip_error           ; Skip if not error

; Step 4: Error handling (if -1 returned)
MOVE.L global_error, (A2)  ; Write error code via pointer

; Step 5: Return (both paths converge)
MOVEA.L (-0x4, A6), A2     ; Restore A2
UNLK A6                    ; Standard epilogue
RTS
```

### Variants in Codebase:
This wrapper appears in a series at:
- **0x00006340 (FUN_00006340):** Calls 0x050022E8, size 44 bytes
- **0x0000636c (FUN_0000636c):** Calls 0x0500284c, size 44 bytes
- **0x00006398 (FUN_00006398):** Calls 0x0500324E, size 40 bytes
- **0x000063c0 (FUN_000063c0):** Calls 0x05002228, size 40 bytes
- **0x000063e8 (FUN_000063e8):** Calls 0x0500222e, size 44 bytes (THIS FUNCTION)
- **0x00006414 (FUN_00006414):** Calls 0x05002234, size 48 bytes

All follow identical pattern: parameters → external call → error check → return.

---

## 11. CALLING CONVENTION ANALYSIS

### 68000 Calling Convention (Motorola Standard):

**Motorola 68000 Parameter Passing:**
- **Small parameters (1-4 words):** Passed on stack (right-to-left)
- **Large structures:** Passed by reference (address on stack)
- **Return values:** In D0 (32-bit) or D0:D1 (64-bit)
- **Registers preserved:** A6 (frame pointer), A7/SP (stack pointer)
- **Registers caller-saved:** D0-D7, A0-A5

### This Function's Calling Convention:
```
Entry State:
  A7/SP: Points to return address
  A6: Already set up by caller (6-word offset assumed)

Stack Layout:
  [SP + 24]: Return address from LINK A6
  [SP + 20]: A2 saved value
  [SP + 16]: Parameter 2 (high 32 bits)
  [SP + 12]: Parameter 1 (low 32 bits)
  [SP +  8]: Return address to external handler

Exit State:
  A7/SP: Restored to pre-call state
  D0: Undefined (caller doesn't expect return value)
  A2: Restored to original value
```

### Parameter Semantics:
- **Parameter 1 (A6+0x10):** Likely configuration/flags/command code
- **Parameter 2 (A6+0x14):** Likely data pointer or value
- **Parameter 3 (A6+0x0C):** **Output parameter** - stores result/error in handle buffer

This suggests the function implements a **result-by-reference** pattern common in embedded C code where return values are too complex for simple register passing.

---

## 12. ERROR HANDLING & EXCEPTION PATHS

### Error Handling Flow:

**Case 1: Success (D0 ≠ -1)**
```
External handler returns
    │
    ├─→ MOVEQ #-1, D1  (D1 = 0xFFFFFFFF)
    │
    ├─→ CMP.L D0, D1   (Compare D0 with -1)
    │
    ├─→ BNE.B skip     (D0 ≠ D1, so branch taken)
    │
    └─→ Jump to 0x0000640C (skip error write, proceed to cleanup)
```

**Case 2: Error (D0 == -1)**
```
External handler returns
    │
    ├─→ MOVEQ #-1, D1  (D1 = 0xFFFFFFFF)
    │
    ├─→ CMP.L D0, D1   (Compare D0 with -1)
    │
    ├─→ BNE.B skip     (D0 == D1, so branch NOT taken)
    │
    ├─→ MOVE.L (0x040105b0).l, (A2)
    │      Read from global error location
    │      Write to caller's buffer (via A2 pointer)
    │
    └─→ Fall through to 0x0000640C (proceed to cleanup)
```

### Error Code Storage:
- **Location:** 0x040105b0 (static/global memory)
- **Semantics:** Error code/status value
- **Size:** 32 bits (long word)
- **Access:** Read by this wrapper, written elsewhere (at 0x00007066, 0x00007090, 0x0000743a, 0x000075bc)

### Exception Handling:
- **No explicit exception handling** (no trap instructions, no exception frame)
- **Implicit:** Caller must check output buffer for error code
- **Assumption:** External handler (0x0500222E) won't throw hardware exceptions

---

## 13. PERFORMANCE CHARACTERISTICS

### Instruction Count:
| Phase | Instructions | Bytes | Execution Time |
|-------|--------------|-------|-----------------|
| Prologue (LINK, MOVE A2) | 2 | 8 | 12 cycles |
| Parameter setup | 2 | 8 | 8 cycles |
| External call (BSR.L) | 1 | 6 | 18 cycles |
| Error check | 3 | 6 | 6 cycles |
| Conditional write (if taken) | 1 | 6 | 16 cycles |
| Epilogue (MOVEA, UNLK, RTS) | 3 | 8 | 20 cycles |
| **TOTAL (success path)** | **12** | **42** | **64 cycles** |
| **TOTAL (error path)** | **13** | **44** | **80 cycles** |

### Performance Notes:
- **Overhead:** ~15 cycles wrapper overhead (prologue/epilogue)
- **Bottleneck:** External function call (0x0500222E) dominates execution time
- **Memory access:** 1 global read (if error) adds 16 cycles
- **Optimization opportunity:** No inline optimization possible; wrapper is minimal

### Code Size Efficiency:
- **44 bytes for wrapper + 2-parameter call** = Typical for 68000 code
- **Compared to inline call:** Would save ~20 bytes but lose error handling abstraction
- **Trade-off:** Size vs. reusability (multiple callers benefit from single wrapper)

---

## 14. RELATED FUNCTIONS & PATTERNS

### Function Family (Wrappers with identical pattern):

```
0x00006340 (44 bytes) → Calls 0x050022E8
0x0000636c (44 bytes) → Calls 0x0500284c
0x00006398 (40 bytes) → Calls 0x0500324E (variant: 1 parameter instead of 2)
0x000063c0 (40 bytes) → Calls 0x05002228 (variant: 1 parameter instead of 2)
0x000063e8 (44 bytes) → Calls 0x0500222e ← THIS FUNCTION
0x00006414 (48 bytes) → Calls 0x05002234 (variant: 3 parameters instead of 2)
```

### Calling Patterns:
All wrappers in this family:
1. Accept parameters and output handle pointer
2. Push parameters onto stack
3. Call external handler (likely ROM/external code at 0x05xxxxxx range)
4. Check D0 return for -1 (error)
5. Write global error code to handle on error
6. Return to caller

### Variants by Parameter Count:
- **2-parameter versions (0x6340, 0x636c, 0x63e8, others):** 44-48 bytes
- **1-parameter versions (0x6398, 0x63c0):** 40 bytes
- **3-parameter version (0x6414):** 48 bytes

---

## 15. HARDWARE & DEVICE CONTEXT

### Inferred Hardware Function:
Based on address patterns and calling structure, this wrapper likely facilitates:

1. **Hardware register access with validation**
   - Parameter 1: Register offset or command code
   - Parameter 2: Data value or pointer to data
   - Output: Status/result in caller's buffer

2. **Possible applications:**
   - RAMDAC color lookup table updates
   - DMA controller configuration
   - Interrupt handler registration
   - Memory controller status checks
   - Device driver callbacks

### Memory Regions Referenced:
- **0x0500222e:** External ROM/handler code (high address suggests ROM area)
- **0x040105b0:** Global error status (within main RAM, likely .data or .bss section)
- **Stack frame:** Parameter passing via standard ABI

### Execution Context:
- **Likely context:** Hardware driver initialization or device communication
- **Caller context:** FUN_00006ac2 (186 bytes) - larger handler function
- **Time-sensitive:** No loops or delays observed; minimal latency wrapper

---

## 16. SYMBOLIC AND DEBUG INFORMATION

### Symbol Analysis:
- **Function name:** FUN_000063e8 (auto-generated by Ghidra; no symbol in source)
- **Type tag:** Non-thunk function (not a simple branch alias)
- **Visibility:** Internal/static (no external references found)

### Likely Original Name (reconstructed):
Based on pattern analysis:
- `hw_callback_wrapper()` - Hardware callback wrapper
- `register_access_wrapper()` - Register access with error checking
- `device_cmd_handler()` - Device command with result validation
- `rom_call_wrapper()` - Wrapper for ROM function with error checking

### Symbol Hints from Usage:
- Called by FUN_00006ac2 in sequence with similar wrappers
- Error handling pattern suggests device control/status function
- Global error location (0x040105b0) suggests stateful device interaction

---

## 17. CROSS-REFERENCE ANALYSIS

### References to This Function:
```
Called from:
  └─ FUN_00006ac2 @ offset ~0x6abc (via BSR.L)
     └─ This is a handler function (186 bytes) that dispatches to multiple wrappers
```

### References from This Function:
```
Calls:
  ├─ 0x0500222e (external ROM/handler)
  └─ Accesses global memory at 0x040105b0

Stack frame data:
  ├─ (A6 + 0x0C): Parameter from caller (output handle)
  ├─ (A6 + 0x10): Parameter from caller (param1)
  └─ (A6 + 0x14): Parameter from caller (param2)
```

### Global Memory References:
```
0x040105b0: Global error status register
  Read by:  FUN_000063e8 @ 0x00006406 (on error)
  Also by:  FUN_00006340, FUN_0000636c, FUN_00006398, FUN_000063c0, FUN_00006414
  Written by: Multiple functions at 0x00007066, 0x00007090, 0x0000743a, 0x000075bc
```

---

## 18. ARCHITECTURAL ROLE & FUNCTIONAL SUMMARY

### Functional Purpose:
**Hardware Access Callback Wrapper with Error Handling**

This function serves as a **thin abstraction layer** between NeXTdimension firmware and ROM-resident hardware control routines. Its primary roles are:

1. **Parameter Marshaling:**
   - Accept three parameters (two data values, one output pointer)
   - Reformat for external ROM function calling convention
   - Push parameters on stack in expected order

2. **Delegation to ROM Handler:**
   - Call external function at 0x0500222e (likely in ROM address space)
   - This external function handles actual hardware access/control
   - No local computation; purely a pass-through

3. **Error Handling & Status Reporting:**
   - Check return code in D0 for error condition (-1)
   - If error, retrieve error details from global status location (0x040105b0)
   - Store error code in caller-provided buffer (via A2 pointer)
   - Caller can then check this buffer for operation status

4. **Resource Management:**
   - Preserve A2 (work register) used for output pointer
   - Clean up stack frame on exit
   - Follow standard 68000 ABI

### Architectural Pattern:
```
                    ┌─────────────────────┐
                    │  FUN_00006ac2       │
                    │  (Handler dispatch) │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
         ┌──────▼──────┐ ┌────▼──────┐ ┌────▼──────┐
         │0x00006340   │ │ 0x0000636c│ │0x000063e8 │
         │   Wrapper1  │ │  Wrapper2 │ │ Wrapper3  │
         └──────┬──────┘ └────┬──────┘ └────┬──────┘
                │              │              │
         ┌──────▼──────┐ ┌────▼──────┐ ┌────▼──────┐
         │0x050022E8   │ │0x0500284c │ │0x0500222e │
         │   ROM Func1 │ │ ROM Func2 │ │ROM Func3  │
         └─────────────┘ └───────────┘ └───────────┘
                │              │              │
         ┌──────▼──────┐ ┌────▼──────┐ ┌────▼──────┐
         │ Hardware    │ │ Hardware  │ │ Hardware  │
         │ (RAMDAC)    │ │ (DMA)     │ │ (Status)  │
         └─────────────┘ └───────────┘ └───────────┘
```

### Usage Context:
- Part of larger NeXTdimension board ROM initialization/control sequence
- Likely called during:
  - Board detection (reading configuration)
  - RAMDAC programming (color/timing setup)
  - Memory configuration (DRAM sizing)
  - Interrupt routing (handler registration)

### Coupling & Dependencies:
- **Tight coupling:** Directly calls external ROM function (0x0500222e)
- **Loose coupling:** Caller unaware of internal implementation details
- **Dependency:** Global error location (0x040105b0) must be maintained by caller

### Optimization & Maintainability:
- **Optimization:** Already minimal; function is core wrapper code
- **Maintainability:** Simple, understandable flow; suitable for firmware code
- **Testing:** Can verify by checking:
  - D0 return codes from external handler
  - Error code written to output buffer
  - Consistency with other similar wrappers

---

## SUMMARY TABLE

| Property | Value |
|----------|-------|
| **Address** | 0x000063e8 |
| **Size** | 44 bytes |
| **Decimal Offset** | 25,576 |
| **Type** | Hardware callback wrapper |
| **Parameters** | 3 (param1, param2, output handle) |
| **Return Type** | void |
| **Stack Overhead** | 24 bytes |
| **Execution Time** | 64-80 cycles (success/error paths) |
| **Calling Convention** | Motorola 68000 ABI |
| **Called By** | FUN_00006ac2 (handler dispatch function) |
| **Calls** | 0x0500222e (ROM external function) |
| **Preserved Registers** | A6, A2, A7 |
| **Modified Registers** | D0, D1, SP |
| **Error Handling** | Sentinel value (-1) with global error code storage |
| **Global References** | 0x040105b0 (error status) |
| **Pattern Family** | 6+ similar wrappers (0x6340-0x6414) |

---

## CONCLUSION

Function 0x000063e8 is a **minimal hardware abstraction wrapper** that facilitates safe, error-aware access to ROM-based hardware control routines. It follows a consistent pattern used throughout the NeXTdimension firmware for abstracting ROM function calls with error handling. The function's simplicity and consistency with related wrappers suggest it's part of an automatically generated or templated code section, likely created by a hardware abstraction layer generator or macro system during firmware build.

The wrapper's primary value is in **standardizing error handling** across multiple hardware control points, ensuring that hardware operation failures are consistently captured and reported to calling code via a standard mechanism (writing to a caller-provided output buffer).
