# Callback Function Analysis: FUN_0000366e

## Quick Summary

**Function**: `FUN_0000366e` at address `0x0000366e`
**Type**: Callback Adapter / Utility Wrapper
**Size**: 30 bytes
**Complexity**: LOW
**Priority**: HIGH (Callback)

---

## What It Does

This function is a lightweight adapter that chains two external library function calls:

```
Input (3 params)
    ↓
[Call libfunc_1 with params 2 & 3]
    ↓
[Pass result to libfunc_2]
    ↓
Return final result
```

---

## Function Signature

```c
int32_t FUN_0000366e(
    void *context,      // A6+0x08 (parameter 1, unused)
    int32_t param2,     // A6+0x0c (first computation input)
    int32_t param3      // A6+0x10 (second computation input)
)
{
    // Call external function 1
    int32_t result = libfunc_1(param2, param3);  // 0x0500315e

    // Pass result through function 2
    return libfunc_2(result);                     // 0x050032ba
}
```

---

## Assembly Code

```asm
0x0000366e:  link.w     A6,0x0              ; Setup stack frame
0x00003672:  move.l     (0x10,A6),-(SP)     ; Push param 3
0x00003676:  move.l     (0x0c,A6),-(SP)     ; Push param 2
0x0000367a:  bsr.l      0x0500315e          ; Call libfunc_1
0x00003680:  move.l     D0,-(SP)            ; Push result
0x00003682:  bsr.l      0x050032ba          ; Call libfunc_2
0x00003688:  unlk       A6                  ; Cleanup
0x0000368a:  rts                            ; Return
```

---

## Called By

Single caller: **FUN_000060d8** at offset `0x00006132`
- Context: Structure validation function
- Timing: Called when validation succeeds
- Result usage: Stored to output structure at offset +0x1c

### Calling Context

```asm
; In FUN_000060d8:
0x00006126:  move.l     (0x24,A0),-(SP)    ; Push param from data struct
0x0000612a:  move.l     (0x1c,A0),-(SP)    ; Push param from data struct
0x0000612e:  move.l     (0xc,A0),-(SP)     ; Push param from data struct
0x00006132:  bsr.l      0x0000366e         ; CALL THIS FUNCTION ←
0x00006138:  move.l     D0,(0x1c,A2)       ; Store result to output
```

---

## Calls Made

Two external library functions (addresses in 0x05XXXXXX range):

| Address | Usage | Used By | Purpose |
|---------|-------|---------|---------|
| `0x0500315e` | Primary transformation | 15+ functions | Takes 2 params, returns 32-bit value |
| `0x050032ba` | Final processor | 11+ functions | Takes 1 param, returns 32-bit value |

Both functions are widely used throughout the codebase, suggesting they are core utility functions.

---

## Stack Analysis

### Stack Layout at Entry

```
A6+0x10 ← Parameter 3 (int32_t value2)
A6+0x0c ← Parameter 2 (int32_t value1)
A6+0x08 ← Parameter 1 (void *context - unused)
A6+0x04 ← Return address
A6+0x00 ← Saved A6 (set by LINK.W)
```

### Parameters

All 3 parameters come from caller's data structure:
- **Param 1** (`A6+0x08`): Pointer to source structure (unused in this function)
- **Param 2** (`A6+0x0c`): First value (from `source+0x1c`)
- **Param 3** (`A6+0x10`): Second value (from `source+0x24`)

---

## Data Flow

```
Caller's A0 (data structure)
├─ Offset +0x0c → Param 1 (passed but not used)
├─ Offset +0x1c → Param 2 → libfunc_1 input 1
└─ Offset +0x24 → Param 3 → libfunc_1 input 2

libfunc_1(param2, param3)
└─ Returns in D0 → pushed to stack

libfunc_2(D0)
└─ Returns in D0 (final result)

Result (in D0)
└─ Caller stores to A2+0x1c (output structure)
```

---

## Control Flow

**Straight-line execution** (no branches):

```
Entry
  ↓
LINK (setup frame)
  ↓
Push param 3
  ↓
Push param 2
  ↓
Call libfunc_1 (always returns)
  ↓
Push result
  ↓
Call libfunc_2 (always returns)
  ↓
UNLK (cleanup)
  ↓
RTS (return)
```

No conditional branches. Linear execution path.

---

## Register Impact

| Register | Input | Output | Purpose |
|----------|-------|--------|---------|
| A6 | Saved by caller | Restored by UNLK | Frame pointer |
| D0 | Arbitrary | Result value | Return register |
| A0-A5 | Preserved | Preserved | Not modified |
| D1-D7 | Preserved | Preserved | Not modified |
| SP | Stack position | Adjusted by UNLK | Stack pointer |

---

## Hardware Access

**NONE**: This function performs no hardware register access
- No I/O memory operations
- No NeXTdimension register access
- No video/DMA/SCSI control
- Pure software computation

---

## Performance Characteristics

### Instruction Count
- Total instructions: 8
- Instruction types:
  - Frame management: 2 (LINK, UNLK)
  - Memory operations: 3 (MOVE, MOVE, MOVE)
  - External calls: 2 (BSR, BSR)
  - Control flow: 1 (RTS)

### Estimated Cycles (approximate)
- LINK.W: ~4 cycles
- MOVE.L (read): ~4 cycles each (×2 moves)
- MOVE.L (write): ~4 cycles
- BSR.L: ~6 cycles each (×2 calls)
- UNLK: ~3 cycles
- RTS: ~4 cycles
- **Total frame ops**: ~24 cycles
- **Dominated by**: External function call overhead

### Bottleneck
External function calls dominate execution time. Actual performance depends entirely on:
1. `libfunc_1` implementation and complexity
2. `libfunc_2` implementation and complexity

---

## Security Analysis

### Input Validation
**Status**: NOT PERFORMED
- No bounds checking
- No null pointer checks
- Relies entirely on caller validation

### Robustness
- Stack operations are safe (balanced LINK/UNLK)
- No buffer overflows
- No format string vulnerabilities
- No type confusion

### Threat Model
- **DoS vector**: If external functions hang or crash on bad input
- **Exploitability**: LOW (no obvious vulnerabilities in this function)
- **Information disclosure**: No sensitive data handling

---

## Classification & Purpose

### Type: CALLBACK ADAPTER FUNCTION

**Evidence:**
1. Minimal logic (only parameter forwarding)
2. Bridges two external functions
3. Stateless (no persistent state)
4. Called from validation framework
5. Auto-generated name (FUN_XXXX pattern)

### Suspected Use Cases
1. **Math pipeline**: Coordinate transform → normalize
2. **Validation pipeline**: Check constraints → finalize status
3. **State update**: Compute delta → apply change
4. **Error handling**: Validate input → generate error code

### Typical Invocation Pattern
```
validation_framework()
  ├─ Check parameter validity
  ├─ If valid: Call this callback
  ├─ If callback succeeds: Mark status OK, store result
  └─ If validation fails: Set error code, skip callback
```

---

## Related Functions

### Direct References
- **Caller**: FUN_000060d8 (single caller)
- **Called**: libfunc_1 (0x0500315e), libfunc_2 (0x050032ba)

### Similar Functions
- **FUN_0000368c**: Similar structure, 4-parameter version
- Multiple dispatch table entries: Similar callback patterns

### Widespread Callers
- **libfunc_1** (0x0500315e): Used by 15+ functions
- **libfunc_2** (0x050032ba): Used by 11+ functions

---

## Key Findings

1. **Minimal complexity**: Only 30 bytes, pure wrapper function
2. **Clear purpose**: Chains two transformations
3. **No direct hardware access**: Pure software
4. **Single caller**: Only called from one place
5. **External dependencies**: Functionality hidden in external functions
6. **Safe stack operations**: Proper frame management
7. **No input validation**: Assumes valid parameters
8. **Linear control flow**: No branches or loops

---

## Recommendations

### For Understanding
1. **Analyze external functions** (0x0500315e, 0x050032ba)
2. **Study caller** (FUN_000060d8) for context
3. **Look for similar patterns** in other callback functions

### For Optimization
1. Consider inlining if external functions are simple
2. Profile to confirm external calls are bottleneck
3. Cache results if same parameters called frequently

### For Development
1. Add symbolic names when purpose identified
2. Document what the external functions do
3. Add parameter validation or document assumptions

### For Testing
1. Test with boundary value parameters
2. Verify error handling in external functions
3. Check output structure field updates in caller

---

## Files

### Analysis Documents
- **Comprehensive**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/functions/ANALYSIS_0x0000366e_COMPREHENSIVE.md`
- **This document**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/CALLBACK_ANALYSIS_0x366e.md`

### Assembly Documentation
- **Annotated ASM**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/assembly/FUN_0000366e_ANNOTATED.asm`

### Source Data
- **Disassembly**: `/Users/jvindahl/Development/nextdimension/ndserver_re/ghidra_export/disassembly_full.asm` (lines 665-677)
- **Functions**: `/Users/jvindahl/Development/nextdimension/ndserver_re/ghidra_export/functions.json`
- **Call Graph**: `/Users/jvindahl/Development/nextdimension/ndserver_re/ghidra_export/call_graph.json`

---

## Metadata

| Field | Value |
|-------|-------|
| Function Address | 0x0000366e |
| Decimal Address | 13,934 |
| Function Size | 30 bytes |
| Analysis Date | November 08, 2025 |
| Binary | NDserver (Mach-O m68k) |
| Complexity | LOW |
| Classification | Callback Adapter |
| Priority | HIGH |

---

**END OF ANALYSIS**
