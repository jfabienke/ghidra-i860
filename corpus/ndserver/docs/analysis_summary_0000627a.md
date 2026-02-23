# Quick Reference: FUN_0000627a Analysis

## The Function at a Glance

**Address**: 0x0000627a
**Name**: FUN_0000627a (errno_wrapper)
**Size**: 62 bytes
**Type**: Callback / Hardware Access Wrapper
**Complexity**: LOW

## What It Does

This is a **system call wrapper** that:

1. Calls an external function (0x05002d62) with 3 parameters
2. Returns success result OR error code, depending on outcome
3. Reads global errno (0x040105b0) on error to report detailed error

## Quick Example

```c
// Caller sets up:
long result_output;
long error_output;

FUN_0000627a(
    &error_output,      // A3: where to put errno if error
    arg1, arg2, arg3,   // Parameters for external call
    &result_output      // A2: where to put success result
);

// After return:
// If call succeeded: result_output has the result
// If call failed: error_output has errno value, result_output = 0
```

## Key Points

| Aspect | Detail |
|--------|--------|
| **Hardware Access** | Reads 0x040105b0 (errno global) |
| **External Call** | Jumps to 0x05002d62 |
| **Stack Frame** | 0 bytes (LINKW #0) |
| **Registers Saved** | A2, A3 |
| **Return Path** | D0 (unchanged from external call) |

## Where It's Called

```
ND_MessageDispatcher → FUN_00006518 → FUN_0000627a → 0x05002d62
```

## Assembly Summary

| Instruction | Purpose |
|-------------|---------|
| LINKW #0 | Setup frame (no locals) |
| MOVEL A3,A2 | Save registers |
| MOVEAL offsets | Load parameters from caller frame |
| MOVEL 3x pushes | Push arguments for external call |
| BSR.L 0x05002d62 | **Call external function** |
| TSTL D0 | Check if success or error |
| BLE.B error | Branch if D0 <= 0 (error) |
| MOVEL D0,(A2) | Success: store result |
| BRA cleanup | Jump to return |
| CLRL (A2) | Error: clear output |
| MOVEL errno,(A3) | Error: read errno |
| UNLK / RTS | Return to caller |

## Error Handling Pattern

```
if (external_call() > 0) {
    output_result = external_call_result;
} else {
    output_result = 0;
    output_errno = read_from_0x040105b0;
}
```

## Security Concerns

1. **No NULL checks**: Assumes A2/A3 are valid pointers
2. **No bounds checking**: May overflow target buffers
3. **Unvalidated pointers**: Caller provides all pointers

## Related Functions

Part of **errno wrapper family**:
- 0x000061f4 (largest, 134B)
- 0x0000627a (THIS, 62B)
- 0x000062b8, 0x000062e8, 0x00006318, ... (more variants)

All use same pattern: external call + errno handling

## Why It Matters

This function is:
- Part of the **message handling pipeline** (high-level operations)
- Called when **validating messages** from NeXTdimension board
- Critical for **error reporting** in NDserver driver
- Example of **callback-style error handling** in m68k code

## Next Steps for Analysis

1. ✓ Identify function purpose (errno wrapper)
2. ✓ Understand calling context (message validation)
3. → Identify what 0x05002d62 does (external function)
4. → Trace caller FUN_00006518 for full context
5. → Analyze entire errno wrapper family

---

**Files Created**:
- `/docs/functions/0000627a_FUN_0000627a_COMPLETE.md` (18-section deep analysis)
- `/disassembly/annotated/0000627a_FUN_0000627a_errno_wrapper.asm` (annotated assembly)
- `/docs/analysis_summary_0000627a.md` (this file)

**Analysis Date**: November 08, 2025
