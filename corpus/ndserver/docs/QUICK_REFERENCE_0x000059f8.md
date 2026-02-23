# Quick Reference: FUN_000059f8

## At a Glance

| Property | Value |
|----------|-------|
| **Address** | 0x000059f8 |
| **Size** | 70 bytes |
| **Category** | Callback (Wrapper) |
| **Complexity** | LOW |
| **Priority** | HIGH |
| **Hardware** | None |

## Instructions (15 total, 70 bytes)

```
linkw    A6,-0x20          ; Create 32-byte frame
move.l   (0x7c88).l,-8(A6) ; Load global → local -8
move.l   12(A6),-4(A6)     ; Copy arg2 → local -4
move.b   #1,-29(A6)        ; Set flag
moveq    #0x20,D1          ; D1 = 0x20
move.l   D1,-28(A6)        ; Store to local -28
clr.l    -24(A6)           ; Clear local -24
move.l   8(A6),-16(A6)     ; Copy arg1 → local -16
clr.l    -20(A6)           ; Clear local -20
move.l   #0x82,-12(A6)     ; Magic value → local -12
clr.l    -(SP)             ; Push 0
clr.l    -(SP)             ; Push 0
pea      -32(A6)           ; Push frame address
bsr.l    0x050029d2        ; Call external function
unlk     A6                ; Destroy frame
rts                        ; Return
```

## Stack Frame (32 bytes)

```
A6-4:   Copy of arg @ A6+12
A6-8:   Global from 0x7c88
A6-12:  Constant 0x82
A6-16:  Copy of arg @ A6+8
A6-20:  Zero
A6-24:  Zero
A6-28:  Value 0x20
A6-29:  Flag 0x01
```

## Function Behavior

1. **Input**: Two arguments on caller's stack (A6+8, A6+12)
2. **Setup**: Create 32-byte structure, initialize with args + magic values
3. **Delegate**: Call 0x050029d2 with (0, 0, &structure)
4. **Return**: Result from 0x050029d2 in D0

## Pattern Classification

**Callback Wrapper** - Minimal pattern matching:
- Frame setup (LINKW) ✓
- Argument repackaging ✓
- Single external call ✓
- Standard return (UNLK/RTS) ✓

## Key Values

| Value | Meaning |
|-------|---------|
| 0x20 | Frame size (32 bytes) |
| 0x82 | Magic type/version identifier |
| 0x01 | Boolean flag (active) |
| 0x7c88 | Global variable address |
| 0x050029d2 | External system function |

## Entry Point

**Not called by any internal function** → Likely callback dispatch target

## Analysis Status

- **Pattern**: 95% confidence (clear callback structure)
- **Purpose**: 40% confidence (need caller context)
- **External function**: 30% confidence (unknown API)

## Next Steps to Full Analysis

1. Find function pointer table containing 0x000059f8
2. Analyze what 0x050029d2 does
3. Trace how this callback gets invoked
4. Compare with 0x00005d60, 0x00005da6 (similar callbacks)

## Related Callouts

- **0x050029d2**: External function called (used 7x in codebase)
- **0x7c88**: Global variable referenced
- **0x00005d60**: Similar 70-byte callback
- **0x00005da6**: Similar 68-byte callback
- **0x00003eae**: Related 140-byte callback

---

**Full Analysis**: ANALYSIS_0x000059f8_FUN_000059f8_CALLBACK.md
**Annotated Assembly**: 000059f8_FUN_000059f8_CALLBACK.asm
