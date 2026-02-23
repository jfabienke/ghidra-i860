# Quick Reference: FUN_00006398

**Address**: `0x00006398`
**Size**: 40 bytes
**Type**: Hardware Callback Wrapper
**Complexity**: Low

---

## Function Signature

```c
long FUN_00006398(
    long *out_buffer,   // (0xc,A6) - Output buffer for error data
    long param1         // (0x10,A6) - Parameter to external function
);
```

---

## One-Liner
Single-parameter hardware service wrapper that delegates to ROM function 0x0500324e and writes system diagnostic data to output buffer on error (-1).

---

## Execution Flow

1. **Setup**: Create stack frame, save A2
2. **Load**: Move output buffer pointer to A2
3. **Push**: Push single parameter on stack
4. **Call**: `bsr.l 0x0500324e` → external service
5. **Check**: Compare D0 with -1 (error sentinel)
6. **Branch**: If D0 ≠ -1 (success), skip error handler
7. **Error**: If D0 == -1, write system data from 0x040105b0 to (A2)
8. **Return**: Restore A2, unlink frame, return with D0 unchanged

---

## Return Values

| D0 Value | Meaning | Output Buffer |
|----------|---------|----------------|
| 0 | Success | Unchanged |
| > 0 | Success | Unchanged |
| -1 | **Error** | **Filled with 0x040105b0** |

---

## Key Details

| Aspect | Value |
|--------|-------|
| **Called By** | FUN_00006a08 (NDserver message handler) |
| **Calls** | 0x0500324e (ROM hardware service) |
| **Hardware Access** | 0x040105b0 (SYSTEM_PORT+0x31c, error data) |
| **Registers Preserved** | A2, A6 |
| **Registers Destroyed** | D0 (return), D1 (temporary) |
| **Stack Cleanup** | Possible issue (parameter may not be cleaned) |

---

## Stack Frame

```
(0x10,A6) ← param1
(0xc,A6)  ← out_buffer pointer
(0x8,A6)  ← return address
(0x4,A6)  ← saved A6
(0x0,A6)  ← locals (none)
```

---

## Instructions (10 total)

| Offset | Instruction | Cycles | Effect |
|--------|-------------|--------|--------|
| +0x00 | link.w A6,0x0 | 16 | Frame setup |
| +0x04 | move.l A2,-(SP) | 8 | Save A2 |
| +0x06 | movea.l (0xc,A6),A2 | 12 | Load output ptr |
| +0x0a | move.l (0x10,A6),-(SP) | 12 | Push param |
| +0x0e | bsr.l 0x0500324e | 18 | Call external |
| +0x14 | moveq -0x1,D1 | 4 | Load -1 |
| +0x16 | cmp.l D0,D1 | 6 | Compare |
| +0x18 | bne.b 0x63b8 | 8-10 | Branch (conditional) |
| +0x1a | move.l (0x040105b0).l,(A2) | 28 | Write error data |
| +0x20 | movea.l (-0x4,A6),A2 | 12 | Restore A2 |
| +0x24 | unlk A6 | 12 | Teardown |
| +0x26 | rts | 16 | Return |

**Total (success)**: ~126 cycles
**Total (error)**: ~150 cycles
*External function dominates latency*

---

## Common Issues

### 1. NULL Pointer Crash
If caller passes NULL for `out_buffer`:
- Error path executes when D0 == -1
- Instruction `move.l (0x040105b0).l,(A2)` writes to address 0x00000000
- Bus error → crash

**Fix**: Add `cmp.l #0,A2; beq error_invalid` after loading A2

### 2. Stack Imbalance
Parameter pushed at 0x63a2 but not explicitly cleaned:
- After unlk: SP still points to pushed parameter
- rts doesn't clean parameter from stack

**Assumption**: External function at 0x0500324e uses callee-cleanup convention

### 3. Error Data Unknown
System data written from 0x040105b0, but meaning is opaque:
- Caller receives error data but doesn't know what it represents
- No documentation of error codes

**Workaround**: Consult NeXTdimension hardware documentation for 0x040105b0 layout

---

## Comparison to Similar Functions

### FUN_000062b8 (3-parameter version)
```
Size: 48 bytes (vs 40 bytes)
Parameters: 3 (vs 1)
External call: 0x0500330e (vs 0x0500324e)
Error handling: Identical
System data address: Same (0x040105b0)
```

**Pattern**: Both are isomorphic wrappers, differing only in arity.

---

## Testing Checklist

- [ ] Success path (D0 ≠ -1) returns result unchanged
- [ ] Success path leaves output buffer unmodified
- [ ] Error path (D0 == -1) writes system data to buffer
- [ ] A2 register preserved across function
- [ ] Stack frame properly set up/torn down
- [ ] Parameter correctly passed to external function
- [ ] NULL pointer check added (security fix)

---

## Related Memory Addresses

```
0x040105b0  System error/status data
0x0500324e  External hardware service function
0x00006398  This function
0x00006a08  Caller (NDserver message handler)
0x00006a80  Call site in caller
```

---

## Code Pattern

```asm
link.w A6,0          ; Setup frame
move.l A2,-(SP)      ; Save A2
movea.l (0xc,A6),A2  ; Load output ptr
move.l (0x10,A6),-(SP)  ; Push param
bsr.l 0x0500324e     ; Call service
moveq -0x1,D1        ; Load error sentinel
cmp.l D0,D1          ; Compare
bne.b skip_error     ; Skip if success
move.l (0x040105b0).l,(A2)  ; Write error data
skip_error:
movea.l (-0x4,A6),A2 ; Restore A2
unlk A6              ; Teardown
rts                  ; Return
```

---

## Assembly Idioms Used

1. **Frame Setup/Teardown**: Standard m68k prologue/epilogue
2. **Stack Arguments**: Caller passes parameters on stack (cdecl convention)
3. **Register Save/Restore**: A2 preserved using stack
4. **Sentinel Value Error Detection**: Compare return value with -1
5. **Conditional Short Branch**: bne.b for success fast path

---

## Key Insight

This function implements a **hardware abstraction layer** pattern:

```
Caller (NDserver kernel message handler)
    ↓
FUN_00006398 (wrapper with error reporting)
    ↓
0x0500324e (ROM hardware service)
    ↓
Hardware operation (device I/O, register access)
```

Separates concerns:
- **Caller**: Message routing, validation
- **Wrapper**: Error detection, diagnostic reporting
- **Service**: Hardware interaction

---

## Context: NeXTdimension NDserver

- **Binary**: NDserver (i860 Mach microkernel)
- **Purpose**: Graphics processing on i860 processor
- **Command**: 0x42c (message type handled by FUN_00006a08)
- **Role**: Part of message dispatch system

This function is called when host (68040) sends command 0x42c to i860 graphics processor. NDserver message handler extracts parameters, calls this wrapper, and returns result to host.

---

**Last Updated**: November 9, 2025
**Source**: Ghidra 11.2.1 disassembly analysis
