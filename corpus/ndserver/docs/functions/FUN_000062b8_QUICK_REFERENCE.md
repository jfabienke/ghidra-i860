# FUN_000062b8 - Quick Reference Card

| Property | Value |
|----------|-------|
| **Address** | 0x000062b8 |
| **Size** | 48 bytes |
| **Instructions** | 12 |
| **Type** | Callback / Wrapper |
| **Category** | Hardware |
| **Complexity** | Low |
| **Called By** | FUN_00006602 (at 0x0000669c) |
| **Calls** | 0x0500330e (external service) |

## Function Prototype

```c
long FUN_000062b8(
    long param1,
    long param2,
    long param3,
    long *output_buffer
);
```

## Quick Behavior

1. **Setup**: Creates stack frame, saves A2 register
2. **Load**: Gets output buffer pointer from arg[0]
3. **Call**: Invokes external function at 0x0500330e with 3 arguments
4. **Check**: Tests if return value equals -1 (error)
5. **Error Handler**: If error, writes system data from 0x040105b0 to output buffer
6. **Return**: Returns with D0 unchanged from external call

## Pseudo-C

```c
long FUN_000062b8(long p1, long p2, long p3, long *out) {
    long result = external_service(p1, p2, p3);
    if (result == -1) {
        *out = *(long*)0x040105b0;  // System error data
    }
    return result;
}
```

## Control Flow

```
START
  ↓
[Frame Setup]
  ↓
[Load Output Ptr → A2]
  ↓
[Push 3 Arguments]
  ↓
[Call External @ 0x0500330e]
  ↓
[Check D0 == -1?]
  ├─→ YES: [Write System Data to (A2)]
  │         ↓
  └─→ NO:  [Skip Error Handler]
            ↓
[Restore A2]
  ↓
[Unlink Frame]
  ↓
[Return with D0]
  ↓
END
```

## Key Instructions

| Offset | Instruction | Purpose |
|--------|-------------|---------|
| +0x00 | `link.w A6,0x0` | Stack frame prologue |
| +0x02 | `move.l A2,-(SP)` | Save A2 (callee-saved) |
| +0x04 | `movea.l (0xc,A6),A2` | Load output buffer pointer |
| +0x08 | `move.l (0x18,A6),-(SP)` | Push arg[3] |
| +0x0c | `move.l (0x14,A6),-(SP)` | Push arg[2] |
| +0x10 | `move.l (0x10,A6),-(SP)` | Push arg[1] |
| +0x14 | `bsr.l 0x0500330e` | Call external function |
| +0x1a | `moveq -0x1,D1` | Load error sentinel |
| +0x1c | `cmp.l D0,D1` | Compare return vs -1 |
| +0x1e | `bne.b 0x000062e0` | Skip error if not -1 |
| +0x20 | `move.l (0x040105b0).l,(A2)` | Write error data |
| +0x26 | `movea.l (-0x4,A6),A2` | Restore A2 |
| +0x2a | `unlk A6` | Unlink frame |
| +0x2c | `rts` | Return |

## Register Usage

| Register | Input | Output | Notes |
|----------|-------|--------|-------|
| A2 | Output buffer ptr | Restored | Callee-saved |
| A6 | Caller's frame ptr | Restored | Frame pointer |
| D0 | (undefined) | Function result | Return value |
| D1 | (undefined) | (destroyed) | Temp (comparison) |
| SP | Stack | Balanced | Adjusted by link/unlk |

## Stack Frame Layout

```
(0x18,A6)  ← arg[3] (parameter 3)
(0x14,A6)  ← arg[2] (parameter 2)
(0x10,A6)  ← arg[1] (parameter 1)
(0x0c,A6)  ← arg[0] (output buffer pointer)
(0x08,A6)  ← return address
(0x04,A6)  ← saved A6
(0x00,A6)  ← locals (none)
```

## Hardware Access

### Read
- **0x040105b0** (SYSTEM_PORT+0x31c)
  - System data area
  - Accessed only on error (D0 == -1)
  - Value written to output buffer

### Write
- **(A2)** (output buffer)
  - System error data written here
  - Only if D0 == -1
  - Must be valid pointer

## Error Handling

**Error Condition**: D0 == -1
**Action**: Write system data from 0x040105b0 to (*A2)
**Return**: D0 unchanged (-1)

**Success Condition**: D0 != -1
**Action**: Skip error write
**Return**: D0 (external function result)

## Calling Context

Called from **FUN_00006602** (message handler):
```asm
0x0000669c:  bsr.l 0x000062b8
0x000066a2:  move.l D0,(0x24,A3)  ; Store result
```

## Memory Map

| Address | Content | Purpose |
|---------|---------|---------|
| 0x000062b8 | This function | Callback wrapper |
| 0x0500330e | External service | Core business logic |
| 0x040105b0 | System data | Error information |

## Related Functions

- **FUN_00006602** - Caller (message handler)
- **FUN_000062e8** - Similar wrapper (48 bytes)
- **FUN_00006318** - Similar wrapper (40 bytes)
- **FUN_00006340** - Similar wrapper (44 bytes)

## Performance Profile

| Metric | Value |
|--------|-------|
| **Size** | 48 bytes |
| **Instructions** | 12 |
| **Cycles (est)** | 20-30 cycles (overhead only) |
| **Bottleneck** | External call (0x0500330e) |
| **Overhead %** | ~5% of total time |

## Testing Checklist

- [ ] Success path: D0 ≠ -1 (skip error handler, return D0)
- [ ] Error path: D0 == -1 (write system data, return -1)
- [ ] Register preservation: A2 saved and restored correctly
- [ ] Stack balance: SP correct on entry and exit
- [ ] Frame pointer: A6 properly linked and unlinked
- [ ] Output buffer: Write occurs only on error

## Security Notes

⚠️ **Risks**:
- No validation of output buffer pointer (A2)
- Assumes system data at 0x040105b0 is readable
- No timeout or recovery if external call hangs
- Single error code (-1) limits diagnosis

✓ **Strengths**:
- Standard calling convention
- Proper register preservation
- Clear error detection
- Simple, auditable code

## Future Investigation

**HIGH PRIORITY**:
- Identify function at 0x0500330e (external service)
- Determine meaning of system data at 0x040105b0
- Document error codes and semantics

**MEDIUM PRIORITY**:
- Map message handler to command types
- Test error handling paths
- Trace caller relationships

## Document Info

- **Generated**: November 8, 2025
- **Tool**: Ghidra 11.2.1
- **Status**: Complete
- **Full Analysis**: See FUN_000062b8_COMPREHENSIVE_ANALYSIS.md
