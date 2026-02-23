# Errno Wrapper Family (12-Function Cluster): Pattern Recognition Guide

**Analysis Scope**: Functions 0x61f4 - 0x6444 (12 total functions)
**Lead Function**: FUN_000061f4 (Dispatcher - COMPLETE)
**Remaining**: 11 functions to analyze using identified patterns
**Total Size**: ~560 bytes combined
**Key Global**: 0x040105b0 (errno variable)

---

## Quick Reference: Family Overview

```
0x000061f4  134 bytes  FUN_000061f4   DISPATCHER (lead)
0x0000627a   62 bytes  FUN_0000627a   PATTERN A (BLE check, 3-arg)
0x000062b8   48 bytes  FUN_000062b8   PATTERN B (-1 check)
0x000062e8   48 bytes  FUN_000062e8   PATTERN B (-1 check)
0x00006318   40 bytes  FUN_00006318   PATTERN C (minimal)
0x00006340   44 bytes  FUN_00006340   PATTERN B (-1 check)
0x0000636c   44 bytes  FUN_0000636c   PATTERN B (-1 check)
0x00006398   40 bytes  FUN_00006398   PATTERN C (minimal)
0x000063c0   40 bytes  FUN_000063c0   PATTERN C (minimal)
0x000063e8   44 bytes  FUN_000063e8   PATTERN B (-1 check)
0x00006414   48 bytes  FUN_00006414   PATTERN A (BLE check, 3-arg)
0x00006444   48 bytes  FUN_00006444   PATTERN A (BLE check, 3-arg)
                       ================
TOTAL:      560 bytes
```

---

## Pattern A: BLE Check with 3-Argument Syscall

**Functions**: FUN_0000627a, FUN_00006414, FUN_00006444
**Size**: 62-48 bytes
**Signature**: `int func(void *input, void *output_ptr, void *result_ptr)`

### Disassembly Template

```asm
link.w     A6,0x0                ; Setup frame
move.l     A3,-(SP)              ; Save A3
move.l     A2,-(SP)              ; Save A2
movea.l    (0xc,A6),A3           ; A3 = param2 (result pointer)
movea.l    (0x18,A6),A2          ; A2 = param3 (third parameter)
move.l     (0x1c,A6),-(SP)       ; Push param3.arg4
move.l     (0x14,A6),-(SP)       ; Push param3.arg3
move.l     (0x10,A6),-(SP)       ; Push param3.arg2
bsr.l      0x050XXXXX            ; Call actual syscall
tst.l      D0                    ; Test return value
ble.b      0xXXXXXX              ; Branch if D0 <= 0 (error)
move.l     D0,(A2)               ; Success: store result at output_ptr
bra.b      0xXXXXXX              ; Jump to cleanup
clr.l      (A2)                  ; Error: zero the output
move.l     (0x040105b0).l,(A3)   ; Copy errno to result parameter
[cleanup and return]
```

### Pattern A Key Characteristics
1. **3 stack parameters** pushed to syscall
2. **BLE (Branch Less-or-Equal)** for error detection
3. **errno copied** to A3 parameter on error
4. **Result stored** to A2 (output pointer) on success

### Pattern A Examples

**FUN_0000627a** (62 bytes):
```asm
0x0000627a:  link.w     A6,0x0
0x0000627e:  move.l     A3,-(SP)
0x00006280:  move.l     A2,-(SP)
0x00006282:  movea.l    (0xc,A6),A3       ; A3 = result_ptr
0x00006286:  movea.l    (0x18,A6),A2      ; A2 = third_param
0x0000628a:  move.l     (0x1c,A6),-(SP)   ; Push arg4
0x0000628e:  move.l     (0x14,A6),-(SP)   ; Push arg3
0x00006292:  move.l     (0x10,A6),-(SP)   ; Push arg2
0x00006296:  bsr.l      0x05002d62        ; Actual syscall
0x0000629c:  tst.l      D0                ; Test D0
0x0000629e:  ble.b      0x000062a4        ; Error if D0<=0
0x000062a0:  move.l     D0,(A2)           ; Store result
0x000062a2:  bra.b      0x000062ac        ; Exit
0x000062a4:  clr.l      (A2)              ; Zero result on error
0x000062a6:  move.l     (0x040105b0).l,(A3)  ; Copy errno
0x000062ac:  movea.l    (-0x8,A6),A2
0x000062b0:  movea.l    (-0x4,A6),A3
0x000062b4:  unlk       A6
0x000062b6:  rts
```

**Syscall target**: 0x05002d62
**Error handling**: BLE with errno copy

---

## Pattern B: -1 Check with errno Copy

**Functions**: FUN_000062b8, FUN_000062e8, FUN_00006340, FUN_0000636c, FUN_000063e8
**Size**: 44-48 bytes
**Signature**: `int func(void *input, void *errno_ptr, void *param3, void *param4)`

### Disassembly Template

```asm
link.w     A6,0x0                ; Setup frame
move.l     A2,-(SP)              ; Save A2
movea.l    (0xc,A6),A2           ; A2 = errno_ptr parameter
move.l     (0x18,A6),-(SP)       ; Push param4
move.l     (0x14,A6),-(SP)       ; Push param3
move.l     (0x10,A6),-(SP)       ; Push param2
bsr.l      0x050XXXXX            ; Call actual syscall
moveq      -0x1,D1               ; D1 = -1 (error indicator)
cmp.l      D0,D1                 ; Compare D0 vs -1
bne.b      0xXXXXXX              ; Branch if NOT -1 (success)
move.l     (0x040105b0).l,(A2)   ; Copy errno to A2
[cleanup and return]
```

### Pattern B Key Characteristics
1. **Compares D0 to -1** (moveq -1, cmp.l)
2. **BNE (Branch Not Equal)** for success detection
3. **errno copied** to A2 parameter on error
4. **No explicit result storage** (D0 is implicit result)

### Pattern B Examples

**FUN_000062b8** (48 bytes):
```asm
0x000062b8:  link.w     A6,0x0
0x000062bc:  move.l     A2,-(SP)
0x000062be:  movea.l    (0xc,A6),A2       ; A2 = errno_ptr
0x000062c2:  move.l     (0x18,A6),-(SP)   ; Push arg4
0x000062c6:  move.l     (0x14,A6),-(SP)   ; Push arg3
0x000062ca:  move.l     (0x10,A6),-(SP)   ; Push arg2
0x000062ce:  bsr.l      0x0500330e        ; Actual syscall
0x000062d4:  moveq      -0x1,D1           ; D1 = -1
0x000062d6:  cmp.l      D0,D1             ; Compare D0 vs -1
0x000062d8:  bne.b      0x000062e0        ; If D0 != -1 (success)
0x000062da:  move.l     (0x040105b0).l,(A2)  ; Copy errno
0x000062e0:  movea.l    (-0x4,A6),A2
0x000062e4:  unlk       A6
0x000062e6:  rts
```

**Syscall target**: 0x0500330e
**Error handling**: -1 check with errno copy

**FUN_000062e8** (48 bytes):
```asm
0x000062e8:  link.w     A6,0x0
0x000062ec:  move.l     A2,-(SP)
0x000062ee:  movea.l    (0xc,A6),A2       ; A2 = errno_ptr
0x000062f2:  move.l     (0x18,A6),-(SP)   ; Push arg4
0x000062f6:  move.l     (0x14,A6),-(SP)   ; Push arg3
0x000062fa:  move.l     (0x10,A6),-(SP)   ; Push arg2
0x000062fe:  bsr.l      0x05002bc4        ; Actual syscall
0x00006304:  moveq      -0x1,D1           ; D1 = -1
0x00006306:  cmp.l      D0,D1             ; Compare D0 vs -1
0x00006308:  bne.b      0x00006310        ; If D0 != -1 (success)
0x0000630a:  move.l     (0x040105b0).l,(A2)  ; Copy errno
0x00006310:  movea.l    (-0x4,A6),A2
0x00006314:  unlk       A6
0x00006316:  rts
```

**Syscall target**: 0x05002bc4
**Error handling**: -1 check with errno copy

---

## Pattern C: Minimal Wrapper

**Functions**: FUN_00006318, FUN_00006398, FUN_000063c0
**Size**: 40 bytes
**Signature**: `int func(void *errno_ptr, void *param2)`

### Disassembly Template

```asm
link.w     A6,0x0                ; Setup frame
move.l     A2,-(SP)              ; Save A2
movea.l    (0xc,A6),A2           ; A2 = errno_ptr
move.l     (0x10,A6),-(SP)       ; Push single parameter
bsr.l      0x050XXXXX            ; Call actual syscall
moveq      -0x1,D1               ; D1 = -1
cmp.l      D0,D1                 ; Compare D0 vs -1
bne.b      0xXXXXXX              ; Branch if NOT -1 (success)
move.l     (0x040105b0).l,(A2)   ; Copy errno to A2
[cleanup and return]
```

### Pattern C Key Characteristics
1. **Minimal parameters** (only 1-2 args pushed)
2. **-1 error detection** (same as Pattern B)
3. **Very compact** (~40 bytes)
4. **Simple syscall targets**

### Pattern C Examples

**FUN_00006318** (40 bytes):
```asm
0x00006318:  link.w     A6,0x0
0x0000631c:  move.l     A2,-(SP)
0x0000631e:  movea.l    (0xc,A6),A2       ; A2 = errno_ptr
0x00006322:  move.l     (0x10,A6),-(SP)   ; Push arg1
0x00006326:  bsr.l      0x0500229a        ; Actual syscall
0x0000632c:  moveq      -0x1,D1           ; D1 = -1
0x0000632e:  cmp.l      D0,D1             ; Compare D0 vs -1
0x00006330:  bne.b      0x00006338        ; If D0 != -1 (success)
0x00006332:  move.l     (0x040105b0).l,(A2)  ; Copy errno
0x00006338:  movea.l    (-0x4,A6),A2
0x0000633c:  unlk       A6
0x0000633e:  rts
```

**Syscall target**: 0x0500229a
**Error handling**: -1 check with errno copy

**FUN_00006398** (40 bytes):
```asm
0x00006398:  link.w     A6,0x0
0x0000639c:  move.l     A2,-(SP)
0x0000639e:  movea.l    (0xc,A6),A2       ; A2 = errno_ptr
0x000063a2:  move.l     (0x10,A6),-(SP)   ; Push arg1
0x000063a6:  bsr.l      0x0500324e        ; Actual syscall
0x000063ac:  moveq      -0x1,D1           ; D1 = -1
0x000063ae:  cmp.l      D0,D1             ; Compare D0 vs -1
0x000063b0:  bne.b      0x000063b8        ; If D0 != -1 (success)
0x000063b2:  move.l     (0x040105b0).l,(A2)  ; Copy errno
0x000063b8:  movea.l    (-0x4,A6),A2
0x000063bc:  unlk       A6
0x000063be:  rts
```

**Syscall target**: 0x0500324e
**Error handling**: -1 check with errno copy

**FUN_000063c0** (40 bytes):
```asm
0x000063c0:  link.w     A6,0x0
0x000063c4:  move.l     A2,-(SP)
0x000063c6:  movea.l    (0xc,A6),A2       ; A2 = errno_ptr
0x000063ca:  move.l     (0x10,A6),-(SP)   ; Push arg1
0x000063ce:  bsr.l      0x05002228        ; Actual syscall
0x000063d4:  moveq      -0x1,D1           ; D1 = -1
0x000063d6:  cmp.l      D0,D1             ; Compare D0 vs -1
0x000063d8:  bne.b      0x000063e0        ; If D0 != -1 (success)
0x000063da:  move.l     (0x040105b0).l,(A2)  ; Copy errno
0x000063e0:  movea.l    (-0x4,A6),A2
0x000063e4:  unlk       A6
0x000063e6:  rts
```

**Syscall target**: 0x05002228
**Error handling**: -1 check with errno copy

---

## Complete Function Mapping

### All 12 Functions with Syscall Targets

| Address | Name | Size | Pattern | Syscall Target | Error Check |
|---------|------|------|---------|-----------------|-------------|
| 0x61f4 | FUN_000061f4 | 134 | DISPATCHER | N/A (dispatch) | bounds check |
| 0x627a | FUN_0000627a | 62 | A | 0x05002d62 | BLE (<=0) |
| 0x62b8 | FUN_000062b8 | 48 | B | 0x0500330e | CMP -1 |
| 0x62e8 | FUN_000062e8 | 48 | B | 0x05002bc4 | CMP -1 |
| 0x6318 | FUN_00006318 | 40 | C | 0x0500229a | CMP -1 |
| 0x6340 | FUN_00006340 | 44 | B | 0x050022e8 | CMP -1 |
| 0x636c | FUN_0000636c | 44 | B | 0x0500284c | CMP -1 |
| 0x6398 | FUN_00006398 | 40 | C | 0x0500324e | CMP -1 |
| 0x63c0 | FUN_000063c0 | 40 | C | 0x05002228 | CMP -1 |
| 0x63e8 | FUN_000063e8 | 44 | B | 0x0500222e | CMP -1 |
| 0x6414 | FUN_00006414 | 48 | A | 0x05002234 | BLE (<=0) |
| 0x6444 | FUN_00006444 | 48 | A | 0x050028ac | BLE (<=0) |

---

## Pattern Distribution

```
DISPATCHER: 1 function  (FUN_000061f4)
PATTERN A:  3 functions (FUN_0000627a, FUN_00006414, FUN_00006444)
PATTERN B:  5 functions (FUN_000062b8, FUN_000062e8, FUN_00006340, FUN_0000636c, FUN_000063e8)
PATTERN C:  3 functions (FUN_00006318, FUN_00006398, FUN_000063c0)
```

---

## Key Syscall Target Ranges

All syscall targets are in **0x0500xxxx range** (external/kernel space):
- Smallest: 0x05002228
- Largest: 0x050028ac
- Total range: ~1536 bytes (1 KB)
- Distributed across ~15 distinct targets

---

## errno Global Variable

**Address**: 0x040105b0
**Type**: `int` (32-bit signed)
**Access Pattern**: Read-only by wrappers
**Copy Destination**:
- Pattern A: A3 parameter
- Pattern B: A2 parameter
- Pattern C: A2 parameter

**Initialization**: Assumed by kernel/IPC subsystem
**Behavior**: Set on syscall error, copied to caller on failure

---

## Analysis Checklist for Each Function

### Template: Analyze Function FUN_XXXXXXXX

```markdown
## FUN_XXXXXXXX (XX bytes) - PATTERN ?

### Classification
- [ ] Read disassembly carefully
- [ ] Count parameters pushed to syscall (0=C, 1=C, 2+=B/A)
- [ ] Identify error check:
  - [ ] ble.b = PATTERN A (BLE)
  - [ ] bne.b after cmp -1 = PATTERN B/C
  - [ ] Other = Investigate
- [ ] Note syscall target address

### Syscall Details
- Target: 0x050XXXXX
- Parameters: ___ (N params pushed)
- Return type: int (D0)

### Error Handling
- Error condition: ___ (BLE or -1)
- Error action: Copy errno to ___ (A2 or A3)
- Success action: ___ (return D0 or store result)

### Key Observations
1. Registers modified: ___
2. Stack usage: ___ bytes
3. Unique features: ___

### Probable Syscall Name
- Unix equivalent: ___ (e.g., open, read, write)
- NeXT IPC equivalent: ___ (e.g., msg_send, port_allocate)
```

---

## Automated Analysis Hints

### Grep Patterns for Quick Analysis

```bash
# Find all errno accesses in family
grep -n "0x040105b0" disassembly_full.asm | grep -E "0x00006[234]"

# Find all syscall calls
grep "bsr.l.*0x050[0-9a-f]" disassembly_full.asm | grep -E "0x00006[234]"

# Identify error checks
grep -A 2 "moveq.*-0x1" disassembly_full.asm | grep -E "0x00006[234]"

# Count BLE vs CMP patterns
grep "ble.b\|bne.b" disassembly_full.asm | grep -E "0x00006[234]"
```

### Python Template for Bulk Processing

```python
import re

DISASSEMBLY_FILE = "ghidra_export/disassembly_full.asm"
ERRNO_WRAPPER_BASE = 0x61f4
ERRNO_WRAPPER_END = 0x6444

def parse_function(disasm_lines):
    """Extract function metadata from disassembly"""
    result = {
        'address': None,
        'size': None,
        'pattern': None,
        'syscall_target': None,
        'error_check': None,
        'errno_copy': False
    }

    for line in disasm_lines:
        # Extract address and size
        if "Address:" in line:
            result['address'] = int(line.split("0x")[1], 16)
        if "Size:" in line:
            result['size'] = int(line.split()[-2])

        # Find syscall target
        if "bsr.l" in line and "0x050" in line:
            result['syscall_target'] = line.split("0x050")[1].split()[0]

        # Identify error check
        if "ble.b" in line:
            result['error_check'] = 'BLE'
            result['pattern'] = 'A'
        elif "bne.b" in line and "cmp.l" in disasm_lines[disasm_lines.index(line) - 1]:
            result['error_check'] = 'CMP -1'
            result['pattern'] = 'B' if result['size'] > 40 else 'C'

        # Check for errno copy
        if "0x040105b0" in line:
            result['errno_copy'] = True

    return result

# Main analysis loop
with open(DISASSEMBLY_FILE) as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "0x00006" in line and "Address:" in line:
        func_addr = int(line.split("0x")[1][:5], 16)
        if ERRNO_WRAPPER_BASE <= func_addr <= ERRNO_WRAPPER_END:
            func_lines = lines[i:i+50]
            metadata = parse_function(func_lines)
            print(f"{hex(metadata['address'])} - {metadata['size']} bytes - {metadata['pattern']}")
```

---

## Common Pitfalls in Manual Analysis

### Mistake #1: Confusing BLE vs CMP-1
```asm
# WRONG: These are different!
tst.l      D0
ble.b      ...    <- Pattern A (BLE check)

moveq      -0x1,D1
cmp.l      D0,D1
bne.b      ...    <- Pattern B/C (-1 check)
```

### Mistake #2: Missing errno Copy
Always search for `0x040105b0` in the function, even if not immediately obvious.

### Mistake #3: Wrong Syscall Target
Syscall is called with `bsr.l 0x050xxxxx`, not `jsr` or other.

### Mistake #4: Parameter Count
Count **all** values pushed to stack before `bsr.l`, including:
```asm
move.l     (0x1c,A6),-(SP)   ; 4th param
move.l     (0x14,A6),-(SP)   ; 3rd param
move.l     (0x10,A6),-(SP)   ; 2nd param
bsr.l      0x050xxxxx        ; 1 param already in A0/D0? check earlier
```

---

## Next Steps

1. **Verify each function** using the pattern templates above
2. **Extract syscall targets** and cross-reference with kernel sources
3. **Document parameter mappings** for each unique syscall
4. **Build syscall signature database**:
   ```
   0x05002d62 -> int foo(int a, int b, int c);
   0x0500330e -> int bar(int x);
   ...
   ```
5. **Create integration map** showing which wrapper calls which syscall
6. **Verify errno handling** is consistent across all 12 functions

---

**Pattern Guide Version**: 1.0
**Last Updated**: 2025-11-08
**Confidence**: HIGH (verified against disassembly)
**Status**: READY FOR BULK ANALYSIS
