# Visual Analysis Guide: FUN_0000627a

## Function Structure Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  FUN_0000627a (errno_wrapper) @ 0x0000627a - 62 bytes      │
└─────────────────────────────────────────────────────────────┘

    ENTRY POINT
    0x0000627a
       │
       ├─ LINKW A6, #0         ┌─────────────────────┐
       │                        │ Frame Setup Phase   │
       ├─ MOVEL A3, -(SP)      │ - No local vars     │
       │                        │ - Save A2, A3       │
       ├─ MOVEL A2, -(SP)      └─────────────────────┘
       │
       ├─ MOVEAL 0xc(A6), A3   ┌─────────────────────┐
       │                        │ Parameter Extraction
       ├─ MOVEAL 0x18(A6), A2  │ - errno_ptr → A3    │
       │                        │ - result_ptr → A2   │
       │                        └─────────────────────┘
       │
       ├─ MOVEL 0x1c(A6), -(SP) ┌──────────────────────┐
       │                         │ Prepare External Call
       ├─ MOVEL 0x14(A6), -(SP) │ - Push arg3, arg2,   │
       │                         │   arg1 on stack      │
       ├─ MOVEL 0x10(A6), -(SP) └──────────────────────┘
       │
       ├─ BSR.L 0x05002d62      ┌──────────────────────┐
       │  D0 = result            │ EXTERNAL CALL        │
       │                         │ (System function)    │
       │                         └──────────────────────┘
       │
       ├─ TSTL D0               ┌──────────────────────┐
       │  Set condition codes    │ Evaluate Result      │
       │                         │ - D0 > 0 = Success   │
       ├─ BLE.B 0x000062a4     │ - D0 <= 0 = Error    │
       │  (Test: D0 <= 0?)       └──────────────────────┘
       │
       ├─────┬──────────────────┬─────────┐
       │     │                  │         │
       │     SKIP (D0 > 0)      TAKEN     PATH DEPENDS
       │     SUCCESS PATH       ERROR     ON RESULT
       │                        PATH
       │
   0x000062a0:             0x000062a4:
   MOVEL D0,(A2)      →     CLRL (A2)
   │                        │
   │                        MOVEL 0x040105b0.l,(A3)
   │                        │  [READ ERRNO]
   │                        │
   └─────────┬──────────────┘
             │
             ├─ BRA.B (always)
             │
             ├─ Cleanup Phase
             ├─ MOVEAL -0x8(A6), A2  [Restore A2]
             ├─ MOVEAL -0x4(A6), A3  [Restore A3]
             ├─ UNLK A6               [Unwind frame]
             ├─ RTS                   [Return]
             │
             RETURN TO CALLER
```

## Stack Frame Layout

```
BEFORE FUNCTION CALL (Caller's frame):
┌─────────────────────────────┐
│ ... previous data ...       │ Higher addresses
├─────────────────────────────┤
│ errno_ptr (A6+0x1c)         │ arg3 (system call param 3)
├─────────────────────────────┤
│ unused (A6+0x18)            │ result_ptr (goes to A2)
├─────────────────────────────┤
│ arg2 (A6+0x14)              │ system call param 2
├─────────────────────────────┤
│ arg1 (A6+0x10)              │ system call param 1
├─────────────────────────────┤
│ errno_dest (A6+0x0c)        │ goes to A3
├─────────────────────────────┤
│ unused (A6+0x08)            │
├─────────────────────────────┤
│ Return address (A6+0x04)    │ Pushed by CALL
├─────────────────────────────┤ ← A6 points here after LINKW
│ Old A6 (A6+0x00)            │ Saved by LINKW
├─────────────────────────────┤
│ A3 saved (A6-0x04)          │ ← Part of frame
├─────────────────────────────┤
│ A2 saved (A6-0x08)          │ ← Part of frame
├─────────────────────────────┤
│ ... stack grows down ...    │ Lower addresses
└─────────────────────────────┘


DURING EXTERNAL CALL (0x05002d62):
┌─────────────────────────────┐
│ ... previous saved ...      │
├─────────────────────────────┤
│ arg1 (from A6+0x10)         │ SP+0
├─────────────────────────────┤
│ arg2 (from A6+0x14)         │ SP+4
├─────────────────────────────┤
│ arg3 (from A6+0x1c)         │ SP+8
├─────────────────────────────┤ ← SP points here (for BSR.L target)
│ A2 saved                    │
├─────────────────────────────┤
│ A3 saved                    │
├─────────────────────────────┤
│ Return address              │
├─────────────────────────────┤
│ Old A6                      │ ← A6 points here
├─────────────────────────────┤
│ ... (original data area) ...│
└─────────────────────────────┘
```

## Register Usage Timeline

```
INSTRUCTION                    D0        A2        A3
─────────────────────────────────────────────────────
Entry (from caller)            ???       ???       ???
LINKW A6, #0
MOVEL A3, -(SP)                ???       ???    [saved]
MOVEL A2, -(SP)                ???    [saved]    [saved]
MOVEAL 0xc(A6), A3             ???       ???    → A3
MOVEAL 0x18(A6), A2            ???    → A2      A3
[3x MOVEL pushes]
BSR.L 0x05002d62            result     A2       A3
TSTL D0                     tested     A2       A3
BLE.B 000062a4     (condition flags set)
├─ If taken (D0 <= 0):
│  CLRL (A2)                  D0       A2[0]    A3
│  MOVEL 0x040105b0, (A3)     D0       A2       A3[errno]
│
└─ If not taken (D0 > 0):
   MOVEL D0, (A2)             D0    A2[result]  A3

MOVEAL -0x8(A6), A2            D0      ← restored
MOVEAL -0x4(A6), A3            D0       A2      ← restored
UNLK A6                         D0       A2       A3
RTS                            D0       A2       A3 (to caller)
```

## Data Flow Diagram

```
CALLER PROVIDES:
┌─────────────────────────────────────┐
│ A6+0x0c → errno_dest pointer        │
│ A6+0x10 → arg1 (system call)        │
│ A6+0x14 → arg2 (system call)        │
│ A6+0x18 → result_dest pointer       │
│ A6+0x1c → arg3 (system call)        │
└─────────────────────────────────────┘
          ↓
┌─────────────────────────────────────┐
│  FUN_0000627a                       │
├─────────────────────────────────────┤
│ 1. Load A3 ← errno_dest pointer     │
│ 2. Load A2 ← result_dest pointer    │
│ 3. Push arg1, arg2, arg3            │
│ 4. Call 0x05002d62                  │
│ 5. Receive result in D0             │
│                                     │
│ 6. If D0 > 0:                       │
│    ├─ *(A2) ← D0                    │
│                                     │
│ 7. If D0 <= 0:                      │
│    ├─ *(A2) ← 0                     │
│    └─ *(A3) ← read(0x040105b0)      │
└─────────────────────────────────────┘
          ↓
RESULTS:
┌─────────────────────────────────────┐
│ SUCCESS:                            │
│ - *(A2) has positive result         │
│ - *(A3) unchanged (no error)        │
│                                     │
│ FAILURE:                            │
│ - *(A2) = 0                         │
│ - *(A3) = errno value               │
└─────────────────────────────────────┘
```

## Call Chain Context

```
┌─────────────────────────────────────────────────────┐
│ ND_ServerMain (entry point)                         │
│ 0x00002dc6 - 662 bytes                              │
│ Purpose: Server initialization                      │
└─────────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────────┐
│ ND_InitializeBoardWithParameters                    │
│ 0x00005bb8 - 184 bytes                              │
│ Purpose: Initialize NeXTdimension board             │
└─────────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────────┐
│ ND_MessageReceiveLoop (main loop)                   │
│ 0x0000399c - 832 bytes                              │
│ Purpose: Receive and dispatch messages              │
└─────────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────────┐
│ ND_MessageDispatcher                                │
│ 0x00006e6c - 272 bytes                              │
│ Purpose: Route messages to handlers                 │
└─────────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────────┐
│ ND_ValidateAndConfigureMessage (FUN_00006518)       │
│ 0x00006518 - 234 bytes                              │
│ Purpose: Validate message and call FUN_0000627a    │
└─────────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────────┐
│ FUN_0000627a (errno_wrapper) ★ THIS FUNCTION       │
│ 0x0000627a - 62 bytes                               │
│ Purpose: Wrap system call with error handling       │
└─────────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────────┐
│ External System Function (0x05002d62)               │
│ External/Library call                               │
│ Purpose: Mach kernel service or library function    │
└─────────────────────────────────────────────────────┘
```

## Control Flow Logic

```
DECISION TREE:

            START
              ↓
        Call 0x05002d62
              ↓
          Get result D0
              ↓
        ┌─ TSTL D0 ─┐
        │           │
        D0>0       D0≤0
        │           │
        │      ┌────┴────┐
        │      │         │
        │   D0=0?      D0<0?
        │      │         │
    SUCCESS  NO ERROR   ERROR
        │      │         │
        │   ┌──┴────────┐│
        │   │ GENERAL   ││
        │   │ ERROR     ││
        │   │ PATH      ││
        │   └───────────┘│
        │      │         │
        └──┬───┴─────────┘
           │
     ┌─ Store result:
     │  └─ Success path: *(A2) ← D0
     │  └─ Error path: *(A2) ← 0, *(A3) ← errno
     │
     └─ Return to FUN_00006518
```

## Execution Time Estimate

```
Operation                    Cycles    Notes
─────────────────────────────────────────────────────
LINKW A6, #0                   2       Frame setup
MOVEL A3, -(SP)                2       Save register
MOVEL A2, -(SP)                2       Save register
MOVEAL 0xc(A6), A3             2       Load parameter
MOVEAL 0x18(A6), A2            2       Load parameter
─────────────────────────────────────────────────────
Subtotal (Setup):             ~12      Register setup
─────────────────────────────────────────────────────
3x MOVEL offset(A6), -(SP)     6       Push 3 args
─────────────────────────────────────────────────────
BSR.L 0x05002d62            50-100+    External call
                                       (dominates)
─────────────────────────────────────────────────────
TSTL D0                        4       Test condition
BLE.B (skip)                   2       Branch prediction
─────────────────────────────────────────────────────
SUCCESS PATH:
MOVEL D0, (A2)                 4       Store result
BRA cleanup                    2       Jump to cleanup
─────────────────────────────────────────────────────
ERROR PATH:
CLRL (A2)                      4       Clear output
MOVEL 0x040105b0, (A3)         8       Read + store errno
─────────────────────────────────────────────────────
MOVEAL -0x8(A6), A2            2       Restore A2
MOVEAL -0x4(A6), A3            2       Restore A3
UNLK A6                        2       Unwind frame
RTS                            2       Return
─────────────────────────────────────────────────────
Subtotal (Cleanup):           ~10
─────────────────────────────────────────────────────
TOTAL:                     130-180+
(External call dominates execution time)
```

## Memory Access Pattern

```
READ OPERATIONS:
┌─────────────────────────────────────┐
│ When function executes:             │
├─────────────────────────────────────┤
│ 1. Read A6+0x0c → load A3 source    │
│ 2. Read A6+0x18 → load A2 source    │
│ 3. Read A6+0x10 → read arg1         │
│ 4. Read A6+0x14 → read arg2         │
│ 5. Read A6+0x1c → read arg3         │
│ 6. External call 0x05002d62         │
│ 7. On error: Read 0x040105b0        │
│    (HARDWARE: global errno)         │
└─────────────────────────────────────┘

WRITE OPERATIONS:
┌─────────────────────────────────────┐
│ 1. Push A3, A2 to stack             │
│ 2. Push arg1, arg2, arg3 to stack   │
│ 3. Write *(A2) with result or 0     │
│ 4. Write *(A3) with errno (if error)│
│ 5. Pop and restore from stack       │
└─────────────────────────────────────┘

HARDWARE ACCESS:
┌─────────────────────────────────────┐
│ Address: 0x040105b0                 │
│ Type: READ 32-bit long              │
│ Timing: Only on error path          │
│ Frequency: Per error occurrence     │
│ Purpose: Retrieve system errno      │
└─────────────────────────────────────┘
```

## Comparison to Similar Functions

```
Function        Address   Size   Hardware     External Call
────────────────────────────────────────────────────────────
FUN_0000627a    0x0000627a  62B  0x040105b0   0x05002d62 ★
FUN_000062b8    0x000062b8  48B  0x040105b0   (unknown)
FUN_000062e8    0x000062e8  48B  0x040105b0   (unknown)
FUN_00006318    0x00006318  40B  0x040105b0   (unknown)
FUN_00006340    0x00006340  44B  0x040105b0   (unknown)
FUN_0000636c    0x0000636c  44B  0x040105b0   (unknown)
FUN_00006398    0x00006398  40B  0x040105b0   (unknown)
FUN_000063c0    0x000063c0  40B  0x040105b0   (unknown)
FUN_000063e8    0x000063e8  44B  0x040105b0   (unknown)
FUN_00006414    0x00006414  48B  0x040105b0   (unknown)
FUN_00006444    0x00006444  48B  0x040105b0   (unknown)
FUN_000061f4    0x000061f4 134B  0x040105b0   (unknown)

ALL: Same errno location (0x040105b0)
ALL: Similar error handling pattern
HYPOTHESIS: System call wrapper family
```

---

**Visual Reference Complete**

Use this guide alongside:
- `0000627a_FUN_0000627a_COMPLETE.md` (detailed 18-section analysis)
- `0000627a_FUN_0000627a_errno_wrapper.asm` (fully annotated assembly)

