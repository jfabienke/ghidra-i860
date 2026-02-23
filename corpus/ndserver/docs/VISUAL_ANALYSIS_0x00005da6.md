# Visual Analysis: FUN_00005da6

## Call Flow Diagram

```
FUN_00003284 [Initialization Orchestrator]
│
├─ Call 1: FUN_0500315e [Preparation]
│   └─ Return with D0 (check)
│
├─ Call 2: FUN_00004a52 [Validation A]
│   └─ tst.l D0; bne 0x33aa (error branch)
│
├─ Call 3: FUN_00003820 [Validation B]
│   └─ tst.l D0; bne 0x33aa (error branch)
│
├─ Call 4: FUN_00005dea [Setup A]
│   └─ tst.l D0; bne 0x33aa (error branch)
│
├─ Call 5: FUN_00005da6 [THIS FUNCTION - Callback Init]
│   │  ┌─────────────────────────────────┐
│   │  │ Initialize 32-byte state struct │
│   │  │ Delegate to 0x050029d2          │
│   │  └─────────────────────────────────┘
│   └─ tst.l D0; bne 0x33aa (error branch)
│
├─ Call 6: FUN_05002c54 [Processing]
│   └─ tst.l D0; bne 0x33aa (error branch)
│
└─ Call 7: 0x5002f7e [Notification/Logging]

Success: Continue to system main loop
Failure: Jump to 0x33aa (error handling)
```

## Function Internal Data Flow

```
INPUT (from FUN_00003284):
  arg1 ──→ [A6 + 0x08]
  arg2 ──→ [A6 + 0x0C]

INITIALIZATION:
  0x7c90 ──┐
          ├→ move.l → [A6 - 0x08] (system config handle)

  arg1 ───┬→ move.l → [A6 - 0x10] (copy param 1)

  arg2 ───┬→ move.l → [A6 - 0x04] (copy param 2)

  0x5d5 ──┬→ move.l → [A6 - 0x0C] (callback type ID)

  0x20 ───┬→ move.l → [A6 - 0x1C] (size field)

  0x00 ───┬→ clr.l  → [A6 - 0x18] (reserved)
          ├→ clr.l  → [A6 - 0x14] (reserved)
          └→ clr.b  → [A6 - 0x1D] (status flag)

CALLBACK STATE STRUCTURE (32 bytes):
┌──────────────────────────────────┐
│ [A6 - 0x04] arg2_copy            │
│ [A6 - 0x08] system_handle        │
│ [A6 - 0x0C] callback_type=0x5d5  │
│ [A6 - 0x10] arg1_copy            │
│ [A6 - 0x14] reserved1=0          │
│ [A6 - 0x18] reserved2=0          │
│ [A6 - 0x1C] size=0x20            │
│ [A6 - 0x1D] status_flag=0        │
└──────────────────────────────────┘
        32 bytes total

DELEGATION (push on stack in reverse order):
  NULL ──→ push [stack arg 3]
  NULL ──→ push [stack arg 2]
  &struct → push [stack arg 1 = PEA (-0x20,A6)]

EXTERNAL CALL:
  0x050029d2(&callback_state, NULL, NULL)
        │
        └─→ D0 = return status

OUTPUT:
  D0 ──→ return to FUN_00003284

CALLER CHECKS:
  tst.l D0
  If D0 != 0: Jump to error handler (0x33aa)
  If D0 == 0: Continue to next initialization step
```

## Stack Frame Layout (At Function Entry)

```
Memory Layout (address growth ↓):

[Higher Addresses]
    ↓
┌─────────────────────────┐
│ Previous Frame Data     │  [A6 + 0x10+]
├─────────────────────────┤
│ Arg 2                   │  [A6 + 0x0C]  <- arg2 input param
├─────────────────────────┤
│ Arg 1                   │  [A6 + 0x08]  <- arg1 input param
├─────────────────────────┤
│ Return Address          │  [A6 + 0x04]  <- back to 0x3380
├─────────────────────────┤
│ Old A6 (link.w)         │  [A6 + 0x00]  <- frame pointer
├─────────────────────────┤
│ Status Flag             │  [A6 - 0x01]  <- local var
├─────────────────────────┤
│ Size Field (0x20)       │  [A6 - 0x1C]  <- local var
├─────────────────────────┤
│ Reserved 2              │  [A6 - 0x18]  <- local var (0)
├─────────────────────────┤
│ Reserved 1              │  [A6 - 0x14]  <- local var (0)
├─────────────────────────┤
│ Arg1 Copy               │  [A6 - 0x10]  <- local var
├─────────────────────────┤
│ Callback Type (0x5d5)   │  [A6 - 0x0C]  <- local var
├─────────────────────────┤
│ Arg2 Copy               │  [A6 - 0x04]  <- local var
├─────────────────────────┤
│ System Handle           │  [A6 - 0x08]  <- local var
├─────────────────────────┤
│ Frame End               │  [A6 - 0x20]  <- link.w boundary
└─────────────────────────┘
    ↓
[Lower Addresses]
```

## Instruction Execution Timeline

```
Address    Instruction              Operation                 Cycles
─────────────────────────────────────────────────────────────────
0x5da6    link.w A6,-0x20         Allocate 32-byte frame     16
0x5daa    move.l *0x7c90,-8(A6)   Load system handle         12
0x5db2    move.l 12(A6),-4(A6)    Copy arg2 to local         12
0x5db8    clr.b -29(A6)            Clear status flag           8
0x5dbc    moveq #0x20,D1           Load size constant          4
0x5dbe    move.l D1,-28(A6)        Store size field           12
0x5dc2    clr.l -24(A6)            Clear reserved1             8
0x5dc6    move.l 8(A6),-16(A6)    Copy arg1 to local         12
0x5dcc    clr.l -20(A6)            Clear reserved2             8
0x5dd0    move.l #0x5d5,-12(A6)   Set callback type          12
0x5dd8    clr.l -(SP)              Push NULL (arg3)            8
0x5dda    clr.l -(SP)              Push NULL (arg2)            8
0x5ddc    pea -32(A6)              Push struct address        12
0x5de0    bsr.l 0x50029d2          Call external function     18
         [External function executes - unknown cycles]
0x5de6    unlk A6                  Deallocate frame           12
0x5de8    rts                      Return to caller           16
                                   ──────────────────────
                          Setup Subtotal:  ~168 cycles (before call)
                          Unknown:         Call to 0x50029d2
                          Cleanup:         ~28 cycles (after call)
                          ──────────────────────
                          Estimated Total:  ~200-400 cycles
```

## Register State Tracking

```
Entry State (at 0x5da6):
┌──────────────────────────────────┐
│ D0:  [Unspecified]               │
│ D1:  [Unspecified]               │
│ A6:  [Frame pointer from caller] │
│ SP:  [Stack from caller]         │
└──────────────────────────────────┘

During Execution:
┌──────────────────────────────────┐
│ D1:  Loaded with 0x20            │ @ 0x5dbc
│      (temporary, not preserved)  │
└──────────────────────────────────┘

At bsr.l 0x050029d2:
  Arguments on stack:
  [SP]:     &local_frame (-0x20 relative to A6)
  [SP+4]:   0x00000000 (NULL)
  [SP+8]:   0x00000000 (NULL)

  Control transfers to 0x050029d2

After rts:
┌──────────────────────────────────┐
│ D0:  [Return from 0x050029d2]    │ (error/success code)
│ SP:  [Restored by caller cleanup]│
│ A6:  [Restored by caller unlk]   │
└──────────────────────────────────┘
```

## Dependency Graph

```
┌─────────────────────────────────────────────────────────┐
│                   System Boot/Init                       │
└────────────────┬────────────────────────────────────────┘
                 │
        ┌────────▼──────────┐
        │ FUN_00003284      │ (Main Init Orchestrator)
        │ 0x00003284        │
        └────────┬──────────┘
                 │
         ┌───────┴────────┬────────┬───────────┬────────────┐
         │                │        │           │            │
      [Setup A]      [Setup B]  [Setup C]  [Setup D]   [THIS FUNC]
      FUN_00004a52  FUN_00003820 FUN_00005dea FUN_05002c54 FUN_00005da6
      (Validate)    (Validate)   (Validate)  (Process)    (Callback Init)
         │                │        │           │            │
         └────────────────┼────────┼───────────┼────────────┘
                          │
                   ┌──────▼─────────┐
                   │ 0x050029D2     │ (External Handler)
                   │ (System Call)  │
                   └────────────────┘
```

## Memory Access Map

```
Static Memory References:
┌────────────────────────────────────────────┐
│ Address      │ Access Type │ Value         │
├────────────────────────────────────────────┤
│ 0x00007c90   │ READ 32-bit  │ [System Hdl] │
│              │              │              │
│ (used once)  │              │              │
└────────────────────────────────────────────┘

Hardware Registers: NONE
  ✗ No NeXT hardware (0x02000000-0x02FFFFFF)
  ✗ No NeXTdimension MMIO (0xF8000000-0xFFFFFFFF)
  ✓ Pure software function

Stack Operations:
  PUSH:  arg1 = &local_frame (pea -0x20,A6)
  PUSH:  arg2 = NULL (clr.l -(SP))
  PUSH:  arg3 = NULL (clr.l -(SP))
  [External function call]
  POP:   (implicit in rts)
```

## Instruction Categories

```
┌──────────────────────────────────────────────┐
│ Instruction Category Distribution            │
├──────────────────────────────────────────────┤
│ Data Moves        │ 5  │ ██████              │
│ Logical Ops       │ 4  │ █████               │
│ Arithmetic        │ 1  │ █                   │
│ Control Flow      │ 3  │ ███                 │
│ Total             │ 13 │                     │
└──────────────────────────────────────────────┘

Instruction Frequency:
  move.l:   5 times (38%)
  clr.l:    3 times (23%)
  clr.b:    1 time  (8%)
  moveq:    1 time  (8%)
  pea:      1 time  (8%)
  link.w:   1 time  (8%)
  bsr.l:    1 time  (8%)
  unlk:     1 time  (8%)
  rts:      1 time  (8%)
```

## Callback Type Hierarchy

```
Unknown System
│
├── Graphics/Display
│   ├── RAMDAC Configuration
│   ├── Video Mode Setup
│   └── Frame Buffer Init
│
├── Mailbox/IPC
│   ├── Message Queue Init
│   ├── Command Handler Setup
│   └── Event Dispatcher
│
├── NeXTdimension
│   ├── Board Detection
│   ├── Firmware Loading
│   └── Memory Mapping
│
└── Device Init
    ├── Controller Setup
    ├── Interrupt Config
    └── Status Monitoring

Callback Type 0x5D5 (1493) → ?
                              │
                              └── Likely: Graphics/ND Init Step
```

## Error Path Analysis

```
Entry:  FUN_00005da6
│
├─ Normal Path (Success):
│  │
│  ├─ Initialize 32-byte struct
│  ├─ Call 0x050029d2
│  ├─ Return D0 == 0
│  └─ Caller continues to next step
│
└─ Error Path (Failure):
   │
   ├─ Initialize 32-byte struct
   ├─ Call 0x050029d2
   ├─ Return D0 != 0 (error code)
   └─ Caller jumps to 0x000033aa
      │
      └─ Error handling routine
         (Likely: Clean up resources, log error, exit)
```

## Related Constants Reference

```
┌─────────────────────────────────────────────────┐
│ Constant Values Found in Function               │
├─────────────────────────────────────────────────┤
│ 0x5D5   │ Callback type/operation identifier    │
│         │ Value: 1493 decimal                   │
│         │ Used: Set in callback state struct    │
│         │ Purpose: Handler dispatch selector    │
│         │                                       │
│ 0x20    │ Structure size (32 bytes)             │
│         │ Value: 32 decimal                     │
│         │ Used: Size field in callback struct   │
│         │ Purpose: Descriptor size marker       │
│         │                                       │
│ 0x7C90  │ System configuration handle address   │
│         │ Value: 31,888 decimal                 │
│         │ Used: Load system handle once         │
│         │ Purpose: System-wide config/context   │
│         │                                       │
│ 0x050029D2 │ External handler function address  │
│         │ Value: System ROM/protected memory    │
│         │ Used: Callback processor              │
│         │ Purpose: Handle callback operation    │
└─────────────────────────────────────────────────┘
```

## Structural Composition

```
32-Byte Callback State Structure:

Offset  Size  Type      Field Name              Description
────────────────────────────────────────────────────────────
-0x08   4     uint32_t  config_handle          System handle
-0x04   4     uint32_t  arg2_copy              Parameter 2
-0x0C   4     uint32_t  callback_type          0x5d5
-0x10   4     uint32_t  arg1_copy              Parameter 1
-0x14   4     uint32_t  reserved1              Always 0
-0x18   4     uint32_t  reserved2              Always 0
-0x1C   4     uint32_t  size_field             Always 0x20
-0x1D   1     uint8_t   status_flag            Always 0
────────────────────────────────────────────────────────────
        32 bytes total
```

## Cross-Reference Matrix

```
Function              Address     Relationship
──────────────────────────────────────────────
FUN_00003284          0x00003284  CALLER
  └─> calls at 0x0000337a

FUN_00005da6          0x00005da6  THIS FUNCTION

0x050029D2            (external)  CALLEE
  └─> called at 0x00005de0

FUN_00005dea          0x00005dea  SIBLING (adjacent in code)
  └─> called by same caller before this func

FUN_00003820          0x00003820  SIBLING
  └─> called by same caller earlier

FUN_00004a52          0x00004a52  SIBLING
  └─> called by same caller earliest

FUN_05002c54          0x05002c54  SIBLING
  └─> called by same caller after this func
```

---

**Document Generated**: November 8, 2025
**Visual Analysis Version**: 1.0
**Function**: FUN_00005da6 (Callback Handler)
**Address**: 0x00005da6 / 23,974 decimal

