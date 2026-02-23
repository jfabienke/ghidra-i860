# Visual Analysis: FUN_000062e8

## Execution Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    CALLER (FUN_000066dc)                        │
│                     @ 0x000066dc                                │
│                                                                  │
│  [Validation logic]                                             │
│        │                                                         │
│        ├─ Prepare arg0                                          │
│        ├─ Prepare arg1                                          │
│        ├─ Prepare arg2                                          │
│        └─ Allocate output buffer                                │
│             │                                                    │
│             v                                                    │
│        [bsr.l FUN_000062e8]                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ (A6 frame established)
                              │ arg0 @ A6+0x10
                              │ arg1 @ A6+0x14
                              │ arg2 @ A6+0x18
                              │ out_ptr @ A6+0x0c
                              │
                              v
┌─────────────────────────────────────────────────────────────────┐
│           FUN_000062e8: ERROR-HANDLING WRAPPER                  │
│                    @ 0x000062e8                                 │
│                     (48 bytes)                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PROLOGUE:                                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ link.w A6, 0x0                                             │ │
│  │   → Establish stack frame (0 locals)                       │ │
│  │                                                             │ │
│  │ move.l A2, -(SP)                                           │ │
│  │   → Save A2 on stack                                       │ │
│  │                                                             │ │
│  │ movea.l (0xc, A6), A2                                      │ │
│  │   → A2 = address of output buffer                          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│                           v                                      │
│  PARAMETER MARSHALLING:                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ move.l (0x18, A6), -(SP)  ; Push arg2 (3rd parameter)    │ │
│  │ move.l (0x14, A6), -(SP)  ; Push arg1 (2nd parameter)    │ │
│  │ move.l (0x10, A6), -(SP)  ; Push arg0 (1st parameter)    │ │
│  │                                                             │ │
│  │ Stack now: [arg0][arg1][arg2]                             │ │
│  │           (ready for called function)                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│                           v                                      │
│  EXTERNAL CALL:                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ bsr.l 0x05002bc4                                           │ │
│  │   → Call external/privileged function                      │ │
│  │   → Passes: arg0, arg1, arg2 via stack                    │ │
│  │   → Returns: D0 (success or error code)                   │ │
│  │   → Return address pushed on stack                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│                           v                                      │
│                      [D0 = result]                               │
│                                                                  │
│  ERROR CHECKING:                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ moveq -0x1, D1            ; D1 = -1 (0xFFFFFFFF)          │ │
│  │ cmp.l D0, D1              ; Compare D0 (result) to -1     │ │
│  │ bne.b 0x00006310          ; If D0 != -1, branch to exit  │ │
│  │                                                             │ │
│  │ Set condition codes:                                        │ │
│  │   • If D0 == -1: Zero flag SET → branch NOT taken        │ │
│  │   • If D0 != -1: Zero flag CLEAR → branch IS taken       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           │                                      │
│        ┌──────────────────┴──────────────────┐                 │
│        │                                      │                 │
│        v (D0 != -1)                          v (D0 == -1)      │
│    [SUCCESS PATH]                    [ERROR PATH]              │
│    Jump to exit                                                  │
│    No write                          ERROR PROPAGATION:         │
│                                       ┌──────────────────────┐ │
│                                       │ move.l (0x040105b0), │ │
│                                       │        (A2)          │ │
│                                       │   → Read error code  │ │
│                                       │     from 0x040105b0  │ │
│                                       │   → Write to output  │ │
│                                       │     buffer (*A2)     │ │
│                                       └──────────────────────┘ │
│                        │                                        │
│                        └────────────────┬──────────────────┐   │
│                                         │                   │   │
│                                         v                   v   │
│  EPILOGUE:                          ┌─────────────────────────┐ │
│  ┌────────────────────────────────┐ │                         │ │
│  │ movea.l (-0x4, A6), A2          │ │ Restore A2 from stack  │ │
│  │ unlk A6                         │ │ Dismantle frame        │ │
│  │ rts                             │ │ Return to caller       │ │
│  └─────────────────────────────────┘ │                         │ │
│                                       └─────────────────────────┘ │
│                                               │                   │
└───────────────────────────────────────────────┼───────────────────┘
                                                │
                                                v
┌─────────────────────────────────────────────────────────────────┐
│                    RETURN TO CALLER                             │
│              (FUN_000066dc continues execution)                 │
│                                                                  │
│  Result in output buffer:                                       │
│    • If error: *out_ptr = error code from 0x040105b0           │
│    • If success: *out_ptr = unchanged (or caller set default)  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Stack Frame Diagram

### At Function Entry (0x000062e8)

```
HIGHER ADDRESSES
┌──────────────────────────────────┐
│  Previous frame's local vars      │
├──────────────────────────────────┤
│ Return address from caller        │ ← 0xA6+0x08
├──────────────────────────────────┤
│ Saved A6 (old frame pointer)      │ ← 0xA6+0x04
├──────────────────────────────────┤
│ A6 ─────────────────────────────→ ├──────────────── 0xA6 (current)
├──────────────────────────────────┤
│ A2 (saved by function)            │ ← 0xA6-0x04
├──────────────────────────────────┤
│ SP (stack pointer grows down)      │
└──────────────────────────────────┘
LOWER ADDRESSES
```

### During Parameter Push (0x000062f2 - 0x000062fa)

```
After all parameters pushed:

HIGHER ADDRESSES
┌──────────────────────────────────┐
│ Return address from caller        │ ← 0xA6+0x08
├──────────────────────────────────┤
│ Saved A6                          │ ← 0xA6+0x04
├──────────────────────────────────┤
│ A6 ──────────────────────────────→├────────────────── 0xA6
├──────────────────────────────────┤
│ A2 (saved)                        │ ← 0xA6-0x04
├──────────────────────────────────┤
│ arg0 (from 0xA6+0x10)             │ ← 0xA6-0x08 (SP)
├──────────────────────────────────┤
│ arg1 (from 0xA6+0x14)             │ ← 0xA6-0x0C
├──────────────────────────────────┤
│ arg2 (from 0xA6+0x18)             │ ← 0xA6-0x10
├──────────────────────────────────┤
│ SP ──────────────────────────────→├────────────────── Stack pointer
└──────────────────────────────────┘
LOWER ADDRESSES

(Ready for external function call at 0x05002bc4)
```

---

## Register State Timeline

```
TIME    │  A6      │  D0        │  D1    │  A2             │  SP
────────┼──────────┼────────────┼────────┼─────────────────┼─────────
Entry   │ valid    │ (unknown)  │ (undef)│ (saved on stack)│ -0x04
        │          │            │        │                 │
+link   │ valid    │ (unknown)  │ (undef)│ (on stack)      │ -0x04
        │          │            │        │                 │
+movea  │ valid    │ (unknown)  │ (undef)│ out_ptr value   │ -0x04
        │          │            │        │ (loaded)        │
        │          │            │        │                 │
+push   │ valid    │ (unknown)  │ (undef)│ out_ptr         │ -0x10
        │          │            │        │                 │
+call   │ valid    │ result !!! │ (undef)│ out_ptr         │ -0x10
        │          │            │        │                 │
+moveq  │ valid    │ result     │ -1     │ out_ptr         │ -0x10
        │          │            │        │                 │
+cmp    │ valid    │ result     │ -1     │ out_ptr         │ -0x10
        │ CC set   │            │        │                 │
        │          │            │        │                 │
+bne    │ valid    │ result     │ -1     │ out_ptr         │ ±varies
        │          │            │        │                 │
[error] │ valid    │ error_code │ -1     │ → *A2 written  │ -0x10
        │          │            │        │                 │
+restorer│ valid   │ (unchanged)│ -1     │ restored        │ -0x04
        │          │            │        │                 │
RTS     │ restored │ (unchanged)│ (undef)│ restored        │ restored
```

---

## Memory Access Pattern

```
┌─────────────────────────────────────────────────────────┐
│             MEMORY ACCESS TIMING                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Instruction         Address        Type      Action   │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  movea.l (c,A6),A2   [A6+0xc]       READ     Load ptr │
│                                                         │
│  move.l (18,A6),-(SP) [A6+0x18]     READ     Arg3    │
│                      [SP]           WRITE    Push     │
│                                                         │
│  move.l (14,A6),-(SP) [A6+0x14]     READ     Arg2    │
│                      [SP]           WRITE    Push     │
│                                                         │
│  move.l (10,A6),-(SP) [A6+0x10]     READ     Arg1    │
│                      [SP]           WRITE    Push     │
│                                                         │
│  bsr.l 0x05002bc4                            CALL     │
│    [external function executes here]                   │
│    Returns D0 = result                                 │
│                                                         │
│  [If D0 == -1]                                         │
│  move.l (040105b0).l, (A2)                            │
│                      [0x40105b0]    READ     Error    │
│                      [A2]           WRITE    Result   │
│                                                         │
│  movea.l (-4,A6),A2  [-0x4 from A6] READ     Restore │
│                                                         │
│  rts                 [SP]           READ     Ret addr  │
│                      [SP]           WRITE    Pop       │
│                                                         │
└─────────────────────────────────────────────────────────┘

Legend:
  [addr]   = Memory location
  WRITE    = Store operation
  READ     = Load operation
  CALL     = Branch with return
```

---

## Control Flow Branching

```
                         ┌─ ENTRY ─┐
                         │ 0x62e8  │
                         └────┬────┘
                              │
                    ┌─────────────────────┐
                    │  Setup & Prologue   │
                    │  0x62e8 - 0x62ee    │
                    └─────────────────────┘
                              │
                    ┌─────────────────────┐
                    │  Load Output Ptr    │
                    │  A2 = (A6+0xc)      │
                    │  0x62ee - 0x62f0    │
                    └─────────────────────┘
                              │
                    ┌─────────────────────┐
                    │  Marshal Parameters │
                    │  Push arg0,1,2      │
                    │  0x62f2 - 0x62fc    │
                    └─────────────────────┘
                              │
                    ┌─────────────────────┐
                    │  Call External      │
                    │  0x05002bc4(...)    │
                    │  0x62fe             │
                    └─────────────────────┘
                              │
                              │ Returns D0
                              │
                    ┌─────────────────────┐
                    │  Compare to Error   │
                    │  D1 = -1            │
                    │  CMP D0, D1         │
                    │  0x6304 - 0x6308    │
                    └─────────────────────┘
                              │
                    ┌─────────┴──────────┐
                    │                    │
              D0 != -1              D0 == -1
              (SUCCESS)             (ERROR)
                    │                    │
                    │          ┌──────────────────────┐
                    │          │  Read Error Code     │
                    │          │  Load 0x040105b0     │
                    │          │  0x630a              │
                    │          │                      │
                    │          │  Write to Output     │
                    │          │  *(A2) = error code  │
                    │          └──────────────────────┘
                    │                    │
                    └────────┬───────────┘
                             │
                    ┌─────────────────────┐
                    │  Restore Registers  │
                    │  0x6310 - 0x6314    │
                    └─────────────────────┘
                             │
                    ┌─────────────────────┐
                    │  Dismantle Frame    │
                    │  unlk A6            │
                    │  0x6314             │
                    └─────────────────────┘
                             │
                    ┌─────────────────────┐
                    │  Return             │
                    │  rts                │
                    │  0x6316             │
                    └─────────────────────┘
                             │
                      ┌──────▼──────┐
                      │  RETURN     │
                      │  (to caller)│
                      └─────────────┘
```

---

## Relationship Diagram

```
SYSTEM ARCHITECTURE VIEW
═════════════════════════════════════════════════════════════════

┌───────────────────────────────────────────────────────────────┐
│                    USER/HOST CODE                            │
│                  FUN_000066dc                                 │
│                (Dispatcher/Validator)                         │
│                   @ 0x000066dc                               │
│                    220 bytes                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ [Calls with 3 params]
                       │
                       v
┌──────────────────────────────────────────────────────────────┐
│              KERNEL/CALLBACK LAYER                           │
│            FUN_000062e8 (Error Wrapper)                      │
│                @ 0x000062e8                                  │
│               48 bytes (14 instructions)                     │
│                                                              │
│  • RPC Wrapper                                              │
│  • Error handler                                            │
│  • Output parameter marshaller                              │
└──────────┬───────────────────────────────────────────────────┘
           │
           │ [Calls with same 3 params]
           │
           v
┌──────────────────────────────────────────────────────────────┐
│           PRIVILEGED/REMOTE FUNCTION                         │
│          @ 0x05002bc4                                        │
│      (Kernel service or device driver)                       │
│                                                              │
│  • Executes privileged operation                            │
│  • Returns D0: success (!=  -1) or error (== -1)           │
└──────────────────────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────────────────────┐
│           STATIC MEMORY LOCATION                             │
│           @ 0x040105b0                                       │
│                                                              │
│  Error code register (read on error path)                   │
│  32-bit value delivered to caller via output parameter      │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

```
INPUT PARAMETERS
═════════════════════════════════════════════════════════════════

    [A6+0x10]        [A6+0x14]        [A6+0x18]        [A6+0x0c]
    (arg0)           (arg1)           (arg2)           (out_ptr)
       │                 │                │                │
       │                 │                │                │
       └────────────┬────┴────────────┬───┴────────┬────────┘
                    │                │            │
                    v                v            v
              ┌─────────────────────────────────────────────┐
              │  Parameter Marshalling                      │
              │  Push args to stack (reverse order)         │
              │  Load output pointer into A2                │
              └─────────┬───────────────────────────────────┘
                        │
                        v
         ┌──────────────────────────────────┐
         │  External Function Call          │
         │  @ 0x05002bc4                    │
         │                                  │
         │  Stack: [arg0, arg1, arg2]       │
         │  Execution...                    │
         │  Returns in D0                   │
         └──────────┬───────────────────────┘
                    │
                    v
                  [D0]  ← Return value
                    │
         ┌──────────┴──────────┐
         │                     │
         v                     v
    [D0 != -1]           [D0 == -1]
    (SUCCESS)            (ERROR)
         │                     │
         │                  [Read 0x040105b0]
         │                     │
         │                     v
         │                 [error_code]
         │                     │
         │              [Write to A2]
         │                     │
         └──────────┬──────────┘
                    │
                    v
            OUTPUT PARAMETER
             (*out_ptr)

    ┌─────────────────────────────┐
    │ Success Path:               │
    │ *out_ptr = (unchanged)      │
    │                             │
    │ Error Path:                 │
    │ *out_ptr = error_code       │
    └─────────────────────────────┘
```

---

## Instruction Bytes Layout

```
ADDRESS    HEX BYTES                       INSTRUCTION
═════════════════════════════════════════════════════════════════
0x000062e8 4E 56 00 00                    link.w A6,0x0
0x000062ec 48 E7 80 00                    move.l A2,-(SP)
0x000062ee 20 6E 00 0C                    movea.l (0xc,A6),A2
0x000062f2 2F 6E 00 18                    move.l (0x18,A6),-(SP)
0x000062f6 2F 6E 00 14                    move.l (0x14,A6),-(SP)
0x000062fa 2F 6E 00 10                    move.l (0x10,A6),-(SP)
0x000062fe 4E B9 05 00 2B C4              bsr.l 0x05002bc4
0x00006304 70 FF                          moveq -0x1,D1
0x00006306 B0 81                          cmp.l D0,D1
0x00006308 66 06                          bne.b 0x00006310
0x0000630a 2B 79 04 01 05 B0 00 00        move.l (0x040105b0).l,(A2)
0x00006312 [implied continuation]
0x00006310 20 5E FF FC                    movea.l (-0x4,A6),A2
0x00006314 4E 5E                          unlk A6
0x00006316 4E 75                          rts
```

---

Document Version: 1.0
Generated: November 8, 2025
Source: Ghidra Static Analysis
