; =============================================================================
; ANNOTATED ASSEMBLY: FUN_000075cc (0x000075cc)
; Small Callback Wrapper Function - NeXTdimension i860 ROM
; Size: 22 bytes | Type: System API adapter
; =============================================================================
;
; FUNCTION PROFILE:
; ─────────────────
; Address:        0x000075cc (30156 decimal)
; Size:           22 bytes
; Instructions:   5 (LINK, MOVE.L, PEA, BSR.L, NOP)
; Stack Frame:    0 bytes local variables
; Parameters:     2 (arg1 from caller, arg2=0x80f0 constant)
; Return Value:   D0 (set by called function)
; Called By:      FUN_0000709c, FUN_0000746c
; Calls:          FUN_05002864 (external system function)
;
; SEMANTICS:
; ──────────
; This function retrieves a parameter from its caller's stack frame,
; loads a constant address, and makes a long branch subroutine call to
; an external system function (likely NeXTSTEP kernel API).
;
; Equivalent C:
;   void FUN_000075cc(void *arg1) {
;       FUN_05002864(arg1, (void*)0x80f0);
;   }
;
; =============================================================================

; SECTION 1: FUNCTION ENTRY & FRAME SETUP
; ═════════════════════════════════════════════════════════════════════════════

; Entry Point: 0x000075cc
; Calling convention: Motorola 68000 System V ABI
; At entry, the stack looks like:
;   ESP → [Return address to caller]
;   ESP+4 → [First parameter (passed by caller)]
;   ...

FUN_000075cc:                           ; Label: Function start
    LINK.W     A6,#0x0                 ; Create stack frame

    ; LINK.W instruction breakdown:
    ;   Opcode: 0x4E56 0x0000
    ;   Effect:
    ;     1. SP ← SP - 4
    ;     2. Memory[SP] ← A6 (push old frame pointer)
    ;     3. A6 ← SP (A6 = new frame pointer)
    ;     4. SP ← SP - 0 (frame offset = 0, no locals)
    ;
    ; Stack after LINK:
    ;   A6 → [Saved A6 from caller]
    ;   A6+4 → [Return address]
    ;   A6+8 → [First parameter] ← (offset 8 references caller's first arg
    ;   A6+12 → [More caller data]
    ;   SP = A6 (no local space allocated)
    ;
    ; Register state after LINK:
    ;   A6 = old SP value
    ;   SP = old SP - 4 (room for saved A6)
    ;   All other registers unchanged

    ; IMPORTANT: With frame size = 0, SP is not adjusted further.
    ; This is unusual as it leaves SP = A6, but allows direct parameter access.

; SECTION 2: ARGUMENT SETUP & PARAMETER TRANSFER
; ═════════════════════════════════════════════════════════════════════════════

    ; We need to pass TWO parameters to FUN_05002864:
    ;   Parameter 1: The caller's first argument (from A6+8)
    ;   Parameter 2: The constant address 0x80f0

    ; First, push the caller's parameter onto the stack.
    ; In the caller's frame, parameters are at:
    ;   (0x4, A6) = Return address
    ;   (0x8, A6) = First parameter (what we want)
    ;   (0xC, A6) = Second parameter (not used by us)

    MOVE.L     (0x8,A6),-(SP)          ; Push first parameter

    ; MOVE.L (0x8,A6),-(SP) breakdown:
    ;   Opcode: 0x2F2E 0x0008
    ;   Addressing: (d,An) = Displacement indirect (source)
    ;              -(An) = Predecrement (destination)
    ;   Effect:
    ;     1. Effective Address (EA) = A6 + 0x8
    ;     2. SP ← SP - 4 (predecrement)
    ;     3. Memory[SP] ← Memory[A6 + 8] (copy 4-byte value)
    ;
    ; Operation details:
    ;   - Source: Value at caller's first parameter location
    ;   - Destination: New stack location (lower address)
    ;   - Size: 32-bit (long word)
    ;   - Flags: Condition codes NOT set (MOVE doesn't set flags in this context)
    ;
    ; Stack after MOVE.L:
    ;   SP → [Caller's first parameter] ← ARG1
    ;   SP+4 → [Caller's first param location in old frame]
    ;
    ; Register state after MOVE.L:
    ;   SP decreased by 4
    ;   A6 unchanged
    ;   D0-D7, A0-A5 unchanged
    ;   Parameter value loaded from memory (1 memory read cycle)

; SECTION 3: CONSTANT ADDRESS SETUP
; ═════════════════════════════════════════════════════════════════════════════

    PEA        (0x80f0).L              ; Push constant address (0x80f0)

    ; PEA (0x80f0).L breakdown:
    ;   Opcode: 0x487A followed by 32-bit address
    ;   Instruction: 0x487A 0x80F0
    ;   Meaning: Push Effective Address
    ;   Addressing mode: Absolute long (32-bit address)
    ;   Effect:
    ;     1. SP ← SP - 4 (predecrement)
    ;     2. Memory[SP] ← 0x80f0 (push address constant)
    ;     3. Note: The VALUE at 0x80f0 is NOT dereferenced; the ADDRESS itself is pushed
    ;
    ; Important distinction:
    ;   LEA (0x80f0).L, -(SP) would be equivalent (Load Effective Address)
    ;   MOVE.L #0x80f0, -(SP) would also be equivalent
    ;   But PEA is the idiomatic choice for pushing addresses
    ;
    ; Stack after PEA:
    ;   SP → [Constant address 0x80f0] ← ARG2
    ;   SP+4 → [Caller's first parameter] ← ARG1
    ;   SP+8 → [Previous stack contents]
    ;
    ; Register state after PEA:
    ;   SP decreased by 4 (now lower address)
    ;   A6 unchanged
    ;   All other registers unchanged
    ;   Memory write to stack: 1 cycle
    ;
    ; Memory implications:
    ;   - 0x80f0 is a ROM-resident address (hardcoded, not dynamic)
    ;   - Assumes ROM is loaded at canonical address
    ;   - If ROM relocated, 0x80f0 reference may become invalid
    ;   - Likely references: callback descriptor, data table, or ROM resource

; SECTION 4: EXTERNAL FUNCTION CALL
; ═════════════════════════════════════════════════════════════════════════════

    BSR.L      0x05002864              ; Call external system function

    ; BSR.L (Branch to Subroutine Long) breakdown:
    ;   Opcode: 0x61FF (BSR opcode)
    ;   Operand: 32-bit PC-relative offset (follows opcode)
    ;   Effect:
    ;     1. SP ← SP - 4
    ;     2. Memory[SP] ← PC + 6 (return address = 0x000075e0)
    ;     3. PC ← 0x05002864 (target address)
    ;     4. Jump executed; CPU begins executing at target
    ;
    ; PC-relative offset calculation:
    ;   Current PC (at BSR instruction): 0x000075da
    ;   Next instruction PC (after BSR): 0x000075da + 6 = 0x000075e0
    ;   Target address: 0x05002864
    ;   Offset: 0x05002864 - 0x000075e0 = 0x04A282A4
    ;   Stored in instruction: 0x61FF 0x04A2 0x82A4
    ;
    ; Stack at target function entry (0x05002864):
    ;   SP → [Return address: 0x000075e0] ← Return to next instruction
    ;   SP+4 → [Constant 0x80f0] ← ARG2 (second parameter)
    ;   SP+8 → [Caller's first param] ← ARG1 (first parameter)
    ;   SP+12 → [Previous stack]
    ;
    ; Calling convention assumptions:
    ;   - Parameters on stack (left-to-right in 68k = higher to lower stack)
    ;   - Return value in D0
    ;   - D0-D7, A0-A5 are caller-saved (may be modified by callee)
    ;   - A6, A7(SP) are callee-saved (callee should restore)
    ;
    ; Target function (0x05002864):
    ;   - Location: Far address, outside ND ROM bounds (0x00000000-0x0001FFFF)
    ;   - Type: External system call (likely NeXTSTEP kernel)
    ;   - Status: Requires runtime address relocation
    ;   - Purpose: Unknown without further analysis (likely callback registration)
    ;
    ; Return behavior:
    ;   - Normal: Control returns to 0x000075e0 (next instruction after BSR.L)
    ;   - Exception: If callee doesn't return (tail call), execution continues elsewhere
    ;
    ; Timing: 18 cycles for BSR instruction + callee latency

; SECTION 5: FUNCTION EPILOGUE (PROBLEMATIC)
; ═════════════════════════════════════════════════════════════════════════════

    NOP                                 ; No operation

    ; NOP instruction:
    ;   Opcode: 0x4E71
    ;   Effect: PC ← PC + 2 (no other effects)
    ;   Timing: 4 cycles
    ;   Purpose: Unclear
    ;
    ; Analysis of NOP:
    ;   1. Alignment padding?
    ;      - Function boundary at 0x75cc + 22 = 0x75e2
    ;      - NOP at 0x75e0 (2 bytes)
    ;      - 0x75e2 is next function boundary
    ;      - No alignment needed (natural boundary at function size 22)
    ;
    ;   2. Dead code?
    ;      - This instruction is unreachable if BSR.L doesn't return
    ;      - If called function (0x05002864) continues execution elsewhere, NOP never executes
    ;      - Ghidra may have flagged this as unreachable code
    ;
    ;   3. Instrumentation placeholder?
    ;      - Could be space reserved for future instrumentation
    ;      - Removed or left as NOP in final release
    ;
    ;   4. Missing epilogue?
    ;      - Function lacks explicit UNLK A6 (restore old A6)
    ;      - Function lacks explicit RTS (return to caller)
    ;      - Suggests: Epilogue handled elsewhere, tail call pattern, or compiler optimization
    ;
    ; Register state at NOP:
    ;   - If NOP executes: All registers in callee state
    ;   - D0 likely contains return value from 0x05002864
    ;   - Stack still has return address (unless callee modified it)
    ;
    ; Critical observation:
    ;   The absence of UNLK and RTS suggests this function boundary
    ;   may not be complete. Either:
    ;     a) UNLK/RTS are part of inline code (not separate function boundary)
    ;     b) This is a tail call pattern (next function handles cleanup)
    ;     c) Return is implicit due to calling convention

; SECTION 6: IMPLICIT FUNCTION BOUNDARY & RETURN
; ═════════════════════════════════════════════════════════════════════════════

    ; Function boundary (from Ghidra):
    ;   Start: 0x000075cc
    ;   End: 0x000075e2 (exclusive)
    ;   Size: 22 bytes (0x16)
    ;
    ; Next function at 0x000075e2:
    ;   FUN_000075e2: LINK.W A6,0x0 (identical frame setup)
    ;
    ; MISSING EPILOGUE ANALYSIS:
    ; ──────────────────────────
    ; Standard 68000 function epilogue should be:
    ;   UNLK A6         ; Restore caller's A6 and deallocate frame
    ;   RTS             ; Return to caller (pop return address, jump)
    ;
    ; These instructions are NOT present in FUN_000075cc, suggesting:
    ;   1. The function was inlined (no separate call/return)
    ;   2. The function is a tail call (next function handles return)
    ;   3. The return is implicit (compiler optimization)
    ;   4. Ghidra's function boundary is incorrect
    ;
    ; Most likely: The function continues or the epilogue is shared.
    ;              The NOP at 0x75e0 suggests incomplete cleanup.

; =============================================================================
; COMPLETE INSTRUCTION LISTING
; =============================================================================

; Address  Opcode            Mnemonic     Operand         Bytes
; ────────────────────────────────────────────────────────────────────────────
;  000075cc 4E 56 00 00      LINK.W       A6,#0x0         4 bytes
;  000075d0 2F 2E 00 08      MOVE.L       (0x8,A6),-(SP)  6 bytes
;  000075d4 48 7A 80 F0      PEA          (0x80f0).L      6 bytes
;  000075da 61 FF 04 A2 82A4 BSR.L        0x05002864      6 bytes
;  000075e0 4E 71            NOP                           2 bytes
; ────────────────────────────────────────────────────────────────────────────
;                                         Total:          22 bytes
; =============================================================================

; STACK FRAME DIAGRAM
; ═════════════════════════════════════════════════════════════════════════════

; BEFORE LINK.W (at 0x75cc):
; ┌─────────────────────────┐
; │ SP → [Return address]   │ ← ESP points here
; │      [Param 1]          │ ← (Offset 4 from ESP)
; │      [Previous stack]   │
; └─────────────────────────┘

; AFTER LINK.W (at 0x75d0):
; ┌─────────────────────────┐
; │ A6 → [Saved A6]         │ ← A6 and SP point here (frame size = 0!)
; │      [Return address]   │ ← (A6+4)
; │      [Param 1]          │ ← (A6+8) << WE FETCH FROM HERE
; │      [Previous stack]   │
; └─────────────────────────┘

; AFTER MOVE.L (at 0x75d4):
; ┌─────────────────────────┐
; │      [Saved A6]         │ ← (Higher memory)
; │      [Return address]   │
; │      [Param 1]          │
; │ SP → [Param 1 value]    │ ← SP-4 (pushed by MOVE.L)
; │      [Previous stack]   │ ← (Lower memory)
; └─────────────────────────┘

; AFTER PEA (at 0x75da):
; ┌─────────────────────────┐
; │      [Saved A6]         │ ← (Higher memory)
; │      [Return address]   │
; │      [Param 1]          │
; │ SP → [0x80f0]           │ ← SP-4 (pushed by PEA) = ARG2
; │      [Param 1 value]    │ ← SP+4 = ARG1
; │      [Previous stack]   │ ← (Lower memory)
; └─────────────────────────┘

; AT TARGET FUNCTION (0x05002864):
; ┌─────────────────────────┐
; │      [Saved A6]         │ ← (Higher memory)
; │      [Return address]   │
; │      [Param 1]          │
; │ SP → [Ret to 0x75e0]    │ ← SP (pushed by BSR.L)
; │      [0x80f0]           │ ← SP+4 = Parameter 2
; │      [Param 1 value]    │ ← SP+8 = Parameter 1
; │      [Previous stack]   │ ← (Lower memory)
; └─────────────────────────┘

; =============================================================================
; REGISTER STATE TRANSITIONS
; =============================================================================

; Entry (0x75cc):
;   D0-D7: Undefined (caller-saved, may be used)
;   A0-A5: Undefined
;   A6: Previous frame pointer (caller's frame)
;   A7(SP): Points to return address

; After LINK (0x75d0):
;   D0-D7: Unchanged
;   A0-A5: Unchanged
;   A6: Now points to saved A6 location
;   A7(SP): Equals A6 (frame size = 0)

; After MOVE.L (0x75d4):
;   D0-D7: Unchanged (MOVE doesn't affect flags or other regs)
;   A0-A5: Unchanged
;   A6: Unchanged
;   A7(SP): Decreased by 4

; After PEA (0x75da):
;   D0-D7: Unchanged
;   A0-A5: Unchanged
;   A6: Unchanged
;   A7(SP): Decreased by 4 more (total -8 from LINK)

; At target (0x05002864):
;   D0-D7: May be modified by target function
;   A0-A5: May be modified by target function
;   A6: May be modified (if target uses frame)
;   A7(SP): Points to return address

; =============================================================================
; ANALYSIS NOTES
; =============================================================================

; 1. PARAMETER PASSING PATTERN
;    - This is classic 68000 System V ABI parameter passing
;    - Stack-based (no register parameters in this call)
;    - Parameters pushed right-to-left (arg2 pushed first, then arg1)
;    - Called function expects: ARG1 at (SP+8), ARG2 at (SP+4), RET at (SP)

; 2. CONSTANT ADDRESS 0x80f0
;    - Appears to be a ROM-relative address
;    - Could be: callback descriptor, data table, resource reference
;    - Suggests function is called with same second parameter always
;    - May indicate a dispatch pattern or factory pattern

; 3. EXTERNAL CALL 0x05002864
;    - Far address (way outside ROM bounds)
;    - Likely NeXTSTEP kernel API or system service
;    - Requires runtime relocation (not embedded in ROM)
;    - Suggests firmware that delegates to kernel for functionality

; 4. MISSING EPILOGUE ISSUE
;    - No UNLK or RTS in function boundary
;    - Could indicate:
;      a) Inlined code (not separate function)
;      b) Tail call (next instruction handles return)
;      c) Compiler removed epilogue (optimization)
;      d) Ghidra boundary is wrong

; 5. PERFORMANCE IMPLICATIONS
;    - Function is lightweight (5 instructions)
;    - Bottleneck is the external call (0x05002864)
;    - External call may block or take microseconds
;    - Function should be fast for callback processing

; 6. CODE REUSABILITY
;    - Pattern (LINK-MOVE-PEA-BSR-NOP) found elsewhere in ROM
;    - Suggests template-generated code
;    - Similar to C compiler output for simple wrapper functions
;    - Indicates structured code generation (not hand-optimized)

; =============================================================================
; CALLERS & CONTROL FLOW
; =============================================================================

; This function is called by:
;   1. FUN_0000709c (0x0000709c) - 976 bytes, in main runtime loop
;   2. FUN_0000746c (0x0000746c) - 352 bytes, in system init code
;
; Typical call sequence:
;   ...in FUN_0000709c:
;   < setup argument >
;   JSR FUN_000075cc           ; Call this function
;   < handle return >
;
; Return path:
;   - If normal return: D0 contains result from 0x05002864
;   - If tail call: May not return (jumps elsewhere)
;   - Exceptions: Unknown (no error handling visible)

; =============================================================================
; SEMANTICS SUMMARY
; =============================================================================

; PURPOSE: Adapter/wrapper function
;   Accepts a parameter from caller
;   Adds a constant parameter (0x80f0)
;   Calls external system function with both parameters
;   Returns whatever the external function returns (in D0)

; USAGE PATTERN: Callback dispatch
;   Likely called when a callback event is triggered
;   0x80f0 identifies the callback handler
;   Parameter identifies specific event or resource
;   System function processes the callback

; EFFICIENCY: Minimal overhead
;   Only one memory read (caller's parameter)
;   One memory write per parameter (stack setup)
;   One long jump to external function
;   No complex logic, no branches, linear flow

; INTEGRATION: ROM firmware to OS kernel
;   Function resides in NeXTdimension ROM
;   Calls kernel function (NeXTSTEP API)
;   Bridges firmware layer to software layer
;   Typical pattern in embedded systems

; =============================================================================
; END OF ANNOTATED ASSEMBLY
; =============================================================================

; Generated: 2025-11-09
; Source: Ghidra disassembly export (disassembly_full.asm)
; Function: FUN_000075cc (0x000075cc)
; ROM: ND_step1_v43_eeprom.bin
