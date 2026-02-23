; ============================================================================
; FILE: FUN_0000366e_ANNOTATED.asm
; PURPOSE: Detailed assembly analysis of callback adapter function
; FUNCTION: FUN_0000366e (Address: 0x0000366e)
; SIZE: 30 bytes
; CLASSIFICATION: Callback Wrapper / Utility Function
; ============================================================================
; ANALYSIS DATE: November 08, 2025
; BINARY: NDserver (Mach-O m68k)
; TOOL: Ghidra 11.2.1
; ============================================================================

; ============================================================================
; FUNCTION HEADER
; ============================================================================
;
; Function Name: FUN_0000366e (auto-generated)
; Address: 0x0000366e (13,934 decimal)
; Size: 30 bytes (0x1E)
; Complexity: LOW (2 external function calls only)
;
; CALLING CONVENTION: M68000 Standard
;   - Parameters: Pushed on stack (caller responsibility)
;   - Return Value: D0.L (32-bit integer)
;   - Stack Frame: Established via LINK.W
;
; DEDUCED SIGNATURE:
;   int32_t FUN_0000366e(void *context, int32_t param2, int32_t param3)
;
; PURPOSE: Adapter function that chains two external library functions
;   1. Calls libfunc_1(param2, param3) → D0
;   2. Calls libfunc_2(D0) → D0
;   Returns final D0
;

; ============================================================================
; CALLER CONTEXT (From FUN_000060d8)
; ============================================================================
;
; Call site at 0x00006126:
;   0x6126: move.l (0x24,A0),-(SP)    ; Push parameter 3 (from A0+0x24)
;   0x612a: move.l (0x1c,A0),-(SP)    ; Push parameter 2 (from A0+0x1c)
;   0x612e: move.l (0xc,A0),-(SP)     ; Push parameter 1 (from A0+0x0c)
;   0x6132: bsr.l  0x0000366e         ; <-- CALL THIS FUNCTION
;   0x6138: move.l D0,(0x1c,A2)       ; Store result to (A2+0x1c)
;
; STACK FRAME AT ENTRY:
;   A6+0x10 ← Parameter 3 (int32_t value2 from A0+0x24)
;   A6+0x0c ← Parameter 2 (int32_t value1 from A0+0x1c)
;   A6+0x08 ← Parameter 1 (void *context from A0+0x0c)
;   A6+0x04 ← Return address (0x00006138 in caller)
;   A6+0x00 ← Saved A6 register (will be set by LINK.W)
;

; ============================================================================
; ASSEMBLY CODE WITH DETAILED ANNOTATIONS
; ============================================================================

  0x0000366e:  link.w     A6,0x0
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: LINK.W A6,0x0
  ; SIZE: 4 bytes
  ; OPERATION: Establish stack frame with 0 local bytes
  ;
  ; Execution:
  ;   1. SP ← SP - 4
  ;   2. (SP) ← A6               [Save caller's A6]
  ;   3. A6 ← SP                 [A6 now points to frame base]
  ;
  ; Stack effect:
  ;   Before: SP → [Return addr] [Param1] [Param2] [Param3] ...
  ;   After:  SP → [Old A6] | A6 (now points here)
  ;               [Return addr] [Param1] [Param2] [Param3]
  ;
  ; Result: Stack frame established with:
  ;   - A6 as frame pointer
  ;   - 0 bytes allocated for local variables
  ;   - Parameters accessible via (0xc,A6) and (0x10,A6)
  ; ─────────────────────────────────────────────────────────────────────

  0x00003672:  move.l     (0x10,A6),-(SP)
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: MOVE.L (0x10,A6),-(SP)
  ; SIZE: 4 bytes
  ; OPERATION: Push parameter 3 to stack
  ;
  ; Addressing: (0x10,A6) = indirect displacement addressing
  ;   - Effective address: A6 + 0x10
  ;   - Value read: 32-bit value from parameter 3 location
  ;
  ; Addressing: -(SP) = predecrement addressing
  ;   - Stack pointer decremented by 4
  ;   - Value written to new SP location
  ;
  ; Effect:
  ;   - Load parameter 3 (int32_t from A6+0x10)
  ;   - Push onto stack (SP -= 4, then store)
  ;   - Prepares stack for first external function call
  ;
  ; Register changes: SP ← SP - 4
  ; Memory: Stack grows with parameter 3 value
  ; ─────────────────────────────────────────────────────────────────────

  0x00003676:  move.l     (0xc,A6),-(SP)
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: MOVE.L (0xc,A6),-(SP)
  ; SIZE: 4 bytes
  ; OPERATION: Push parameter 2 to stack
  ;
  ; Addressing: (0xc,A6) = indirect displacement addressing
  ;   - Effective address: A6 + 0x0c
  ;   - Value read: 32-bit value from parameter 2 location
  ;
  ; Stack effect:
  ;   - Load parameter 2 (int32_t from A6+0x0c)
  ;   - Push onto stack (SP -= 4, then store)
  ;   - Now SP points to parameter 2, parameter 3 is at SP+4
  ;
  ; Call stack now contains:
  ;   SP+0x0 ← Param2 (will be second arg to libfunc_1)
  ;   SP+0x4 ← Param3 (will be first arg to libfunc_1)
  ;
  ; Register changes: SP ← SP - 4
  ; ─────────────────────────────────────────────────────────────────────

  0x0000367a:  bsr.l      0x0500315e
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: BSR.L 0x0500315e
  ; SIZE: 6 bytes
  ; OPERATION: Branch to subroutine (call) external library function
  ;
  ; Function address: 0x0500315e
  ; Format: Long (32-bit address offset)
  ;
  ; Execution:
  ;   1. PC ← PC + 6               [Skip over this instruction]
  ;   2. SP ← SP - 4               [Make room on stack]
  ;   3. (SP) ← PC                 [Push return address]
  ;   4. PC ← 0x0500315e           [Jump to function]
  ;
  ; Stack state BEFORE call:
  ;   SP+0x00 ← Param2
  ;   SP+0x04 ← Param3
  ;   SP+0x08 ← ... (will become return address)
  ;
  ; Stack state AFTER call setup:
  ;   SP+0x00 ← Return address (0x00003680)
  ;   SP+0x04 ← Param2
  ;   SP+0x08 ← Param3
  ;
  ; EXTERNAL FUNCTION BEING CALLED:
  ;   Address: 0x0500315e
  ;   Name: UNKNOWN (likely math or utility function)
  ;   Params: 2 (Param2 and Param3 from stack)
  ;   Return: 32-bit result in D0
  ;   Used by: 15+ functions in codebase
  ;
  ; After return, D0 will contain the computation result
  ; ─────────────────────────────────────────────────────────────────────

  0x00003680:  move.l     D0,-(SP)
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: MOVE.L D0,-(SP)
  ; SIZE: 2 bytes
  ; OPERATION: Push D0 register result to stack
  ;
  ; Purpose: Transfer result from first function to stack for second call
  ;
  ; State at entry:
  ;   D0 = Result from libfunc_1(param2, param3)
  ;   SP = Points to return address (from previous bsr.l)
  ;
  ; Stack before:
  ;   SP+0x00 ← Return address (0x00003680)
  ;   SP+0x04 ← Param2 (now garbage, no longer needed)
  ;   SP+0x08 ← Param3 (now garbage, no longer needed)
  ;
  ; Stack after:
  ;   SP+0x00 ← D0 result        [New top of stack]
  ;   SP+0x04 ← Return address
  ;
  ; Register changes: SP ← SP - 4
  ; Memory: Push 32-bit result value
  ;
  ; Note: Stack has been cleaned by libfunc_1's return
  ;       Previous parameter 2 and 3 are no longer on stack
  ;       Only return address remains, then we push result
  ; ─────────────────────────────────────────────────────────────────────

  0x00003682:  bsr.l      0x050032ba
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: BSR.L 0x050032ba
  ; SIZE: 6 bytes
  ; OPERATION: Branch to subroutine (call) second external library function
  ;
  ; Function address: 0x050032ba
  ; Format: Long (32-bit address offset)
  ;
  ; Stack state BEFORE call:
  ;   SP+0x00 ← Result from libfunc_1 (parameter for this call)
  ;   SP+0x04 ← Return address (0x00003688)
  ;
  ; Execution:
  ;   1. PC ← PC + 6               [Skip over this instruction]
  ;   2. SP ← SP - 4               [Make room on stack]
  ;   3. (SP) ← PC                 [Push return address for this call]
  ;   4. PC ← 0x050032ba           [Jump to function]
  ;
  ; Stack state AFTER call setup:
  ;   SP+0x00 ← Return address (0x00003688)
  ;   SP+0x04 ← Result parameter
  ;   SP+0x08 ← Previous return address (0x00006138 to original caller)
  ;
  ; EXTERNAL FUNCTION BEING CALLED:
  ;   Address: 0x050032ba
  ;   Name: UNKNOWN (likely processing or finalization function)
  ;   Params: 1 (Result from previous function)
  ;   Return: 32-bit result in D0 (FINAL RESULT)
  ;   Used by: 11+ functions in codebase
  ;
  ; After return:
  ;   D0 = Final computation result
  ;   Stack = Still needs cleanup by UNLK
  ; ─────────────────────────────────────────────────────────────────────

  0x00003688:  unlk       A6
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: UNLK A6
  ; SIZE: 2 bytes
  ; OPERATION: Destroy stack frame and restore caller's A6
  ;
  ; Execution:
  ;   1. SP ← A6                   [Point to saved A6 on stack]
  ;   2. A6 ← (SP)                 [Restore caller's A6 from stack]
  ;   3. SP ← SP + 4               [Pop the saved A6 from stack]
  ;
  ; State before:
  ;   A6 = Points to frame base
  ;   SP = Points to result value on stack
  ;   (A6) = Saved caller's A6 (from LINK.W)
  ;   D0 = Final result from libfunc_2
  ;
  ; State after:
  ;   A6 = Restored to caller's value
  ;   SP = Points to return address (0x00006138 in caller)
  ;   D0 = Unchanged (still contains final result)
  ;
  ; Effect: Stack frame destroyed, ready for RTS
  ; ─────────────────────────────────────────────────────────────────────

  0x0000368a:  rts
  ; ─────────────────────────────────────────────────────────────────────
  ; INSTRUCTION: RTS
  ; SIZE: 2 bytes
  ; OPERATION: Return from subroutine
  ;
  ; Execution:
  ;   1. PC ← (SP)                 [Pop return address from stack]
  ;   2. SP ← SP + 4               [Adjust stack pointer]
  ;   3. Jump to PC                [Resume execution at caller]
  ;
  ; State at RTS:
  ;   D0 = Contains final result from libfunc_2
  ;   SP = Points to return address (0x00006138 in FUN_000060d8)
  ;
  ; Return to caller (FUN_000060d8) at 0x6138:
  ;   0x00006138: move.l D0,(0x1c,A2)  ← This instruction executes next
  ;                                       (stores D0 to output structure)
  ;
  ; Control flow returns to caller who will:
  ;   1. Store D0 to output structure at offset 0x1c
  ;   2. Continue with remaining validation
  ;   3. Set success flag in output structure
  ; ─────────────────────────────────────────────────────────────────────

; ============================================================================
; FUNCTION SUMMARY
; ============================================================================
;
; Total instruction sequence:
;   0x366e: LINK.W A6,0x0              (4 bytes) - Establish frame
;   0x3672: MOVE.L (0x10,A6),-(SP)     (4 bytes) - Push param 3
;   0x3676: MOVE.L (0x0c,A6),-(SP)     (4 bytes) - Push param 2
;   0x367a: BSR.L  0x0500315e          (6 bytes) - Call libfunc_1
;   0x3680: MOVE.L D0,-(SP)            (2 bytes) - Push result
;   0x3682: BSR.L  0x050032ba          (6 bytes) - Call libfunc_2
;   0x3688: UNLK A6                    (2 bytes) - Destroy frame
;   0x368a: RTS                        (2 bytes) - Return
;                                     ─────────
;                                     30 bytes total ✓
;
; Register usage:
;   A6: Frame pointer (modified by LINK/UNLK)
;   SP: Stack pointer (modified throughout)
;   D0: Return value (input from libfunc_1, output from libfunc_2)
;   Other registers: Not modified (preserved for caller)
;
; Data flow:
;   Caller → [Push params] → Stack
;   Stack → [Load by MOVE] → Registers
;   Registers → [Pass to libfunc_1] → D0 result
;   D0 → [Push to stack] → libfunc_2 parameter
;   libfunc_2 → [Return result] → D0
;   D0 → [Caller pops] → Output structure
;

; ============================================================================
; EXECUTION TRACE EXAMPLE
; ============================================================================
;
; Assuming:
;   param2 = 0x12345678
;   param3 = 0x87654321
;   libfunc_1(0x12345678, 0x87654321) returns 0xABCDEF00
;   libfunc_2(0xABCDEF00) returns 0x11223344
;
; Stack trace:
;
; Entry (0x366e):
;   SP = 0x400000
;   Stack[0x400000] = Return address to 0x6138
;   Stack[0x400004] = param1 (unused)
;   Stack[0x400008] = 0x12345678 (param2)
;   Stack[0x40000c] = 0x87654321 (param3)
;
; After LINK.W A6,0x0:
;   SP = 0x3ffffc
;   A6 = 0x3ffffc
;   Stack[0x3ffffc] = Old A6
;   Stack[0x400000] = Return address to 0x6138
;   Stack[0x400004] = param1
;   Stack[0x400008] = param2
;   Stack[0x40000c] = param3
;
; After first MOVE.L (0x10,A6),-(SP):
;   SP = 0x3ffff8
;   Stack[0x3ffff8] = 0x87654321 (param3, pushed)
;   Stack[0x3ffffc] = Old A6
;   Stack[0x400000] = Return address
;   Stack[0x400004] = param1
;   Stack[0x400008] = param2
;   Stack[0x40000c] = param3 (original)
;
; After second MOVE.L (0x0c,A6),-(SP):
;   SP = 0x3ffff4
;   Stack[0x3ffff4] = 0x12345678 (param2, pushed)
;   Stack[0x3ffff8] = 0x87654321 (param3)
;   Stack[0x3ffffc] = Old A6
;
; After BSR.L 0x0500315e:
;   SP = 0x3ffff0
;   D0 = 0xABCDEF00 (result from libfunc_1)
;   Stack[0x3ffff0] = Return address 0x3680
;   (libfunc_1 cleaned up its parameters from stack)
;
; After MOVE.L D0,-(SP):
;   SP = 0x3ffffec
;   Stack[0x3ffffec] = 0xABCDEF00 (result pushed)
;   Stack[0x3ffff0] = Return address 0x3680
;
; After BSR.L 0x050032ba:
;   SP = 0x3ffff0
;   D0 = 0x11223344 (final result from libfunc_2)
;   Stack[0x3ffff0] = Return address 0x3688
;
; After UNLK A6:
;   SP = 0x3ffffc
;   A6 = Old A6 (restored)
;   D0 = 0x11223344 (unchanged)
;   Stack[0x400000] = Return address to 0x6138
;
; After RTS:
;   PC = 0x6138 (execution continues in caller)
;   D0 = 0x11223344 (returned to caller)
;
; Back in caller (FUN_000060d8) at 0x6138:
;   0x00006138: move.l D0,(0x1c,A2)  ← Stores 0x11223344 to (A2+0x1c)
;

; ============================================================================
; END OF ANNOTATION
; ============================================================================
