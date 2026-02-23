; ============================================================================
; DISASSEMBLY: FUN_0000368c
; Address: 0x0000368c (13964 decimal)
; Size: 38 bytes (10 instructions)
; Type: Callback Wrapper / Adapter Function
; Category: Internal Function
; ============================================================================
;
; FUNCTION SUMMARY:
; ─────────────────────────────────────────────────────────────────────────
;
; This is a 5-argument callback wrapper that implements an adapter pattern:
;
;   1. Receives 5 parameters from caller
;   2. Ignores first parameter (arg1)
;   3. Passes arg2-arg5 to library function 0x0500315e (string/data conversion)
;   4. Takes result from 0x0500315e and combines it with original arg2-arg5
;   5. Passes combined arguments to library function 0x050032c6 (validation)
;   6. Returns final result in D0 to caller
;
; CALLING CONVENTION: Standard m68k ABI
; ─────────────────────────────────────────────────────────────────────────
;   Arguments: Pushed right-to-left on stack
;   Return value: D0 (32-bit)
;   Preserved registers: A2-A7, D2-D7
;   Scratch registers: A0-A1, D0-D1
;
; FUNCTION SIGNATURE (reconstructed):
; ─────────────────────────────────────────────────────────────────────────
;   int32_t FUN_0000368c(
;       int32_t arg1,      // +0x08(A6) - IGNORED BY THIS FUNCTION
;       int32_t arg2,      // +0x0C(A6) - Passed to both lib functions
;       int32_t arg3,      // +0x10(A6) - Passed to both lib functions
;       int32_t arg4,      // +0x14(A6) - Passed to both lib functions
;       int32_t arg5       // +0x18(A6) - Passed to both lib functions
;   );
;
;   Return value: int32_t in D0
;
; CALLER: FUN_00006156 (board initialization function)
; ─────────────────────────────────────────────────────────────────────────
;   Called from offset 0x000061d0
;   Arguments extracted from structure at A0 (offsets: 0x0C, 0x1C, 0x24, 0x2C, 0x34)
;   Result stored in structure at A2 (offset: 0x1C)
;   Tested for zero/non-zero: if non-zero, error path
;
; STACK FRAME DIAGRAM:
; ─────────────────────────────────────────────────────────────────────────
;   At entry (after BSR.L from caller):
;
;   SP+0x00 = Return address (inserted by BSR.L)
;   SP+0x04 = arg1 (NOT ACCESSED)
;   SP+0x08 = arg2
;   SP+0x0C = arg3
;   SP+0x10 = arg4
;   SP+0x14 = arg5
;
;   After LINK.W A6,0x0:
;
;   A6+0x08 = Return address
;   A6+0x0C = arg2
;   A6+0x10 = arg3
;   A6+0x14 = arg4
;   A6+0x18 = arg5
;
; ============================================================================

  0x0000368c:  link.w     A6,0x0
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: LINK.W A6,0x0
  ; Mnemonic: Link Frame
  ; Operands: A6 (register), 0x0 (immediate: local variable space)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Push A6 onto stack: [-(SP)] = A6
  ;   2. Set A6 to current SP: A6 = SP
  ;   3. Allocate local space: SP -= 0 (no locals in this case)
  ;
  ; RESULT:
  ;   - A6 now points to frame base
  ;   - SP points to return address
  ;   - Old A6 saved on stack for restoration by UNLK
  ;   - No local variables allocated (0x0 offset)
  ;
  ; STACK AFTER:
  ;   [A6] = Old A6 (saved)
  ;   [A6+0x04] = Return PC
  ;   [A6+0x08] = arg1
  ;   [A6+0x0C] = arg2
  ;   [A6+0x10] = arg3
  ;   [A6+0x14] = arg4
  ;   [A6+0x18] = arg5
  ; ────────────────────────────────────────────────────────────────────

  0x00003690:  move.l     (0x18,A6),-(SP)
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: MOVE.L (0x18,A6),-(SP)
  ; Mnemonic: Move Long (argument push)
  ; Operands: (0x18,A6) → -(SP)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Calculate source EA: 0x18 + A6
  ;   2. Load 32-bit value from that address: D = [A6+0x18]
  ;   3. Pre-decrement SP: SP -= 4
  ;   4. Write value to stack: [SP] = D
  ;
  ; SEMANTIC: Push arg5 (5th parameter) to stack
  ;   arg5 is at A6+0x18 (5th parameter in calling convention)
  ;
  ; RESULT:
  ;   Stack:
  ;   SP → arg5 (newly pushed)
  ;   SP+0x04 → (previous SP before decrement)
  ;   ...
  ;
  ; PURPOSE:
  ;   Preparing arguments for call to 0x0500315e
  ;   Arguments must be pushed right-to-left for standard ABI
  ;   This is the 4th push (of 4 required pushes)
  ; ────────────────────────────────────────────────────────────────────

  0x00003694:  move.l     (0x14,A6),-(SP)
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: MOVE.L (0x14,A6),-(SP)
  ; Mnemonic: Move Long (argument push)
  ; Operands: (0x14,A6) → -(SP)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Load arg4 from A6+0x14
  ;   2. Push to stack (pre-decrement)
  ;
  ; SEMANTIC: Push arg4 (4th parameter) to stack
  ;
  ; STACK AFTER THIS INSTRUCTION:
  ;   SP → arg4
  ;   SP+0x04 → arg5
  ;   SP+0x08 → (previous)
  ;
  ; PURPOSE: Continue argument preparation (right-to-left order)
  ; ────────────────────────────────────────────────────────────────────

  0x00003698:  move.l     (0x10,A6),-(SP)
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: MOVE.L (0x10,A6),-(SP)
  ; Mnemonic: Move Long (argument push)
  ; Operands: (0x10,A6) → -(SP)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Load arg3 from A6+0x10
  ;   2. Push to stack (pre-decrement)
  ;
  ; SEMANTIC: Push arg3 (3rd parameter) to stack
  ;
  ; STACK AFTER:
  ;   SP → arg3
  ;   SP+0x04 → arg4
  ;   SP+0x08 → arg5
  ;   SP+0x0C → (previous)
  ;
  ; PURPOSE: Continue right-to-left argument setup
  ; ────────────────────────────────────────────────────────────────────

  0x0000369c:  move.l     (0xc,A6),-(SP)
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: MOVE.L (0xc,A6),-(SP)
  ; Mnemonic: Move Long (argument push)
  ; Operands: (0xc,A6) → -(SP)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Load arg2 from A6+0x0C
  ;   2. Push to stack (pre-decrement)
  ;
  ; SEMANTIC: Push arg2 (2nd parameter) to stack
  ;
  ; NOTE: arg1 at A6+0x08 is DELIBERATELY IGNORED (not pushed)
  ;   This is intentional - the wrapper doesn't need arg1
  ;   Suggests arg1 was required by original caller but not this function
  ;
  ; STACK AFTER:
  ;   SP → arg2
  ;   SP+0x04 → arg3
  ;   SP+0x08 → arg4
  ;   SP+0x0C → arg5
  ;   SP+0x10 → (previous SP)
  ;
  ; STACK STATE FOR LIBRARY CALL:
  ;   Arguments for 0x0500315e are now arranged on stack:
  ;   [SP+0x00] = return PC (from BSR.L instruction)
  ;   [SP+0x04] = arg2 (parameter 1 for 0x0500315e)
  ;   [SP+0x08] = arg3 (parameter 2)
  ;   [SP+0x0C] = arg4 (parameter 3)
  ;   [SP+0x10] = arg5 (parameter 4)
  ; ────────────────────────────────────────────────────────────────────

  0x000036a0:  bsr.l      0x0500315e
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: BSR.L 0x0500315e
  ; Mnemonic: Branch to Subroutine Long
  ; Operands: 0x0500315e (absolute address)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Save return address on stack: [-(SP)] = PC+4 (= 0x000036a6)
  ;   2. Jump to subroutine at 0x0500315e
  ;   3. Execute code at 0x0500315e
  ;   4. When called function executes RTS, return to 0x000036a6
  ;
  ; LIBRARY FUNCTION: 0x0500315e
  ;   Type: Library/system call (not internal to NDserver)
  ;   Frequency: Used 15 times across codebase
  ;   Likely Purpose: String-to-integer conversion (atoi, strtol, etc.)
  ;
  ;   Arguments received by 0x0500315e:
  ;     SP+0x00 = return address (0x000036a6)
  ;     SP+0x04 = arg2 (string pointer or data buffer)
  ;     SP+0x08 = arg3 (format/radix parameter)
  ;     SP+0x0C = arg4 (context or buffer pointer)
  ;     SP+0x10 = arg5 (size/length parameter)
  ;
  ;   Return value: D0 (32-bit converted value)
  ;
  ; BEHAVIOR:
  ;   - Input: arg2-arg5 (context-dependent, likely string conversion params)
  ;   - Output: D0 = converted/processed value
  ;   - May modify: D0, D1, A0, A1 (scratch registers)
  ;   - Preserves: A2-A7, D2-D7, A6 (callee-save registers)
  ;   - Stack usage: Unknown (depends on implementation)
  ;
  ; CONTROL FLOW:
  ;   This is a CALL instruction - execution pauses here until function returns
  ;   Subsequent instruction (0x000036a6) will execute after 0x0500315e's RTS
  ; ────────────────────────────────────────────────────────────────────

  0x000036a6:  move.l     D0,-(SP)
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: MOVE.L D0,-(SP)
  ; Mnemonic: Move Long (push register to stack)
  ; Operands: D0 → -(SP)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Get value from D0 register (return value from 0x0500315e)
  ;   2. Pre-decrement SP: SP -= 4
  ;   3. Write D0 to stack: [SP] = D0
  ;
  ; SEMANTIC: Save result from first library function
  ;   D0 contains the processed value from 0x0500315e
  ;   This is the PRIMARY ARGUMENT for the next function call
  ;
  ; STACK AFTER:
  ;   SP → D0 (result from 0x0500315e) ← This becomes arg1 to 0x050032c6
  ;   SP+0x04 → (previous SP value after first call)
  ;
  ;   Note: arg2-arg5 are still on stack (not popped)
  ;   They were already used by 0x0500315e
  ;   Stack pointer has been cleaned by 0x0500315e's RTS
  ;
  ;   Current stack layout before next BSR:
  ;   SP+0x00 = D0 (result, new arg1)
  ;   SP+0x04 = arg2 (old parameter)
  ;   SP+0x08 = arg3 (old parameter)
  ;   SP+0x0C = arg4 (old parameter)
  ;   SP+0x10 = arg5 (old parameter)
  ;   SP+0x14 = (previous value, from before arg2-arg5 pushes)
  ;
  ; PURPOSE:
  ;   Setup for second function call (0x050032c6)
  ;   The converted value (D0) becomes first argument
  ;   Original context arguments (arg2-arg5) remain for validation
  ;   This implements the adapter pattern: conversion → validation chain
  ; ────────────────────────────────────────────────────────────────────

  0x000036a8:  bsr.l      0x050032c6
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: BSR.L 0x050032c6
  ; Mnemonic: Branch to Subroutine Long
  ; Operands: 0x050032c6 (absolute address)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Save return address on stack: [-(SP)] = PC+4 (= 0x000036ae)
  ;   2. Jump to subroutine at 0x050032c6
  ;   3. Execute code at 0x050032c6
  ;   4. When called function executes RTS, return to 0x000036ae
  ;
  ; LIBRARY FUNCTION: 0x050032c6
  ;   Type: Library/system call (not internal to NDserver)
  ;   Frequency: Used 1 time ONLY in entire codebase (specific to this context)
  ;   Likely Purpose: Validation/processing callback for converted data
  ;
  ;   Arguments received by 0x050032c6:
  ;     SP+0x00 = return address (0x000036ae)
  ;     SP+0x04 = D0/arg1 (result from 0x0500315e - converted value)
  ;     SP+0x08 = arg2 (original 2nd parameter from FUN_0000368c)
  ;     SP+0x0C = arg3 (original 3rd parameter)
  ;     SP+0x10 = arg4 (original 4th parameter)
  ;     SP+0x14 = arg5 (original 5th parameter)
  ;
  ;   Return value: D0 (32-bit result - passed to FUN_0000368c's caller)
  ;
  ; ADAPTER PATTERN DETAILS:
  ;   The function pair (0x0500315e + 0x050032c6) works together:
  ;
  ;   Step 1: 0x0500315e(arg2, arg3, arg4, arg5)
  ;           Input:  Raw parameters
  ;           Output: D0 = converted value
  ;
  ;   Step 2: 0x050032c6(D0, arg2, arg3, arg4, arg5)
  ;           Input:  D0 (converted), plus original context
  ;           Output: D0 = validated/processed result
  ;
  ;   This chains conversion + validation atomically
  ;   Caller sees only final result, not intermediate state
  ;
  ; BEHAVIOR:
  ;   - Input: D0 (converted value), arg2-arg5 (validation context)
  ;   - Output: D0 = final result
  ;   - May modify: D0, D1, A0, A1 (scratch registers)
  ;   - Preserves: A2-A7, D2-D7, A6 (callee-save registers)
  ;   - Stack usage: Unknown (depends on implementation)
  ;   - Side effects: Unknown (could modify global state)
  ;
  ; CONTROL FLOW:
  ;   This is a CALL instruction
  ;   After 0x050032c6 returns, execution continues at 0x000036ae
  ;   D0 contains final result for return to FUN_0000368c's caller
  ;
  ; CRITICAL OBSERVATION:
  ;   0x050032c6 is ONLY called from this one location
  ;   This suggests it's a callback specific to this validation scenario
  ;   The function triple is likely:
  ;     - FUN_0000368c = Wrapper/orchestrator
  ;     - 0x0500315e = Conversion step
  ;     - 0x050032c6 = Validation step
  ; ────────────────────────────────────────────────────────────────────

  0x000036ae:  unlk       A6
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: UNLK A6
  ; Mnemonic: Unlink Frame
  ; Operands: A6 (register)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Restore SP to frame base: SP = A6
  ;   2. Restore A6 from stack: A6 = [SP]+, SP += 4
  ;
  ; RESULT:
  ;   - Stack pointer reset to original position
  ;   - Old A6 restored for caller
  ;   - All local variables/temporary data discarded
  ;   - Frame completely unwound
  ;
  ; STACK BEFORE UNLK:
  ;   A6 → Old A6 (saved by LINK)
  ;   A6+0x04 → Return PC (for RTS)
  ;   A6+0x08 → arg1 (caller's stack frame)
  ;   ...
  ;
  ; STACK AFTER UNLK:
  ;   SP → Return PC (for RTS)
  ;   SP+0x04 → arg1 (caller's stack frame)
  ;   ...
  ;   A6 = Old A6 (restored)
  ;
  ; NOTE:
  ;   Caller is responsible for cleaning up arguments from stack
  ;   This function doesn't execute ADDQ to remove arguments
  ;   The 5 parameters (20 bytes) are still on stack
  ;   Caller must do: ADD.Q #20,SP after RTS returns
  ; ────────────────────────────────────────────────────────────────────

  0x000036b0:  rts
  ; ────────────────────────────────────────────────────────────────────
  ; Instruction: RTS
  ; Mnemonic: Return from Subroutine
  ; Operands: (none)
  ; ────────────────────────────────────────────────────────────────────
  ;
  ; ACTION:
  ;   1. Load return address from stack: PC = [SP]
  ;   2. Increment SP: SP += 4
  ;   3. Jump to return address (resume caller)
  ;
  ; RETURN VALUE:
  ;   D0 = Final result from 0x050032c6 validation function
  ;   This is returned to FUN_00006156 (the caller)
  ;
  ; STACK BEFORE RTS:
  ;   SP → Return PC (0x000061d6 - location in FUN_00006156)
  ;   SP+0x04 → arg1 (caller's first argument)
  ;   SP+0x08 → arg2 (caller's second argument)
  ;   SP+0x0C → arg3 (caller's third argument)
  ;   SP+0x10 → arg4 (caller's fourth argument)
  ;   SP+0x14 → arg5 (caller's fifth argument)
  ;
  ; STACK AFTER RTS:
  ;   SP → arg1 (caller must clean these 20 bytes)
  ;   SP+0x04 → arg2
  ;   ...
  ;
  ;   PC = 0x000061d6 (executing caller's code now)
  ;
  ; CONTROL FLOW RETURN:
  ;   Execution returns to FUN_00006156 at 0x000061d6
  ;
  ;   Caller continues with:
  ;   0x000061d6:  move.l     D0,(0x1c,A2)     ; Store result
  ;   0x000061da:  tst.l      (0x1c,A2)        ; Test if zero
  ;   0x000061de:  bne.b      0x000061ec       ; Branch if non-zero
  ;
  ;   Implication: D0 return value is tested for success/failure
  ;
  ; CALLEE-SAVE RESTORATION:
  ;   Any A2-A7, D2-D7 that caller uses are already preserved
  ;   (0x0500315e and 0x050032c6 maintain these registers)
  ;   Caller can resume without additional register restoration
  ; ────────────────────────────────────────────────────────────────────

; ============================================================================
; SUMMARY OF FUNCTION EXECUTION
; ============================================================================
;
; ENTRY POINT: 0x0000368c (called from FUN_00006156 at 0x000061d0)
;
; STEP-BY-STEP EXECUTION:
;
;   1. [0x368c] LINK.W A6,0x0
;      - Create stack frame (no locals)
;      - A6 now points to frame base
;
;   2-5. [0x3690-0x369c] MOVE.L (xx,A6),-(SP) × 4
;        - Push arg2, arg3, arg4, arg5 to stack (right-to-left order)
;        - arg1 is DELIBERATELY NOT PUSHED (design choice)
;        - Stack now ready for 0x0500315e call
;
;   6. [0x36a0] BSR.L 0x0500315e
;      - Call library function (string conversion or similar)
;      - Conversion function processes arg2-arg5
;      - Returns result in D0
;
;   7. [0x36a6] MOVE.L D0,-(SP)
;      - Push conversion result to stack
;      - D0 becomes arg1 for next function
;      - Original arg2-arg5 still on stack (validation context)
;
;   8. [0x36a8] BSR.L 0x050032c6
;      - Call validation/processing function
;      - Receives: converted value (D0) + context (arg2-arg5)
;      - Returns validated result in D0
;
;   9. [0x36ae] UNLK A6
;      - Unwind stack frame
;      - Restore A6 for caller
;
;   10. [0x36b0] RTS
;       - Return to caller (FUN_00006156 at 0x61d6)
;       - D0 = final validation result
;       - Caller responsible for cleaning up 20 bytes of arguments
;
; END STATE:
;   D0 = Validation result (tested by caller for success/failure)
;   All other registers preserved (callee-save convention maintained)
;
; ============================================================================
; CALLING CONTEXT
; ============================================================================
;
; CALLER: FUN_00006156 (Board initialization function)
; CALLED AT: 0x000061d0
;
; CALLER'S CODE:
;   0x000061bc:  move.l     (0x34,A0),-(SP)  ; arg5
;   0x000061c0:  move.l     (0x2c,A0),-(SP)  ; arg4
;   0x000061c4:  move.l     (0x24,A0),-(SP)  ; arg3
;   0x000061c8:  move.l     (0x1c,A0),-(SP)  ; arg2
;   0x000061cc:  move.l     (0xc,A0),-(SP)   ; arg1 (unused)
;   0x000061d0:  bsr.l      0x0000368c       ; CALL FUN_0000368c
;   0x000061d6:  move.l     D0,(0x1c,A2)     ; Store result
;   0x000061da:  tst.l      (0x1c,A2)        ; Test result
;   0x000061de:  bne.b      0x000061ec       ; Branch if error
;   0x000061e0:  move.b     #0x1,(0x3,A2)    ; Set flag
;   0x000061e6:  moveq      0x20,D1          ; Load constant
;   0x000061e8:  move.l     D1,(0x4,A2)      ; Store constant
;
; RESULT USAGE:
;   D0 is stored at [A2+0x1C] for later access
;   Tested for zero/non-zero (zero = error path)
;   If zero, flags are set at [A2+0x03] and [A2+0x04]
;
; IMPLICATION:
;   Board initialization involves validating/converting data
;   0x0000368c encapsulates the conversion + validation chain
;   Result (success/failure) is stored in board structure
;
; ============================================================================
; RELATED FUNCTIONS
; ============================================================================
;
; PREDECESSOR: FUN_0000366e (0x0000366e, size 30 bytes)
; SIMILAR PATTERN:
;   - Also takes 2 args
;   - Also calls 0x0500315e (first conversion)
;   - Also calls second function (0x050032ba instead of 0x050032c6)
;   - Suggests templated adapter pattern
;
; SUCCESSOR: FUN_000036b2 (0x000036b2, size 366 bytes)
; DIFFERENT PATTERN:
;   - Larger function (366 bytes vs 38 bytes)
;   - More complex (uses many more registers)
;   - Called by unknown function
;
; ============================================================================
; ANALYSIS NOTES
; ============================================================================
;
; CONFIDENCE LEVELS:
; ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
;   ✅ HIGH: Function mechanics (disassembly is clear and unambiguous)
;   ⚠️ MEDIUM: Function purpose (likely adapter/validator, not 100% certain)
;   ⚠️ MEDIUM: arg1 usage (why is it passed but ignored?)
;   ❓ LOW: Library function identities (0x0500315e and 0x050032c6)
;
; UNKNOWNS:
; ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
;   1. Why is arg1 passed to FUN_0000368c but ignored?
;   2. What exactly does 0x0500315e do? (atoi? string parsing? format checking?)
;   3. What exactly does 0x050032c6 do? (only called here - very specific)
;   4. What are arg2-arg5 in this context? (pointers? values? structures?)
;   5. What indicates success vs failure in return value D0?
;
; NEXT ANALYSIS STEPS:
; ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
;   1. Examine FUN_00006156 more closely (what's in structure at A0?)
;   2. Cross-reference 0x0500315e across codebase (15 uses total)
;   3. Search for 0x050032c6 in other binaries or documentation
;   4. Use dynamic debugger to trace execution flow
;   5. Look for error codes or return value semantics
;
; ============================================================================

