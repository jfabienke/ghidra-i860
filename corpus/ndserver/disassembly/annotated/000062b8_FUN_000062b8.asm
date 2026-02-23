; =============================================================================
; DETAILED DISASSEMBLY: FUN_000062b8
; =============================================================================
; Address Range: 0x000062b8 - 0x000062e6 (48 bytes, 12 instructions)
; Function Type: Callback/Wrapper
; Category: Hardware
; Complexity: Low
; Called By: FUN_00006602 (at 0x0000669c)
; Calls: 0x0500330e (external library function)
; =============================================================================
;
; STACK FRAME STRUCTURE (A6-relative offsets):
;
;   (0x18,A6)  ← Parameter 3 (arg[3])
;   (0x14,A6)  ← Parameter 2 (arg[2])
;   (0x10,A6)  ← Parameter 1 (arg[1])
;   (0x0c,A6)  ← Output Buffer Pointer (arg[0], → A2)
;   (0x08,A6)  ← Return Address
;   (0x04,A6)  ← Saved A6 (frame pointer)
;   (0x00,A6)  ← No local variables
;
; REGISTER MAPPING:
;   A6 = Frame pointer (set by link.w, restored by unlk)
;   A2 = Output buffer pointer (callee-saved, input from (0xc,A6))
;   A1 = Scratch (used by external function)
;   D0 = Return value (from external function, also function return)
;   D1 = Temporary (comparison value)
;   SP = Stack pointer
;
; CALLING CONVENTION:
;   m68k Standard C ABI
;   - Arguments passed on stack (left-to-right)
;   - First pointer argument in pseudo-register location
;   - Return value in D0
;   - Callee preserves A2-A7, D2-D7
;
; ERROR HANDLING:
;   Return value -1 indicates error
;   On error: write system data (at 0x040105b0) to output buffer
;   Return value still propagated to caller
;
; =============================================================================

; SECTION 1: STACK FRAME SETUP & PROLOGUE
; =============================================================================

0x000062b8:  link.w     A6,0x0
  ; Create new stack frame with 0 bytes of local variables
  ; Effect:
  ;   - SP -= 4 (push old A6)
  ;   - A6 = SP (new frame pointer)
  ; Stack After:  [saved_A6, ret_addr, arg3, arg2, arg1, arg0]
  ;               ^SP/A6

0x000062bc:  move.l     A2,-(SP)
  ; Save A2 register (callee-saved in m68k ABI)
  ; This function will modify A2, so caller expects it restored
  ; Effect:
  ;   - SP -= 4 (push A2 value)
  ;   - (SP) = A2 (previous value)
  ; Stack After:  [saved_A2, saved_A6, ret_addr, arg3, arg2, arg1, arg0]
  ;               ^SP

; SECTION 2: LOAD OUTPUT BUFFER POINTER
; =============================================================================

0x000062be:  movea.l    (0xc,A6),A2
  ; Load output buffer pointer from arg[0]
  ; A6+0xc points to the output buffer pointer parameter
  ; Effect:
  ;   - A2 = *(A6 + 0xc)
  ;   - A2 now contains the address of the output buffer
  ; Note:
  ;   This pointer will be used for writing error data if needed
  ; Stack State: Unchanged

; SECTION 3: PREPARE ARGUMENTS & CALL EXTERNAL FUNCTION
; =============================================================================

0x000062c2:  move.l     (0x18,A6),-(SP)
  ; Push arg[3] (third parameter to external function)
  ; Effect:
  ;   - SP -= 4 (push longword)
  ;   - (SP) = *(A6 + 0x18)
  ; Purpose: Argument for external service call
  ; Stack After:  [arg3, saved_A2, saved_A6, ret_addr, arg3_arg, arg2_arg, arg1_arg, arg0_arg]
  ;               ^SP

0x000062c6:  move.l     (0x14,A6),-(SP)
  ; Push arg[2] (second parameter to external function)
  ; Effect:
  ;   - SP -= 4 (push longword)
  ;   - (SP) = *(A6 + 0x14)
  ; Purpose: Argument for external service call
  ; Stack After:  [arg2, arg3, saved_A2, saved_A6, ...]
  ;               ^SP

0x000062ca:  move.l     (0x10,A6),-(SP)
  ; Push arg[1] (first parameter to external function)
  ; Effect:
  ;   - SP -= 4 (push longword)
  ;   - (SP) = *(A6 + 0x10)
  ; Purpose: Argument for external service call
  ; Stack After:  [arg1, arg2, arg3, saved_A2, saved_A6, ...]
  ;               ^SP
  ; Note:
  ;   All three arguments are now on the stack in proper order for call

0x000062ce:  bsr.l      0x0500330e
  ; Branch to external service routine with long displacement
  ; Call: EXTERNAL_SERVICE(arg1, arg2, arg3)
  ; Effect:
  ;   - (--SP) = PC + 6 (save return address)
  ;   - PC = 0x0500330e (jump to external function)
  ; Execution:
  ;   External function at 0x0500330e executes with arguments on stack
  ;   Function may modify: D0, D1, A0, A1 (caller-saved registers)
  ;   Function should preserve: A2-A7, D2-D7 (callee-saved registers)
  ; Return:
  ;   - D0 contains return value (0=success, -1=error, other=data)
  ;   - SP still points to arguments (NOT cleaned by callee)
  ; Note:
  ;   Caller (this function) is responsible for stack cleanup
  ;   The called function uses bsr.l, so cleanup is implicit on rts

; SECTION 4: ERROR CHECKING
; =============================================================================

0x000062d4:  moveq      -0x1,D1
  ; Load -1 (0xFFFFFFFF) into D1 for comparison
  ; This is the error sentinel value
  ; Effect:
  ;   - D1 = -0x1 (same as -1 in two's complement)
  ;   - CPU state: D1 modified, condition codes updated
  ; Instruction: moveq (move quick) - 8-bit sign-extended to 32-bit
  ; Encoding: -0x1 → 0xFF (8-bit) → 0xFFFFFFFF (32-bit)
  ; Purpose: Setup for comparison

0x000062d6:  cmp.l      D0,D1
  ; Compare D0 (external function return) with D1 (-1)
  ; Effect:
  ;   - Performs D1 - D0, updates condition codes
  ;   - Zero flag (Z) set if D0 == -1
  ;   - Carry flag (C) set if D0 < -1
  ;   - Sign flag (N) reflects result sign
  ;   - NO REGISTERS MODIFIED
  ; Semantics:
  ;   - If D0 == -1 → Z flag = 1 (equal)
  ;   - If D0 != -1 → Z flag = 0 (not equal)
  ; Purpose: Prepare condition codes for error check

0x000062d8:  bne.b      0x000062e0
  ; Branch if NOT EQUAL (Z flag = 0)
  ; This branch skips the error handler if D0 ≠ -1 (success case)
  ; Condition: Taken if D0 != -1
  ; Displacement: 0x000062e0 - 0x000062da = 0x6 (6 bytes forward)
  ; Effect when TAKEN (success):
  ;   - PC = 0x000062e0 (skip error handler)
  ;   - Goes directly to restore A2 and exit
  ; Effect when NOT TAKEN (error):
  ;   - PC = next instruction (0x000062da)
  ;   - Fall through to error handler
  ;   - Execute move.l (0x040105b0).l,(A2)
  ;
  ; CONTROL FLOW DECISION POINT:
  ;   SUCCESS CASE: D0 ≠ -1 → branch to 0x000062e0 → exit
  ;   ERROR CASE:   D0 == -1 → fall through → handle error → exit

; SECTION 5: ERROR HANDLER (CONDITIONAL)
; =============================================================================

0x000062da:  move.l     (0x040105b0).l,(A2)
  ; Write system data to output buffer (ERROR CASE ONLY)
  ; This instruction is ONLY executed if D0 == -1
  ; If D0 != -1, this instruction is skipped by the branch above
  ;
  ; Effect:
  ;   - Load longword from 0x040105b0 (system data area)
  ;   - Store to address in A2 (output buffer)
  ;   - (A2) = *(long*)0x040105b0
  ;
  ; Addressing Mode: (ea).l meaning absolute long address
  ;   - 0x040105b0 is treated as 32-bit constant address
  ;   - Not a relative address
  ;
  ; System Data Address Reference:
  ;   0x040105b0 = SYSTEM_PORT + 0x31c (offset 0x31c from SYSTEM_PORT base)
  ;   This contains system-wide error data or status information
  ;
  ; Purpose:
  ;   When external function returns -1 (error):
  ;   - Retrieve diagnostic/error data from system area
  ;   - Write to caller's output buffer for error reporting
  ;   - Allows caller to determine error cause
  ;
  ; Safety Notes:
  ;   - A2 is assumed to be a valid pointer (NOT VALIDATED)
  ;   - If A2 is NULL or invalid → crash/bus error
  ;   - Caller must ensure output buffer is valid
  ;   - System data at 0x040105b0 must be readable
  ;
  ; Execution Trace (error case):
  ;   1. D0 == -1 (error from external function)
  ;   2. cmp.l D0,D1 sets Z flag
  ;   3. bne.b condition fails → Z flag is set → DO NOT BRANCH
  ;   4. PC falls through to this instruction
  ;   5. Read longword from 0x040105b0
  ;   6. Write longword to (A2)
  ;   7. Continue to restore and exit

; SECTION 6: CLEANUP & EPILOGUE
; =============================================================================

0x000062e0:  movea.l    (-0x4,A6),A2
  ; Restore A2 register from stack
  ; -0x4 relative to A6 points to saved A2 (pushed at 0x000062bc)
  ; Effect:
  ;   - A2 = *(A6 - 4)
  ;   - A2 restored to original value before function call
  ;
  ; Why -0x4?
  ;   - Stack layout: [saved_A2, saved_A6, ret_addr, ...]
  ;   - A6 points to saved_A6
  ;   - A6 - 4 = &saved_A2
  ;   - This undoes the save from 0x000062bc
  ;
  ; Note:
  ;   This instruction is reachable from both:
  ;   - Success path: via bne.b branch at 0x000062d8
  ;   - Error path: via fall-through after error handler
  ;   In both cases, A2 must be restored before returning

0x000062e4:  unlk       A6
  ; Unlink stack frame
  ; Effect:
  ;   - SP = A6 (restore old SP)
  ;   - A6 = (A6) (restore old A6 from stack)
  ;   - Effectively: SP += 4, A6 = *(SP after increment)
  ;
  ; This undoes the link.w instruction from the prologue
  ;
  ; Stack State After:
  ;   - SP points to return address (pushed by bsr)
  ;   - Stack ready for rts to return to caller

0x000062e6:  rts
  ; Return from subroutine
  ; Effect:
  ;   - PC = (SP)+
  ;   - SP += 4 (pop return address)
  ;   - Control returns to caller (FUN_00006602)
  ;
  ; Return Value:
  ;   - D0 contains the return value from external function
  ;   - D0 == -1 if error (caller should check)
  ;   - D0 == 0 or positive if success
  ;   - Output buffer at (A2) contains error data if D0 == -1
  ;
  ; Caller Assumptions:
  ;   - A2 is restored
  ;   - Stack is balanced
  ;   - D0 contains result

; =============================================================================
; EXECUTION SUMMARY
; =============================================================================
;
; HAPPY PATH (SUCCESS): D0 ≠ -1
;   0x62b8: link.w A6,0x0        → Setup frame
;   0x62bc: move.l A2,-(SP)      → Save A2
;   0x62be: movea.l (0xc,A6),A2  → Load output ptr
;   0x62c2: move.l (0x18,A6),-(SP) → Push arg3
;   0x62c6: move.l (0x14,A6),-(SP) → Push arg2
;   0x62ca: move.l (0x10,A6),-(SP) → Push arg1
;   0x62ce: bsr.l 0x0500330e      → Call external (D0 ≠ -1 returned)
;   0x62d4: moveq -0x1,D1         → D1 = -1
;   0x62d6: cmp.l D0,D1           → Compare D0 vs -1 (Z flag = 0)
;   0x62d8: bne.b 0x000062e0     → BRANCH TAKEN (skip error handler)
;   0x62e0: movea.l (-0x4,A6),A2 → Restore A2
;   0x62e4: unlk A6              → Unlink frame
;   0x62e6: rts                  → Return with D0
;
; ERROR PATH: D0 == -1
;   0x62b8: link.w A6,0x0        → Setup frame
;   0x62bc: move.l A2,-(SP)      → Save A2
;   0x62be: movea.l (0xc,A6),A2  → Load output ptr
;   0x62c2: move.l (0x18,A6),-(SP) → Push arg3
;   0x62c6: move.l (0x14,A6),-(SP) → Push arg2
;   0x62ca: move.l (0x10,A6),-(SP) → Push arg1
;   0x62ce: bsr.l 0x0500330e      → Call external (D0 == -1 returned)
;   0x62d4: moveq -0x1,D1         → D1 = -1
;   0x62d6: cmp.l D0,D1           → Compare D0 vs -1 (Z flag = 1)
;   0x62d8: bne.b 0x000062e0     → BRANCH NOT TAKEN (execute error handler)
;   0x62da: move.l (0x040105b0).l,(A2) → Write system error data
;   0x62e0: movea.l (-0x4,A6),A2 → Restore A2
;   0x62e4: unlk A6              → Unlink frame
;   0x62e6: rts                  → Return with D0 (-1)
;
; =============================================================================
; REGISTER STATE CHANGES
; =============================================================================
;
; Entry:
;   D0 = ? (undefined, will contain external function result)
;   D1 = ? (undefined)
;   A2 = ? (will be loaded from stack frame)
;   A6 = frame pointer from caller
;   SP = points to return address
;
; After 0x62b8 (link.w):
;   A6 = SP (new frame)
;   SP -= 4 (adjusted)
;
; After 0x62bc (move.l A2,-(SP)):
;   SP -= 4 (A2 saved)
;   (SP) = old A2 value
;
; After 0x62be (movea.l):
;   A2 = output buffer pointer (from arg[0])
;
; After 0x62c2-0x62ca (push arguments):
;   SP -= 12 (3 longwords pushed)
;   Arguments ready for external call
;
; After 0x62ce (bsr.l):
;   D0 = external function return value
;   D1 may be modified by external function
;   A2 should still be valid (callee-saved)
;
; After 0x62d4 (moveq):
;   D1 = -1 (0xFFFFFFFF)
;
; After 0x62d6 (cmp.l):
;   Condition codes set:
;   - Z = 1 if D0 == -1
;   - Z = 0 if D0 != -1
;   - C, N, V flags also modified
;
; After 0x62d8 (bne.b):
;   If D0 != -1: PC = 0x62e0 (branch taken)
;   If D0 == -1: PC = 0x62da (fall through)
;
; After error handler (0x62da if executed):
;   (A2) = system error data from 0x040105b0
;   No register changes
;
; After 0x62e0 (movea.l):
;   A2 = restored to original value
;
; After 0x62e4 (unlk):
;   A6 = restored to caller's A6
;   SP = adjusted back to point to return address
;
; Exit (0x62e6 rts):
;   PC = return address (to FUN_00006602)
;   SP = adjusted by rts
;   D0 = function return value (unchanged from external call)
;
; =============================================================================
; CROSS-REFERENCE INFORMATION
; =============================================================================
;
; Called From:
;   FUN_00006602 at address 0x0000669c
;   Context: Within message handler/dispatcher
;
; Calls:
;   0x0500330e (external service/library function)
;
; Related Functions:
;   FUN_000062e8 (similar wrapper, 48 bytes)
;   FUN_00006318 (similar wrapper, 40 bytes)
;   FUN_00006340 (similar wrapper, 44 bytes)
;
; Memory References:
;   0x000062b8 - This function (entry)
;   0x040105b0 - System error data (error handling)
;   0x0500330e - External service routine
;
; =============================================================================
; ANALYSIS NOTES
; =============================================================================
;
; 1. PATTERN RECOGNITION:
;    This is a standard callback wrapper pattern:
;    - Setup frame
;    - Load output pointer
;    - Push arguments
;    - Call service
;    - Check return value
;    - Handle error case
;    - Return
;
; 2. CALLING CONVENTION COMPLIANCE:
;    Follows standard m68k ABI:
;    - Stack arguments passed left-to-right
;    - Return value in D0
;    - Callee-saved registers preserved
;
; 3. ERROR HANDLING:
;    Uses sentinel value approach:
;    - -1 = error
;    - Other values = success (including 0)
;    - Limited error information (only one error code)
;
; 4. SAFETY CONCERNS:
;    - No validation of output buffer pointer (A2)
;    - Assumes system data at 0x040105b0 always readable
;    - No recovery/retry logic
;
; 5. OPTIMIZATION:
;    Function is already well-optimized:
;    - Minimal overhead
;    - External call dominates execution time
;    - No improvements needed
;
; =============================================================================
; END OF DISASSEMBLY
; =============================================================================
