; ============================================================================
; Function: FUN_00006398 (Hardware Access Callback Wrapper)
; Address Range: 0x00006398 - 0x000063bf
; Size: 40 bytes (10 instructions)
; Purpose: Single-parameter hardware service delegation with error reporting
; Complexity: Low (simple linear control flow)
; Register Usage: A2 (save/restore), D0 (return), D1 (temporary)
; ============================================================================

; STACK FRAME LAYOUT (A6-relative):
;   (0x10,A6) = param1 (hardware service parameter)
;   (0xc,A6)  = output_ptr (pointer to error output buffer)
;   (0x8,A6)  = return address
;   (0x4,A6)  = saved A6
;   (0x0,A6)  = local variables (none in this function)

; CALLING CONVENTION: m68k ABI (stack-based arguments)
; RETURN VALUE: D0 (0 or positive = success, -1 = error)
; SIDE EFFECTS: Writes to system address 0x040105b0 if D0 == -1

; ============================================================================
; PROLOGUE: Stack frame setup and register preservation
; ============================================================================

0x00006398:
  link.w     A6,0x0
  ; Create new stack frame with 0 local variables
  ; Input:  SP -> [return_addr], A6 = old_A6
  ; Output: SP -> [saved_A6], A6 = SP
  ; Cycles: 16
  ; Allows addressing arguments via (offset,A6)

0x0000639c:
  move.l     A2,-(SP)
  ; Save A2 register (callee-saved in m68k ABI)
  ; Input:  A2 = any value, SP -> [saved_A6]
  ; Output: SP -> [saved_A2, saved_A6], A2 unchanged
  ; Cycles: 8
  ; A2 will be used as output buffer pointer

; ============================================================================
; SETUP PHASE: Load arguments and prepare for external call
; ============================================================================

0x0000639e:
  movea.l    (0xc,A6),A2
  ; Load output buffer pointer from argument 0 into A2
  ; Source: (0xc,A6) = caller's argument (output buffer address)
  ; Dest:   A2 = this address
  ; Cycles: 12
  ; Purpose: A2 will point to where error data is written (if error occurs)
  ; Example: If caller passed &error_buffer, A2 = &error_buffer

0x000063a2:
  move.l     (0x10,A6),-(SP)
  ; Push argument 1 onto stack for external function call
  ; Source: (0x10,A6) = caller's argument (hardware parameter)
  ; Dest:   SP -= 4, stack now contains this parameter
  ; Cycles: 12
  ; Calling convention: stack-based, arguments in reverse order (cdecl)
  ; Stack: [param1, saved_A2, saved_A6, ...]

; ============================================================================
; DELEGATION PHASE: Call external hardware service function
; ============================================================================

0x000063a6:
  bsr.l      0x0500324e
  ; Branch to subroutine at 0x0500324e (external ROM function)
  ; This call:
  ;   1. Pushes return address (0x000063ac) onto stack
  ;   2. Jumps to 0x0500324e
  ;   3. External function accesses stack parameter at (SP)
  ;   4. External function returns with result in D0
  ;   5. Returns to next instruction (0x000063ac)
  ; Cycles: 18 (branch cost) + variable (external function cost)
  ; Note: Stack cleanup NOT done here; external function leaves parameter
  ; D0 on return: result code (0/positive = success, -1 = error, other = varies)
  ; Stack: [param1, saved_A2, saved_A6, ...] (parameter still on stack!)

; ============================================================================
; ERROR DETECTION PHASE: Check if external function returned error
; ============================================================================

0x000063ac:
  moveq      -0x1,D1
  ; Load error sentinel value into D1
  ; Loads: D1 = -1 (0xFFFFFFFF in 32-bit)
  ; Cycles: 4
  ; Purpose: Set up comparison value for error detection
  ; Efficiency: moveq uses 8-bit immediate (4 cycles vs 8 for move.l)
  ; D1 = -1 (1111_1111_1111_1111_1111_1111_1111_1111 binary)

0x000063ae:
  cmp.l      D0,D1
  ; Compare D0 (external function result) with -1
  ; Input:  D0 = external result, D1 = -1
  ; Effect: Sets condition codes (NZVC flags)
  ;   Z flag = 1 if D0 == D1 (D0 == -1, ERROR)
  ;   Z flag = 0 if D0 != D1 (D0 != -1, SUCCESS)
  ;   C flag = 1 if D0 < D1 (D0 < -1, unlikely but possible)
  ; Cycles: 6
  ; Note: D0 not modified; can still return it after error check
  ; Typical results:
  ;   D0 = 0:  Z clear (success)
  ;   D0 = 1:  Z clear (success)
  ;   D0 = -1: Z set (ERROR)
  ;   D0 = -2: Z clear, C set (not an error in this convention)

; ============================================================================
; CONDITIONAL ERROR HANDLING: Branch decision based on comparison
; ============================================================================

0x000063b0:
  bne.b      0x000063b8
  ; Branch if Not Equal: skip to 0x000063b8 if D0 != -1 (SUCCESS)
  ; This is a SHORT branch (8-bit offset, only 127 bytes forward/backward)
  ; Offset: 0x000063b8 - 0x000063b2 = 6 bytes (0x06)
  ;
  ; Flow:
  ;   IF (D0 != -1):  [Z flag clear]
  ;     Jump to 0x000063b8 (skip error handler)
  ;     TAKEN on success path (~10 cycles)
  ;
  ;   IF (D0 == -1):  [Z flag set]
  ;     Fall through to next instruction (no branch)
  ;     NOT taken on error path
  ;
  ; In other words:
  ;   - Success: jump over error handler to cleanup
  ;   - Error: fall through to execute error handler
  ;
  ; Note: Branch instruction appears "backwards" (jumps ahead)
  ;   This is standard for conditional jumps:
  ;   bne (branch if not equal) = typical "success fast path" pattern

; ============================================================================
; ERROR HANDLER: Execute only if D0 == -1 (error condition)
; ============================================================================

0x000063b2:
  move.l     (0x040105b0).l,(A2)
  ; Load system data from fixed hardware address, write to caller's buffer
  ; Source: 0x040105b0 (SYSTEM_PORT+0x31c, system error/status data)
  ; Dest:   (A2) (output buffer pointer, loaded at 0x0000639e)
  ; Cycles: 28 (4 bytes, absolute long address, indirect register dest)
  ;
  ; Assembly breakdown:
  ;   (0x040105b0).l = access 32-bit value at absolute address 0x040105b0
  ;   (A2) = dereference pointer in A2, store result there
  ;
  ; This instruction ONLY executes if bne.b at 0x000063b0 did NOT branch
  ; (i.e., only if D0 == -1, the error condition)
  ;
  ; Effect:
  ;   1. Read 4-byte value from 0x040105b0
  ;      This address is SYSTEM_PORT base (0x04000000) + offset 0x105b0 (0x31c)
  ;      Contains system error/status data
  ;   2. Write that value to buffer pointed to by A2
  ;      A2 = output buffer address (from caller's argument)
  ;      Caller can examine this data to understand error details
  ;
  ; Example (error case):
  ;   0x040105b0 contains: 0xDEADBEEF (system error code)
  ;   A2 points to:        &caller_buffer
  ;   After:               caller_buffer = 0xDEADBEEF
  ;
  ; Security note: No validation that (A2) is valid
  ;   If A2 = NULL:        Bus error (crash)
  ;   If A2 = ROM area:    Bus error (write to read-only, if protected)
  ;   If A2 = registers:   Hardware side effects

; ============================================================================
; EPILOGUE: Register restoration and stack frame teardown
; ============================================================================

0x000063b8:
  movea.l    (-0x4,A6),A2
  ; Restore A2 register from stack (pair with move.l at 0x0000639c)
  ; Source: (-0x4,A6) = saved A2 on stack
  ; Dest:   A2 = restored value
  ; Cycles: 12
  ; Stack: Still contains [saved_A2, saved_A6, ...] (will be cleaned by unlk)
  ; This is THE entry point for the success path (jumped here by bne.b)

0x000063bc:
  unlk       A6
  ; Unlink stack frame (pair with link.w at 0x00006398)
  ; Effect:
  ;   1. SP = A6 (discard any local variables, but there are none)
  ;   2. A6 = (SP) (restore caller's A6)
  ;   3. SP += 4 (pop saved A6)
  ;   Result: SP -> [return_addr], A6 = caller's A6
  ; Cycles: 12
  ; Note: This cleans up saved_A6 but NOT the parameter on stack!
  ;       Parameter at 0x000063a2 is still on stack after unlk
  ;       (This may be intentional if external function is callee-cleanup)

0x000063be:
  rts
  ; Return to caller
  ; Effect:
  ;   1. PC = (SP) (pop return address)
  ;   2. SP += 4 (pop return address)
  ;   Result: Control returns to instruction after bsr.l that called us
  ; Cycles: 16
  ; Return value: D0 unchanged from external function result
  ;   D0 = -1 (error) or non-negative (success)

; ============================================================================
; REGISTER STATE AT RETURN
; ============================================================================
; D0: Result from external function (unchanged)
;     -1 = error (system data written to output buffer)
;     0/positive = success (output buffer NOT modified)
; D1: Garbage (destroyed by comparison)
; A2: Restored to caller's original value
; A6: Restored to caller's frame pointer
; SP: Pointing to next instruction's location after rts
; PC: Caller's instruction after bsr.l 0x00006398

; ============================================================================
; STACK STATE AT RETURN
; ============================================================================
; PROBLEM: Parameter from 0x000063a2 still on stack!
; After unlk: SP -> [param1, ...]
; After rts:  SP -> [param1, ...] (rts doesn't clean parameters)
; Consequence: Caller must either:
;   a) Clean stack with add.l #4,SP (caller-cleanup)
;   b) Parameter gets cleaned by external function somehow (callee-cleanup)
;   c) There's a bug in the stack management
;
; LIKELY: External function at 0x0500324e uses callee-cleanup convention
;         (leaves stack imbalanced for caller to clean)
;         This is non-standard for m68k C calling convention

; ============================================================================
; EXECUTION TIME ANALYSIS
; ============================================================================

; SUCCESS PATH (D0 != -1):
; 0x6398: link.w        = 16 cycles
; 0x639c: move.l A2,    = 8 cycles
; 0x639e: movea.l       = 12 cycles
; 0x63a2: move.l push   = 12 cycles
; 0x63a6: bsr.l         = 18 cycles + external function
; 0x63ac: moveq         = 4 cycles
; 0x63ae: cmp.l         = 6 cycles
; 0x63b0: bne.b (taken) = 10 cycles (branch taken)
; 0x63b8: movea.l       = 12 cycles
; 0x63bc: unlk          = 12 cycles
; 0x63be: rts           = 16 cycles
; Total (excluding external function): ~126 cycles

; ERROR PATH (D0 == -1):
; (same as success, up to 0x63b0)
; 0x63b0: bne.b (not taken) = 8 cycles (no branch)
; 0x63b2: move.l (write)    = 28 cycles (system data write)
; 0x63b8: movea.l           = 12 cycles
; 0x63bc: unlk              = 12 cycles
; 0x63be: rts               = 16 cycles
; Total (excluding external function): ~150 cycles

; EXTERNAL FUNCTION DOMINATES: Latency > 1000 cycles likely (I/O operation)

; ============================================================================
; PSEUDO-C EQUIVALENT
; ============================================================================
;
; long FUN_00006398(long *out_buffer, long param1) {
;     // Call external service function
;     long result = external_service_at_0x0500324e(param1);
;
;     // Error detection
;     if (result == -1) {
;         // Error path: write system diagnostic data
;         *out_buffer = *(long*)0x040105b0;
;     }
;     // Success path: output buffer unchanged
;
;     // Return result (either error code or success value)
;     return result;
; }

; ============================================================================
; COMPARISON TO FUN_000062b8 (3-parameter version)
; ============================================================================
;
; FUN_000062b8:                  FUN_00006398:
; ├─ link.w A6,0x0              ├─ link.w A6,0x0
; ├─ move.l A2,-(SP)            ├─ move.l A2,-(SP)
; ├─ movea.l (0xc,A6),A2        ├─ movea.l (0xc,A6),A2
; ├─ move.l (0x18,A6),-(SP)      ├─ move.l (0x10,A6),-(SP)
; ├─ move.l (0x14,A6),-(SP)      ├─ bsr.l 0x0500324e
; ├─ move.l (0x10,A6),-(SP)      ├─ moveq -0x1,D1
; ├─ bsr.l 0x0500330e           ├─ cmp.l D0,D1
; ├─ moveq -0x1,D1              ├─ bne.b 0x000063b8
; ├─ cmp.l D0,D1                ├─ move.l (0x040105b0).l,(A2)
; ├─ bne.b 0x000062e0           ├─ movea.l (-0x4,A6),A2
; ├─ move.l (0x040105b0).l,(A2) ├─ unlk A6
; ├─ movea.l (-0x4,A6),A2       └─ rts
; ├─ unlk A6
; └─ rts
;
; Difference: FUN_000062b8 pushes 3 arguments (lines 2-4 in its version)
;             FUN_00006398 pushes 1 argument
; Same error handling, same external function pattern, different arities

; ============================================================================
; USAGE CONTEXT
; ============================================================================
;
; Called by: FUN_00006a08 (NDserver message handler for command 0x42c)
; Call site: 0x00006a80 in FUN_00006a08
; Message structure:
;   message[0x0c] = param1 (hardware service parameter)
;   message[0x2c] = output buffer address (where error data goes)
; Caller:
;   push message[0x2c]      (output buffer)
;   push message[0x0c]      (parameter)
;   bsr.l 0x00006398        (call this function)
;   move.l D0,...           (store result)
;
; Return value stored in message reply at offset 0x24
; Error data stored in message data area at offset 0x2c (if error)

; ============================================================================
; SECURITY NOTES
; ============================================================================
;
; VULNERABILITY: Unchecked pointer dereference at 0x000063b2
;   move.l (0x040105b0).l,(A2)
;
;   If (A2) is NULL:
;     → Bus error (memory fault), crash
;   If (A2) points to invalid memory:
;     → Bus error (invalid address access)
;   If (A2) points to read-only memory:
;     → Bus error (write protection fault)
;   If (A2) points to hardware register:
;     → Side effects (hardware operation triggered)
;
; RECOMMENDATION: Add NULL check:
;   cmp.l #0,A2
;   beq error_invalid
;
; ASSUMPTION: Caller provides valid output buffer
;   This is reasonable for kernel code
;   Not reasonable for user-space untrusted input

; ============================================================================
; END OF FUNCTION
; ============================================================================
