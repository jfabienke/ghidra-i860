; ============================================================================
; ANNOTATED DISASSEMBLY: FUN_00006340
; ============================================================================
;
; Function: Hardware Access Callback Wrapper
; Address: 0x00006340 - 0x0000636a
; Size: 44 bytes (0x2c)
;
; Classification: CALLBACK WRAPPER - Hardware Access Pattern
; Complexity: LOW (simple parameter forwarding + conditional register copy)
; Called By: FUN_00006856 (single caller)
; Calls: ROM function at 0x050022e8
; Hardware Access: YES - reads 0x040105b0 (conditional)
;
; Purpose: Bridge between caller's data structure and ROM-based hardware
;          operation. Conditionally copies hardware register value based on
;          ROM function's return status (error checking pattern).
;
; ============================================================================
; EXECUTION MODEL:
; ============================================================================
;
; M68k Calling Convention (Motorola ABI):
;   - D0-D1: Return registers (main return in D0)
;   - A0-A1: Address arguments
;   - D2-D7, A2-A7: Callee-save (preserved)
;   - Stack: Additional arguments passed right-to-left
;
; ============================================================================
; STACK FRAME AT ENTRY:
; ============================================================================
;
;   A6+0x14 ──► Arg 3 (int32_t param3) - passed to ROM function
;   A6+0x10 ──► Arg 2 (int32_t param2) - passed to ROM function
;   A6+0x0c ──► Arg 1 (pointer) - output buffer address (loaded to A2)
;   A6+0x08 ──► Arg 0 (pointer) - unused parameter
;   A6+0x04 ──► Return Address
;   A6+0x00 ──► Old A6 (saved by LINK.W)
;
; ============================================================================
; DISASSEMBLY WITH ANNOTATIONS:
; ============================================================================

0x00006340:  link.w     A6,0x0
             ; OPERATION: Setup stack frame
             ; A6 <- SP (save caller's A6)
             ; SP <- SP - 0 (allocate 0 bytes of locals)
             ; PURPOSE: Create new frame pointer for accessing parameters
             ; TIMING: ~16 cycles
             ; REGISTERS: A6 modified, SP adjusted

0x00006344:  move.l     A2,-(SP)
             ; OPERATION: Save A2 register on stack (callee-save)
             ; Memory: SP <- A2 value, SP <- SP - 4
             ; PURPOSE: Preserve A2 for caller (required by M68k ABI)
             ; TIMING: ~12 cycles
             ; NOTE: A2 will be used as temporary buffer pointer below

0x00006346:  movea.l    (0xc,A6),A2
             ; OPERATION: Load output buffer pointer from parameter
             ; A2 <- *(A6 + 0x0c) [i.e., A2 <- arg1 from caller]
             ; PURPOSE: Setup A2 as output buffer address for later use
             ; TIMING: ~8 cycles
             ; NOTE: This is the pointer where hardware value will be written
             ;       (but only if ROM function returns non-(-1))

0x0000634a:  move.l     (0x14,A6),-(SP)
             ; OPERATION: Push arg3 onto stack for ROM function
             ; Memory: SP <- *(A6 + 0x14), SP <- SP - 4
             ; PURPOSE: Pass param3 to upcoming ROM function call
             ; TIMING: ~12 cycles
             ; STACK: Now have [arg3] on stack

0x0000634e:  move.l     (0x10,A6),-(SP)
             ; OPERATION: Push arg2 onto stack for ROM function
             ; Memory: SP <- *(A6 + 0x10), SP <- SP - 4
             ; PURPOSE: Pass param2 to upcoming ROM function call
             ; TIMING: ~12 cycles
             ; STACK: Now have [arg3, arg2] on stack (arg2 on top)
             ; NOTE: arg2 and arg3 will be popped by called function

0x00006352:  bsr.l      0x050022e8
             ; OPERATION: Call external ROM function at 0x050022e8
             ; Memory: SP <- (return address), SP <- SP - 4, PC <- 0x050022e8
             ; PURPOSE: Invoke hardware operation with param2, param3
             ; TIMING: ~18 cycles (return happens in called function)
             ; FUNCTION SIGNATURE (inferred):
             ;   int32_t rom_func_050022e8(int32_t param2, int32_t param3)
             ; RETURN VALUE: D0 = result from ROM function
             ;   D0 == -1: Error condition
             ;   D0 != -1: Success/status value
             ; SIDE EFFECTS: May modify hardware state (implementation-dependent)

0x00006358:  moveq      -0x1,D1
             ; OPERATION: Load error constant -1 (0xFFFFFFFF) into D1
             ; D1 <- -1 (sign-extended 8-bit to 32-bit)
             ; PURPOSE: Setup comparison value for error checking
             ; TIMING: ~4 cycles
             ; VALUE: D1 = 0xFFFFFFFF = -1 (error marker in M68k convention)

0x0000635a:  cmp.l      D0,D1
             ; OPERATION: Compare ROM function result (D0) with error value (D1)
             ; Sets condition codes based on D1 - D0
             ; PURPOSE: Check if D0 == -1 (error condition)
             ; TIMING: ~8 cycles
             ; CONDITION CODES SET:
             ;   Z = 1 if D0 == -1 (values equal)
             ;   Z = 0 if D0 != -1 (values not equal)
             ;   N, V, C set per subtraction result
             ; NOTE: This is defensive error checking pattern

0x0000635c:  bne.b      0x00006364
             ; OPERATION: Branch if NOT EQUAL (BNE.B branch)
             ; IF (condition codes Z == 0): PC <- 0x00006364
             ; IF (condition codes Z == 1): continue to next instruction
             ; PURPOSE: Skip hardware register copy if D0 != -1 (success)
             ; TIMING: ~8 cycles (if branch taken), ~8 cycles (if fall-through)
             ; SEMANTICS: If ROM call succeeded (D0 != -1), skip the register copy
             ; NOTE: This is UNUSUAL - typical pattern copies on success,
             ;       not on error. Suggests error recovery: if ROM failed,
             ;       copy hardware state as fallback/diagnostic.

0x0000635e:  move.l     (0x040105b0).l,(A2)
             ; OPERATION: Conditional hardware register read and copy
             ; [ONLY EXECUTED IF BRANCH NOT TAKEN - i.e., D0 == -1]
             ; Memory: *(A2) <- *(0x040105b0) [hardware register read]
             ; PURPOSE: Copy hardware register to caller's output buffer on error
             ; TIMING: ~12 cycles
             ; ADDRESS: 0x040105b0 = System data area register
             ;   Likely contains: device status, config, or state information
             ;   This is a READ operation (no side effects expected)
             ; CONDITION: Only executed if ROM function returned -1 (error)
             ; SIDE EFFECT: Writes 32-bit value to address pointed by A2
             ; HARDWARE REGISTER ANALYSIS:
             ;   Space: 0x040105b0 is in system data area (0x04XXXXXX)
             ;   Type: Likely status/configuration register
             ;   Purpose: Provide error recovery data or diagnostic info
             ;   Access: Read-only in this function

0x00006364:  movea.l    (-0x4,A6),A2
             ; OPERATION: Restore saved A2 register from stack
             ; A2 <- *(A6 - 0x04) [restore from where we pushed it earlier]
             ; PURPOSE: Restore A2 to its value before this function
             ; TIMING: ~8 cycles
             ; NOTE: This is required for M68k ABI callee-save compliance
             ; STACK POSITION: (-0x4, A6) points to saved A2 from move.l A2,-(SP)

0x00006368:  unlk       A6
             ; OPERATION: Unlink (deallocate stack frame)
             ; A6 <- *(A6 + 0x00) [restore old A6]
             ; SP <- A6 + 4 [deallocate frame and remove return address space]
             ; PURPOSE: Clean up stack frame created by link.w
             ; TIMING: ~12 cycles
             ; EFFECT: After this, A6 = old A6, SP points to return address

0x0000636a:  rts
             ; OPERATION: Return from subroutine
             ; PC <- *(SP), SP <- SP + 4 [pop return address and jump]
             ; PURPOSE: Return to caller at next instruction after bsr.l
             ; TIMING: ~16 cycles
             ; RETURN VALUE: D0 = ROM function result (unchanged from call)
             ; NOTE: D0 is not modified after ROM call returns, so caller
             ;       receives exact value returned by ROM function

; ============================================================================
; EXECUTION FLOW DIAGRAM:
; ============================================================================
;
; Entry (from FUN_00006856)
;   │
;   ├─► LINK.W: Setup frame
;   │
;   ├─► MOVE.L A2,-(SP): Save A2
;   │
;   ├─► MOVEA.L arg1 into A2: Load output buffer pointer
;   │
;   ├─► MOVE.L arg3,-(SP): Push param3
;   ├─► MOVE.L arg2,-(SP): Push param2
;   │
;   ├─► BSR.L 0x050022e8: Call ROM function
;   │   │ [ROM function executes with params on stack]
;   │   │ [Returns with result in D0]
;   │   └─ Result in D0
;   │
;   ├─► MOVEQ -1, D1: Load error value
;   ├─► CMP.L D0, D1: Compare result with -1
;   │
;   ├─► BNE.B +0x08: If NOT error, branch forward
;   │   │
;   │   │ [Path 1: D0 == -1 (error)]
;   │   ├─► MOVE.L (0x040105b0), (A2): Copy hardware register
;   │   │
;   │   │ [Path 2: D0 != -1 (success)]
;   │   └─ (skip the move.l instruction)
;   │
;   ├─► MOVEA.L (-4,A6), A2: Restore A2
;   ├─► UNLK A6: Deallocate frame
;   ├─► RTS: Return to caller
;   │
;   └─ Exit (to FUN_00006856, D0 contains ROM result)

; ============================================================================
; REGISTER STATE CHANGES:
; ============================================================================
;
; ENTRY STATE:
;   A6 = (previous caller's A6)
;   A2 = (arbitrary, will be saved/restored)
;   D0 = (arbitrary, will be overwritten by ROM call)
;   SP = (points to return address)
;
; AFTER LINK.W:
;   A6 = old SP (frame pointer set)
;   SP = A6 (new stack pointer)
;
; AFTER MOVEA.L (0xc,A6), A2:
;   A2 = arg1 from caller (output buffer pointer)
;
; AFTER BSR.L ROM_FUNC:
;   D0 = return value from ROM function
;   A2 = (unchanged, still has output buffer pointer)
;   Other registers = (potentially modified by ROM function)
;
; AFTER CMP.L D0, D1:
;   Condition codes set (Z flag important for BNE.B)
;   D0, D1 unchanged
;
; CONDITIONAL: MOVE.L (0x040105b0), (A2):
;   Memory [(A2)] = *(0x040105b0) if taken
;   (No register changes)
;
; AFTER MOVEA.L (-4,A6), A2:
;   A2 = restored to original value
;
; AFTER UNLK A6:
;   A6 = restored to caller's A6
;   SP = restored to point to return address
;
; EXIT STATE (at RTS):
;   A6 = (caller's A6, restored)
;   A2 = (caller's A2, restored)
;   D0 = ROM function result (unchanged)
;   SP = (points to return address)

; ============================================================================
; STACK USAGE DIAGRAM:
; ============================================================================
;
; [Before LINK.W]
;   SP+4 ──► Return address (from FUN_00006856)
;   SP   ──► (undefined)
;
; [After LINK.W (frame=0)]
;   A6+4 ──► Return address
;   A6   ──► Old A6 (just saved by LINK.W)
;
; [After MOVE.L A2,-(SP)]
;   A6+4 ──► Return address
;   A6   ──► Old A6
;   SP   ──► Saved A2 (A6-4)
;
; [After MOVE.L arg3,-(SP) and MOVE.L arg2,-(SP)]
;   A6+4 ──► Return address
;   A6   ──► Old A6
;   A6-4 ──► Saved A2
;   A6-8 ──► arg3 copy
;   SP   ──► arg2 copy (A6-12)
;
; [Before BSR.L]
;   TOS ──► arg2 (will be arg in ROM function)
;   TOS+4 ──► arg3 (will be arg in ROM function)
;   ...
;
; [Inside ROM function]
;   (ROM function manages its own stack)
;   Returns with D0 = result
;
; [After BSR.L (implicit stack cleanup)]
;   Stack restored to state before BSR.L
;   arg2, arg3 copies removed from stack
;
; [After MOVEA.L (-4,A6), A2]
;   A2 restored (but still in memory at -4,A6)
;
; [After UNLK A6]
;   SP ──► Return address (ready for RTS)
;   A6 restored to caller's A6

; ============================================================================
; MEMORY ACCESS SUMMARY:
; ============================================================================
;
; READS:
;   A6+0x08: arg0 (unused)
;   A6+0x0c: arg1 (output buffer pointer) ──► loaded to A2
;   A6+0x10: arg2 (passed to ROM function)
;   A6+0x14: arg3 (passed to ROM function)
;   0x040105b0: hardware register (CONDITIONAL - only if D0 == -1)
;   -4,A6: saved A2 (for restoration)
;
; WRITES:
;   Stack: saved A2 (via move.l A2,-(SP))
;   Stack: arg3 copy (via move.l arg3,-(SP))
;   Stack: arg2 copy (via move.l arg2,-(SP))
;   A2 points to: *(0x040105b0) value (CONDITIONAL - only if D0 == -1)
;   Stack (implicit): return address modified by BSR.L and RTS

; ============================================================================
; ANALYSIS: WHY IS HARDWARE COPY CONDITIONAL ON ERROR?
; ============================================================================
;
; UNUSUAL PATTERN:
;   Most callback wrappers copy data on SUCCESS (D0 != -1)
;   This function copies on FAILURE (D0 == -1)
;
; POSSIBLE REASONS:
;
; 1. ERROR RECOVERY PATTERN
;    ┌─ ROM function performs hardware operation
;    ├─ On success: operation complete, no recovery needed
;    └─ On failure: copy current hardware state for diagnostics
;
; 2. FALLBACK STATUS
;    ┌─ ROM function indicates error via D0 = -1
;    ├─ Caller needs to know hardware state before failure
;    └─ Copy register as "last known good" state
;
; 3. DIAGNOSTIC INFORMATION
;    ┌─ Register 0x040105b0 contains error details
;    ├─ Only meaningful if operation fails
;    └─ Copy to output buffer for caller analysis
;
; 4. STATE PRESERVATION
;    ┌─ Protect hardware state from modification on error
;    ├─ Copy original state for caller recovery
;    └─ Allows caller to restore/retry operation
;
; IMPLICATION FOR CALLER:
;   - If result == -1: output buffer contains hardware state snapshot
;   - If result != -1: output buffer unchanged (caller must handle separately)

; ============================================================================
; COMPARISON WITH SIBLING FUNCTIONS:
; ============================================================================
;
; FUN_00006340 (THIS FUNCTION):
;   Address: 0x00006340
;   Size: 44 bytes
;   ROM Call: 0x050022e8
;   HW Reg: 0x040105b0
;   Pattern: Identical to FUN_0000636c, FUN_000063e8
;
; FUN_0000636c (SIBLING - 44 bytes):
;   Address: 0x0000636c
;   Size: 44 bytes
;   ROM Call: 0x0500284c (different)
;   HW Reg: 0x040105b0 (same)
;   Pattern: Identical structure, different ROM function
;
; FUN_00006398 (SIBLING - 40 bytes):
;   Address: 0x00006398
;   Size: 40 bytes
;   ROM Call: 0x0500324e (different)
;   HW Reg: 0x040105b0 (same)
;   Pattern: Similar, fewer parameters (1 param instead of 2)
;
; CONCLUSION: Templated callback wrapper library with:
;   - Standardized error handling
;   - Conditional hardware register copy
;   - Different ROM functions for different operations

; ============================================================================
; HARDWARE REGISTER ANALYSIS: 0x040105b0
; ============================================================================
;
; ADDRESS BREAKDOWN:
;   0x040105b0
;   ├─ 0x04: System data area (not I/O)
;   └─ 0x0105b0: Specific register offset
;
; CHARACTERISTICS:
;   - Read-only in this function (defensive read)
;   - Only accessed on error (error recovery)
;   - 32-bit value
;   - Conditional access (not always used)
;
; LIKELY PURPOSES:
;   1. System status register
;   2. Device configuration cache
;   3. Error status/code register
;   4. Hardware revision/capability word
;   5. Interrupt status flags
;   6. Memory controller state
;   7. NeXTdimension hardware state
;
; USAGE PATTERN:
;   - On ROM function failure (D0 == -1)
;   - Copy to caller's output buffer
;   - Allows caller to inspect hardware state
;   - No interpretation in this function

; ============================================================================
; ROM FUNCTION ANALYSIS: 0x050022e8
; ============================================================================
;
; ADDRESS CHARACTERISTICS:
;   0x050022e8
;   ├─ 0x05: ROM or special memory space
;   └─ 0x0022e8: Function offset
;   NOTE: Unusual address range (usually ROM in 0x01XXXXXX for m68k)
;         Suggests special ROM bank or memory-mapped device firmware
;
; CALLING CONVENTION:
;   Parameters: arg2, arg3 (passed on stack, right-to-left)
;   Return: D0 (32-bit value)
;
; RETURN VALUE SEMANTICS:
;   0xFFFFFFFF (-1): Error/failure condition
;   Other values: Success or status code
;
; SIDE EFFECTS:
;   - May modify hardware state
;   - May modify CPU state (other registers, memory)
;   - May affect system behavior
;   - Unknown details without disassembly
;
; PROBABLE FUNCTIONS:
;   1. Hardware initialization step
;   2. Device state verification
;   3. Configuration validation
;   4. Interrupt setup
;   5. Memory system initialization

; ============================================================================
; CALLER CONTEXT: FUN_00006856
; ============================================================================
;
; CALLER ADDRESS: 0x00006856
; CALLER SIZE: 204 bytes
; CALL SITE: 0x000068e0 (bsr.l 0x00006340)
;
; CALLING SEQUENCE:
;   [At 0x000068d0]
;   move.l     (0x430,A2),-(SP)      ; Push extra param (hardware register offset?)
;   pea        (0x2c,A2)             ; Push &source[0x2c]
;   pea        (0x1c,A2)             ; Push &source[0x1c]
;   move.l     (0xc,A2),-(SP)        ; Push &source[0x0c]
;   bsr.l      0x00006340            ; CALL THIS FUNCTION
;   move.l     D0,(0x24,A3)          ; Store result to output[0x24]
;
; PARAMETER MAPPING:
;   arg0 (A6+0x08) = source.pointer_0c
;   arg1 (A6+0x0c) = &source[0x1c]
;   arg2 (A6+0x10) = &source[0x2c]
;   arg3 (A6+0x14) = source[0x430]
;
; VALIDATION CONTEXT:
;   FUN_00006856 performs extensive validation before calling this function:
;   - Checks structure size field (0x434)
;   - Validates ID field (== 1)
;   - Compares memory addresses against system constants
;   - Verifies field values match expected patterns
;   - Only calls FUN_00006340 if all validations pass
;
; POST-CALL HANDLING:
;   - Result stored to output_struct[0x24]
;   - Clears output_struct[0x1c]
;   - Sets output_struct status fields

; ============================================================================
; DEFENSIVE PROGRAMMING ANALYSIS:
; ============================================================================
;
; PROTECTION MECHANISM 1: Register Preservation
;   - Save/restore A2 on stack (callee-save compliance)
;   - Prevent caller's state from being corrupted
;
; PROTECTION MECHANISM 2: Conditional Hardware Access
;   - Only copy hardware register on error
;   - Prevents exposing invalid/stale hardware state on success
;   - Defensive against hardware inconsistency
;
; PROTECTION MECHANISM 3: No Local Variables
;   - Use registers only, no stack locals
;   - Minimize stack pressure
;   - Simplify frame management
;
; PROTECTION MECHANISM 4: Zero-Sized Frame
;   - link.w A6,0x0 (no local allocation)
;   - Efficient frame setup
;   - Minimal stack overhead
;
; PROTECTION MECHANISM 5: Error-Driven Logic
;   - D0 == -1 signals error
;   - Standard M68k convention
;   - Clear error indication to caller

; ============================================================================
; PERFORMANCE NOTES:
; ============================================================================
;
; INSTRUCTION COUNT: 11 instructions
; CRITICAL PATH:
;   - BSR.L dominates (18 cycles + ROM function execution)
;   - Hardware register read (12 cycles, conditional)
;   - Setup/teardown minimal (44 cycles total frame operations)
;
; BOTTLENECK: External ROM function call
;   - Time to complete depends entirely on 0x050022e8 implementation
;   - Likely 100+ cycles (hardware operation)
;   - This wrapper adds minimal overhead (<10%)
;
; OPTIMIZATION OPPORTUNITIES:
;   1. Inline if ROM function is simple
;   2. Batch multiple operations if possible
;   3. Cache hardware register value if used frequently
;
; MEMORY BANDWIDTH:
;   - Parameter passing: 4 MOVE.L instructions
;   - Hardware read: 1 MOVE.L (conditional)
;   - Total: ~5 memory operations (excluding ROM function)

; ============================================================================
; END OF ANNOTATED DISASSEMBLY
; ============================================================================
