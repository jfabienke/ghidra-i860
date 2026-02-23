; ============================================================================
; Function: FUN_00006414
; Address: 0x00006414
; Size: 48 bytes (12 instructions)
; Type: Hardware access callback wrapper with error handling
; ============================================================================
;
; FUNCTION SIGNATURE (Reconstructed):
;   int hw_access_with_fallback(void* arg1,
;                              void** output_ptr,    // @ A6+0xC
;                              void* arg3,            // @ A6+0x14
;                              void* arg4);           // @ A6+0x18
;
; RETURN VALUE: D0 = Library status code (0=success, -1=error, other=various)
;
; HARDWARE RESOURCES USED:
;   - System port at 0x040105b0 (fallback on error)
;   - External library function at 0x05002234
;
; CALLING CONVENTION: Standard m68k ABI (NeXTSTEP variant)
;   - Arguments: Pushed right-to-left on stack (arg4, arg3, arg2)
;   - Return: D0 (32-bit integer/status)
;   - Preserved: A6, A2 (callee-saved)
;   - Stack: Cleaned up by function
;
; ============================================================================

; SECTION 1: PROLOGUE & FRAME SETUP
; ============================================================================
; Purpose: Establish stack frame and save callee-saved register

  0x00006414:  link.w     A6,0x0
              ; Operation: A6 ← SP; SP ← SP - 0
              ; Effect: Set up frame pointer, allocate 0 local variables
              ; Stack before: [return_addr] [arg1] [arg2_1] [arg2_2] [arg3] [arg4]
              ; Stack after:  [return_addr] [arg1] [arg2_1] [arg2_2] [arg3] [arg4]
              ;               ↑                                                 ↑
              ;               A6                                               SP

  0x00006418:  move.l     A2,-(SP)
              ; Operation: Push A2 onto stack (pre-decrement)
              ; Effect: Save callee-saved register
              ; Stack before: [return_addr] [arg1] [arg2_1] [arg2_2] [arg3] [arg4]
              ; Stack after:  [return_addr] [arg1] [arg2_1] [arg2_2] [arg3] [arg4] [saved_A2]
              ;               ↑
              ;               A6                                                  ↑
              ;                                                                   SP

; Stack Frame at this point (offsets from A6):
;   A6+00: Previous A6 (set by caller)
;   A6+04: Return address (set by BSR in caller)
;   A6+08: arg1 (hardware parameter)
;   A6+0C: arg2 (output_ptr - pointer to result)
;   A6+10: arg2 (duplicate? or aligned)
;   A6+14: arg3 (configuration parameter)
;   A6+18: arg4 (options/flags)
;   A6-04: Saved A2 (just pushed)

; ============================================================================
; SECTION 2: ARGUMENT LOADING
; ============================================================================
; Purpose: Extract arg2 from stack into A2 for later use
; Note: This is the output pointer where library result will be written

  0x0000641a:  movea.l    (0xc,A6),A2
              ; Operation: A2 ← *(A6 + 0xC) = *(A6 + 12)
              ; Meaning: A2 = arg2 (output_ptr parameter)
              ; Effect: Load pointer for later error handling
              ; Addressing: Register indirect with displacement
              ; Operand size: Long (32-bit pointer)

; Register state after this instruction:
;   A2 ← Pointer to result location (output variable)
;   Example: If arg2 was 0x80000100, A2 = 0x80000100
;   Usage: Will be written to on error (see 0x6436)

; ============================================================================
; SECTION 3: ARGUMENT SETUP FOR LIBRARY CALL
; ============================================================================
; Purpose: Push remaining arguments onto stack in proper order
; Note: Arguments passed right-to-left (arg4 first pushed, last popped)
; Stack grows downward (toward lower addresses)

  0x0000641e:  move.l     (0x18,A6),-(SP)
              ; Operation: Push *(A6 + 0x18) = arg4
              ; Effect: Argument 4 on stack for library call
              ; Addressing: Register indirect with displacement
              ; Stack effect: SP ← SP - 4, then write to [SP]
              ; Stack after: [... A6 ...] [arg4]
              ;                            ↑
              ;                            SP

  0x00006422:  move.l     (0x14,A6),-(SP)
              ; Operation: Push *(A6 + 0x14) = arg3
              ; Effect: Argument 3 on stack for library call
              ; Addressing: Register indirect with displacement
              ; Stack effect: SP ← SP - 4, then write to [SP]
              ; Stack after: [... A6 ...] [arg4] [arg3]
              ;                                    ↑
              ;                                    SP

  0x00006426:  move.l     (0x10,A6),-(SP)
              ; Operation: Push *(A6 + 0x10) = arg2
              ; Effect: Argument 2 on stack for library call
              ; Note: arg2 is pushed even though already in A2
              ; Addressing: Register indirect with displacement
              ; Stack effect: SP ← SP - 4, then write to [SP]
              ; Stack after: [... A6 ...] [arg4] [arg3] [arg2]
              ;                                          ↑
              ;                                          SP

; Stack frame after all pushes (for library call):
;   SP+00: arg2 (rightmost argument, will be popped last)
;   SP+04: arg3
;   SP+08: arg4
;   SP+0C: Saved A2 (from prologue)
;   A6+00-A6+18: Original caller's frame + arguments

; ============================================================================
; SECTION 4: EXTERNAL LIBRARY CALL
; ============================================================================
; Purpose: Call system library function for hardware access
; Library: libsys_s.B.shlib @ 0x05000000 offset
; Function: Unknown routine @ offset 0x2234

  0x0000642a:  bsr.l      0x05002234
              ; Instruction: Branch to Subroutine, Long addressing
              ; Operation:
              ;   1. Push current PC (next instruction at 0x6430) onto stack
              ;   2. Jump to absolute address 0x05002234
              ; Effect: Transfer execution to library function
              ; Stack before call: [arg2] [arg3] [arg4] [saved_A2]
              ; Stack after call:  [arg2] [arg3] [arg4] [saved_A2] [return_addr_0x6430]
              ;
              ; LIBRARY FUNCTION BEHAVIOR (Inferred):
              ;   Input:  Stack args: arg2, arg3, arg4
              ;           Implicit arg1 (unknown how passed)
              ;   Output: D0 = Result code (0=success, -1=error, other=status)
              ;           *arg2 = May be modified with hardware result
              ;           Stack cleanup: Called function removes its args
              ;
              ; Return execution: Resumes at 0x00006430
              ; Return value location: D0 register
              ; Register state: A2 preserved (callee-saved), D0 has result

; Estimated library function behavior:
;   if (hardware_operation(arg1, arg2, arg3, arg4) == SUCCESS) {
;       *arg2 = hardware_resource;
;       return 0;  // or specific success code
;   } else {
;       // *arg2 unchanged or set to error state
;       return -1;  // or error code
;   }

; ============================================================================
; SECTION 5: ERROR STATUS CHECK
; ============================================================================
; Purpose: Determine if library call succeeded or failed
; Success: Any return code except -1
; Error: Return code == -1

  0x00006430:  moveq      -0x1,D1
              ; Instruction: Move quick, unsigned
              ; Operation: D1 ← -1 (sign-extended from 8-bit immediate)
              ; Effect: Load error sentinel value
              ; Operand: Immediate -1 (0xFF in 8-bit, 0xFFFFFFFF in 32-bit)
              ; Advantages: Very short instruction (2 bytes vs. 6 for MOVE.L #-1,D1)
              ; Purpose: Prepare comparison value

  0x00006432:  cmp.l      D0,D1
              ; Instruction: Compare Long
              ; Operation: Subtract D0 from D1, set condition codes
              ;            (does NOT store result, only affects flags)
              ; Comparison: D1 - D0 = (-1) - library_result
              ; Effect: Set flags for conditional branch
              ; Condition codes after:
              ;   Z flag: Set if D0 == -1 (comparison result is 0)
              ;   Z flag: Clear if D0 != -1 (comparison result is non-zero)
              ; Used by: Next instruction (BNE)

; Condition code states:
;   If D0 == -1: Z=1 (zero flag set) → comparison result is zero
;   If D0 == 0:  Z=0 (zero flag clear) → comparison result is non-zero
;   If D0 > 0:   Z=0 (zero flag clear) → comparison result is non-zero
;   If D0 < 0:   Z=0 (zero flag clear) → comparison result is non-zero (unless ==−1)

  0x00006434:  bne.b      0x0000643c
              ; Instruction: Branch if Not Equal, short addressing
              ; Condition: Z=0 (i.e., comparison result was non-zero)
              ; Logic: If (D1 - D0) != 0, branch
              ;        i.e., If D0 != -1, branch
              ; Target address: 0x643c (epilogue/cleanup)
              ; Offset from next instruction: 0x643c - 0x6436 = 6 bytes
              ; Branch distance: Relative, 8-bit signed offset
              ;
              ; EXECUTION PATHS:
              ; Path A (Success: D0 != -1):
              ;   - Condition is TRUE (NE = not equal)
              ;   - Branch taken → Jump to 0x643c (skip error handling)
              ;   - A2 still contains output_ptr (unchanged)
              ;   - Output was already set by library at line 0x0000642a
              ;
              ; Path B (Error: D0 == -1):
              ;   - Condition is FALSE (comparison was equal)
              ;   - No branch → Fall through to 0x6436
              ;   - Execute error handling code

; ============================================================================
; SECTION 6: ERROR RECOVERY (FALLBACK PATH)
; ============================================================================
; Purpose: On library error, write system default value to output
; Note: This section ONLY executes if D0 == -1
; Not executed if D0 has any other value (success or different error)

  0x00006436:  move.l     (0x040105b0).l,(A2)
              ; Instruction: Move Long
              ; Source: (0x040105b0).l = Absolute long address
              ; Destination: (A2) = Address register indirect
              ;
              ; Operation:
              ;   1. Load 32-bit value from absolute address 0x040105b0
              ;   2. Store into memory location pointed to by A2
              ;
              ; Equivalent C code:
              ;   *output_ptr = *(void**)0x040105b0;
              ;   // Where output_ptr was passed as arg2, now in A2
              ;
              ; Address 0x040105b0: System-wide constant or port
              ;   - Likely contains TASK_SELF or SYSTEM_PORT
              ;   - Used as fallback when hardware allocation fails
              ;   - Accessed by 12+ similar wrapper functions
              ;   - Located in system DATA segment
              ;   - Persistence: Initialized at boot, never modified by app code
              ;
              ; Effect: On library error, output pointer receives system default
              ; Example:
              ;   if (library_failed) {
              ;       *output_ptr = *(mach_port_t*)SYSTEM_PORT_ADDRESS;
              ;       return -1;  // Error still reported
              ;   }

; Addressing mode details:
;   (0x040105b0).l = Absolute long address (fixed 32-bit address)
;   (A2) = Address register indirect (use A2 as pointer)
;   Size: 32-bit (long word)

; This instruction is the only error recovery mechanism in this function.
; It provides graceful degradation by using system default when allocation fails.

; ============================================================================
; SECTION 7: EPILOGUE & CLEANUP
; ============================================================================
; Purpose: Restore function state and return to caller
; Note: Execution reaches here from both success and error paths

  0x0000643c:  movea.l    (-0x4,A6),A2
              ; Instruction: Move Address Long
              ; Operation: A2 ← *(A6 - 4)
              ; Effect: Restore A2 from stack (where we saved it at 0x6418)
              ; Stack offset: -4 relative to A6
              ; Addressing: Register indirect with displacement
              ; Purpose: Restore callee-saved register (required by ABI)

; Frame state at 0x643c:
;   A6-04: Points to saved A2 value (pushed at entry)
;   A6: Frame pointer (about to be destroyed)
;   A6+04: Return address to caller
;   SP: Points to return address (stack not yet cleaned)
;   D0: Library return value (untouched since 0x642a)

  0x00006440:  unlk       A6
              ; Instruction: Unlink (destroy frame)
              ; Operation:
              ;   1. SP ← A6 (restore stack pointer)
              ;   2. A6 ← *(A6) (restore frame pointer from stack)
              ; Effect: Remove entire frame, restore caller's context
              ;
              ; Before unlk:
              ;   A6 points to old frame
              ;   A6[0] contains caller's A6
              ;   SP somewhere below A6
              ;
              ; After unlk:
              ;   SP points to return address (next instruction)
              ;   A6 = previous value
              ;   Ready for RTS
              ;
              ; This single instruction handles:
              ;   - Stack pointer restoration
              ;   - Frame pointer restoration
              ;   - Caller's old A6 recovery

  0x00006442:  rts
              ; Instruction: Return from Subroutine
              ; Operation:
              ;   1. Pop return address from stack: PC ← *(SP)
              ;   2. SP ← SP + 4
              ;   3. Jump to return address (resume in caller)
              ;
              ; Effect: Transfer execution back to caller at instruction after BSR
              ; Return value: D0 (library result, unmodified)
              ;
              ; At this point:
              ;   D0 = Original library return code (-1 on error, 0+ on success)
              ;   A2 = Caller's original A2 (restored)
              ;   A6 = Caller's original A6 (restored)
              ;   SP = Caller's stack level (after removing return address)
              ;
              ; Caller sees:
              ;   Function returned successfully
              ;   D0 contains status code
              ;   *output_ptr contains either:
              ;     - Hardware result (from library) if successful
              ;     - System default (from 0x040105b0) if error

; ============================================================================
; FUNCTION SUMMARY & CONTROL FLOW
; ============================================================================
;
; ENTRY: Caller has pushed arguments onto stack and executed BSR
;        Arguments: arg1, arg2 (output_ptr), arg3, arg4
;        Stack contains return address
;
; SETUP: Frame pointer established, A2 loaded with output_ptr
;
; EXECUTION:
;   1. Push arguments (arg2, arg3, arg4) for library call
;   2. Call external library function @ 0x05002234
;   3. Library executes hardware operation, returns status in D0
;   4. Check: Did library return -1 (error)?
;      - If NO (success): Skip error handling, go to epilogue
;      - If YES (error): Write fallback value to *output_ptr, then epilogue
;   5. Restore state and return to caller
;
; EXIT: D0 contains library return code (unchanged)
;       *output_ptr contains either library result or fallback value
;       Caller's registers restored
;
; ============================================================================
; EQUIVALENT C PSEUDOCODE
; ============================================================================
;
; int hardware_access_wrapper(void* arg1,
;                            void** output_ptr,
;                            void* arg3,
;                            void* arg4)
; {
;     // Local variable: A2 will hold output_ptr
;
;     // Call library function
;     int result = lib_hardware_access_0x05002234(arg1, arg2, arg3, arg4);
;
;     // Error handling: Check if result is -1 (error code)
;     if (result == -1) {
;         // On error, provide system default
;         *output_ptr = *(void**)0x040105b0;  // System port/default
;     }
;     // Note: If result != -1, output_ptr was already set by library
;
;     // Return library's status code (unchanged)
;     return result;
; }
;
; ============================================================================
; DESIGN PATTERN: FAIL-SAFE WITH FALLBACK
; ============================================================================
;
; This function implements a "graceful degradation" pattern:
;
;   - Primary path: Use library's allocation/resource
;   - Error handling: Fall back to system default
;   - Error reporting: Still return error code to caller
;   - Result: System continues with default resource instead of failing
;
; Benefits:
;   ✓ Robustness: Doesn't crash on allocation failure
;   ✓ Debugging: Returns actual error code for logging
;   ✓ Fallback: System can continue with reduced functionality
;   ✓ Compatibility: Matches expected interface
;
; ============================================================================
; PERFORMANCE CHARACTERISTICS
; ============================================================================
;
; Instruction Count: 12 instructions, 48 bytes
;
; Cycle Estimates (Motorola 68040):
;   link.w A6,0x0         : 2 cycles
;   move.l A2,-(SP)       : 1 cycle (register move)
;   movea.l (0xc,A6),A2   : 3 cycles (frame access)
;   move.l (0x18,A6),-(SP): 5 cycles (memory to stack)
;   move.l (0x14,A6),-(SP): 5 cycles (memory to stack)
;   move.l (0x10,A6),-(SP): 5 cycles (memory to stack)
;   bsr.l 0x05002234      : 4 cycles (branch save)
;   [Library execution]   : 50-1000+ cycles (DOMINATES)
;   moveq -0x1,D1         : 1 cycle (quick immediate)
;   cmp.l D0,D1           : 1 cycle (register compare)
;   bne.b 0x643c          : 1-3 cycles (branch cost varies)
;   move.l (0x040105b0),(A2): 6 cycles (memory load + store)
;   movea.l (-0x4,A6),A2  : 3 cycles (frame access)
;   unlk A6               : 2 cycles (frame destroy)
;   rts                   : 4 cycles (return)
;
; Total (wrapper only): ~45-50 cycles
; Total (with library): 50-1050+ cycles (library dominates)
;
; Bottleneck: External library call at 0x05002234
; Optimization: Minimal wrapper overhead, unavoidable for this architecture
;
; ============================================================================
; REGISTER USAGE SUMMARY
; ============================================================================
;
; Entry State:
;   D0: Undefined
;   D1: Undefined
;   A2: Undefined
;   A6: Caller's frame pointer (set by caller)
;   SP: Caller's stack pointer
;
; Modified During Execution:
;   D0: Loaded from library (preserves library return value)
;   D1: Loaded with -1 (for comparison)
;   SP: Modified by pushes and pops
;   A2: Loaded with arg2 (output_ptr) at 0x641a
;
; Exit State:
;   D0: Library return value (0/-1/other) - NOT MODIFIED
;   D1: -1 (not cleaned up, but caller shouldn't use)
;   A2: Restored to entry value (callee-saved)
;   A6: Restored to caller's value
;   SP: Restored to caller's level
;
; Calling Convention Compliance: ✓ FULL
;   - Preserves callee-saved registers (A2)
;   - Returns via standard RTS
;   - Cleans up stack properly (UNLK)
;   - Passes return value in D0
;
; ============================================================================
; CROSS-REFERENCES & RELATED CODE
; ============================================================================
;
; Called by: FUN_00006c48 (hardware validator)
;            Address 0x00006ce2: bsr.l 0x00006414
;            Context: Hardware initialization sequence
;
; Calls: libsys_s.B.shlib @ 0x05002234
;        Unknown routine (likely Mach port allocation or resource config)
;
; Similar wrappers with identical pattern:
;   FUN_00006384 → bsr.l 0x05002228
;   FUN_000063e8 → bsr.l 0x0500222e
;   FUN_00006444 → bsr.l 0x050028ac
;   ... and 8+ more with same structure
;
; Fallback source: 0x040105b0 (system port/resource)
;   Accessed by 12+ functions
;   Read-only constant
;   Purpose: Default resource when allocation fails
;
; ============================================================================
; ANALYSIS METADATA
; ============================================================================
;
; Analysis Date: November 9, 2025
; Tool: Ghidra 11.2.1
; Binary: NDserver (Mach-O m68k)
; Classification: Hardware access callback wrapper
; Complexity: Simple (1 library call + 1 conditional error check)
; Hardware Interaction: Yes (system port fallback)
; Confidence: HIGH (architecture), MEDIUM (purposes)
;
; ============================================================================
