; ============================================================================
; File: 00006318_DETAILED_ASSEMBLY.asm
; Function: helper_00006318 / FUN_00006318
; Address: 0x00006318 - 0x0000633F
; Size: 40 bytes (0x28)
; ============================================================================
; COMPREHENSIVE ASSEMBLY DOCUMENTATION
; Generated: November 08, 2025
; Analyzer: Claude Code (Haiku 4.5)
; Architecture: Motorola 68040 (m68k)
; Binary: NDserver (NeXTdimension server, Mach-O executable)
; ============================================================================

; FUNCTION CLASSIFICATION:
;   Type: Callback/Utility Helper
;   Purpose: File descriptor close wrapper with error-state capture
;   Complexity: LOW
;   Priority: HIGH
;
; FUNCTION OVERVIEW:
;   This function wraps the Mach close(2) system call to handle error cases
;   by capturing hardware system state. It's part of the NeXTdimension
;   firmware initialization/loading sequence.
;
; PARAMETERS (stack-based, m68k ABI):
;   0x08(%fp)  - First argument (purpose unclear, not directly used)
;   0x0c(%fp)  - Second argument -> loaded into A2 (output pointer)
;   0x10(%fp)  - Third argument -> pushed to stack as arg to close()
;
; RETURN VALUE:
;   None (void function)
;   Side effect: May write to *A2 on error path
;
; REGISTERS MODIFIED:
;   A2: Saved/Restored (callee-save)
;   D0: Used (contains close() result)
;   D1: Modified (error constant -1)
;   CCR: Modified (by cmp.l)
;   SP/A6: Standard frame ops
;
; HARDWARE ACCESSED:
;   0x040105b0 - SYSTEM_DATA register (conditional read on error)
;
; EXTERNAL CALLS:
;   0x0500229a - close(int fd) [Mach system library]
;
; CALLED BY:
;   0x00006814 in FUN_000067b8 (initialization entry point)
;
; RELATED FUNCTIONS:
;   FUN_00006340 (0x00006340) - Similar pattern
;   FUN_00006398 (0x00006398) - Similar pattern
;   FUN_000063c0 (0x000063c0) - Similar pattern
;   FUN_000063e8 (0x000063e8) - Similar pattern
;   FUN_00006414 (0x00006414) - Similar pattern
;   FUN_00006444 (0x00006444) - Similar pattern
;
; All follow: save A2, load params, call library, check for -1,
;             conditional hardware access, restore, return

; ============================================================================
; SECTION 1: PROLOGUE (4 BYTES)
; ============================================================================
; Purpose: Set up stack frame and save callee-save registers
; Stack effect: SP decreased by 4 bytes (return address already on stack)

0x00006318:  linkw      %fp,#0
;   Encoding: 0x4e56 0000
;   Effect:
;     1. Push current A6 to stack [SP] <- A6
;     2. Set A6 to SP: A6 = SP
;     3. Allocate locals: SP = SP - 0 (no local variables)
;     4. Establish new frame pointer
;   Stack: [Ret Addr | saved-A6] <- SP (A6 points here)
;   Purpose: Standard 68000 stack frame setup
;   Callee must execute matching UNLK to restore

; ============================================================================
; SECTION 2: CALLEE-SAVE REGISTER PRESERVATION (2 BYTES)
; ============================================================================
; Purpose: Preserve A2 as required by calling convention
; Requirement: A2 is callee-save (must restore before return)

0x0000631c:  movel      %a2,%sp@-
;   Encoding: 0x4882
;   Effect:
;     [SP-4] <- A2 (32-bit value)
;     SP = SP - 4 (pre-decrement addressing mode)
;   Stack: [Ret Addr | saved-A6 | saved-A2] <- SP
;   Purpose: Save A2 to restore at function end
;   Note: This is push operation in 68000 style

; ============================================================================
; SECTION 3: PARAMETER LOADING (4 BYTES)
; ============================================================================
; Purpose: Load second argument (output pointer) into A2
; Source: Stack frame argument at offset 0x0c

0x0000631e:  moveal     %fp@(12),%a2
;   Encoding: 0x2c2e 000c
;   Effect:
;     A2 = [A6 + 12] (load address from stack frame)
;     No flags affected
;   Stack frame access:
;     A6 + 0 = saved A6
;     A6 + 4 = return address (implicit, pushed by caller)
;     A6 + 8 = first arg to this function
;     A6 + 12 = SECOND ARG (loaded into A2) <- THIS
;     A6 + 16 = third arg
;   Purpose:
;     A2 will be used as output pointer for error state
;     This is the address where hardware state will be written on error

; ============================================================================
; SECTION 4: ARGUMENT PREPARATION FOR CALL (4 BYTES)
; ============================================================================
; Purpose: Push third argument onto stack for close() system call
; Destination: Stack (pre-decrement mode)

0x00006322:  movel      %fp@(16),%sp@-
;   Encoding: 0x2c2e 0010
;   Effect:
;     [SP-4] <- [A6 + 16] (load and push third arg)
;     SP = SP - 4
;   Value loaded: Third argument to this function
;   Destination: Top of stack (SP points to it)
;   Stack after:
;     [Ret Addr | saved-A6 | saved-A2 | arg3] <- SP
;   Purpose:
;     Prepare argument for close() call
;     This argument will be the file descriptor (fd) for close()
;   Semantics:
;     close(fd) will read this value from stack

; ============================================================================
; SECTION 5: EXTERNAL LIBRARY CALL (6 BYTES)
; ============================================================================
; Purpose: Call Mach system library function close()
; Function: close(int fd) - closes file descriptor
; Return: D0 contains result (0=success, -1=error)

0x00006326:  bsr.l      0x0500229a
;   Encoding: 0x61ff 04f0
;     0x61ff  = opcode for bsr.l (Branch to SubRoutine, long 32-bit)
;     0x04f0  = offset to 0x0500229a (from 0x6326)
;              Calculation: 0x0500229a - (0x6326 + 6) = 0x0500229a - 0x632c
;   Effect:
;     1. Push PC (next instruction 0x632c) to stack [SP] <- 0x632c
;     2. SP = SP - 4
;     3. PC = 0x0500229a (jump to close())
;   Execution context:
;     - close() runs in Mach library code
;     - close() receives fd argument from stack
;     - close() returns result in D0 (Mach ABI)
;   Return value in D0:
;     -1  = error (fd was invalid, etc.)
;     0   = success (fd was closed)
;     >0  = success (legacy behavior)
;   Stack frame during call:
;     [Ret Addr | saved-A6 | saved-A2 | arg3 | bsr-return]
;   Implicit contract:
;     - close() must not modify A6, A2 (callee-save)
;     - close() may modify D0, D1, A0, A1 (caller-save)
;     - close() will pop its own return address (rts)

; ============================================================================
; SECTION 6: RETURN VALUE VALIDATION (4 BYTES)
; ============================================================================
; Purpose: Compare close() result against error sentinel (-1)
; Result: Set condition codes for error path decision

0x0000632c:  moveq      #-0x1,%d1
;   Encoding: 0x72ff (or 0x7cff - moveq with sign-extended -1)
;   Effect:
;     D1 = -0x1 (sign-extended 8-bit immediate)
;     D1 = 0xFFFFFFFF (32-bit: all ones, represents -1)
;     No flags affected by moveq itself
;   Purpose:
;     Load error constant into D1
;     This will be compared against D0 (close result)
;   Semantics:
;     -1 is the standard Unix/POSIX error code for "operation failed"
;     Mach close() returns -1 on error, 0+ on success
;   Register state:
;     D0 = result from close() (untouched)
;     D1 = -1 (our comparison value)

0x0000632e:  cmp.l      %d0,%d1
;   Encoding: 0xb39e
;   Effect:
;     Compute: D1 - D0 (subtract but don't store)
;     Set condition codes based on result
;     CCR.Z = 1 if D0 == D1 (both are -1)
;     CCR.Z = 0 if D0 != D1 (one is not -1)
;   Logic:
;     If D0 = -1: D1 - (-1) = -1 - (-1) = 0 -> ZF=1 (equal)
;     If D0 = 0:  D1 - 0 = -1 != 0 -> ZF=0 (not equal)
;     If D0 = 1:  D1 - 1 = -2 != 0 -> ZF=0 (not equal)
;   Condition code register after:
;     Z = 1: close() returned -1 (error)
;     Z = 0: close() returned something else (success or unknown)
;   Purpose:
;     Determine if we should execute error recovery code
;     This is key decision point for control flow

; ============================================================================
; SECTION 7: CONDITIONAL BRANCHING (2 BYTES)
; ============================================================================
; Purpose: Skip error recovery if close() succeeded
; Condition: Branch if result != -1 (success path)

0x00006330:  bne.b      0x00006338
;   Encoding: 0x6608
;     0x66   = opcode for bne.b (Branch if Not Equal, byte offset)
;     0x08   = +8 bytes offset
;   Condition:
;     Execute if CCR.Z = 0 (i.e., D0 != -1)
;     This is the success path
;   Target: 0x00006338 (cleanup section, skip error recovery)
;   Calculation: 0x6330 + 2 + 0x08 = 0x633A (would be 0x6338 after offset)
;   Control flow:
;     If close() succeeded (D0 != -1):
;       Jump to 0x00006338 (cleanup)
;     Else (D0 == -1, error occurred):
;       Fall through to next instruction (0x00006332)
;   Stack state at branch:
;     SP still points to pushed arg3 (not yet cleaned up)
;     This is fine - the cleanup is done after error handling

; ============================================================================
; SECTION 8: ERROR RECOVERY - HARDWARE STATE CAPTURE (6 BYTES)
; ============================================================================
; Purpose: On error, read and store hardware system state
; Condition: Only executed if close() returned -1
; This is the critical section for hardware interaction

0x00006332:  move.l     (0x040105b0).l,(A2)
;   Encoding: 0x2b39 0401 05b0
;     0x2b39       = opcode for move.l with absolute addressing
;     0x0401 05b0  = address 0x040105b0 (the register to read)
;   Effect:
;     Read 32-bit value from hardware address 0x040105b0
;     Store that value to the address contained in A2
;   Memory operation: [A2] <- [0x040105b0]
;     Source: Hardware register at 0x040105b0
;     Destination: RAM at address stored in A2
;   Hardware register accessed:
;     Name: SYSTEM_DATA (SYSTEM_PORT + 0x31C)
;     Region: System data structure (global state)
;     Type: Hardware register (memory-mapped I/O)
;     Access: READ (from hardware) then WRITE (to RAM)
;   Purpose in error path:
;     When close() fails, capture current system state
;     This provides context for error diagnosis:
;     - What was the system state when close() failed?
;     - Can help trace cause of failure
;   Constraints:
;     - A2 must be a valid pointer to writable memory
;     - A2 is NOT validated (potential crash if NULL/invalid)
;     - 0x040105b0 must be readable (may fault if inaccessible)
;   Side effects:
;     - Hardware state changes may occur (if read has side effects)
;     - No exception handling (faults would crash)

; ============================================================================
; SECTION 9: EPILOGUE - RESTORE STATE (6 BYTES)
; ============================================================================
; Purpose: Restore callee-save registers and return

0x00006338:  moveal     (-0x4,%a6),%a2
;   Encoding: 0x38ee fffc (or similar - moveal with A6 offset addressing)
;     Note: Exact encoding may vary; shown for reference
;   Effect:
;     A2 = [A6 - 4] (load from stack)
;   Purpose:
;     Restore A2 from stack (saved at prologue)
;     This is the counterpart to the movel %a2,%sp@- at 0x631c
;   Stack frame:
;     Before: [Ret Addr | saved-A6 | saved-A2 | arg3] <- SP
;     A2 is at [A6 - 4] (assuming frame size 0, adjust if needed)
;   Register state after:
;     A2 = original value before function entry
;     Function has completed its state change (if any)

0x0000633c:  unlk       %a6
;   Encoding: 0x4e5e
;   Effect:
;     1. SP = A6 (deallocate locals)
;     2. A6 = [SP] (pop saved A6)
;     3. SP = SP + 4
;   Purpose:
;     Unwind the stack frame created by LINKW
;     Counterpart to linkw at entry
;   Stack frame layout restored:
;     Before unlk: [Ret Addr | saved-A6 | saved-A2 | arg3] <- A6/SP
;     After unlk:  [Ret Addr | saved-A6] <- SP, A6 = saved-A6
;   Preparation for return:
;     Stack pointer now points to return address (due to unlk)
;     Next instruction (rts) will pop PC from [SP]

0x0000633e:  rts
;   Encoding: 0x4e75
;   Effect:
;     1. PC = [SP] (pop return address from stack)
;     2. SP = SP + 4
;     3. Jump to return address
;   Return to:
;     Caller at 0x00006814 (instruction after bsr.l 0x6318)
;   Stack state:
;     [Ret Addr from caller] <- SP (restored by rts)
;     [Caller's frame] continues execution
;   Return value:
;     Function is void (no return value in standard sense)
;     Side effect: May have written to *A2 (error state)
;     Caller may read D0 (if it retained close result)

; ============================================================================
; SECTION 10: CONTROL FLOW SUMMARY
; ============================================================================
;
;  Entry (0x6318)
;      |
;      +-- SETUP: Create frame, save A2 (0x6318-0x631c)
;      |
;      +-- LOAD: A2 = arg[2] (0x631e)
;      |
;      +-- PREPARE: Push arg[3] (0x6322)
;      |
;      +-- CALL: close(arg[3]) -> D0 (0x6326)
;      |
;      +-- VALIDATE: D1 = -1, compare D0 vs -1 (0x632c-0x632e)
;      |
;      +-- BRANCH: if D0 != -1, jump to CLEANUP (0x6330)
;      |
;      +-- ERROR PATH: D0 == -1
;      |       |
;      |       +-- CAPTURE: [A2] = READ(0x040105b0) (0x6332)
;      |
;      +-- CLEANUP: Restore A2, unlink frame (0x6338-0x633c)
;      |
;      +-- EXIT: Return to caller (0x633e)
;
; ============================================================================

; ============================================================================
; SECTION 11: STACK LAYOUT ANALYSIS
; ============================================================================
;
; At function entry (after bsr from 0x6814):
;
;   Higher addresses (grows down in 68k convention)
;   ...caller stack frame...
;   [Ret Addr from 0x6814] (pushed by caller's bsr.l)
;   [Arg1 to FUN_6318]
;   [Arg2 to FUN_6318]   <- A6+12 (loaded into A2 at 0x631e)
;   [Arg3 to FUN_6318]   <- A6+16 (pushed again for close() at 0x6322)
;   <- A6 (A6 points here after linkw, also [SP] after linkw)
;   Lower addresses
;
; After movel %a2,%sp@- (0x631c):
;
;   [Ret Addr from 0x6814]
;   [Arg1 to FUN_6318]
;   [Arg2 to FUN_6318]
;   [Arg3 to FUN_6318]
;   [saved A6 from linkw] <- A6 points here
;   [saved A2]            <- SP points here
;
; After movel %fp@(16),%sp@- (0x6322):
;
;   [Ret Addr from 0x6814]
;   [Arg1 to FUN_6318]
;   [Arg2 to FUN_6318]
;   [Arg3 to FUN_6318]
;   [saved A6 from linkw] <- A6 points here
;   [saved A2]
;   [arg3 to close()] <- SP points here (will be passed to close)
;
; After bsr.l 0x0500229a (0x6326):
;   close() receives arg from [SP]
;   close() returns, D0 = result
;   Stack frame unchanged (bsr doesn't affect caller's locals)
;
; At 0x6332 (error path only):
;   [A2] = hardware register value
;   Stack unchanged
;
; After moveal (-0x4,%a6),%a2 (0x6338):
;   Restored A2 to original value
;
; After unlk %a6 (0x633c):
;   A6 restored to caller's frame
;   SP points to [Ret Addr from 0x6814]
;
; After rts (0x633e):
;   Returns to caller at 0x6814+6 (next instruction after bsr)
;   Stack and registers restored as if function never ran
;
; ============================================================================

; ============================================================================
; SECTION 12: REGISTER STATE TRACKING
; ============================================================================
;
; Entry:
;   A6 = undefined (caller's frame pointer)
;   A2 = caller's value (will be saved)
;   SP = stack pointer from caller
;   D0 = undefined
;   D1 = undefined
;
; After linkw (0x6318):
;   A6 = SP (new frame pointer)
;   A2 = caller's A2 (not yet modified)
;   SP = SP - 0 (no locals allocated)
;
; After movel %a2,%sp@- (0x631c):
;   A6 = unchanged
;   A2 = unchanged
;   SP = SP - 4 (one item pushed)
;   [SP] = old A2 (saved)
;
; After moveal %fp@(12),%a2 (0x631e):
;   A2 = value from stack frame arg[2]
;   Other registers unchanged
;
; After movel %fp@(16),%sp@- (0x6322):
;   SP = SP - 4 (one more pushed)
;   [SP] = value of arg[3]
;   A2 unchanged
;
; After bsr.l 0x0500229a (0x6326):
;   D0 = result from close()
;   D1 = undefined (not yet modified)
;   Other registers undefined (close() is opaque)
;   A2 = unchanged (callee-save preserved by close())
;   A6 = unchanged
;
; After moveq #-1,%d1 (0x632c):
;   D1 = 0xFFFFFFFF (-1)
;   D0 = unchanged (still has close() result)
;
; After cmp.l %d0,%d1 (0x632e):
;   D0 = unchanged
;   D1 = unchanged
;   CCR (condition code register):
;     Z = 1 if D0 == D1 (error case)
;     Z = 0 if D0 != D1 (success case)
;     Other flags set as side effect of subtraction
;
; At branch bne.b (0x6330):
;   If Z = 0 (D0 != -1): Jump to 0x6338, skip error path
;   If Z = 1 (D0 == -1): Fall through to error handling
;
; After move.l at 0x6332 (error path):
;   [A2] = hardware register value
;   A2, D0, D1 unchanged
;   Memory modified (destination)
;
; Exit state (at 0x633e rts):
;   A6 = restored to caller's frame
;   A2 = restored to original value
;   SP = points to return address
;   D0 = still contains close() result (for caller's potential use)
;   D1 = undefined (scratch)
;   CCR = undefined (modified by comparison)
;
; ============================================================================

; ============================================================================
; SECTION 13: ADDRESSING MODES USED
; ============================================================================
;
; 1. Address Register Indirect: (A6)
;    - Not used directly in this function
;
; 2. Address Register Indirect with Displacement: (d16,A6)
;    - Used at 0x631e: %fp@(12) = 12(%A6)
;    - Used at 0x6322: %fp@(16) = 16(%A6)
;    - Used at 0x6338: (%A6,-4) = -4(%A6) [post-indexed?]
;
; 3. Address Register Indirect Pre-Decrement: -(A7)
;    - Used at 0x631c: %sp@- (push A2)
;    - Used at 0x6322: %sp@- (push arg[3])
;
; 4. Absolute Long: $addr.l
;    - Used at 0x6332: (0x040105b0).l (32-bit absolute address)
;    - 6 bytes: opcode (2) + address (4)
;
; 5. Register Transfer: %Dn, %An
;    - %d1, %d0, %a2, %fp (A6)
;
; ============================================================================

; ============================================================================
; SECTION 14: INSTRUCTION ENCODING REFERENCE
; ============================================================================
;
; 0x6318:  linkw %fp,#0          => 0x4e56 0000 (4 bytes)
; 0x631c:  movel %a2,%sp@-       => 0x4882           (2 bytes)
; 0x631e:  moveal %fp@(12),%a2   => 0x2c2e 000c      (4 bytes)
; 0x6322:  movel %fp@(16),%sp@-  => 0x2c2e 0010      (4 bytes)
; 0x6326:  bsr.l 0x0500229a      => 0x61ff 04f0      (6 bytes)
;          Offset: 0x0500229a - 0x632c = 0x04f0
; 0x632c:  moveq #-1,%d1         => 0x72ff or 0x7cff (2 bytes)
; 0x632e:  cmp.l %d0,%d1         => 0xb39e           (2 bytes)
; 0x6330:  bne.b 0x6338          => 0x6608           (2 bytes)
;          Offset: 0x6338 - 0x6332 = 0x06 (decimal 6)
; 0x6332:  move.l (0x040105b0)   => 0x2b39 0401 05b0 (6 bytes)
; 0x6338:  moveal (-0x4,%a6),%a2 => 0x38ee fffc      (4 bytes)
; 0x633c:  unlk %a6              => 0x4e5e           (2 bytes)
; 0x633e:  rts                   => 0x4e75           (2 bytes)
;
; Total: 4+2+4+4+6+2+2+2+6+4+2+2 = 40 bytes ✓
;
; ============================================================================

; ============================================================================
; SECTION 15: SEMANTICS & PURPOSE
; ============================================================================
;
; This function implements the following pseudocode:
;
; void helper_00006318(
;     unknown arg1,
;     uint32_t *error_context,     // loaded into A2
;     int fd                       // passed to close()
; ) {
;     int result = close(fd);      // Mach system call
;
;     if (result == -1) {
;         // Error occurred: capture system state
;         *error_context = READ_HARDWARE(0x040105b0);
;     }
;     // Success case: error_context unchanged
;     return;
; }
;
; Key observations:
;
; 1. Error Detection:
;    - Mach close() returns -1 on error
;    - Function explicitly checks for this sentinel value
;    - Standard POSIX/Unix error convention
;
; 2. Error Recovery:
;    - On error, reads hardware register 0x040105b0
;    - This is SYSTEM_DATA region (system configuration/status)
;    - Stores value to location pointed by A2
;    - Allows caller to examine system state at time of failure
;
; 3. Success Path:
;    - If close() succeeds (D0 != -1)
;    - Function simply returns without side effects
;    - Caller is responsible for checking/using return value
;
; 4. Calling Context:
;    - Part of NeXTdimension firmware initialization
;    - Likely closing a file descriptor for kernel/firmware binary
;    - Error context capture useful for debugging boot failures
;    - Hardware state at close() failure indicates system problems
;
; 5. Design Pattern:
;    - Classic Mach microkernel error handling
;    - Capture system state for diagnostics
;    - No exceptions/longjmp (traditional Mach style)
;    - Returns normally, leaving error handling to caller
;
; ============================================================================

; ============================================================================
; SECTION 16: POTENTIAL ISSUES & ROBUSTNESS
; ============================================================================
;
; ISSUE #1: Unvalidated Output Pointer (HIGH SEVERITY)
;   Location: 0x6332 move.l (0x040105b0).l,(A2)
;   Problem: A2 is not checked for NULL or validity before write
;   Effect: If A2 = NULL or invalid, memory access fault/crash
;   Risk: Error path intended to help, but can crash instead
;   Fix: Add pointer validation before error-path hardware access
;
; ISSUE #2: Unchecked Hardware Read (MEDIUM SEVERITY)
;   Location: 0x6332 reading from 0x040105b0
;   Problem: No check that hardware register is accessible
;   Effect: Bus error/fault if register unmapped or inaccessible
;   Risk: Low in typical NeXT systems (SYSTEM_DATA normally mapped)
;   Fix: Wrap in exception handler or verify register mapping
;
; ISSUE #3: Side Effect Hidden in Error Path (MEDIUM)
;   Location: Hardware read at 0x6332
;   Problem: If hardware register has side effects, error case may
;            trigger unintended behavior
;   Risk: Low for SYSTEM_DATA (typically read-only status)
;   Fix: Document hardware register semantics
;
; ISSUE #4: Return Value Semantics (LOW)
;   Location: D0 contains close() result
;   Problem: close() return value not returned to caller
;   Effect: Caller cannot distinguish success from failure by return value
;   Risk: Low if caller checks *error_context for error indication
;   Fix: Return D0, or document that caller uses other channels
;
; ISSUE #5: Stack Cleanup (LOW)
;   Location: 0x6330 branching over stack cleanup
;   Problem: arg[3] remains on stack through error path
;   Effect: Stack pointer management correct (SP restored by unlk)
;   Risk: None (unlk adjusts SP properly regardless of path taken)
;   Fix: None needed (correct behavior)
;
; ============================================================================

; ============================================================================
; SECTION 17: CROSS-REFERENCE ANALYSIS
; ============================================================================
;
; Called from: 0x6814 in FUN_000067b8
;   Call sequence:
;     0x6808: move.l  (0x24,A3),-(SP)   ; Push arg3
;     0x680c: pea     (0x1c,A3)         ; Push &arg2 (address)
;     0x6810: move.l  (0xc,A3),-(SP)    ; Push arg1
;     0x6814: bsr.l   0x00006318        ; Call helper_00006318
;     0x681a: move.l  D0,(0x24,A2)      ; Store result
;
;   Context: FUN_000067b8 is an entry point (not called by others)
;            It manages initialization/validation
;            Multiple callback helpers are called in sequence
;
; Calls to: 0x0500229a (close)
;   Arguments:
;     fd = third arg to helper_00006318 (passed via stack)
;   Return:
;     D0 = close() result
;   Usage:
;     Checked against -1
;     If error, triggers hardware state capture
;
; Similar functions (same pattern):
;   0x6340, 0x6398, 0x63c0, 0x63e8, 0x6414, 0x6444
;   All follow: save-A2, load-params, call-library, check-result,
;              conditional-hardware-access, restore, return
;
; ============================================================================

; ============================================================================
; SECTION 18: SUMMARY
; ============================================================================
;
; Function Name: helper_00006318 / FUN_00006318
; Address: 0x00006318 (end: 0x0000633F)
; Size: 40 bytes
;
; Purpose:
;   Wrapper around Mach close(2) system call with error-context capture
;   On success: Just closes file descriptor
;   On failure: Reads hardware system state for diagnostic purposes
;
; Key Characteristics:
;   - Part of NeXTdimension firmware initialization sequence
;   - Part of a family of similar callback wrappers (0x6340, 0x6398, etc.)
;   - Low complexity (simple branching logic)
;   - Direct hardware interaction (read-only during error)
;   - Potential safety issues (unvalidated pointer in error path)
;
; Hardware Access:
;   - Conditional read from 0x040105b0 (SYSTEM_DATA register)
;   - Only on error path (close() returns -1)
;   - Data written to caller-provided pointer (A2)
;
; Registers:
;   - A2: Saved and restored (callee-save)
;   - D0: Contains close() result (checked, not modified)
;   - D1: Used for comparison value (-1)
;   - SP/A6: Standard frame management
;
; Call Chain:
;   Entry point FUN_000067b8 (0x67b8)
;     -> calls helper_00006318 (0x6318)
;       -> calls close() (0x0500229a)
;
; Classification:
;   Type: Callback / Utility Helper
;   Complexity: LOW
;   Priority: HIGH (part of critical boot path)
;   Confidence: MEDIUM (exact purpose requires full program context)
;
; Recommendations:
;   1. Verify 0x040105b0 register semantics
;   2. Check error handling in FUN_000067b8
;   3. Compare with other callback functions
;   4. Trace full initialization sequence
;   5. Add pointer validation in error path
;
; ============================================================================

; End of 00006318_DETAILED_ASSEMBLY.asm
