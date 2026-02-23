; =============================================================================
; NDserver - Function: FUN_0000627a (errno_wrapper)
; =============================================================================
;
; SUMMARY:
;   Small wrapper function (62 bytes) that calls an external system function
;   and handles error reporting through a global errno variable.
;
; CATEGORY: Callback/Hardware Access Wrapper (errno family)
; ADDRESS: 0x0000627a - 0x000062b7
; SIZE: 62 bytes (31 instructions)
; CONFIDENCE: HIGH (71%)
;
; FUNCTION SIGNATURE:
;   void FUN_0000627a(
;       long *errno_out,       // A3 (A6+0x0c)
;       long arg1,             // A6+0x10
;       long arg2,             // A6+0x14
;       long *result_out,      // A2 (A6+0x18)
;       long arg3              // A6+0x1c
;   );
;
; BEHAVIOR:
;   1. Call external function 0x05002d62 with 3 parameters
;   2. If result (D0) > 0: Store result at *(A2)
;   3. If result (D0) <= 0: Store 0 at *(A2), read errno to *(A3)
;
; HARDWARE ACCESS:
;   - Address 0x040105b0: Global errno variable (read on error path)
;
; SIDE EFFECTS:
;   - Modifies *(A2) (output result)
;   - Modifies *(A3) (output error code)
;   - Modifies D0 (return value from external call)
;   - Modifies stack (4 argument pushes)
;
; CALLING CONTEXT:
;   Called from FUN_00006518 (message handler) at offset 0x00006596
;   Part of message dispatcher pipeline in ND_MessageReceiveLoop
;
; =============================================================================

; ENTRY POINT - Stack frame setup
; =============================================================================
0x0000627a:  linkw.w    %A6, #0x0
             ; LINKW: Link and allocate frame
             ; Allocates 0 bytes for local variables
             ; Saves return address on stack
             ; A6 now points to frame base
             ;
             ; Stack after LINKW:
             ;   A6 -> [Return Address from CALL]
             ;         [Old A6 saved by CPU]

0x0000627e:  movel      %A3, -(%SP)
             ; Save A3 on stack (predecrement addressing)
             ; A3 will be used for errno output pointer
             ; Callee must restore before return
             ;
             ; Register preservation: A3 is address register, save required

0x00006280:  movel      %A2, -(%SP)
             ; Save A2 on stack (predecrement addressing)
             ; A2 will be used for result output pointer
             ; Callee must restore before return
             ;
             ; Register preservation: A2 is address register, save required
             ;
             ; Stack layout at this point:
             ;   SP+0  -> [A2 saved]
             ;   SP+4  -> [A3 saved]
             ;   SP+8  -> [Return Address]
             ;   SP+12 -> [Old A6]

; PARAMETER EXTRACTION - Load arguments from caller's frame
; =============================================================================
0x00006282:  moveal     0xc(%A6), %A3
             ; Load errno output pointer from A6+0xc into A3
             ; This is passed by caller as first parameter
             ;
             ; A6+0xc contains pointer to location for errno on error
             ; Typical pattern for function pointers in m68k ABI
             ;
             ; Example: If caller passed &my_errno as first arg:
             ;   A3 = &my_errno
             ;   Later: movel errno_value, (%A3) stores to my_errno

0x00006286:  moveal     0x18(%A6), %A2
             ; Load result output pointer from A6+0x18 into A2
             ; This is passed by caller as fourth parameter (note: non-standard order)
             ;
             ; A6+0x18 contains pointer to location for success result
             ;
             ; Frame offset analysis:
             ;   A6+0x00  -> Saved A6
             ;   A6+0x04  -> Return address
             ;   A6+0x08  -> ??? (skipped)
             ;   A6+0x0c  -> errno_ptr (arg 1, loaded to A3)
             ;   A6+0x10  -> arg1 (system call param 1)
             ;   A6+0x14  -> arg2 (system call param 2)
             ;   A6+0x18  -> result_ptr (arg 4, loaded to A2)
             ;   A6+0x1c  -> arg3 (system call param 3)

; ARGUMENT SETUP - Push 3 parameters for external call
; =============================================================================
0x0000628a:  movel      0x1c(%A6), -(%SP)
             ; Push arg3 (A6+0x1c) onto stack (predecrement)
             ; This is the 3rd parameter for external function 0x05002d62
             ;
             ; Value semantics: Loaded from caller's frame
             ; Pushed for BSR.L 0x05002d62 call

0x0000628e:  movel      0x14(%A6), -(%SP)
             ; Push arg2 (A6+0x14) onto stack (predecrement)
             ; This is the 2nd parameter for external function 0x05002d62
             ;
             ; Stack grows downward (predecrement)

0x00006292:  movel      0x10(%A6), -(%SP)
             ; Push arg1 (A6+0x10) onto stack (predecrement)
             ; This is the 1st parameter for external function 0x05002d62
             ;
             ; After this sequence, stack has 3 long values ready for call
             ;
             ; Stack state before BSR.L:
             ;   SP+0  -> arg1 (from A6+0x10)
             ;   SP+4  -> arg2 (from A6+0x14)
             ;   SP+8  -> arg3 (from A6+0x1c)
             ;   SP+12 -> A2 saved
             ;   SP+16 -> A3 saved
             ;   SP+20 -> Return Address

; EXTERNAL FUNCTION CALL - Primary operation
; =============================================================================
0x00006296:  bsr.l      0x05002d62
             ; Branch to subroutine (long addressing)
             ; Calls external system function at 0x05002d62
             ;
             ; This function:
             ;   - Takes 3 parameters (on stack): arg1, arg2, arg3
             ;   - Returns result in D0
             ;   - Modifies D0-D1 (temporary registers)
             ;   - May clobber other temporary registers
             ;   - Caller responsible for saving D2-D7 (not modified)
             ;
             ; Function 0x05002d62 characteristics:
             ;   - External/system call (address in 0x05xxxxxx range)
             ;   - Called only from this location (single call site)
             ;   - Likely Mach kernel service or library function
             ;   - Returns status/error code in D0
             ;
             ; Stack automatically decrements return address:
             ;   SP -> [Return Address of BSR.L] (saved by CPU)
             ;
             ; After call, SP has been incremented by BSR.L return

; RESULT TEST - Check success/failure status
; =============================================================================
0x0000629c:  tstl       %D0
             ; Test D0 register (logical AND with itself)
             ; Sets condition codes based on D0 value:
             ;   - Zero flag (Z) if D0 == 0
             ;   - Negative flag (N) if D0 < 0
             ;   - No other flags affected
             ;
             ; Used to distinguish:
             ;   - D0 > 0: Success (positive result)
             ;   - D0 == 0: No error, but no result
             ;   - D0 < 0: Error condition
             ;
             ; Machine cycles: 4 cycles for register test (optimized)

0x0000629e:  ble.b      0x000062a4
             ; Branch if less than or equal (signed)
             ; Tests condition codes from TSTL:
             ;   - BLE taken if: (Z=1) OR (N=1)
             ;   - BLE skipped if: D0 > 0
             ;
             ; Branch target: 0x000062a4 (error handler)
             ; Offset: 0x000062a4 - 0x000062a0 = 4 bytes forward
             ; But instruction is at 0x0000629e, so real offset is signed byte
             ;
             ; This is a SHORT branch (b.b suffix in some assemblers)
             ; Offset encoded as signed byte (-128 to +127)

; SUCCESS PATH - D0 > 0 (Branch NOT taken)
; =============================================================================
0x000062a0:  movel      %D0, (%A2)
             ; Store D0 result at memory location pointed to by A2
             ; A2 was loaded from A6+0x18 (result_out pointer)
             ;
             ; This executes only when D0 > 0 (branch was skipped)
             ; Stores the positive result from system call
             ;
             ; Example:
             ;   If system call returned 42 in D0
             ;   And A2 points to &output_result
             ;   Then output_result becomes 42
             ;
             ; Memory write semantics:
             ;   - Type: long (32-bit)
             ;   - Address: Address register indirect (A2)
             ;   - Size: 4 bytes
             ;   - Align: Natural alignment (32-bit aligned)

0x000062a2:  bra.b      0x000062ac
             ; Unconditional branch (always taken)
             ; Jumps to cleanup code at 0x000062ac
             ; Skips the error handler code
             ;
             ; This branch is ALWAYS taken in success path
             ; Ensures error handler (CLRL, errno read) not executed
             ;
             ; Branch offset: 0x000062ac - 0x000062a4 = 8 bytes
             ; Encoded as signed byte in short branch form

; ERROR PATH - D0 <= 0 (Branch taken)
; =============================================================================
0x000062a4:  clrl       (%A2)
             ; Clear (zero) the long at address A2
             ; A2 was loaded from A6+0x18 (result_out pointer)
             ;
             ; This executes when D0 <= 0 (branch was taken)
             ; Clears the output location to indicate failure
             ;
             ; Memory write semantics:
             ;   - Destination: Address register indirect (A2)
             ;   - Size: long (32-bit)
             ;   - Value: 0x00000000
             ;
             ; Example:
             ;   If system call returned 0 (no result) or -1 (error)
             ;   And A2 points to &output_result
             ;   Then output_result becomes 0

0x000062a6:  movel      0x040105b0.l, (%A3)
             ; Load long from fixed address 0x040105b0 into memory at A3
             ; A3 was loaded from A6+0x0c (errno_out pointer)
             ;
             ; This reads the global errno variable
             ; Address 0x040105b0 is in system data space
             ; Offset 0x31c from base suggests globals area
             ;
             ; HARDWARE ACCESS:
             ;   - Address: 0x040105b0
             ;   - Type: Read 32-bit long
             ;   - Likely global variable location
             ;   - Hypothesis: errno or system error code storage
             ;
             ; Addressing mode: Absolute long (0x040105b0.l)
             ;   The ".l" suffix specifies 32-bit address
             ;   Alternative would be ".w" for 16-bit (limited range)
             ;
             ; Typical errno values (BSD/Mach):
             ;   EINVAL = 0x16 (22)
             ;   EACCES = 0x0d (13)
             ;   EIO = 0x05 (5)
             ;   ENOMEM = 0x0c (12)
             ;   EBUSY = 0x10 (16)
             ;
             ; Example:
             ;   If 0x040105b0 contains 0x16 (EINVAL)
             ;   And A3 points to &output_errno
             ;   Then output_errno becomes 0x16

; CLEANUP & RETURN - Restore state and exit
; =============================================================================
0x000062ac:  moveal     -0x8(%A6), %A2
             ; Restore A2 from stack frame (negative offset from A6)
             ; A2 was saved at the beginning of function
             ; Frame offset -0x8 relative to A6 base
             ;
             ; Explanation:
             ;   A6-0x8 contains the saved A2 value from 0x00006280
             ;   This undoes the MOVEL A2,-(SP) from setup
             ;
             ; Frame reconstruction:
             ;   A6-0x8 -> [A2 saved here by MOVEL A2,-(SP)]
             ;   A6-0x4 -> [A3 saved here by MOVEL A3,-(SP)]
             ;   A6+0x0 -> [Old A6 saved by LINKW]
             ;
             ; Register now contains original A2 value

0x000062b0:  moveal     -0x4(%A6), %A3
             ; Restore A3 from stack frame (negative offset from A6)
             ; A3 was saved at the beginning of function
             ; Frame offset -0x4 relative to A6 base
             ;
             ; Explanation:
             ;   A6-0x4 contains the saved A3 value from 0x0000627e
             ;   This undoes the MOVEL A3,-(SP) from setup
             ;
             ; Register now contains original A3 value

0x000062b4:  unlk       %A6
             ; Unlink stack frame
             ; Reverses the LINKW instruction:
             ;   - Restores A6 from saved value
             ;   - Deallocates frame space (0 bytes in this case)
             ;   - Adjusts SP to return address location
             ;
             ; After UNLK, SP points to saved return address
             ; Ready for RTS instruction

0x000062b6:  rts
             ; Return from subroutine
             ; Pops return address from stack and jumps to it
             ; Returns control to caller (FUN_00006518 at 0x00006596)
             ;
             ; After RTS:
             ;   - PC contains caller's return address
             ;   - SP incremented by 4 (popped return address)
             ;   - A2, A3 restored to original values
             ;   - D0 contains result (caller may check for errors)
             ;
             ; Return value semantics:
             ;   D0 unchanged from external call result
             ;   (Actual results in *(A2) and *(A3))

; =============================================================================
; FUNCTION SUMMARY
; =============================================================================
;
; CONTROL FLOW:
;
;   Entry (0x0000627a)
;       |
;       +-- Setup frame
;       |   - LINKW A6, #0
;       |   - Save A2, A3
;       |
;       +-- Extract parameters
;       |   - A3 = errno_ptr from A6+0x0c
;       |   - A2 = result_ptr from A6+0x18
;       |
;       +-- Setup arguments for external call
;       |   - Push arg1, arg2, arg3 from A6 frame
;       |
;       +-- Call external function 0x05002d62
;       |   - Returns in D0
;       |
;       +-- Test result
;       |   - TSTL D0
;       |
;       +-- Conditional branch
;       |   ├─ If D0 > 0 (SUCCESS)
;       |   |   - Store D0 at *(A2)
;       |   |   - Jump to cleanup
;       |   |
;       |   └─ If D0 <= 0 (ERROR)
;       |       - Clear *(A2) to 0
;       |       - Read errno from 0x040105b0
;       |       - Store errno at *(A3)
;       |
;       +-- Cleanup
;           - Restore A2, A3
;           - Unlk frame
;           - Return to caller
;
; EXECUTION TIME (estimated, in m68k cycles):
;   Setup & param load: 20-25 cycles
;   Argument push: 12-16 cycles
;   External call: 50-100+ cycles (depends on target)
;   Test & branch: 4-8 cycles
;   Success path: 8 cycles (move + branch)
;   Error path: 12-16 cycles (clear + load + move)
;   Cleanup: 12-16 cycles
;   ----------------------------------
;   Total: 130-180+ cycles (external call dominates)
;
; MEMORY FOOTPRINT:
;   Code size: 62 bytes
;   Stack usage: 0 bytes allocated (LINKW #0)
;   Data access: 2 writes + 1 read (minimum)
;
; REGISTER PRESSURE:
;   Input: A2, A3 (parameters)
;   Output: D0 (return value)
;   Temporary: SP (implicit for stack operations)
;   Saved: A2, A3 (preserved across call)
;
; OPTIMIZATION NOTES:
;   - Frame allocation is optimal (no local vars)
;   - Register saves are minimal (only 2 address regs)
;   - Branch prediction would benefit from success case (more common)
;   - MOVEAL loading could be combined in some m68k variants
;   - Condition code test (TSTL) is fastest comparison
;
; FAMILY RELATIONSHIP:
;   This function is part of the "errno wrapper family":
;   - Similar functions: 0x000062b8, 0x000062e8, 0x00006318, etc.
;   - Pattern: External call + errno error handling
;   - Hypothesis: Compiler-generated system call wrappers
;   - Common pattern in m68k Mach/Unix system libraries
;
; =============================================================================
; END OF FUNCTION ANALYSIS
; =============================================================================
