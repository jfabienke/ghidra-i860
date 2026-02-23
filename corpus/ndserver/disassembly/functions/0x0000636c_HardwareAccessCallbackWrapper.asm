; ====================================================================================
; FUNCTION: FUN_0000636c - Hardware Access Callback Wrapper
; ====================================================================================
; Address: 0x0000636c (25452 decimal)
; Size: 44 bytes (0x2C)
; Type: System Wrapper / Hardware Access Handler
; ====================================================================================
;
; DESCRIPTION:
; This is a lightweight callback wrapper that performs hardware access operations
; with error handling. It wraps calls to system function at 0x0500284c and conditionally
; fetches cached system data from 0x040105b0 on error return (-1).
;
; CALLING CONVENTION: Motorola 68k System V ABI
; PARAMETERS:
;   (0x10,A6) - param1 (uint32_t) - First parameter to hardware function
;   (0x14,A6) - param2 (uint32_t) - Second parameter to hardware function
;   (0xC,A6)  - result_ptr (uint32_t*) - Output pointer for results
;
; RETURN VALUE:
;   D0 - Result from external function (0x0500284c)
;
; REGISTERS PRESERVED: A2 (saved/restored on stack)
; REGISTERS DESTROYED: D0, D1 (working registers)
;
; HARDWARE ACCESSED:
;   0x040105B0 - SYSTEM_DATA (SYSTEM_PORT + 0x31c) - Read on error path
;
; CALLED BY: FUN_00006922 at address 0x000069c6
; CALLS: 0x0500284c (external hardware access function)
;
; ====================================================================================

.section .text
.align 2

.globl FUN_0000636c
FUN_0000636c:

    ; ========== SECTION 1: PROLOGUE ==========
    ; Create minimal stack frame for parameter access

    0x0000636c:  link.w     A6, #0x0
    ;           Create frame with 0-byte local variable space
    ;           Stack layout after LINK:
    ;             [return_addr] ← SP before LINK
    ;             [old_A6]      ← A6 (becomes new frame base)


    ; ========== SECTION 2: REGISTER PRESERVATION ==========
    ; Save A2 register (used as output pointer holder)

    0x00006370:  move.l     A2, -(SP)
    ;           Push A2 to preserve it
    ;           Stack: [saved_A2 | old_A6 | return_addr]


    ; ========== SECTION 3: LOAD OUTPUT POINTER ==========
    ; Load third parameter (result_ptr) from stack into A2
    ; Parameter at offset 0xC from A6 in stack frame

    0x00006372:  movea.l    (0xc,A6), A2
    ;           A2 ← (A6+0xC)
    ;           Load output pointer address into A2
    ;           This pointer will be used later to store results


    ; ========== SECTION 4: PUSH SECOND PARAMETER ==========
    ; Push param2 (at offset 0x14 from A6) to stack
    ; Parameters are pushed in reverse order (right-to-left)

    0x00006376:  move.l     (0x14,A6), -(SP)
    ;           Push param2 to stack (predecrement SP)
    ;           Stack: [param2 | saved_A2 | old_A6 | return_addr]


    ; ========== SECTION 5: PUSH FIRST PARAMETER ==========
    ; Push param1 (at offset 0x10 from A6) to stack

    0x0000637a:  move.l     (0x10,A6), -(SP)
    ;           Push param1 to stack (predecrement SP)
    ;           Stack: [param1 | param2 | saved_A2 | old_A6 | return_addr]
    ;           This is the state when entering the called function


    ; ========== SECTION 6: CALL EXTERNAL HARDWARE FUNCTION ==========
    ; Long branch with subroutine call to system hardware access function
    ; This function performs the actual hardware operation

    0x0000637e:  bsr.l      0x0500284c
    ;           BSR.L = Branch to Subroutine, Long addressing
    ;           PC ← 0x0500284c
    ;           Stack: [return_to_caller (pushed by BSR)]
    ;           D0 ← Result from 0x0500284c function
    ;           Function processes param1 and param2, returns result in D0


    ; ========== SECTION 7: LOAD COMPARISON VALUE ==========
    ; Load -1 (0xFFFFFFFF) into D1 for comparison
    ; This is used to check if the hardware function returned an error

    0x00006384:  moveq      #-0x1, D1
    ;           D1 ← 0xFFFFFFFF (as a signed -1)
    ;           MOVEQ loads immediate -1 into D1 (quick form, 2 bytes)
    ;           This represents an error return value from 0x0500284c


    ; ========== SECTION 8: COMPARE RETURN VALUE ==========
    ; Compare D0 (result) with D1 (-1)
    ; Sets condition codes: Z flag = 1 if equal

    0x00006386:  cmp.l      D0, D1
    ;           CMP.L D0, D1 performs: D0 - D1 (sets CCR)
    ;           If D0 == -1: Z flag = 1 (equal)
    ;           If D0 != -1: Z flag = 0 (not equal)


    ; ========== SECTION 9: CONDITIONAL BRANCH (SUCCESS PATH) ==========
    ; Branch if NOT EQUAL (D0 != -1)
    ; If D0 is -1, fall through to fetch cached data
    ; If D0 is not -1, skip the data fetch and jump to epilogue

    0x00006388:  bne.b      0x00006390
    ;           BNE = Branch if Not Equal (Z flag = 0)
    ;           Short branch (8-bit displacement) forward to 0x00006390
    ;           This skips the conditional data read instruction
    ;
    ;           EXECUTION PATHS:
    ;           SUCCESS PATH (D0 != -1):
    ;             Jump directly to epilogue at 0x00006390
    ;             Result remains in D0 (unmodified)
    ;
    ;           ERROR PATH (D0 == -1):
    ;             Fall through to next instruction (0x0000638a)
    ;             Read cached value from system data area


    ; ========== SECTION 10: CONDITIONAL HARDWARE REGISTER READ ==========
    ; This instruction executes ONLY if D0 == -1 (error condition)
    ; Read cached/system value from SYSTEM_DATA at 0x040105B0
    ; Store result to location pointed to by A2 (output pointer)

    0x0000638a:  move.l     (0x040105b0).l, (A2)
    ;           MOVE.L (addr.l), (A2)
    ;           Load 32-bit long word from absolute address 0x040105b0
    ;           Store to address pointed to by A2 (output buffer)
    ;
    ;           Hardware Memory Details:
    ;           - Source: 0x040105B0 (SYSTEM_PORT + 0x31c)
    ;           - Destination: *A2 (caller-provided output pointer)
    ;           - Access Type: 32-bit (long word)
    ;           - Region: SYSTEM_DATA (persistent system information)
    ;
    ;           This acts as a fallback mechanism:
    ;           - If hardware function fails (returns -1)
    ;           - Read previously cached/default value
    ;           - Store to caller's output location
    ;           - Result value remains -1 (indicating error)


    ; ========== SECTION 11: EPILOGUE - RESTORE OUTPUT POINTER ==========
    ; Restore A2 register from stack frame
    ; A2 was saved during prologue and must be restored per ABI

    0x00006390:  movea.l    (-0x4,A6), A2
    ;           A2 ← (A6-0x4)
    ;           This reads A2 from its saved location on stack
    ;           The value at A6-4 contains the saved A2 register
    ;           (saved during prologue via MOVE.L A2, -(SP))


    ; ========== SECTION 12: EPILOGUE - UNLINK FRAME ==========
    ; Deallocate stack frame and restore frame pointer

    0x00006394:  unlk       A6
    ;           UNLK A6 = Unlink Frame
    ;           A6 ← (A6)          (restore old frame pointer)
    ;           SP ← A6 + 4        (deallocate frame)
    ;           Result: Stack pointer restored to point at return address


    ; ========== SECTION 13: RETURN TO CALLER ==========
    ; Return from subroutine to caller

    0x00006396:  rts
    ;           RTS = Return from Subroutine
    ;           PC ← (SP)+                  (pop return address)
    ;           SP ← SP + 4                 (clean stack)
    ;           D0 still contains result (either original or -1 on error path)

; ====================================================================================
; FUNCTION END
; ====================================================================================


; ====================================================================================
; CONTROL FLOW DIAGRAM
; ====================================================================================
;
; ENTRY: 0x0000636c
;   ↓
; [LINK.W A6, #0]
;   ↓
; [MOVE.L A2, -(SP)]                           ← Save A2
;   ↓
; [MOVEA.L (0xC,A6), A2]                       ← Load output_ptr
;   ↓
; [MOVE.L (0x14,A6), -(SP)]                    ← Push param2
;   ↓
; [MOVE.L (0x10,A6), -(SP)]                    ← Push param1
;   ↓
; [BSR.L 0x0500284c]                           ← Call external function
;   ↓                                          D0 = result
; [MOVEQ #-1, D1]                              ← Load comparison value
;   ↓
; [CMP.L D0, D1]                               ← Compare D0 with -1
;   ↓
; [BNE.B 0x00006390] ← D0 != -1?
;   ↓                    ↓
;   │                 YES: Skip to epilogue
;   │                    (Success path)
;   │
;   NO: Fall through (D0 == -1)
;   │                    (Error path)
;   ↓
; [MOVE.L (0x040105B0).l, (A2)]                ← Read system data to output
;   ↓
; [MOVEA.L (-0x4,A6), A2]                      ← Restore A2
;   ↓
; [UNLK A6]
;   ↓
; [RTS]
;   ↓
; EXIT: Return to FUN_00006922


; ====================================================================================
; PARAMETER MAPPING
; ====================================================================================
;
; Stack Frame Layout (Motorola 68k System V):
;
;   Old SP →  [return_addr]        ← Point BSR.L jumped here
;   A6-0x0 =  [old_A6]             ← Link data from LINK.W
;   A6-0x4 =  [saved_A2]           ← Preserved A2 register
;   A6-0x8 =  (no local variables)
;
;   Stack parameters (offsets from A6):
;   A6+0x8 =  [return_address]     ← Set by BSR.L caller
;   A6+0x10 = [param1]             ← First parameter (uint32_t)
;   A6+0x14 = [param2]             ← Second parameter (uint32_t)
;   A6+0xC =  [result_ptr]         ← Output pointer (uint32_t*)
;
; ABI Notes:
;   - CDECL/System V: Parameters on stack (pushed right-to-left)
;   - Return value in D0
;   - A2 must be preserved (saved/restored)
;   - D0-D1 are working registers (not preserved)


; ====================================================================================
; HARDWARE MEMORY MAP
; ====================================================================================
;
; Address: 0x040105B0
; Region:  SYSTEM_DATA (SYSTEM_PORT + 0x31c)
; Type:    System-level data structure
; Access:  Read (conditional, only when D0 == -1)
; Size:    32-bit (1 long word)
; Purpose: Cached system configuration value for fallback
;
; Notes:
;   - Accessed as absolute long addressing (0x040105b0).l
;   - Used only on error path (when hardware function returns -1)
;   - Value is stored to caller-provided buffer via output pointer (A2)
;   - No modification of source (read-only access)


; ====================================================================================
; CALL INFORMATION
; ====================================================================================
;
; Calls External Function:
;   Address: 0x0500284C
;   Name: (Unknown - likely system ROM or library service)
;   Parameters: 2 (uint32_t param1, uint32_t param2)
;   Return: D0 (int32_t result)
;   Type: Long branch call (BSR.L)
;   Use Count: 1 (called once per invocation of this function)
;   Purpose: Perform actual hardware access operation
;
; Called From:
;   Function: FUN_00006922
;   Address: 0x00006922
;   Call Site: 0x000069c6
;   Branch Type: BSR.L
;   Context: Unknown (part of initialization or handler sequence)


; ====================================================================================
; INSTRUCTION SUMMARY
; ====================================================================================
;
; Total Instructions: 14
; Total Bytes: 44 (0x2C)
;
; Instruction Breakdown:
;   LINK.W        1 instruction,  2 bytes  (frame setup)
;   MOVE.L        5 instructions, 16 bytes (parameter handling, register save)
;   MOVEA.L       2 instructions, 8 bytes  (pointer loading)
;   BSR.L         1 instruction,  6 bytes  (external call)
;   MOVEQ         1 instruction,  2 bytes  (constant load)
;   CMP.L         1 instruction,  4 bytes  (comparison)
;   BNE.B         1 instruction,  2 bytes  (conditional branch)
;   UNLK          1 instruction,  2 bytes  (frame deallocation)
;   RTS           1 instruction,  2 bytes  (return)
;
; Code Density: 0.31 bytes/instruction (44 / 14 = 3.14 avg)


; ====================================================================================
; PERFORMANCE ANALYSIS (68040 Reference Timing)
; ====================================================================================
;
; Successful Path (D0 ≠ -1):  ~20-25 cycles
;   - Stack frame setup: 2-3 cycles (LINK)
;   - Register save: 2-3 cycles (MOVE.L A2)
;   - Parameter preparation: 4-5 cycles (3x MOVE.L)
;   - External call: 4-6 cycles (BSR.L to 0x0500284c)
;   - Comparison: 2-3 cycles (MOVEQ, CMP.L)
;   - Branch taken: 2-3 cycles (BNE.B)
;   - Register restore: 2-3 cycles (MOVEA.L, UNLK, RTS)
;   Total: Skips conditional MOVE.L to memory
;
; Error Path (D0 = -1):  ~30-35 cycles
;   - Same as above, PLUS:
;   - System memory read: 5-10 cycles (MOVE.L with absolute long addressing)
;   - Output store: 3-5 cycles (nested addressing [A2])
;   Total: Additional 8-15 cycles for memory access


; ====================================================================================
; RELATED FUNCTIONS (Similar Wrappers in Address Proximity)
; ====================================================================================
;
; FUN_0000636c: Address 0x0000636c, Size 44 bytes  ← Current function
; FUN_00006398: Address 0x00006398, Size 40 bytes
; FUN_000063c0: Address 0x000063c0, Size 40 bytes
; FUN_000063e8: Address 0x000063e8, Size 44 bytes
; FUN_00006414: Address 0x00006414, Size 48 bytes
; FUN_00006444: Address 0x00006444, Size 48 bytes
; FUN_00006474: Address 0x00006474, Size 164 bytes
;
; Pattern: Family of wrapper functions for hardware access
; All follow similar structure (parameter setup → external call → result handling)
; All call functions in 0x0500xxxx range (system library/ROM)


; ====================================================================================
; ERROR HANDLING NOTES
; ====================================================================================
;
; Error Condition:
;   When external function (0x0500284c) returns D0 = -1 (0xFFFFFFFF)
;
; Error Recovery:
;   1. Detect error via comparison (CMP.L D0, D1 where D1 = -1)
;   2. Load cached/default value from system data at 0x040105B0
;   3. Store fallback value to caller-provided output pointer (A2)
;   4. Return with error indicator (-1) still in D0
;
; Potential Issues:
;   - No validation of output pointer (A2)
;   - If A2 = 0 (null), conditional write would crash/fault
;   - Caller responsibility to provide valid pointer
;   - No explicit error code mapping (all errors return -1)


; ====================================================================================
; CROSS-REFERENCES
; ====================================================================================
;
; Related Addresses:
;   0x0500284c  - External hardware access function (called)
;   0x040105b0  - SYSTEM_DATA memory location (read on error path)
;   0x00006922  - FUN_00006922 (calling function)
;   0x000069c6  - Call site from FUN_00006922
;
; Associated Files:
;   ghidra_export/disassembly_full.asm  - Full disassembly
;   ghidra_export/functions.json        - Function metadata
;   ghidra_export/call_graph.json       - Call graph
;
; Documentation:
;   docs/functions/0x0000636c_HardwareAccessCallbackWrapper.md


; ====================================================================================
; Assembly Analysis Complete
; ====================================================================================
; Instruction Count: 14 | Total Size: 44 bytes | Complexity: Low
; Last Updated: 2025-11-09 | Status: Complete Analysis
; ====================================================================================
