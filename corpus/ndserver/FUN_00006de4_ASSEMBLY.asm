; ============================================================================
; Function: FUN_00006de4
; Address: 0x00006de4 (28,132 decimal)
; Size: 136 bytes (34 instructions)
; Type: Callback function / Handler dispatcher
; Complexity: Medium
; ============================================================================
;
; PURPOSE:
;   Initialize a command/handler structure and dispatch execution to a
;   handler function selected via a validated index parameter.
;
; PARAMETERS:
;   A2 (0x8,A6):  Pointer to source structure (Type_A)
;   A1 (0xc,A6): Pointer to destination structure (Type_B)
;
; RETURN:
;   D0: 0 = Handler invalid or call failed
;       1 = Handler executed successfully
;
; STACK FRAME:
;   (A6)+0x0    Old A6 (frame pointer)
;   (A6)+0x4    Return address
;   (A6)+0x8    Param 1 (param1 pointer)
;   (A6)+0xc    Param 2 (param2 pointer)
;   (A6)-0x4    Saved A2 register
;
; ============================================================================

; ============================================================================
; SECTION 1: STACK FRAME SETUP
; ============================================================================
; Establish standard C frame and save callee-save registers

0x00006de4:  link.w A6,0x0
             ; Allocate 0 bytes on stack, save old A6
             ; This establishes the frame pointer for parameter access

0x00006de8:  move.l A2,-(SP)
             ; Save A2 (callee-save register) on stack
             ; Stack: [saved_A2]


; ============================================================================
; SECTION 2: LOAD FUNCTION PARAMETERS
; ============================================================================
; Extract the two structure pointers from the stack frame

0x00006dea:  movea.l (0x8,A6),A2
             ; A2 = param1 (source structure)
             ; Offset 0x8 from frame pointer is first parameter

0x00006dee:  movea.l (0xc,A6),A1
             ; A1 = param2 (destination structure)
             ; Offset 0xc from frame pointer is second parameter


; ============================================================================
; SECTION 3: INITIALIZE DESTINATION STRUCTURE - STATUS & PAYLOAD
; ============================================================================
; Set initial fields in the destination structure

0x00006df2:  move.b #0x1,(0x3,A1)
             ; param2[0x3] = 0x01 (status byte)
             ; Mark structure as initialized/ready

0x00006df8:  moveq 0x20,D1
             ; D1 = 0x20 (32 decimal)
             ; Load fixed payload size/value into data register

0x00006dfa:  move.l D1,(0x4,A1)
             ; param2[0x4] = 0x20
             ; Store payload size at offset 0x4


; ============================================================================
; SECTION 4: COPY DATA FIELD & CLEAR INTERMEDIATE FIELD
; ============================================================================
; Transfer data from source to destination structure

0x00006dfe:  move.l (0x8,A2),(0x8,A1)
             ; param2[0x8] = param1[0x8]
             ; Copy 32-bit data field from source to destination

0x00006e04:  clr.l (0xc,A1)
             ; param2[0xc] = 0x00000000
             ; Clear the field at offset 0xc (likely reserved/unused)


; ============================================================================
; SECTION 5: COPY CONFIGURATION & CALCULATE OFFSET FIELD
; ============================================================================
; Copy configuration and perform arithmetic on index value

0x00006e08:  move.l (0x10,A2),(0x10,A1)
             ; param2[0x10] = param1[0x10]
             ; Copy configuration field from source

0x00006e0e:  moveq 0x64,D1
             ; D1 = 0x64 (100 decimal)
             ; Load base offset value

0x00006e10:  add.l (0x14,A2),D1
             ; D1 = 0x64 + param1[0x14]
             ; Add the index value from source to base offset


; ============================================================================
; SECTION 6: STORE CALCULATED OFFSET & LOAD HANDLER POINTER
; ============================================================================
; Store computed offset and initialize handler function pointer

0x00006e14:  move.l D1,(0x14,A1)
             ; param2[0x14] = D1
             ; Store the calculated offset value

0x00006e18:  move.l (0x00007da0).l,(0x18,A1)
             ; param2[0x18] = ROM[0x7da0]
             ; Load handler function pointer from ROM address
             ; Note: Using absolute long addressing to ROM


; ============================================================================
; SECTION 7: SET CONSTANT FIELD
; ============================================================================
; Initialize a constant value in the structure

0x00006e20:  move.l #-0x12f,(0x1c,A1)
             ; param2[0x1c] = -0x12f (-303 decimal)
             ; Set constant value (likely flags or configuration)


; ============================================================================
; SECTION 8: PARAMETER VALIDATION - STAGE 1: BOUNDS CHECK
; ============================================================================
; Validate the index parameter is within acceptable range
;
; The validation algorithm:
;   1. Get the index from source structure
;   2. Normalize it by subtracting a constant (0x2af8 = -12024)
;   3. Check if result is <= 0x96 (150 decimal)
;   4. If > 0x96, skip to error handler

0x00006e28:  move.l (0x14,A2),D0
             ; D0 = param1[0x14]
             ; Load the index value from source structure

0x00006e2c:  addi.l #-0x2af8,D0
             ; D0 -= 0x2af8 (normalize index)
             ; This subtracts 12024, effectively checking a range

0x00006e32:  cmpi.l #0x96,D0
             ; Compare D0 with 0x96 (150)
             ; Set CCR based on comparison

0x00006e38:  bhi.b 0x00006e4a
             ; Branch if Higher Unsigned (D0 > 0x96)
             ; Jump to error handler at 0x6e4a if out of bounds


; ============================================================================
; SECTION 9: PARAMETER VALIDATION - STAGE 2: DISPATCH TABLE LOOKUP
; ============================================================================
; Check if this index has a valid handler in the dispatch table
;
; The algorithm:
;   1. Get original index value
;   2. Load dispatch table base address
;   3. Access table[index * 4] (indexed by scaled offset)
;   4. If entry == 0, skip to error handler
;   5. If entry != 0, proceed to handler invocation

0x00006e3a:  move.l (0x14,A2),D0
             ; D0 = param1[0x14]
             ; Reload original index (not normalized)

0x00006e3e:  lea (-0x2e3c).l,A0
             ; A0 = base_address - 0x2e3c
             ; Load dispatch table base address
             ; Note: Using PC-relative calculation with negative offset
             ; Effective address: PC + (-0x2e3c)

0x00006e44:  tst.l (0x0,A0,D0*0x4)
             ; Test value at A0[D0*4] (indexed, scaled by 4)
             ; Each table entry is 32 bits (4 bytes)
             ; This accesses dispatch_table[index] without modifying it

0x00006e48:  bne.b 0x00006e4e
             ; Branch if Not Equal (to zero)
             ; If table entry is non-zero, proceed to handler call


; ============================================================================
; SECTION 10: ERROR PATH - INVALID HANDLER
; ============================================================================
; If either validation stage fails, return failure code

0x00006e4a:  clr.l D0
             ; D0 = 0 (failure/invalid code)
             ; Mark the operation as failed

0x00006e4c:  bra.b 0x00006e64
             ; Jump to cleanup section
             ; Skip handler invocation and go straight to return


; ============================================================================
; SECTION 11: SUCCESS PATH - INVOKE HANDLER
; ============================================================================
; Call the handler function with the initialized structure as parameters
;
; Handler calling convention:
;   - Two parameters passed on stack (pushed right-to-left by caller)
;   - Return value in D0
;   - Stack cleanup by caller (implicit in jsr)

0x00006e4e:  move.l (0x14,A2),D0
             ; D0 = param1[0x14]
             ; Reload index (prepare for handler dispatch)

0x00006e52:  lea (-0x2e3c).l,A0
             ; A0 = dispatch_table base address
             ; Reload table address

0x00006e58:  move.l A1,-(SP)
             ; Push param2 (destination structure)
             ; This becomes the second argument to handler
             ; Stack: [param2, saved_A2]

0x00006e5a:  move.l A2,-(SP)
             ; Push param1 (source structure)
             ; This becomes the first argument to handler
             ; Stack: [param1, param2, saved_A2]

0x00006e5c:  movea.l (0x0,A0,D0*0x4),A0
             ; A0 = dispatch_table[D0]
             ; Load the handler function pointer from the table
             ; Each table entry (4 bytes) contains a function pointer

0x00006e60:  jsr A0
             ; Jump to Subroutine at address in A0
             ; Call the handler function
             ; The handler will receive:
             ;   - param1 (A2) at (SP)+0x4
             ;   - param2 (A1) at (SP)+0x8
             ; Stack: [...caller's frame...]

0x00006e62:  moveq 0x1,D0
             ; D0 = 1 (success code)
             ; Mark operation as successful


; ============================================================================
; SECTION 12: CLEANUP & RETURN
; ============================================================================
; Restore registers and return to caller

0x00006e64:  movea.l (-0x4,A6),A2
             ; A2 = saved value from stack
             ; Restore the callee-save register A2

0x00006e68:  unlk A6
             ; Pop stack frame and restore old A6
             ; Deallocate any local variables (none in this case)

0x00006e6a:  rts
             ; Return from Subroutine
             ; Pop return address and jump to it
             ; D0 contains result (0 or 1)


; ============================================================================
; NOTES & ANALYSIS
; ============================================================================
;
; STRUCTURE LAYOUT (Source - param1 at A2):
;   [offset 0x8]:   Data value (copied to param2[0x8])
;   [offset 0x10]:  Configuration value (copied to param2[0x10])
;   [offset 0x14]:  Index/Control value (used for validation & dispatch)
;
; STRUCTURE LAYOUT (Destination - param2 at A1):
;   [offset 0x3]:   Status flag (set to 0x01)
;   [offset 0x4]:   Payload size (set to 0x20)
;   [offset 0x8]:   Data field (from param1[0x8])
;   [offset 0xc]:   Reserved/Unused (cleared to 0x00)
;   [offset 0x10]:  Configuration (from param1[0x10])
;   [offset 0x14]:  Calculated offset (0x64 + param1[0x14])
;   [offset 0x18]:  Handler function pointer (from ROM[0x7da0])
;   [offset 0x1c]:  Constant value (-0x12f = -303)
;
; VALIDATION CONSTANTS:
;   0x2af8:  Index normalization offset (subtract from index)
;   0x96:    Maximum valid normalized index (150 decimal)
;   -0x2e3c: Dispatch table base address offset
;   0x7da0:  ROM address of handler pointer source
;   0x12f:   Constant value magnitude (303 decimal)
;
; ADDRESSING MODES:
;   (0x8,A6)      - Stack frame indirect with displacement
;   (0x3,A1)      - Register indirect with byte offset
;   (0x0,A0,D0*4) - Register indirect with index and scale
;   (0x00007da0).l - Absolute long address
;   (-0x2e3c).l    - PC-relative with negative offset
;
; PERFORMANCE:
;   Best case (validation fails early):  ~25 cycles
;   Worst case (handler invoked):        ~50 cycles
;   Average case:                        ~40 cycles
;
; REGISTER USAGE:
;   A6 - Frame pointer (implicit in LINK/UNLK)
;   A2 - Parameter 1 (source structure), saved/restored
;   A1 - Parameter 2 (destination structure)
;   A0 - Temporary (table address, handler pointer)
;   D0 - Validation value, handler dispatch index, return value
;   D1 - Temporary (payload value, offset calculation)
;   SP - Stack pointer (managed by LINK/UNLK/jsr)
;
; CALLING CONVENTION:
;   Parameters: Passed on stack (standard 68k calling convention)
;   Return: Value in D0
;   Cleanup: Implicit (jsr pops return address)
;
; ERROR HANDLING:
;   1. If index > 0x96 (after normalization): Return D0=0
;   2. If dispatch_table[index] == 0: Return D0=0
;   3. Otherwise: Call handler and return D0=1
;
; TYPICAL USE CASE:
;   This function appears to be a callback dispatcher, likely used in:
;   - Hardware device drivers
;   - Inter-process communication (IPC)
;   - Interrupt handlers
;   - Command routing
;
; POSSIBLE IMPROVEMENTS:
;   - Could avoid reloading index twice (0x6e28 and 0x6e3a)
;   - Could avoid reloading table address twice (0x6e3e and 0x6e52)
;   - These are likely the result of compiler instruction scheduling
;
; ============================================================================

