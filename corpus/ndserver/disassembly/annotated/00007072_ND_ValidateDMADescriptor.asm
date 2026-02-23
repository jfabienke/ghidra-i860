; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateDMADescriptor
; ====================================================================================
; Address: 0x00007072
; Size: 42 bytes (11 instructions)
; Purpose: Validate DMA descriptor structure before calling main DMA processor
; Analysis: docs/functions/00007072_ND_ValidateDMADescriptor.md
; ====================================================================================

; FUNCTION: ND_ValidateDMADescriptor
;
; This function validates that a DMA descriptor structure is non-NULL before
; delegating to the main Mach-O DMA transfer processor (FUN_0000709c). It serves
; as a defensive validation layer in the firmware loading sequence.
;
; The function stores the descriptor pointer in a global variable (0x8018) where
; it can be accessed by the DMA processor, performs a NULL check, and either
; calls the processor or returns an error.
;
; PARAMETERS:
;   mach_o_data (8(A6)): Pointer to Mach-O kernel data or file handle
;   descriptor_structure (12(A6)): Pointer to DMA descriptor (validated here)
;
; RETURNS:
;   D0 = 0 on success (from FUN_0000709c)
;   D0 = -1 on NULL descriptor
;   D0 = error code on DMA processing failure
;
; STACK FRAME: 0 bytes (no local variables)
;
; GLOBAL SIDE EFFECTS:
;   - Sets global_descriptor_ptr @ 0x8018 = descriptor_structure
;   - Sets global_error_code @ 0x040105b0 = 8 (if NULL descriptor)
;
; CALLED BY:
;   - FUN_00005bb8 (Board initialization sequence)
;
; CALLS:
;   - FUN_0000709c (ND_ProcessDMATransfer - main DMA processor)
;
; ====================================================================================

FUN_00007072:

    ; --- PROLOGUE ---
    ; Create stack frame with no local variables
    0x00007072:  link.w     A6,0x0                        ; Standard frame, 0 bytes locals

    ; --- LOAD AND STORE DESCRIPTOR PARAMETER ---
    ; Load the descriptor structure pointer from the second parameter
    ; and store it in the global variable that FUN_0000709c will read
    0x00007076:  move.l     (0xc,A6),D0                   ; D0 = descriptor_structure (arg2)
                                                          ; Offset +12 = second parameter

    0x0000707a:  move.l     D0,(0x00008018).l             ; global_descriptor_ptr = D0
                                                          ; Store descriptor globally for
                                                          ; access by FUN_0000709c
                                                          ; Address 0x8018 in DATA segment

    ; --- VALIDATE DESCRIPTOR IS NON-NULL ---
    ; The move.l instruction sets flags based on the value of D0
    ; If D0 == 0 (NULL), the Z (zero) flag is set
    0x00007080:  beq.b      .error_null_descriptor        ; Branch if descriptor == NULL
                                                          ; beq tests Z flag from move.l

    ; --- SUCCESS PATH: DESCRIPTOR VALID ---
    ; Descriptor is non-NULL, proceed to call the main DMA processor
    ; Pass the Mach-O data parameter to the processor function

    0x00007082:  move.l     (0x8,A6),-(SP)                ; Push mach_o_data (arg1)
                                                          ; Pre-decrement stack, push first param
                                                          ; FUN_0000709c expects 1 parameter

    0x00007086:  bsr.l      0x0000709c                     ; CALL FUN_0000709c (ND_ProcessDMATransfer)
                                                          ; This function will:
                                                          ;   1. Read descriptor from 0x8018
                                                          ;   2. Validate Mach-O magic (0xFEEDAFCE)
                                                          ;   3. Validate file type (execute/dylib)
                                                          ;   4. Parse load commands
                                                          ;   5. Iterate through segments
                                                          ;   6. Translate addresses (host→i860)
                                                          ;   7. Perform DMA transfers
                                                          ; Returns: D0 = 0 (success) or error code
                                                          ; Note: Callee cleans stack (1 param)

    0x0000708c:  bra.b      .exit                         ; Jump to epilogue
                                                          ; Skip error path

    ; --- ERROR PATH: NULL DESCRIPTOR ---
    ; Descriptor parameter was NULL - cannot proceed with DMA operations
    ; Set global error code and return -1 to indicate error

.error_null_descriptor:
    0x0000708e:  moveq      0x8,D1                        ; D1 = ERROR_NULL_DESCRIPTOR (8)
                                                          ; moveq is efficient for small constants
                                                          ; Error code 8 = NULL descriptor

    0x00007090:  move.l     D1,(0x040105b0).l             ; global_error_code = 8
                                                          ; Store error code for debugging
                                                          ; Address 0x040105b0 = errno-style global
                                                          ; Runtime segment (heap/BSS)

    0x00007096:  moveq      -0x1,D0                       ; D0 = -1 (0xFFFFFFFF)
                                                          ; Standard error return value
                                                          ; Indicates validation failure

    ; --- EPILOGUE ---
    ; Common exit path for both success and error cases
    ; D0 contains return value (-1 for NULL, or result from FUN_0000709c)

.exit:
    0x00007098:  unlk       A6                            ; Restore frame pointer
                                                          ; SP = A6, A6 = (A6)

    0x0000709a:  rts                                      ; Return to caller
                                                          ; PC = (SP)+, return to FUN_00005bb8

; ====================================================================================
; END OF FUNCTION: ND_ValidateDMADescriptor
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This 42-byte wrapper function provides defensive validation for DMA descriptor
; structures before delegating to the main DMA transfer processor. It serves as
; a critical gate in the firmware loading sequence, preventing NULL pointer
; crashes in complex Mach-O parsing and DMA operations.
;
; The function uses a global variable pattern where the descriptor is stored at
; address 0x8018 for shared access by the DMA processor. This design allows
; multiple wrapper functions to use the same processor with different validation
; strategies.
;
; CONTROL FLOW:
;   1. Load descriptor parameter
;   2. Store descriptor globally (required by processor)
;   3. Check if descriptor is NULL
;      - If NULL: Set errno=8, return -1
;      - If valid: Call FUN_0000709c (DMA processor)
;   4. Return result to caller
;
; ERROR HANDLING:
;   - NULL descriptor: Immediate return -1, global error code 8
;   - DMA errors: Propagated from FUN_0000709c
;   - Success: Returns 0 from FUN_0000709c
;
; GLOBAL STATE CHANGES:
;   - global_descriptor_ptr @ 0x8018: Always set to descriptor parameter
;   - global_error_code @ 0x040105b0: Set to 8 if descriptor is NULL
;
; ====================================================================================
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; // Global variables
; extern void* global_descriptor_ptr;      // @ 0x8018
; extern int   global_error_code;          // @ 0x040105b0
;
; // Error codes
; #define ND_SUCCESS                 0
; #define ND_ERROR_NULL_DESCRIPTOR   8
; #define ND_GENERAL_ERROR          -1
;
; // External function
; int ND_ProcessDMATransfer(void* mach_o_data);  // @ 0x0000709c
;
; /**
;  * Validates a DMA descriptor structure and processes Mach-O data transfer.
;  *
;  * @param mach_o_data          Pointer to Mach-O kernel data or file handle
;  * @param descriptor_structure Pointer to DMA descriptor (validated here)
;  * @return 0 on success, -1 on NULL descriptor, error code on DMA failure
;  */
; int ND_ValidateDMADescriptor(void* mach_o_data, void* descriptor_structure)
; {
;     // Store descriptor pointer globally (required by processor)
;     global_descriptor_ptr = descriptor_structure;
;
;     // Validate descriptor is non-NULL
;     if (descriptor_structure == NULL) {
;         // Set global error code
;         global_error_code = ND_ERROR_NULL_DESCRIPTOR;
;
;         // Return error
;         return ND_GENERAL_ERROR;
;     }
;
;     // Descriptor valid - delegate to main DMA processor
;     // Processor will read descriptor from global_descriptor_ptr
;     return ND_ProcessDMATransfer(mach_o_data);
; }
;
; ====================================================================================
;
; ARCHITECTURE NOTES:
;
; Register Usage:
;   D0: Descriptor pointer (input), Return value (output)
;   D1: Error code 8 (only on error path)
;   A6: Frame pointer (preserved)
;
; Stack Frame Layout:
;   +12(A6): descriptor_structure parameter
;    +8(A6): mach_o_data parameter
;    +4(A6): Return address
;    +0(A6): Saved A6 (old frame pointer)
;   [No local variables]
;
; Instruction Encoding:
;   - link.w A6,0x0:        4 bytes (0x4E56 0x0000)
;   - move.l (0xc,A6),D0:   4 bytes (0x202E 0x000C)
;   - move.l D0,(addr).l:   8 bytes (0x23C0 + 32-bit address)
;   - beq.b offset:         2 bytes (0x6700 + 8-bit offset)
;   - move.l (0x8,A6),-(SP): 4 bytes (0x2F2E 0x0008)
;   - bsr.l offset:         6 bytes (0x6100 + 32-bit offset)
;   - bra.b offset:         2 bytes (0x6000 + 8-bit offset)
;   - moveq #imm,Dn:        2 bytes (0x7xxx)
;   - unlk A6:              2 bytes (0x4E5E)
;   - rts:                  2 bytes (0x4E75)
;   Total: 42 bytes
;
; Optimization Notes:
;   - Uses moveq for small constants (efficient encoding)
;   - No register preservation needed (doesn't modify callee-save regs)
;   - Short branches (PC-relative) where possible
;   - No stack locals (minimal overhead)
;   - Inline error handling (no call to error function)
;
; ====================================================================================
;
; INTEGRATION WITH NEXTDIMENSION PROTOCOL:
;
; This function is part of the firmware loading sequence during board initialization:
;
; 1. Hardware Detection: Scan NeXTBus for NeXTdimension boards
; 2. Board Registration: Allocate device structures (FUN_000036b2)
; 3. Port Allocation: Obtain Mach IPC ports
; 4. Firmware Loading:
;    a. Read i860 kernel from disk (Mach-O format)
;    b. Parse Mach-O header into descriptor
;    c. ► Validate descriptor (THIS FUNCTION) ◄
;    d. Process DMA transfers (FUN_0000709c)
; 5. i860 Boot: Start i860 processor execution
; 6. Subsystem Init: Video, DMA, interrupts
;
; The global descriptor pattern allows multiple wrapper functions to share the
; same DMA processor while providing different validation strategies.
;
; Related Wrappers (same pattern):
;   - FUN_00006f94: Different validation, calls FUN_0000709c
;   - FUN_00007032: Different validation, calls FUN_0000709c
;   - FUN_00007072: NULL-check validation (THIS FUNCTION)
;
; ====================================================================================
;
; TESTING RECOMMENDATIONS:
;
; Test Case 1: NULL Descriptor
;   Input: mach_o_data = valid, descriptor = NULL
;   Expected: Return -1, errno=8, global_descriptor_ptr=NULL
;
; Test Case 2: Valid Descriptor, DMA Success
;   Input: mach_o_data = valid, descriptor = valid
;   Expected: Return 0, global_descriptor_ptr=descriptor
;
; Test Case 3: Valid Descriptor, DMA Error
;   Input: mach_o_data = invalid, descriptor = valid
;   Expected: Return error code (from FUN_0000709c)
;
; Debugging Breakpoints:
;   0x00007072: Function entry
;   0x0000707a: After global store
;   0x00007080: Before NULL check
;   0x00007086: Before delegate call
;   0x0000708e: Error path
;
; ====================================================================================
;
; ANALYSIS METADATA:
;
; Function Name: ND_ValidateDMADescriptor
; Complexity: LOW (Cyclomatic complexity = 2)
; Size: 42 bytes (Very Small)
; Instructions: 11 (Very Simple)
; Call Depth: 2 (Caller → This → FUN_0000709c)
; Status: ✅ FULLY ANALYZED
; Confidence: HIGH (90%+)
; Related Analysis: docs/functions/0000709c_ND_ProcessDMATransfer.md
;
; ====================================================================================
