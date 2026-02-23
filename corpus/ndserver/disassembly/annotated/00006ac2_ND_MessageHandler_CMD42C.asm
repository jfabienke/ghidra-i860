; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD42C
; ====================================================================================
; Address: 0x00006ac2
; Size: 186 bytes (0xBA)
; Purpose: Validates and processes Mach IPC messages with command type 0x42C
; Analysis: docs/functions/00006ac2_ND_MessageHandler_CMD42C.md
; ====================================================================================

; FUNCTION: void ND_MessageHandler_CMD42C(nd_message_t *msg_in, nd_reply_t *reply_out)
;
; This function is a message handler in the NDserver dispatch system. It validates
; incoming Mach IPC messages with command type 0x42C (1068 decimal) through a series
; of 6 parameter checks before delegating to FUN_000063c0 for the actual I/O operation.
;
; The handler follows a strict validation chain where any check failure immediately
; returns error code -0x130 (304 decimal). On success, it calls FUN_000063c0 (likely
; a Mach VM operation wrapper) and populates the reply structure with global values.
;
; PARAMETERS:
;   msg_in (A6+0x8):  Pointer to incoming message structure (1068 bytes expected)
;   reply_out (A6+0xC): Pointer to reply structure to populate (48 bytes output)
;
; RETURNS:
;   void (modifies reply_out structure in-place)
;   reply_out->error_code = 0 on success, -0x130 on validation failure
;   reply_out->result = return value from FUN_000063c0
;
; STACK FRAME: 0 bytes local + 8 bytes saved registers
;   A6-0x4: Saved A3
;   A6-0x8: Saved A2
;
; VALIDATION CHECKS:
;   1. Message size must equal 0x42C (1068 bytes)
;   2. Message version must equal 1
;   3. Field at offset 0x18 must match global at 0x7d58
;   4. Flags at offset 0x23 must have bits 2&3 set (0x0C)
;   5. Field at offset 0x24 must equal 0x0C (12)
;   6. Field at offset 0x28 must equal 1
;   7. Field at offset 0x26 must equal 0x2000 (8192)
;
; COMPARISON WITH CMD434 HANDLER (0x6b7c):
;   - Simpler: 6 validation checks vs. 7 checks
;   - Smaller message: 0x42C (1068) vs. 0x434 (1076)
;   - Fewer parameters: 3 vs. 4 parameters to operation function
;   - Different globals: 0x7d58/5c/60 vs. 0x7d64/68/6c/70
;   - Different operation: FUN_000063c0 vs. FUN_000063e8
;   - Same error code: -0x130 (common across all handlers)
;
; ====================================================================================

FUN_00006ac2:
ND_MessageHandler_CMD42C:

; ============================================================================
; SECTION: PROLOGUE - Stack Frame Setup and Register Preservation
; ============================================================================
; Create stack frame and save callee-save registers (A2, A3) according to
; m68k System V ABI. Load parameters into address registers for efficient
; repeated access throughout the function.

    0x00006ac2:  link.w     A6,#0x0                   ; Create 0-byte stack frame
                                                       ; A6 becomes frame pointer
                                                       ; No local variables needed

    0x00006ac6:  move.l     A3,-(SP)                  ; Save A3 (callee-save register)
                                                       ; Now at A6-0x4

    0x00006ac8:  move.l     A2,-(SP)                  ; Save A2 (callee-save register)
                                                       ; Now at A6-0x8

    0x00006aca:  movea.l    (0x8,A6),A2               ; A2 = msg_in (first parameter)
                                                       ; Persistent pointer for message access

    0x00006ace:  movea.l    (0xc,A6),A3               ; A3 = reply_out (second parameter)
                                                       ; Persistent pointer for reply access

; ============================================================================
; SECTION: EXTRACT MESSAGE VERSION
; ============================================================================
; Extract the message version byte from offset 0x3 of the message structure.
; This uses the BFEXTU (bit field extract unsigned) instruction which is more
; efficient than a byte move + mask operation on 68020+.

    0x00006ad2:  bfextu     (0x3,A2),0x0,0x8,D0       ; Extract byte at msg_in+0x3 to D0
                                                       ; Syntax: bfextu source,offset,width,dest
                                                       ; source = (0x3,A2) = memory at A2+3
                                                       ; offset = 0 (start at bit 0)
                                                       ; width = 8 (extract 8 bits = 1 byte)
                                                       ; dest = D0 (zero-extended to 32 bits)
                                                       ; This extracts the message version field

; ============================================================================
; SECTION: VALIDATION CHECK #1 - Message Size
; ============================================================================
; First validation: Check that the message size field (at offset 0x4) matches
; the expected size for command type 0x42C. This is the fastest check and
; immediately rejects messages with incorrect sizes.

.validate_size:
    0x00006ad8:  cmpi.l     #0x42c,(0x4,A2)           ; Compare msg_in->size with 0x42C
                                                       ; Expected size: 0x42C (1068 bytes)
                                                       ; Field at offset 0x4 contains message size

    0x00006ae0:  bne.b      .error_invalid_params     ; Branch if not equal to 0x42C
                                                       ; Short branch (within 128 bytes)
                                                       ; Jump to error handler

; ============================================================================
; SECTION: VALIDATION CHECK #2 - Message Version
; ============================================================================
; Second validation: Check that the extracted version byte equals 1. This
; ensures protocol compatibility between client and server.

.validate_version:
    0x00006ae2:  moveq      #0x1,D1                   ; Load expected version = 1
                                                       ; MOVEQ is efficient (2 bytes vs 6 for MOVE.L)
                                                       ; Sign-extends to 32 bits (0x00000001)

    0x00006ae4:  cmp.l      D0,D1                     ; Compare D0 (extracted version) with D1 (1)
                                                       ; Check if message version == 1

    0x00006ae6:  beq.b      .validate_field_0x18      ; Branch if equal (version is correct)
                                                       ; Continue to next validation

    ; FALL THROUGH to error handler if version != 1

; ============================================================================
; SECTION: ERROR PATH #1 - Invalid Message Size or Version
; ============================================================================
; Error handler for the first two validation checks. Sets the standard error
; code -0x130 (304 decimal) in the reply structure and jumps to epilogue.

.error_invalid_params:
    0x00006ae8:  move.l     #-0x130,(0x1c,A3)         ; reply_out->error_code = -0x130
                                                       ; Error code -304 decimal
                                                       ; Standard validation failure code
                                                       ; Used by all message handlers

    0x00006af0:  bra.b      .epilogue                 ; Jump to function exit
                                                       ; Short branch to cleanup code
                                                       ; Skip all remaining validation and operation

; ============================================================================
; SECTION: VALIDATION CHECK #3 - Field at Offset 0x18
; ============================================================================
; Third validation: Check that field at offset 0x18 in the message matches
; a global configuration value at address 0x7d58. This likely validates the
; target task, board identifier, or security token.

.validate_field_0x18:
    0x00006af2:  move.l     (0x18,A2),D1              ; Load msg_in->field_0x18 into D1
                                                       ; Unknown field (task port? board ID?)

    0x00006af6:  cmp.l      (0x00007d58).l,D1         ; Compare with global at 0x7d58
                                                       ; .l suffix = 32-bit absolute addressing
                                                       ; NOTE: Different from CMD434 (uses 0x7d64)
                                                       ; Suggests command-specific configuration

    0x00006afc:  bne.b      .error_field_mismatch     ; Branch if not equal
                                                       ; Jump to field validation error handler

; ============================================================================
; SECTION: VALIDATION CHECK #4 - Flags at Offset 0x23
; ============================================================================
; Fourth validation: Check that specific flag bits are set at offset 0x23.
; The flags byte must have both bits 2 and 3 set (value 0x0C after masking).

.validate_flags_0x23:
    0x00006afe:  move.b     (0x23,A2),D0b             ; Load flags byte at offset 0x23
                                                       ; .b suffix = byte operation
                                                       ; Overwrites lower byte of D0

    0x00006b02:  andi.b     #0xc,D0b                  ; Mask with 0x0C (binary 00001100)
                                                       ; Isolate bits 2 and 3
                                                       ; Clear all other bits

    0x00006b06:  cmpi.b     #0xc,D0b                  ; Compare result with 0x0C
                                                       ; Check if both bits 2&3 are set
                                                       ; Any other combination fails

    0x00006b0a:  bne.b      .error_field_mismatch     ; Branch if not equal to 0x0C
                                                       ; Jump to field validation error handler

; ============================================================================
; SECTION: VALIDATION CHECK #5 - Field at Offset 0x24
; ============================================================================
; Fifth validation: Check that the word at offset 0x24 equals 0x0C (12 decimal).
; This may be a count, size, or type field.

.validate_field_0x24:
    0x00006b0c:  cmpi.w     #0xc,(0x24,A2)            ; Compare msg_in->field_0x24 with 12
                                                       ; .w suffix = word (16-bit) operation
                                                       ; Expected value: 0x000C

    0x00006b12:  bne.b      .error_field_mismatch     ; Branch if not equal to 12
                                                       ; Jump to field validation error handler

; ============================================================================
; SECTION: VALIDATION CHECK #6 - Field at Offset 0x28
; ============================================================================
; Sixth validation: Check that the long word at offset 0x28 equals 1.
; This may be a count, ID, or boolean flag.

.validate_field_0x28:
    0x00006b14:  moveq      #0x1,D1                   ; Load expected value = 1
                                                       ; Efficient immediate load

    0x00006b16:  cmp.l      (0x28,A2),D1              ; Compare msg_in->field_0x28 with 1
                                                       ; Check if field equals 1

    0x00006b1a:  bne.b      .error_field_mismatch     ; Branch if not equal to 1
                                                       ; Jump to field validation error handler

; ============================================================================
; SECTION: VALIDATION CHECK #7 - Field at Offset 0x26 (Final Check)
; ============================================================================
; Seventh and final validation: Check that the word at offset 0x26 equals
; 0x2000 (8192 decimal). This is the same value required by CMD434, suggesting
; it's a common protocol constraint (possibly page size or alignment).

.validate_field_0x26:
    0x00006b1c:  cmpi.w     #0x2000,(0x26,A2)         ; Compare msg_in->field_0x26 with 0x2000
                                                       ; Expected value: 0x2000 (8192)
                                                       ; Same validation as CMD434

    0x00006b22:  beq.b      .call_operation_handler   ; Branch if equal to 0x2000
                                                       ; ALL validations passed!
                                                       ; Proceed to operation call

    ; FALL THROUGH to error handler if field_0x26 != 0x2000

; ============================================================================
; SECTION: ERROR PATH #2 - Field Validation Failure
; ============================================================================
; Error handler for validation checks 3-7. Sets the standard error code -0x130
; and branches to the error check section (which skips response population).

.error_field_mismatch:
    0x00006b24:  move.l     #-0x130,(0x1c,A3)         ; reply_out->error_code = -0x130
                                                       ; Same error code as path #1
                                                       ; -304 decimal

    0x00006b2c:  bra.b      .check_error_code         ; Jump to error code check
                                                       ; Skips operation call
                                                       ; Will skip response population

; ============================================================================
; SECTION: CALL OPERATION HANDLER
; ============================================================================
; All validations passed. Prepare parameters and call the I/O operation handler
; FUN_000063c0. Parameters are pushed right-to-left (C calling convention).
;
; NOTE: This handler pushes 3 parameters, while CMD434 pushes 4 parameters.
; The missing parameter is at offset 0x430 in CMD434's larger message.

.call_operation_handler:
    ; Push parameters for FUN_000063c0 call (right-to-left order)
    ; Stack layout after all pushes:
    ;   SP+0x0: msg_in->field_0xc   (param 1)
    ;   SP+0x4: &msg_in->field_0x1c (param 2)
    ;   SP+0x8: &msg_in->field_0x2c (param 3)

    0x00006b2e:  pea        (0x2c,A2)                 ; Push effective address of msg_in+0x2C
                                                       ; Parameter 3: Pointer to data buffer
                                                       ; PEA is efficient for address calculation

    0x00006b32:  pea        (0x1c,A2)                 ; Push effective address of msg_in+0x1C
                                                       ; Parameter 2: Pointer to data/output buffer
                                                       ; Likely written by FUN_000063c0

    0x00006b36:  move.l     (0xc,A2),-(SP)            ; Push msg_in->field_0xc
                                                       ; Parameter 1: Handle, port, or task ID
                                                       ; Direct value (not pointer)

    ; Call the I/O operation handler
    0x00006b3a:  bsr.l      0x000063c0                ; Branch to subroutine FUN_000063c0
                                                       ; .l suffix = long branch (anywhere in code)
                                                       ; FUN_000063c0 wraps library call 0x05002228
                                                       ; Likely vm_allocate() or vm_deallocate()
                                                       ; Returns result in D0
                                                       ; NOTE: Different from CMD434 (calls 0x63e8)

    ; Store result and clear error code
    0x00006b40:  move.l     D0,(0x24,A3)              ; reply_out->result = return value from FUN_000063c0
                                                       ; D0 contains operation result
                                                       ; Store at offset 0x24 in reply

    0x00006b44:  clr.l      (0x1c,A3)                 ; reply_out->error_code = 0
                                                       ; Clear error code (success)
                                                       ; Overwrites any previous error value

; ============================================================================
; SECTION: CHECK ERROR CODE AND POPULATE RESPONSE
; ============================================================================
; Check if an error occurred (error_code != 0). If no error, populate the
; reply structure with configuration values from globals and message fields.

.check_error_code:
    0x00006b48:  tst.l      (0x1c,A3)                 ; Test reply_out->error_code
                                                       ; Sets condition codes based on value
                                                       ; Zero flag set if error_code == 0

    0x00006b4c:  bne.b      .epilogue                 ; Branch if error_code != 0
                                                       ; Skip response population on error
                                                       ; Jump directly to cleanup

    ; Success path: Populate response structure
.populate_response:
    0x00006b4e:  move.l     (0x00007d5c).l,(0x20,A3)  ; reply_out->field_0x20 = global_0x7d5c
                                                       ; Copy global configuration value to reply
                                                       ; NOTE: Different from CMD434 (uses 0x7d6c)
                                                       ; Offset from CMD434 global: -0x10 bytes

    0x00006b56:  move.l     (0x00007d60).l,(0x28,A3)  ; reply_out->field_0x28 = global_0x7d60
                                                       ; Copy second global configuration value
                                                       ; NOTE: Different from CMD434 (uses 0x7d70)
                                                       ; Offset from CMD434 global: -0x10 bytes
                                                       ; Pattern: globals are 16 bytes lower

    0x00006b5e:  move.l     (0x1c,A2),(0x2c,A3)       ; reply_out->field_0x2c = msg_in->field_0x1c
                                                       ; Echo message field to reply
                                                       ; May be confirmation of allocated address

    0x00006b64:  move.b     #0x1,(0x3,A3)             ; reply_out->version = 1
                                                       ; Set reply version to match message version
                                                       ; Byte write at offset 0x3

    0x00006b6a:  moveq      #0x30,D1                  ; Load reply size value = 0x30 (48 bytes)
                                                       ; MOVEQ for efficiency

    0x00006b6c:  move.l     D1,(0x4,A3)               ; reply_out->size = 0x30
                                                       ; Set reply message size to 48 bytes
                                                       ; Same size as CMD434 reply

; ============================================================================
; SECTION: EPILOGUE - Cleanup and Return
; ============================================================================
; Restore saved registers from stack, destroy stack frame, and return to caller.

.epilogue:
    0x00006b70:  movea.l    (-0x8,A6),A2              ; Restore A2 from stack
                                                       ; Load from A6-0x8 (second saved register)

    0x00006b74:  movea.l    (-0x4,A6),A3              ; Restore A3 from stack
                                                       ; Load from A6-0x4 (first saved register)

    0x00006b78:  unlk       A6                        ; Destroy stack frame
                                                       ; Restores previous A6
                                                       ; Adjusts SP to remove frame

    0x00006b7a:  rts                                  ; Return to caller
                                                       ; Pop return address from stack and jump

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD42C
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This message handler validates incoming Mach IPC messages with command type 0x42C
; through a 6-step validation chain. Any validation failure immediately returns error
; code -0x130 (304 decimal). On success, it calls FUN_000063c0 (likely a Mach VM
; operation wrapper for vm_allocate or vm_deallocate) with 3 parameters extracted
; from the message, then populates the reply structure with global configuration
; values and the operation result.
;
; The handler is part of a family of similar functions in the 0x6000-0x7000 range,
; all following the same pattern but with different command types, validation checks,
; and operation functions. It is invoked indirectly by the message dispatcher at
; 0x6e6c via a jump table lookup based on the message type field.
;
; VALIDATION LOGIC SUMMARY:
;   1. Size must be 0x42C (1068 bytes)
;   2. Version must be 1
;   3. Field 0x18 must match global 0x7d58
;   4. Flags 0x23 must have bits 2&3 set (0x0C)
;   5. Field 0x24 must be 0x0C (12)
;   6. Field 0x28 must be 1
;   7. Field 0x26 must be 0x2000 (8192)
;
; COMPARISON WITH CMD434 HANDLER (0x6b7c):
;   Similarities:
;   - Identical control flow structure
;   - Same error code (-0x130)
;   - Same reply size (0x30 = 48 bytes)
;   - Similar validation checks (same offsets and values)
;
;   Differences:
;   - Smaller message: 1068 vs 1076 bytes (8 bytes less)
;   - Fewer parameters: 3 vs 4 to operation function
;   - Different operation: FUN_000063c0 vs FUN_000063e8
;   - Different library call: 0x05002228 vs 0x0500222e
;   - Different globals: 0x7d58/5c/60 vs 0x7d64/68/6c/70 (16 bytes lower)
;   - Missing validation: No check of field at 0x42c (not present in smaller message)
;
; LIKELY PURPOSE:
;   Based on the pattern and comparisons:
;   - CMD42C (this): Memory allocation/deallocation (vm_allocate/vm_deallocate)
;   - CMD434: Memory read operation (vm_read)
;   - CMD43C: Memory write operation (vm_write?)
;
; UNANSWERED QUESTIONS:
;   1. Why are there TWO handlers for command 0x42C (this at 0x6ac2, another at 0x6a08)?
;   2. What is the actual value of globals at 0x7d58, 0x7d5c, 0x7d60?
;   3. Is FUN_000063c0 wrapping vm_allocate or vm_deallocate (or both conditionally)?
;   4. What do the flags at offset 0x23 control (bits 2&3)?
;   5. Why is field 0x26 required to be 0x2000 (8KB) - page size constraint?
;
; NEXT ANALYSIS PRIORITIES:
;   1. FUN_000063c0 (0x63c0) - Determine actual Mach operation
;   2. FUN_00006a08 (0x6a08) - Compare duplicate CMD42C handler
;   3. Global initialization code - Find where 0x7d58/5c/60 are set
;
; ====================================================================================
;
; REVERSE-ENGINEERED C EQUIVALENT (for reference):
;
; void ND_MessageHandler_CMD42C(nd_message_t *msg_in, nd_reply_t *reply_out)
; {
;     uint8_t msg_version = *((uint8_t *)((uint32_t)msg_in + 0x3));
;     int32_t result;
;
;     // Validation chain - any failure returns error -0x130
;     if (msg_in->size != 0x42C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_version != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x18 != g_config_value_0x7d58) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if ((msg_in->flags_0x23 & 0x0C) != 0x0C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x24 != 0x0C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x28 != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x26 != 0x2000) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // All validations passed - execute operation
;     result = FUN_000063c0(
;         msg_in->field_0xc,
;         &msg_in->field_0x1c,
;         &msg_in->field_0x2c
;     );
;
;     reply_out->result = result;
;     reply_out->error_code = 0;
;
;     // Populate response on success
;     if (reply_out->error_code == 0) {
;         reply_out->field_0x20 = g_response_value_0x7d5c;
;         reply_out->field_0x28 = g_response_value_0x7d60;
;         reply_out->field_0x2c = msg_in->field_0x1c;
;         reply_out->version = 1;
;         reply_out->size = 0x30;
;     }
; }
;
; ====================================================================================
