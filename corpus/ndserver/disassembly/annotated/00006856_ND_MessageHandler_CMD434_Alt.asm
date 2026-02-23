; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD434_Alt
; ====================================================================================
; Address: 0x00006856
; Size: 204 bytes (0xCC)
; Purpose: Validate and process Mach IPC messages with command type 0x434 (alternate handler)
; Analysis: docs/functions/00006856_ND_MessageHandler_CMD434_Alt.md
; ====================================================================================
;
; FUNCTION: ND_MessageHandler_CMD434_Alt
;
; This is an alternative handler for command 0x434 messages, distinct from the
; handler at 0x6b7c. It performs 8 validation checks on the incoming message
; structure before delegating to FUN_00006340 for the actual operation.
;
; The function validates:
;   - Message command type and version
;   - Address/ID field against global configuration
;   - Control flags and size parameters
;   - Multiple embedded structure parameters
;
; PARAMETERS:
;   msg_in (A6+0x8):    Pointer to incoming nd_message_t structure (1076 bytes)
;   reply_out (A6+0xC): Pointer to nd_reply_t structure to populate
;
; RETURNS:
;   void (modifies reply_out in-place)
;   reply_out->error_code = 0 on success, -0x130 (304) on validation failure
;   reply_out->result = return value from FUN_00006340 (on success)
;
; STACK FRAME: 0 bytes (no local variables)
;   -0x4(A6): Saved A3
;   -0x8(A6): Saved A2
;
; VALIDATION CHECKS:
;   1. msg_in->command == 0x434 (1076 decimal)
;   2. msg_in->version == 1
;   3. msg_in->field_0x18 == global_0x7d30
;   4. (msg_in->flags_0x23 & 0x0C) == 0x0C (bits 2&3 set)
;   5. msg_in->field_0x24 == 0x000C (12 decimal)
;   6. msg_in->field_0x28 == 1
;   7. msg_in->field_0x26 == 0x2000 (8192 decimal)
;   8. msg_in->field_0x42c == global_0x7d34
;
; GLOBALS ACCESSED:
;   0x7d30 (read):  Validation reference for field_0x18 (board address/ID)
;   0x7d34 (read):  Validation reference for field_0x42c (size/limit)
;   0x7d38 (read):  Response value copied to reply->field_0x20
;   0x7d3c (read):  Response value copied to reply->field_0x28
;
; CALLS TO:
;   FUN_00006340: Performs actual operation with 4 extracted parameters
;
; ====================================================================================

FUN_00006856:
ND_MessageHandler_CMD434_Alt:

; --- PROLOGUE: Create stack frame and save registers ---

    link.w      A6,#0x0                 ; Create 0-byte stack frame
    move.l      A3,-(SP)                ; Save A3 (callee-save register)
    move.l      A2,-(SP)                ; Save A2 (callee-save register)

; --- SETUP: Load function parameters into address registers ---

    movea.l     (0x8,A6),A2             ; A2 = msg_in (first parameter)
    movea.l     (0xc,A6),A3             ; A3 = reply_out (second parameter)

; --- VALIDATION CHECK 1 & 2: Message version and command type ---
; Validates that this is a version 1 command 0x434 message

    ; Extract version byte from message header at offset 0x3
    ; BFEXTU extracts 8 bits starting at bit offset 0 from (A2+3)
    bfextu      (0x3,A2),0x0,0x8,D0     ; D0 = msg_in->version (byte at offset 0x3)

    ; Check if message command type is 0x434 (1076 decimal)
    cmpi.l      #0x434,(0x4,A2)         ; Compare msg_in->command with 0x434
    bne.b       .error_invalid_message  ; If not 0x434, validation failed

    ; Check if version is 1
    moveq       #0x1,D1                 ; D1 = 1 (expected version number)
    cmp.l       D0,D1                   ; Compare extracted version with 1
    beq.b       .validate_field_0x18    ; If version == 1, continue validation

.error_invalid_message:
    ; Validation failed: wrong command type or wrong version
    ; Set error code and skip to epilogue
    move.l      #-0x130,(0x1c,A3)       ; reply_out->error_code = -0x130 (304 decimal)
    bra.w       .epilogue               ; Jump to function exit (long branch)

.validate_field_0x18:
; --- VALIDATION CHECK 3: Field at offset 0x18 must match global ---
; This field appears to be a board address or identifier that must
; match a pre-configured value stored in global variable at 0x7d30

    move.l      (0x18,A2),D1            ; D1 = msg_in->field_0x18
    cmp.l       (0x00007d30).l,D1       ; Compare with global at 0x7d30
    bne.b       .error_validation_failed ; If not equal, validation failed

; --- VALIDATION CHECK 4: Flags at offset 0x23 ---
; Check if bits 2 and 3 are both set (value after masking must be 0x0C)
; This likely controls operation mode or permissions

    move.b      (0x23,A2),D0b           ; D0 = msg_in->flags_0x23 (byte)
    andi.b      #0xc,D0b                ; Mask to keep only bits 2&3 (0000_1100)
    cmpi.b      #0xc,D0b                ; Check if both bits are set
    bne.b       .error_validation_failed ; If not 0x0C, validation failed

; --- VALIDATION CHECK 5: Size/count field at offset 0x24 ---
; This field must be exactly 12 (0x0C), possibly indicating
; structure size or element count

    cmpi.w      #0xc,(0x24,A2)          ; Compare msg_in->field_0x24 with 12
    bne.b       .error_validation_failed ; If not equal, validation failed

; --- VALIDATION CHECK 6: Count field at offset 0x28 ---
; This field must be exactly 1, possibly indicating
; single operation or element count

    moveq       #0x1,D1                 ; D1 = 1 (expected value)
    cmp.l       (0x28,A2),D1            ; Compare msg_in->field_0x28 with 1
    bne.b       .error_validation_failed ; If not equal, validation failed

; --- VALIDATION CHECK 7: Size field at offset 0x26 ---
; This field must be 0x2000 (8192 bytes), likely a buffer size
; or transfer granularity requirement

    cmpi.w      #0x2000,(0x26,A2)       ; Compare msg_in->field_0x26 with 0x2000
    bne.b       .error_validation_failed ; If not equal, validation failed

; --- VALIDATION CHECK 8: Final field at offset 0x42c ---
; This field must match another global value, likely a size limit
; or maximum buffer capacity

    move.l      (0x42c,A2),D1           ; D1 = msg_in->field_0x42c
    cmp.l       (0x00007d34).l,D1       ; Compare with global at 0x7d34
    beq.b       .perform_operation      ; If equal, all checks passed!

.error_validation_failed:
    ; One or more validation checks failed (checks 3-8)
    ; Set error code and skip operation
    move.l      #-0x130,(0x1c,A3)       ; reply_out->error_code = -0x130 (304)
    bra.b       .check_error_and_setup_response

.perform_operation:
; --- DELEGATE TO OPERATION HANDLER ---
; All validation checks passed successfully
; Extract parameters from message and call FUN_00006340

    ; Build parameter list on stack (right to left for C calling convention)
    ; Parameter 4: Value from offset 0x430
    move.l      (0x430,A2),-(SP)        ; Push param4 = msg_in->field_0x430

    ; Parameter 3: Address of embedded structure at offset 0x2c
    pea         (0x2c,A2)               ; Push param3 = &msg_in->embedded_struct_0x2c

    ; Parameter 2: Address of embedded structure at offset 0x1c
    pea         (0x1c,A2)               ; Push param2 = &msg_in->embedded_struct_0x1c

    ; Parameter 1: Descriptor or handle from offset 0xc
    move.l      (0xc,A2),-(SP)          ; Push param1 = msg_in->field_0xc

    ; Call the operation handler
    ; This function likely performs I/O, DMA, or graphics operations
    bsr.l       0x00006340              ; Call FUN_00006340
                                        ; D0 = return value (operation result)
    ; Stack cleanup: 16 bytes (4 parameters × 4 bytes) removed by BSR return

    ; Store operation result in reply structure
    move.l      D0,(0x24,A3)            ; reply_out->result = return_value

    ; Clear error code to indicate success
    clr.l       (0x1c,A3)               ; reply_out->error_code = 0 (success)

.check_error_and_setup_response:
; --- CONDITIONAL RESPONSE SETUP ---
; Only populate response fields if the operation succeeded (error_code == 0)
; If error_code is non-zero, skip response population

    tst.l       (0x1c,A3)               ; Test if error_code == 0
    bne.b       .epilogue               ; If error occurred, skip response setup

; --- SUCCESS RESPONSE SETUP ---
; Populate response structure with global configuration values
; and copy relevant fields from input message

    ; Copy first global value to response field 0x20
    ; This likely contains board status or capability information
    move.l      (0x00007d38).l,(0x20,A3) ; reply_out->field_0x20 = global_0x7d38

    ; Copy second global value to response field 0x28
    ; This likely contains additional board information
    move.l      (0x00007d3c).l,(0x28,A3) ; reply_out->field_0x28 = global_0x7d3c

    ; Copy field from input message to response
    ; This echoes back part of the request for correlation
    move.l      (0x1c,A2),(0x2c,A3)     ; reply_out->field_0x2c = msg_in->field_0x1c

    ; Set response version to 1
    move.b      #0x1,(0x3,A3)           ; reply_out->version = 1

    ; Set response size to 0x30 (48 bytes)
    moveq       #0x30,D1                ; D1 = 0x30 (use MOVEQ for efficiency)
    move.l      D1,(0x4,A3)             ; reply_out->size = 48

.epilogue:
; --- EPILOGUE: Restore registers and return ---

    movea.l     (-0x8,A6),A2            ; Restore A2 from stack
    movea.l     (-0x4,A6),A3            ; Restore A3 from stack
    unlk        A6                      ; Destroy stack frame
    rts                                 ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD434_Alt
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function serves as a strict validation gate for command 0x434 messages in
; the NDserver's message handling system. It performs 8 validation checks to ensure
; message integrity and parameter correctness before allowing the operation to
; proceed. The validation includes checking message type, version, flags, sizes,
; and comparing critical fields against global configuration values.
;
; The function is part of a family of message handlers and appears to be an
; alternative to the handler at 0x6b7c, possibly handling a different variant
; or operational mode of the same command type. The routing logic that determines
; which handler is invoked likely resides in the message dispatcher (0x6e6c).
;
; On successful validation, the function delegates to FUN_00006340 which performs
; the actual operation (likely I/O, DMA, or graphics-related). The operation
; result is returned to the caller via the reply structure along with global
; configuration values.
;
; All validation failures result in the same error code (-0x130 = 304 decimal),
; which limits diagnostic capability but simplifies error handling. The fail-fast
; design ensures that invalid operations never reach the hardware or lower-level
; handlers.
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_MessageHandler_CMD434_Alt(
;     nd_message_t *msg_in,
;     nd_reply_t *reply_out)
; {
;     // Extract version from message header
;     uint8_t version = msg_in->version;
;
;     // VALIDATION CHECK 1 & 2: Command type and version
;     if (msg_in->command != 0x434 || version != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // VALIDATION CHECK 3: Field 0x18 must match global
;     if (msg_in->field_0x18 != g_address_or_id_0x7d30) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // VALIDATION CHECK 4: Flags must have bits 2&3 set
;     if ((msg_in->field_0x23 & 0x0C) != 0x0C) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // VALIDATION CHECK 5: Field 0x24 must be 12
;     if (msg_in->field_0x24 != 0x000C) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // VALIDATION CHECK 6: Field 0x28 must be 1
;     if (msg_in->field_0x28 != 1) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // VALIDATION CHECK 7: Field 0x26 must be 0x2000 (8192)
;     if (msg_in->field_0x26 != 0x2000) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // VALIDATION CHECK 8: Field 0x42c must match global
;     if (msg_in->field_0x42c != g_size_or_limit_0x7d34) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // All validation passed - perform the actual operation
;     uint32_t result = FUN_00006340(
;         msg_in->field_0xc,
;         &msg_in->field_0x1c,
;         &msg_in->field_0x2c,
;         msg_in->field_0x430
;     );
;
;     // Store operation result
;     reply_out->result = result;
;
;     // Clear error code to indicate success
;     reply_out->error_code = 0;
;
; check_error:
;     // Only populate response fields if operation succeeded
;     if (reply_out->error_code == 0) {
;         // Copy global values to response
;         reply_out->field_0x20 = g_response_val1_0x7d38;
;         reply_out->field_0x28 = g_response_val2_0x7d3c;
;
;         // Copy field from input message
;         reply_out->field_0x2c = msg_in->field_0x1c;
;
;         // Set response metadata
;         reply_out->version = 1;
;         reply_out->size = 0x30;  // 48 bytes
;     }
; }
;
; ====================================================================================
; RELATED FUNCTIONS:
;   - ND_MessageHandler_CMD434 (0x6b7c): Sibling handler for same command
;   - FUN_00006340 (0x6340): Operation handler called after validation
;   - ND_MessageDispatcher (0x6e6c): Likely caller via jump table
;   - ND_ValidateMessageType1 (0x6c48): Similar validation pattern
;
; NEXT STEPS FOR ANALYSIS:
;   1. Analyze FUN_00006340 to understand what operation is performed
;   2. Compare with 0x6b7c handler to identify routing criteria
;   3. Examine globals 0x7d30-0x7d3c initialization
;   4. Trace message dispatcher routing logic
; ====================================================================================
