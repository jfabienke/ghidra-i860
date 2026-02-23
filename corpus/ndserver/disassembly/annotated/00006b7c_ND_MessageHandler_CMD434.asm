; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD434
; ====================================================================================
; Address: 0x00006b7c
; Size: 204 bytes (0xCC)
; Purpose: Message handler for command type 0x434 (1076 decimal)
; Analysis: docs/functions/00006b7c_ND_MessageHandler_CMD434.md
; ====================================================================================

; FUNCTION: void ND_MessageHandler_CMD434(nd_message_t *msg_in, nd_reply_t *reply_out)
;
; Validates and processes Mach IPC messages with command type 0x434. This function
; performs extensive parameter validation (7 distinct checks) before delegating to
; a lower-level I/O operation handler. Part of the NDserver message dispatcher
; jump table system.
;
; PARAMETERS:
;   msg_in (A6+0x8):  Pointer to incoming message structure (1076 bytes)
;   reply_out (A6+0xC): Pointer to reply structure (48 bytes on success)
;
; RETURNS:
;   void (modifies reply_out->error_code and reply_out->result)
;
; ERROR CODES:
;   -0x130 (-304 decimal): Any validation check failed
;   0: Success (all validations passed, operation completed)
;
; STACK FRAME: 0 bytes (no local variables)
;   -0x4: Saved A3 register
;   -0x8: Saved A2 register
;
; VALIDATION CHAIN:
;   1. Message size must be exactly 0x434 (1076 bytes)
;   2. Message version must be 1
;   3. Field at offset 0x18 must match global at 0x7d64
;   4. Flags at offset 0x23 must have bits 2&3 set (value 0x0C)
;   5. Field at offset 0x24 must be 0x0C (12 decimal)
;   6. Field at offset 0x28 must be 1
;   7. Field at offset 0x26 must be 0x2000 (8192 decimal)
;   8. Field at offset 0x42c must match global at 0x7d68
;
; ====================================================================================

FUN_00006b7c:
ND_MessageHandler_CMD434:

    ; --- PROLOGUE: Create stack frame and save registers ---
    0x00006b7c:  link.w     A6,#0x0                   ; Create 0-byte stack frame (frame pointer only)
    0x00006b80:  move.l     A3,-(SP)                  ; Save A3 (callee-save register)
    0x00006b82:  move.l     A2,-(SP)                  ; Save A2 (callee-save register)

    ; Load parameters into address registers for faster access
    0x00006b84:  movea.l    (0x8,A6),A2               ; A2 = msg_in (first parameter)
    0x00006b88:  movea.l    (0xc,A6),A3               ; A3 = reply_out (second parameter)

    ; --- VALIDATION STEP 1: Extract message version byte ---
    ; The message version is stored as a single byte at offset 0x3 in the message
    ; header. We use bit field extract to efficiently read it without loading extra bytes.
    0x00006b8c:  bfextu     (0x3,A2),0x0,0x8,D0       ; Extract 8 bits from msg_in+0x3 to D0
                                                       ; bfextu syntax: source, bit_offset, bit_width, dest
                                                       ; This reads the version byte into D0 (zero-extended)

    ; --- VALIDATION STEP 2: Check message size ---
    ; Message size is at offset 0x4 and must be exactly 0x434 (1076 bytes).
    ; This ensures we have a properly formed message with all expected fields.
.validate_size:
    0x00006b92:  cmpi.l     #0x434,(0x4,A2)           ; Compare msg_in->size with 0x434
    0x00006b9a:  bne.b      .error_invalid_params     ; If size != 0x434, reject message

    ; --- VALIDATION STEP 3: Check message version ---
    ; The protocol version must be 1. This ensures compatibility with the
    ; expected message format and prevents processing of future/unknown versions.
.validate_version:
    0x00006b9c:  moveq      #0x1,D1                   ; Load expected version (1) into D1
                                                       ; moveq is faster and smaller than move.l #1,D1
    0x00006b9e:  cmp.l      D0,D1                     ; Compare extracted version with expected
    0x00006ba0:  beq.b      .validate_field_0x18      ; If version == 1, continue to next check

    ; --- ERROR PATH: Invalid parameters detected ---
    ; This path is taken if either the message size or version is invalid.
    ; We set the standard error code -0x130 (304 decimal) and exit.
.error_invalid_params:
    0x00006ba2:  move.l     #-0x130,(0x1c,A3)         ; reply_out->error_code = -304
    0x00006baa:  bra.w      .epilogue                 ; Jump to function exit (use long branch for range)

    ; --- VALIDATION STEP 4: Check field at offset 0x18 ---
    ; This field must match a global configuration value. This could be a
    ; protocol identifier, security token, or board configuration parameter.
.validate_field_0x18:
    0x00006bae:  move.l     (0x18,A2),D1              ; Load msg_in->field_0x18 into D1
    0x00006bb2:  cmp.l      (0x00007d64).l,D1         ; Compare with global configuration value
                                                       ; .l suffix forces long absolute addressing
    0x00006bb8:  bne.b      .error_field_mismatch     ; If mismatch, reject message

    ; --- VALIDATION STEP 5: Check flags at offset 0x23 ---
    ; These flags control some aspect of the operation. Bits 2 and 3 must both
    ; be set (binary 00001100 = 0x0C). This could indicate direction, type, or mode.
.validate_flags_0x23:
    0x00006bba:  move.b     (0x23,A2),D0b             ; Load flags byte into D0 (byte operation)
    0x00006bbe:  andi.b     #0xc,D0b                  ; Mask bits 2&3 (binary 00001100)
                                                       ; All other bits are ignored
    0x00006bc2:  cmpi.b     #0xc,D0b                  ; Check if both bits are set
    0x00006bc6:  bne.b      .error_field_mismatch     ; If not 0xC, reject

    ; --- VALIDATION STEP 6: Check field at offset 0x24 ---
    ; This 16-bit field must be exactly 12 (0xC). Could be a count, type, or size.
.validate_field_0x24:
    0x00006bc8:  cmpi.w     #0xc,(0x24,A2)            ; Compare msg_in->field_0x24 with 12
    0x00006bce:  bne.b      .error_field_mismatch     ; If not 12, reject

    ; --- VALIDATION STEP 7: Check field at offset 0x28 ---
    ; This field must be 1. Could indicate single operation, first element, or enable flag.
.validate_field_0x28:
    0x00006bd0:  moveq      #0x1,D1                   ; Load expected value (1) into D1
    0x00006bd2:  cmp.l      (0x28,A2),D1              ; Compare msg_in->field_0x28 with 1
    0x00006bd6:  bne.b      .error_field_mismatch     ; If not 1, reject

    ; --- VALIDATION STEP 8: Check field at offset 0x26 ---
    ; This 16-bit field must be 0x2000 (8192 decimal). This is likely a page size,
    ; alignment requirement, or maximum transfer size.
.validate_field_0x26:
    0x00006bd8:  cmpi.w     #0x2000,(0x26,A2)         ; Compare msg_in->field_0x26 with 0x2000
    0x00006bde:  bne.b      .error_field_mismatch     ; If not 0x2000, reject

    ; --- VALIDATION STEP 9: Check field at offset 0x42c ---
    ; Final validation check. This field must match another global configuration value.
    ; The separation of two global checks (0x18 and 0x42c) suggests two different
    ; aspects being validated (e.g., source and destination, or type and subtype).
.validate_field_0x42c:
    0x00006be0:  move.l     (0x42c,A2),D1             ; Load msg_in->field_0x42c into D1
    0x00006be4:  cmp.l      (0x00007d68).l,D1         ; Compare with global configuration value
    0x00006bea:  beq.b      .call_operation_handler   ; If match, all validations passed!

    ; --- ERROR PATH: Field validation failed ---
    ; One of the 6 field validation checks (steps 4-9) failed. Set error and exit.
.error_field_mismatch:
    0x00006bec:  move.l     #-0x130,(0x1c,A3)         ; reply_out->error_code = -304
    0x00006bf4:  bra.b      .check_error_code         ; Jump to error code check (near jump)

    ; --- SUCCESS PATH: All validations passed, execute I/O operation ---
    ; At this point, we've validated 7 distinct message fields. Now we extract
    ; parameters from the message and call the actual I/O operation handler.
.call_operation_handler:
    ; Prepare 4 parameters for FUN_000063e8 (pushed right-to-left, C calling convention)
    ; Parameter layout will be: [field_0xc] [&field_0x1c] [&field_0x2c] [field_0x430]

    0x00006bf6:  move.l     (0x430,A2),-(SP)          ; Push param 4: msg_in->field_0x430 (value)
                                                       ; Likely size, count, or flags for operation

    0x00006bfa:  pea        (0x2c,A2)                 ; Push param 3: &msg_in->field_0x2c (pointer)
                                                       ; PEA = Push Effective Address
                                                       ; This is likely a data buffer or descriptor

    0x00006bfe:  pea        (0x1c,A2)                 ; Push param 2: &msg_in->field_0x1c (pointer)
                                                       ; Another buffer or descriptor (16 bytes based on layout)

    0x00006c02:  move.l     (0xc,A2),-(SP)            ; Push param 1: msg_in->field_0xc (value)
                                                       ; Likely a handle, port, task, or file descriptor

    ; Call the I/O operation handler
    0x00006c06:  bsr.l      0x000063e8                ; Branch to subroutine FUN_000063e8
                                                       ; This function wraps a Mach library call (0x0500222e)
                                                       ; Return value will be in D0

    ; Stack cleanup happens automatically in called function (callee cleans)
    ; Store result and clear error code
    0x00006c0c:  move.l     D0,(0x24,A3)              ; reply_out->result = return_value
    0x00006c10:  clr.l      (0x1c,A3)                 ; reply_out->error_code = 0 (success)

    ; --- CHECK ERROR CODE: Determine if response setup is needed ---
    ; We test the error code we just set. If zero (success), we populate the
    ; response structure with additional fields. If non-zero (error from I/O
    ; operation), we skip response setup and just return the error.
.check_error_code:
    0x00006c14:  tst.l      (0x1c,A3)                 ; Test reply_out->error_code
                                                       ; TST sets condition codes based on value
    0x00006c18:  bne.b      .epilogue                 ; If error_code != 0, skip response setup

    ; --- POPULATE RESPONSE STRUCTURE: Success path only ---
    ; When the operation succeeds, we fill in additional response fields from
    ; global configuration values. This appears to be a capability exchange
    ; mechanism where the server advertises its parameters to the client.
.populate_response:
    0x00006c1a:  move.l     (0x00007d6c).l,(0x20,A3)  ; reply_out->field_0x20 = global_0x7d6c
                                                       ; Global value #3 (response parameter)

    0x00006c22:  move.l     (0x00007d70).l,(0x28,A3)  ; reply_out->field_0x28 = global_0x7d70
                                                       ; Global value #4 (response parameter)

    0x00006c2a:  move.l     (0x1c,A2),(0x2c,A3)       ; reply_out->field_0x2c = msg_in->field_0x1c
                                                       ; Echo a field from input message to output
                                                       ; Could be a correlation ID or handle

    0x00006c30:  move.b     #0x1,(0x3,A3)             ; reply_out->version = 1
                                                       ; Set response version to match protocol

    0x00006c36:  moveq      #0x30,D1                  ; Prepare size value (48 bytes)
    0x00006c38:  move.l     D1,(0x4,A3)               ; reply_out->size = 0x30
                                                       ; Response is always 48 bytes for this command

    ; --- EPILOGUE: Restore registers and return ---
    ; Standard function exit sequence: restore callee-save registers and clean up frame.
.epilogue:
    0x00006c3c:  movea.l    (-0x8,A6),A2              ; Restore A2 from stack (offset from frame pointer)
    0x00006c40:  movea.l    (-0x4,A6),A3              ; Restore A3 from stack
    0x00006c44:  unlk       A6                        ; Destroy stack frame (restore previous A6, adjust SP)
    0x00006c46:  rts                                  ; Return to caller (pop return address and jump)

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD434
; ====================================================================================
;
; FUNCTION SUMMARY:
; This message handler validates incoming Mach IPC messages for command type 0x434
; through a 7-step validation chain before delegating to an I/O operation handler.
; All validation failures return error code -304. On success, it calls FUN_000063e8
; with 4 extracted parameters and populates a 48-byte response structure with global
; configuration values.
;
; CONTROL FLOW PATHS:
; 1. Invalid size/version → Error -304 → Return
; 2. Field validation failure → Error -304 → Return
; 3. All validations pass → Call FUN_000063e8 → Populate response → Return
;
; INTEGRATION:
; - Called by: ND_MessageDispatcher (0x6e6c) via jump table
; - Calls: FUN_000063e8 (I/O wrapper) → Library 0x0500222e (Mach VM operation)
; - Part of handler family: 0x6ac2 (cmd 0x42C), 0x6b7c (cmd 0x434), 0x6c48 (cmd 0x43C)
;
; ====================================================================================
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_MessageHandler_CMD434(nd_message_t *msg_in, nd_reply_t *reply_out)
; {
;     uint8_t msg_version;
;     int32_t result;
;
;     // Extract message version byte
;     msg_version = *((uint8_t *)((uint32_t)msg_in + 0x3));
;
;     // Validation chain - any failure returns error -304
;     if (msg_in->size != 0x434 || msg_version != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     if (msg_in->field_0x18 != g_config_value_0x7d64) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     if ((msg_in->flags_0x23 & 0x0C) != 0x0C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     if (msg_in->field_0x24 != 0x0C || msg_in->field_0x28 != 1 ||
;         msg_in->field_0x26 != 0x2000) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     if (msg_in->field_0x42c != g_config_value_0x7d68) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // All validations passed - execute operation
;     result = FUN_000063e8(
;         msg_in->field_0xc,
;         &msg_in->field_0x1c,
;         &msg_in->field_0x2c,
;         msg_in->field_0x430
;     );
;
;     reply_out->result = result;
;     reply_out->error_code = 0;
;
;     // Populate response on success
;     if (reply_out->error_code == 0) {
;         reply_out->field_0x20 = g_response_value_0x7d6c;
;         reply_out->field_0x28 = g_response_value_0x7d70;
;         reply_out->field_0x2c = msg_in->field_0x1c;
;         reply_out->version = 1;
;         reply_out->size = 0x30;
;     }
; }
;
; ====================================================================================
