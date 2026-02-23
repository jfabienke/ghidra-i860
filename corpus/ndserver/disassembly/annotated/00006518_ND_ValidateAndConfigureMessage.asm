; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateAndConfigureMessage
; ====================================================================================
; Address: 0x00006518
; Size: 234 bytes (117 instructions)
; Purpose: Validates message type 0x30 and configures dynamic-size response
; Analysis: docs/functions/00006518_ND_ValidateAndConfigureMessage.md
; ====================================================================================

; FUNCTION: int ND_ValidateAndConfigureMessage(nd_message_t* message, nd_result_t* result)
;
; Performs comprehensive validation of incoming message type 0x30 (48 decimal) before
; dispatching to FUN_0000627a for data processing. Validates message type byte and
; three critical fields against global constants, then builds response structure with
; dynamically calculated size based on processing results.
;
; PARAMETERS:
;   message (A6+0x8):  Pointer to message structure (type 0x30, message type 0x1)
;   result (A6+0xC):   Pointer to result structure (receives response configuration)
;
; RETURNS:
;   result->field_0x1C: 0 on success, -0x130 (304 decimal) on validation failure
;   result->field_0x24: Operation result from FUN_0000627a
;   result->field_0x04: Total response size = 0x3C + ((payload_size + 3) & ~3)
;
; STACK FRAME: 4 bytes
;   -0x4(A6): uint32_t payload_size (written by FUN_0000627a)
;
; VALIDATION SEQUENCE:
;   1. message->type_byte must == 0x1
;   2. message->field_0x04 must == 0x30 (48 decimal)
;   3. message->field_0x18 must == global_constant_0x7CDC
;   4. message->field_0x20 must == global_constant_0x7CE0
;   5. message->field_0x28 must == global_constant_0x7CE4
;
; ====================================================================================

FUN_00006518:
; --- PROLOGUE ---
    link.w      A6, #-0x4                 ; Create 4-byte stack frame for payload_size
    move.l      A3, -(SP)                 ; Save A3 (callee-save register)
    move.l      A2, -(SP)                 ; Save A2 (callee-save register)

; --- LOAD PARAMETERS ---
    movea.l     (0x8,A6), A3              ; A3 = message pointer (first parameter)
    movea.l     (0xc,A6), A2              ; A2 = result pointer (second parameter)

; --- VALIDATION PHASE 1: MESSAGE TYPE BYTE ---
; Extract and validate the message type byte at offset +0x3
    clr.l       D0                        ; Clear D0 to ensure zero-extension
    move.b      (0x3,A3), D0b             ; D0 = message->type_byte (offset +0x3)
                                          ; No bitfield extraction needed, direct byte load

; --- VALIDATION PHASE 2: MESSAGE SIZE/MAGIC FIELD ---
; Check that field_0x04 contains the expected message type value 0x30
    moveq       #0x30, D1                 ; D1 = 0x30 (48 decimal, expected value)
    cmp.l       (0x4,A3), D1              ; Compare message->field_0x04 with 0x30
    bne.b       .validation_failed_early  ; Branch if not equal → validation failed

; --- VALIDATION PHASE 3: TYPE BYTE VALUE CHECK ---
; Verify that the type byte extracted earlier equals 0x1
    moveq       #0x1, D1                  ; D1 = 1 (expected type byte value)
    cmp.l       D0, D1                    ; Compare type_byte with 1
    beq.b       .type_valid               ; Branch if equal → type is valid
                                          ; Fall through to error if not equal

.validation_failed_early:
; --- ERROR PATH A: BASIC VALIDATION FAILED ---
; Either field_0x04 != 0x30 OR type_byte != 0x1
    move.l      #-0x130, (0x1c,A2)        ; result->error_code = -0x130 (304 decimal)
    bra.w       .epilogue                 ; Jump to epilogue, exit with error
                                          ; (Response structure not populated)

.type_valid:
; --- VALIDATION PHASE 4: FIELD 0x18 VS GLOBAL CONSTANT ---
; First of three field validations against global protocol constants
    move.l      (0x18,A3), D1             ; D1 = message->field_0x18
    cmp.l       (0x00007cdc).l, D1        ; Compare with global constant at 0x7CDC
    bne.b       .field_validation_failed  ; Branch if not equal → field validation failed

; --- VALIDATION PHASE 5: FIELD 0x20 VS GLOBAL CONSTANT ---
; Second field validation
    move.l      (0x20,A3), D1             ; D1 = message->field_0x20
    cmp.l       (0x00007ce0).l, D1        ; Compare with global constant at 0x7CE0
    bne.b       .field_validation_failed  ; Branch if not equal → field validation failed

; --- INITIALIZE LOCAL PAYLOAD SIZE VARIABLE ---
; Store magic constant 0x1EDC (7900 bytes) - may be default or max size
; NOTE: This value will be overwritten by FUN_0000627a
    move.l      #0x1edc, (-0x4,A6)        ; local_payload_size = 0x1EDC (7900 decimal)
                                          ; Speculation: Max payload size or sentinel value

; --- VALIDATION PHASE 6: FIELD 0x28 VS GLOBAL CONSTANT ---
; Third and final field validation
    move.l      (0x28,A3), D1             ; D1 = message->field_0x28
    cmp.l       (0x00007ce4).l, D1        ; Compare with global constant at 0x7CE4
    beq.b       .all_validations_passed   ; Branch if equal → all validations passed!
                                          ; Fall through to error if not equal

.field_validation_failed:
; --- ERROR PATH B: FIELD VALIDATION FAILED ---
; One of the three global constant comparisons failed
    move.l      #-0x130, (0x1c,A2)        ; result->error_code = -0x130 (304 decimal)
    bra.b       .check_error_status       ; Jump to error status check

.all_validations_passed:
; --- CALL INTERNAL DATA PROCESSING FUNCTION ---
; All validations passed, now perform the core data operation
; Function: FUN_0000627a(param1, param2, param3, param4, param5, param6)

; Push parameters in reverse order (right-to-left, m68k convention)
    move.l      (0x2c,A3), -(SP)          ; Param 6: message->field_0x2C (operation flags?)
    pea         (-0x4,A6)                 ; Param 5: &local_payload_size (OUTPUT parameter)
    pea         (0x3c,A2)                 ; Param 4: &result->field_0x3C (output buffer)
    move.l      (0x24,A3), -(SP)          ; Param 3: message->field_0x24 (operation param)
    pea         (0x1c,A3)                 ; Param 2: &message->field_0x1C (metadata/timestamp)
    move.l      (0xc,A3), -(SP)           ; Param 1: message->field_0x0C (source address/handle)

    bsr.l       0x0000627a                ; Call FUN_0000627a (data processor)
                                          ; Expected behavior:
                                          ;   - Processes data based on parameters
                                          ;   - Writes output to result->field_0x3C
                                          ;   - Writes bytes written to *param5 (local_payload_size)
                                          ;   - Returns operation status in D0
                                          ; Stack: 6 params × 4 bytes = 24 bytes pushed

; --- STORE OPERATION RESULT AND CLEAR ERROR CODE ---
    move.l      D0, (0x24,A2)             ; result->operation_result = D0 (from FUN_0000627a)
    clr.l       (0x1c,A2)                 ; result->error_code = 0 (success)

.check_error_status:
; --- CONDITIONAL RESPONSE BUILDING ---
; Common merge point for success and error paths
; Only build response structure if error_code == 0
    tst.l       (0x1c,A2)                 ; Test result->error_code
    bne.b       .epilogue                 ; If error (non-zero), skip response building

; --- BUILD SUCCESS RESPONSE STRUCTURE ---
; Populate response metadata fields from global constants

; Copy operation identifiers and flags from global constant table
    move.l      (0x00007ce8).l, (0x20,A2) ; result->field_0x20 = g_operation_id_0x7CE8
    move.l      (0x00007cec).l, (0x28,A2) ; result->field_0x28 = g_operation_flags_0x7CEC

; Echo message timestamp/sequence number to result
    move.l      (0x1c,A3), (0x2c,A2)      ; result->field_0x2C = message->field_0x1C

; Copy additional response metadata from global constants
    move.l      (0x00007cf0).l, (0x30,A2) ; result->field_0x30 = g_metadata_0x7CF0
    move.l      (0x00007cf4).l, (0x34,A2) ; result->field_0x34 = g_metadata_0x7CF4
    move.l      (0x00007cf8).l, (0x38,A2) ; result->field_0x38 = g_metadata_0x7CF8 (temporary)

; --- OVERWRITE WITH ACTUAL PAYLOAD SIZE ---
; Replace the global constant at field_0x38 with actual size from processing function
    move.l      (-0x4,A6), (0x38,A2)      ; result->field_0x38 = actual_payload_size
                                          ; (This overwrites the global constant written above)

; --- CALCULATE ALIGNED TOTAL SIZE ---
; Algorithm: total_size = 0x3C + ((payload_size + 3) & ~3)
; This ensures 4-byte alignment of payload for DMA/network efficiency

; Load payload size and prepare for alignment
    move.l      (-0x4,A6), D0             ; D0 = local_payload_size (from FUN_0000627a)
    addq.l      #0x3, D0                  ; D0 += 3 (prepare for round-down alignment)
    moveq       #-0x4, D1                 ; D1 = 0xFFFFFFFC (4-byte alignment mask)
    and.l       D1, D0                    ; D0 = (payload_size + 3) & 0xFFFFFFFC
                                          ; Example: size=101 → (101+3)&~3 = 104
                                          ;          size=100 → (100+3)&~3 = 100

; --- SET RESPONSE READY FLAG ---
    move.b      #0x1, (0x3,A2)            ; result->type_byte = 0x1 (response ready)

; --- CALCULATE AND STORE TOTAL SIZE ---
    moveq       #0x3c, D1                 ; D1 = 0x3C (60 decimal, header size)
    add.l       D0, D1                    ; D1 = 0x3C + aligned_payload_size
    move.l      D1, (0x4,A2)              ; result->field_0x04 = total_size
                                          ; Total size includes:
                                          ;   - Header: 60 bytes (0x00-0x3B)
                                          ;   - Payload: aligned size (starts at 0x3C)

.epilogue:
; --- EPILOGUE ---
; Restore saved registers and clean up stack frame
    movea.l     (-0xc,A6), A2             ; Restore A2 from stack offset -0xC
    movea.l     (-0x8,A6), A3             ; Restore A3 from stack offset -0x8
    unlk        A6                        ; Destroy stack frame, restore old A6, SP
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_ValidateAndConfigureMessage
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This function validates incoming message type 0x30 through a 5-stage validation
; process, then dispatches to FUN_0000627a for data processing. On success, it builds
; a response structure with dynamically calculated size based on the actual payload
; written by the processing function. The size is 4-byte aligned for efficient
; DMA/network transmission.
;
; Key behaviors:
; - Fail-fast validation: Any check failure immediately returns error -0x130
; - Triple constant validation: Ensures message authenticity via global comparisons
; - Dynamic sizing: Response size calculated at runtime, not fixed
; - 4-byte alignment: Ensures payload size is multiple of 4 for hardware efficiency
;
; ====================================================================================
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int ND_ValidateAndConfigureMessage(nd_message_t* message, nd_result_t* result)
; {
;     uint32_t payload_size;
;     int operation_result;
;
;     // Phase 1: Basic validation
;     uint8_t message_type = message->type_byte;
;     if (message->field_0x04 != 0x30) {
;         result->error_code = -0x130;
;         return -0x130;
;     }
;     if (message_type != 0x1) {
;         result->error_code = -0x130;
;         return -0x130;
;     }
;
;     // Phase 2: Field validation against global constants
;     if (message->field_0x18 != g_expected_0x7CDC) {
;         result->error_code = -0x130;
;         goto cleanup;
;     }
;     if (message->field_0x20 != g_expected_0x7CE0) {
;         result->error_code = -0x130;
;         goto cleanup;
;     }
;
;     // Initialize with magic constant (gets overwritten)
;     payload_size = 0x1EDC;  // 7900 bytes
;
;     if (message->field_0x28 != g_expected_0x7CE4) {
;         result->error_code = -0x130;
;         goto cleanup;
;     }
;
;     // Phase 3: Process data operation
;     operation_result = FUN_0000627a(
;         message->field_0x0C,        // Source/handle
;         &message->field_0x1C,       // Metadata
;         message->field_0x24,        // Operation param
;         &result->field_0x3C,        // Output buffer
;         &payload_size,              // Output size (modified by call)
;         message->field_0x2C         // Flags
;     );
;
;     result->operation_result = operation_result;
;     result->error_code = 0;
;
; cleanup:
;     if (result->error_code != 0) {
;         return result->error_code;
;     }
;
;     // Phase 4: Build response structure
;     result->field_0x20 = g_const_0x7CE8;
;     result->field_0x28 = g_const_0x7CEC;
;     result->field_0x2C = message->field_0x1C;
;     result->field_0x30 = g_const_0x7CF0;
;     result->field_0x34 = g_const_0x7CF4;
;     result->field_0x38 = payload_size;  // Actual size
;
;     // Phase 5: Calculate aligned total size
;     uint32_t aligned_payload = (payload_size + 3) & ~3;
;     result->type_byte = 0x1;
;     result->field_0x04 = 0x3C + aligned_payload;
;
;     return 0;
; }
;
; ====================================================================================
;
; DATA STRUCTURES ACCESSED:
;
; nd_message_t (input):
;   +0x03: type_byte (must be 0x1)
;   +0x04: field_0x04 (must be 0x30)
;   +0x0C: field_0x0C (param to FUN_0000627a)
;   +0x18: field_0x18 (validated vs 0x7CDC)
;   +0x1C: field_0x1C (metadata/timestamp)
;   +0x20: field_0x20 (validated vs 0x7CE0)
;   +0x24: field_0x24 (param to FUN_0000627a)
;   +0x28: field_0x28 (validated vs 0x7CE4)
;   +0x2C: field_0x2C (param to FUN_0000627a)
;
; nd_result_t (output):
;   +0x03: type_byte (set to 0x1)
;   +0x04: field_0x04 (total size = 0x3C + aligned_payload)
;   +0x1C: error_code (0 or -0x130)
;   +0x20: field_0x20 (from g_const_0x7CE8)
;   +0x24: operation_result (from FUN_0000627a)
;   +0x28: field_0x28 (from g_const_0x7CEC)
;   +0x2C: field_0x2C (echoed from message)
;   +0x30: field_0x30 (from g_const_0x7CF0)
;   +0x34: field_0x34 (from g_const_0x7CF4)
;   +0x38: field_0x38 (actual payload size)
;   +0x3C: payload_data[] (variable length, written by FUN_0000627a)
;
; Global Constants (data segment):
;   0x7CDC: Validation constant for field_0x18
;   0x7CE0: Validation constant for field_0x20
;   0x7CE4: Validation constant for field_0x28
;   0x7CE8: Response field_0x20 value
;   0x7CEC: Response field_0x28 value
;   0x7CF0: Response field_0x30 value
;   0x7CF4: Response field_0x34 value
;   0x7CF8: Response field_0x38 placeholder (overwritten)
;
; ====================================================================================
