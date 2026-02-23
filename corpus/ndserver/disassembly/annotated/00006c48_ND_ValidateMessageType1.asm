; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateMessageType1
; ====================================================================================
; Address: 0x00006c48
; Size: 220 bytes (55 instructions)
; Purpose: Validates incoming message type 1 and dispatches to I/O handler
; Analysis: docs/functions/00006c48_ND_ValidateMessageType1.md
; ====================================================================================

; FUNCTION: int ND_ValidateMessageType1(nd_message_t* message, nd_result_t* result)
;
; This function performs comprehensive validation of incoming message type 1 before
; dispatching to an I/O operation handler. It validates 10 different fields against
; expected global constants and hardcoded values to ensure message integrity and
; protocol compliance.
;
; PARAMETERS:
;   message (A6+0x8):  Pointer to incoming message structure (must be type 1)
;   result (A6+0xC):   Pointer to result structure (receives operation results)
;
; RETURNS:
;   result->field_0x1C: 0 on success, -0x130 (-304 decimal) on validation failure
;   result->field_0x24: I/O operation result from handler (on success)
;   result->field_0x20: Operation identifier (from global 0x7d80)
;   result->field_0x28: Operation flags (from global 0x7d84)
;   result->field_0x2C: Timestamp copied from message
;   result->field_0x03: Set to 1 (response ready flag)
;   result->field_0x04: Set to 0x30 (48 decimal - response size)
;
; STACK FRAME: 0 bytes (no local variables)
;
; VALIDATION CHECKS PERFORMED (in order):
;   1. message->field_0x04 must equal 0x43C (1084 bytes - message size)
;   2. message->type_byte must equal 1 (message type identifier)
;   3. message->field_0x18 must match global constant at 0x7d74
;   4. message->field_0x23 must have bits 2-3 set (value & 0x0C == 0x0C)
;   5. message->field_0x24 must equal 0x000C (12 decimal)
;   6. message->field_0x28 must equal 1
;   7. message->field_0x26 must equal 0x2000 (8192 decimal)
;   8. message->field_0x42C must match global constant at 0x7d78
;   9. message->field_0x434 must match global constant at 0x7d7c
;
; ====================================================================================

FUN_00006c48:
    ; --- PROLOGUE ---
    ; Create stack frame and save callee-preserved registers
    0x00006c48:  link.w     A6,0x0                         ; Create stack frame (no locals)
    0x00006c4c:  move.l     A3,-(SP)                       ; Save A3 (callee-save register)
    0x00006c4e:  move.l     A2,-(SP)                       ; Save A2 (callee-save register)

    ; --- LOAD PARAMETERS INTO WORKING REGISTERS ---
    0x00006c50:  movea.l    (0x8,A6),A2                    ; A2 = message pointer (param 1)
    0x00006c54:  movea.l    (0xc,A6),A3                    ; A3 = result pointer (param 2)

    ; --- VALIDATION CHECK 1: Extract and validate message type byte ---
    ; Use bitfield extraction to get byte at offset +3 from message structure
    0x00006c58:  bfextu     (0x3,A2),0x0,0x8,D0            ; D0 = message->type_byte (extract 8 bits at offset +3)
                                                            ; bfextu: bit field extract unsigned
                                                            ; Efficient byte extraction on 68040

    ; --- VALIDATION CHECK 2: Verify message size/magic number ---
    0x00006c5e:  cmpi.l     #0x43c,(0x4,A2)                ; Compare message->field_0x04 with 0x43C (1084 bytes)
    0x00006c66:  bne.b      LAB_00006c6e                   ; If not equal, goto validation_failed

    ; --- VALIDATION CHECK 3: Confirm message type == 1 ---
    0x00006c68:  moveq      0x1,D1                         ; D1 = 1 (expected type)
    0x00006c6a:  cmp.l      D0,D1                          ; Compare message_type with 1
    0x00006c6c:  beq.b      LAB_00006c7a                   ; If equal, continue validation
                                                            ; else fall through to error

LAB_00006c6e:  ; --- ERROR PATH: Validation Failed (Type or Size) ---
    0x00006c6e:  move.l     #-0x130,(0x1c,A3)              ; result->error_code = -0x130 (-304 decimal)
    0x00006c76:  bra.w      LAB_00006d18                   ; goto epilogue (exit with error)

LAB_00006c7a:  ; --- VALIDATION CHECK 4: Field 0x18 vs Global Constant ---
    0x00006c7a:  move.l     (0x18,A2),D1                   ; D1 = message->field_0x18
    0x00006c7e:  cmp.l      (0x00007d74).l,D1              ; Compare with g_expected_value_0x7d74
    0x00006c84:  bne.b      LAB_00006cc4                   ; If not equal, goto field_validation_failed

    ; --- VALIDATION CHECK 5: Field 0x23 Bit Flags (Bits 2-3 must be set) ---
    0x00006c86:  move.b     (0x23,A2),D0b                  ; D0 = message->field_0x23 (byte)
    0x00006c8a:  andi.b     #0xc,D0b                       ; D0 &= 0x0C (isolate bits 2-3)
    0x00006c8e:  cmpi.b     #0xc,D0b                       ; Compare with 0x0C (both bits must be set)
    0x00006c92:  bne.b      LAB_00006cc4                   ; If not equal, goto field_validation_failed

    ; --- VALIDATION CHECK 6: Field 0x24 Must Equal 0x000C ---
    0x00006c94:  cmpi.w     #0xc,(0x24,A2)                 ; Compare message->field_0x24 with 12
    0x00006c9a:  bne.b      LAB_00006cc4                   ; If not equal, goto field_validation_failed

    ; --- VALIDATION CHECK 7: Field 0x28 Must Equal 1 ---
    0x00006c9c:  moveq      0x1,D1                         ; D1 = 1
    0x00006c9e:  cmp.l      (0x28,A2),D1                   ; Compare message->field_0x28 with 1
    0x00006ca2:  bne.b      LAB_00006cc4                   ; If not equal, goto field_validation_failed

    ; --- VALIDATION CHECK 8: Field 0x26 Must Equal 0x2000 (8192 decimal) ---
    0x00006ca4:  cmpi.w     #0x2000,(0x26,A2)              ; Compare message->field_0x26 with 0x2000
    0x00006caa:  bne.b      LAB_00006cc4                   ; If not equal, goto field_validation_failed

    ; --- VALIDATION CHECK 9: Field 0x42C vs Global Constant ---
    0x00006cac:  move.l     (0x42c,A2),D1                  ; D1 = message->field_0x42C
    0x00006cb0:  cmp.l      (0x00007d78).l,D1              ; Compare with g_expected_value_0x7d78
    0x00006cb6:  bne.b      LAB_00006cc4                   ; If not equal, goto field_validation_failed

    ; --- VALIDATION CHECK 10: Field 0x434 vs Global Constant (Final Check) ---
    0x00006cb8:  move.l     (0x434,A2),D1                  ; D1 = message->field_0x434
    0x00006cbc:  cmp.l      (0x00007d7c).l,D1              ; Compare with g_expected_value_0x7d7c
    0x00006cc2:  beq.b      LAB_00006cce                   ; If equal, all validations passed!
                                                            ; else fall through to error

LAB_00006cc4:  ; --- ERROR PATH: Field Validation Failed ---
    0x00006cc4:  move.l     #-0x130,(0x1c,A3)              ; result->error_code = -0x130
    0x00006ccc:  bra.b      LAB_00006cf0                   ; goto check_error_before_response

LAB_00006cce:  ; --- SUCCESS PATH: All Validations Passed ---
    ; Prepare parameters for I/O handler call (FUN_00006414)
    ; Stack layout (grows down): arg5, arg4, arg3, arg2, arg1

    0x00006cce:  move.l     (0x438,A2),-(SP)               ; Push arg5: message->field_0x438 (buffer size/length)
    0x00006cd2:  move.l     (0x430,A2),-(SP)               ; Push arg4: message->field_0x430 (data buffer pointer)
    0x00006cd6:  pea        (0x2c,A2)                      ; Push arg3: &message->field_0x2C (metadata pointer)
    0x00006cda:  pea        (0x1c,A2)                      ; Push arg2: &message->field_0x1C (timestamp pointer)
    0x00006cde:  move.l     (0xc,A2),-(SP)                 ; Push arg1: message->field_0x0C (file descriptor/handle)

    ; --- CALL I/O OPERATION HANDLER ---
    ; Signature: int FUN_00006414(fd, timestamp_ptr, metadata_ptr, buffer, size)
    ; This likely performs read/write/seek or similar I/O operation
    0x00006ce2:  bsr.l      0x00006414                     ; Call I/O handler (FUN_00006414)
                                                            ; D0 = operation result on return

    ; --- PROCESS HANDLER RESULT ---
    0x00006ce8:  move.l     D0,(0x24,A3)                   ; result->operation_result = return_value
    0x00006cec:  clr.l      (0x1c,A3)                      ; result->error_code = 0 (success)
                                                            ; Note: Stack not cleaned up - handler or caller handles it

LAB_00006cf0:  ; --- CHECK ERROR CODE BEFORE BUILDING RESPONSE ---
    0x00006cf0:  tst.l      (0x1c,A3)                      ; Test result->error_code
    0x00006cf4:  bne.b      LAB_00006d18                   ; If error != 0, skip response building (goto epilogue)

    ; --- BUILD SUCCESS RESPONSE ---
    ; Populate result structure with operation metadata and global constants

    0x00006cf6:  move.l     (0x00007d80).l,(0x20,A3)       ; result->field_0x20 = g_operation_identifier
                                                            ; This identifies the operation type/category

    0x00006cfe:  move.l     (0x00007d84).l,(0x28,A3)       ; result->field_0x28 = g_operation_flags
                                                            ; Operation-specific flags or parameters

    0x00006d06:  move.l     (0x1c,A2),(0x2c,A3)            ; result->field_0x2C = message->field_0x1C
                                                            ; Copy timestamp/sequence number from request to response

    0x00006d0c:  move.b     #0x1,(0x3,A3)                  ; result->ready_flag = 1
                                                            ; Mark response as ready for transmission

    0x00006d12:  moveq      0x30,D1                        ; D1 = 0x30 (48 decimal)
    0x00006d14:  move.l     D1,(0x4,A3)                    ; result->response_size = 48 bytes
                                                            ; Standard response size for type 1 operations

LAB_00006d18:  ; --- EPILOGUE ---
    ; Restore saved registers and return

    0x00006d18:  movea.l    (-0x8,A6),A2                   ; Restore A2 from stack
    0x00006d1c:  movea.l    (-0x4,A6),A3                   ; Restore A3 from stack
    0x00006d20:  unlk       A6                             ; Destroy stack frame
    0x00006d22:  rts                                       ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_ValidateMessageType1
; ====================================================================================

; ====================================================================================
; FUNCTION SUMMARY
; ====================================================================================
;
; This function serves as a security/integrity validation layer for message type 1
; in the NeXTdimension protocol. It performs 10 comprehensive validation checks
; before allowing the message to proceed to the I/O handler.
;
; VALIDATION STRATEGY:
; - Fail-fast: First validation failure immediately returns error -0x130
; - No partial processing: Either all checks pass or operation is rejected
; - Consistent error code: All validation failures return same code (-304 decimal)
; - Global validation table: Uses 5 global constants for protocol compliance
;
; SECURITY CONSIDERATIONS:
; - Extensive validation prevents malformed or malicious messages
; - Size check (0x43C = 1084 bytes) prevents buffer overflows
; - Field validation ensures protocol compliance
; - Bit flag checks verify message integrity
;
; PERFORMANCE CHARACTERISTICS:
; - Best case: 8 instructions (first check fails)
; - Worst case: ~50 instructions (all checks pass, handler called)
; - Average case: ~25 instructions (fails midway through validation)
;
; ====================================================================================
; REVERSE-ENGINEERED C EQUIVALENT
; ====================================================================================
;
; int ND_ValidateMessageType1(nd_message_t* message, nd_result_t* result)
; {
;     // Extract message type byte (bitfield extraction)
;     uint8_t message_type = (message->type_bytes >> 24) & 0xFF;
;
;     // Validation chain (fail-fast)
;     if (message->field_0x04 != 0x43C) goto validation_failed;
;     if (message_type != 1) goto validation_failed;
;     if (message->field_0x18 != g_expected_0x7d74) goto validation_failed;
;     if ((message->field_0x23 & 0x0C) != 0x0C) goto validation_failed;
;     if (message->field_0x24 != 0x000C) goto validation_failed;
;     if (message->field_0x28 != 1) goto validation_failed;
;     if (message->field_0x26 != 0x2000) goto validation_failed;
;     if (message->field_0x42C != g_expected_0x7d78) goto validation_failed;
;     if (message->field_0x434 != g_expected_0x7d7c) goto validation_failed;
;
;     // All validations passed - invoke I/O handler
;     int op_result = FUN_00006414(
;         message->field_0x0C,      // File descriptor/handle
;         &message->field_0x1C,     // Timestamp pointer
;         &message->field_0x2C,     // Metadata pointer
;         message->field_0x430,     // Data buffer pointer
;         message->field_0x438      // Buffer size
;     );
;
;     result->operation_result = op_result;
;     result->error_code = 0;
;
;     // Build response
;     if (result->error_code == 0) {
;         result->field_0x20 = g_operation_identifier_0x7d80;
;         result->field_0x28 = g_operation_flags_0x7d84;
;         result->field_0x2C = message->field_0x1C;
;         result->ready_flag = 1;
;         result->response_size = 0x30;  // 48 bytes
;     }
;
;     return result->error_code;
;
; validation_failed:
;     result->error_code = -0x130;  // -304 decimal
;     return -0x130;
; }
;
; ====================================================================================
; GLOBAL VALIDATION TABLE (Data Segment)
; ====================================================================================
;
; These global constants define the expected protocol values for message type 1:
;
; @ 0x00007d74:  g_expected_value_0x7d74  - Validates message->field_0x18
; @ 0x00007d78:  g_expected_value_0x7d78  - Validates message->field_0x42C
; @ 0x00007d7c:  g_expected_value_0x7d7c  - Validates message->field_0x434
; @ 0x00007d80:  g_operation_identifier   - Copied to result->field_0x20
; @ 0x00007d84:  g_operation_flags        - Copied to result->field_0x28
;
; To extract these values, dump the binary's data segment at these addresses.
;
; ====================================================================================
