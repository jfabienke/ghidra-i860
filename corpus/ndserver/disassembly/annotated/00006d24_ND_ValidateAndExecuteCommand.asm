; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateAndExecuteCommand
; ====================================================================================
; Address: 0x00006d24
; Size: 192 bytes (48 instructions)
; Purpose: Validate command message and execute command 0x38 handler
; Analysis: docs/functions/00006d24_ND_ValidateAndExecuteCommand.md
; ====================================================================================

; FUNCTION: ND_ValidateAndExecuteCommand
;
; This function validates incoming command messages for command 0x38 by checking:
; 1. Command ID is 0x38 (56 decimal)
; 2. Message subtype is 0x1
; 3. Four critical parameters match global expected values
;
; Only if ALL validation passes does it call the actual command handler.
; On success, builds standardized 48-byte response message.
; On failure, sets error code -0x130 (-304 decimal).
;
; PARAMETERS:
;   command_message (8(A6)): Pointer to incoming command message structure
;   response_message (12(A6)): Pointer to response message structure to populate
;
; RETURNS:
;   D0 = 0 if all validations passed and command executed successfully
;   D0 = -0x130 (-304) if any validation check failed
;
; STACK FRAME: 0 bytes (no local variables)
;   Saved registers: A2, A3 (8 bytes total)
;
; ====================================================================================

FUN_00006d24:
ND_ValidateAndExecuteCommand:

    ; --- PROLOGUE ---
    ; Create standard stack frame and save callee-save registers
    link.w      A6, #0x0                          ; Create stack frame (no locals)
    move.l      A3, -(SP)                         ; Save A3 (will hold command_message)
    move.l      A2, -(SP)                         ; Save A2 (will hold response_message)

    ; --- LOAD FUNCTION ARGUMENTS ---
    ; Load message structure pointers into address registers for fast access
    movea.l     (0x8,A6), A3                      ; A3 = command_message (arg1)
    movea.l     (0xc,A6), A2                      ; A2 = response_message (arg2)

    ; --- VALIDATION CHECK 1: EXTRACT MESSAGE SUBTYPE ---
    ; Use bitfield extraction to get byte at offset +3 from command message
    ; This is likely the message subtype field
    bfextu      (0x3,A3), #0x0, #0x8, D0          ; D0 = cmd_msg->byte_at_offset_3
                                                  ; Extract 8 bits starting at bit 0

    ; --- VALIDATION CHECK 2: VERIFY COMMAND ID ---
    ; Check if this is the expected command type (0x38 = 56 decimal)
    moveq       #0x38, D1                         ; D1 = 0x38 (expected command ID)
    cmp.l       (0x4,A3), D1                      ; Compare cmd_msg->command_id vs 0x38
    bne.b       .validation_failed_early          ; If not equal, abort immediately

    ; --- VALIDATION CHECK 3: VERIFY MESSAGE SUBTYPE ---
    ; Ensure the extracted subtype is 0x1 (specific variant of command 0x38)
    moveq       #0x1, D1                          ; D1 = 1 (expected subtype)
    cmp.l       D0, D1                            ; Compare extracted subtype vs 1
    beq.b       .subtype_valid                    ; If equal, continue to parameter checks

    ; --- ERROR PATH 1: COMMAND ID OR SUBTYPE INVALID ---
    ; Reached if command_id != 0x38 OR subtype != 0x1
.validation_failed_early:
    move.l      #-0x130, (0x1c,A2)                ; response->error_code = -0x130 (-304)
    bra.w       .epilogue                         ; Skip everything, return error

    ; --- VALIDATION CHECK 4: VERIFY PARAMETER 1 ---
    ; All basic validation passed, now check critical parameters against globals
    ; These globals likely contain expected board configuration values
.subtype_valid:
    move.l      (0x18,A3), D1                     ; D1 = cmd_msg->param1
    cmp.l       (0x00007d88).l, D1                ; Compare vs global_expected_param1
    bne.b       .parameter_validation_failed      ; Branch if mismatch

    ; --- VALIDATION CHECK 5: VERIFY PARAMETER 2 ---
    move.l      (0x20,A3), D1                     ; D1 = cmd_msg->param2
    cmp.l       (0x00007d8c).l, D1                ; Compare vs global_expected_param2
    bne.b       .parameter_validation_failed      ; Branch if mismatch

    ; --- VALIDATION CHECK 6: VERIFY PARAMETER 3 ---
    move.l      (0x28,A3), D1                     ; D1 = cmd_msg->param3
    cmp.l       (0x00007d90).l, D1                ; Compare vs global_expected_param3
    bne.b       .parameter_validation_failed      ; Branch if mismatch

    ; --- VALIDATION CHECK 7: VERIFY PARAMETER 4 ---
    ; Final validation check - if this passes, all validation succeeded
    move.l      (0x30,A3), D1                     ; D1 = cmd_msg->param4
    cmp.l       (0x00007d94).l, D1                ; Compare vs global_expected_param4
    beq.b       .all_validation_passed            ; If equal, execute command

    ; --- ERROR PATH 2: PARAMETER VALIDATION FAILED ---
    ; Reached if any of the 4 parameter comparisons failed
.parameter_validation_failed:
    move.l      #-0x130, (0x1c,A2)                ; response->error_code = -0x130 (-304)
    bra.b       .check_for_success                ; Jump to success check (will skip response)

    ; --- COMMAND EXECUTION ---
    ; All 5 validation checks passed - safe to execute command handler
    ; Push 5 arguments to handler in reverse order (right-to-left C calling convention)
.all_validation_passed:
    move.l      (0x34,A3), -(SP)                  ; arg5 = cmd_msg->field_0x34
    move.l      (0x2c,A3), -(SP)                  ; arg4 = cmd_msg->field_0x2C
    move.l      (0x24,A3), -(SP)                  ; arg3 = cmd_msg->field_0x24
    pea         (0x1c,A3)                         ; arg2 = &cmd_msg->field_0x1C (pointer!)
    move.l      (0xc,A3), -(SP)                   ; arg1 = cmd_msg->field_0x0C

    ; Call the actual command implementation handler
    ; This function performs the real work for command 0x38
    bsr.l       FUN_00006444                      ; CALL command handler
                                                  ; (FUN_00006444 to be analyzed)

    ; Store handler's return value in response structure
    move.l      D0, (0x24,A2)                     ; response->result = handler_return_value

    ; Clear error code to indicate success
    clr.l       (0x1c,A2)                         ; response->error_code = 0 (SUCCESS)

    ; --- SUCCESS PATH: BUILD RESPONSE MESSAGE ---
    ; Populate response message with standard fields (only if no error)
.check_for_success:
    tst.l       (0x1c,A2)                         ; Test if error_code == 0
    bne.b       .epilogue                         ; If error set, skip response building

    ; Build standardized response message using global template values
    move.l      (0x00007d98).l, (0x20,A2)         ; response->field_0x20 = global_value_1
    move.l      (0x00007d9c).l, (0x28,A2)         ; response->field_0x28 = global_value_2
    move.l      (0x1c,A3), (0x2c,A2)              ; response->field_0x2C = cmd_msg->field_0x1C
    move.b      #0x1, (0x3,A2)                    ; response->subtype = 1
    moveq       #0x30, D1                         ; D1 = 0x30 (48 bytes)
    move.l      D1, (0x4,A2)                      ; response->message_size = 48

    ; --- EPILOGUE ---
    ; Restore saved registers and return to caller
.epilogue:
    movea.l     (-0x8,A6), A2                     ; Restore A2
    movea.l     (-0x4,A6), A3                     ; Restore A3
    unlk        A6                                ; Restore frame pointer
    rts                                           ; Return (D0 already contains result)

; ====================================================================================
; END OF FUNCTION: ND_ValidateAndExecuteCommand
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function implements a strict validation chain for command 0x38 messages.
; It performs 5 consecutive validation checks:
;   1. Command ID must be 0x38
;   2. Subtype must be 0x1
;   3-6. Four parameters must match global expected values (@ 0x7d88-0x7d94)
;
; Only if ALL checks pass does it call the command handler (FUN_00006444).
; On success, builds a standardized 48-byte response with global template values.
; On failure, returns error code -0x130 (-304 decimal).
;
; The extensive validation suggests command 0x38 performs a critical operation
; that must only execute when the system is in a known-good configuration state.
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int32_t ND_ValidateAndExecuteCommand(
;     nd_command_msg_t *command_message,
;     nd_response_msg_t *response_message)
; {
;     // Extract subtype from message
;     uint8_t subtype = command_message->message_subtype;
;
;     // Validate command ID and subtype
;     if (command_message->command_id != 0x38 || subtype != 0x1) {
;         response_message->error_code = -0x130;
;         return -0x130;
;     }
;
;     // Validate 4 critical parameters against global expected values
;     if (command_message->param1 != global_expected_param1 ||
;         command_message->param2 != global_expected_param2 ||
;         command_message->param3 != global_expected_param3 ||
;         command_message->param4 != global_expected_param4)
;     {
;         response_message->error_code = -0x130;
;         return -0x130;
;     }
;
;     // All validation passed - execute command handler
;     int32_t result = FUN_00006444(
;         command_message->field_0x0C,
;         &command_message->field_0x1C,  // Note: pointer!
;         command_message->field_0x24,
;         command_message->field_0x2C,
;         command_message->field_0x34
;     );
;
;     // Store result and clear error
;     response_message->result = result;
;     response_message->error_code = 0;
;
;     // Build standard response
;     response_message->field_0x20 = global_response_field1;
;     response_message->field_0x28 = global_response_field2;
;     response_message->field_0x2C = command_message->field_0x1C;
;     response_message->response_subtype = 0x1;
;     response_message->message_size = 0x30;  // 48 bytes
;
;     return 0;
; }
;
; ====================================================================================
;
; KEY OBSERVATIONS:
;
; 1. DEFENSIVE VALIDATION: Five consecutive checks create a strict gate
; 2. GLOBAL CONFIGURATION: Four parameters validated against expected values
; 3. ERROR HANDLING: Single error code (-0x130) for all failures
; 4. RESPONSE BUILDING: Conditional - only on success
; 5. COMMAND HANDLER: Receives 5 validated arguments (4 values + 1 pointer)
; 6. ARCHITECTURE: Part of multi-tier dispatch (dispatcher → validator → handler)
;
; VALIDATION FLOW:
;   Entry → Check cmd_id → Check subtype → Check param1 → Check param2 →
;   Check param3 → Check param4 → Execute → Build response → Return
;
;   Any check fails ↓
;   Error -0x130 → Return
;
; GLOBALS ACCESSED:
;   READ:  0x7d88, 0x7d8c, 0x7d90, 0x7d94 (expected parameters)
;   READ:  0x7d98, 0x7d9c (response template values)
;
; CALLS TO:
;   0x6444 - FUN_00006444 (command implementation handler) - HIGH PRIORITY TO ANALYZE
;
; CALLED BY:
;   0x6c48 - FUN_00006c48 (higher-level dispatcher wrapper)
;
; ====================================================================================
