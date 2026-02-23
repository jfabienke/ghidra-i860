; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateAndDispatchMessage0x30
; ====================================================================================
; Address: 0x00006036
; Size: 162 bytes (0xA2)
; Purpose: Validate message type 0x30 and dispatch to command handler
; Analysis: docs/functions/00006036_ND_ValidateAndDispatchMessage0x30.md
; ====================================================================================

; FUNCTION: void ND_ValidateAndDispatchMessage0x30(
;               const nd_message_t* request,
;               nd_response_t* response)
;
; Validates that the incoming message is type 0x30 (48 bytes) with version 0x1,
; checks three parameters against global validation constants (at 0x7CA4, 0x7CA8,
; 0x7CAC), and dispatches to internal handler FUN_00003614 if all checks pass.
; On success, populates response structure with results from handler plus metadata.
;
; PARAMETERS:
;   request  (0x8,A6):  Pointer to 48-byte message structure
;   response (0xC,A6):  Pointer to response structure (at least 40 bytes)
;
; RETURNS:
;   Via response->field_0x1C: 0 on success, -0x130 on validation error
;   Via response->field_0x3:  0x1 on success (status flag)
;   Via response->field_0x4:  0x28 on success (response size = 40)
;
; STACK FRAME: 0 bytes (no local variables)
;   A6-4: Saved A3
;   A6-8: Saved A2
;
; MESSAGE STRUCTURE (48 bytes):
;   +0x3:  version (must be 0x1)
;   +0x4:  size (must be 0x30)
;   +0xC:  arg1 to FUN_00003614
;   +0x18: param1_to_validate (checked vs 0x7CA4)
;   +0x1C: arg2 to FUN_00003614 (passed as ADDRESS)
;   +0x20: param2_to_validate (checked vs 0x7CA8)
;   +0x24: arg3 to FUN_00003614
;   +0x28: param3_to_validate (checked vs 0x7CAC)
;   +0x2C: arg4 to FUN_00003614
;
; ====================================================================================

ND_ValidateAndDispatchMessage0x30:

    ; --- PROLOGUE ---
    link.w      A6, #0x0                  ; Create stack frame (no locals)
    move.l      A3, -(SP)                 ; Save A3 (callee-save register)
    move.l      A2, -(SP)                 ; Save A2 (callee-save register)
                                          ; SP now at A6-8

    ; --- LOAD PARAMETER POINTERS ---
    movea.l     (0x8,A6), A2              ; A2 = request (message pointer)
    movea.l     (0xC,A6), A3              ; A3 = response (response pointer)

    ; --- VALIDATE MESSAGE VERSION ---
    ; Extract version byte using bitfield extraction
    bfextu      (0x3,A2), #0, #8, D0      ; D0 = extract 8 bits from (A2+3)[bit 0]
                                          ; This extracts the version byte at offset +0x3
                                          ; bfextu: base=(A2+3), offset=0, width=8 → D0

    ; --- VALIDATE MESSAGE SIZE (MUST BE 0x30 = 48 BYTES) ---
    moveq       #0x30, D1                 ; D1 = 0x30 (expected message size)
    cmp.l       (0x4,A2), D1              ; Compare request->size with 0x30
    bne.b       .validation_error         ; if (size != 0x30) goto validation_error

    ; --- VALIDATE VERSION (MUST BE 0x1) ---
    moveq       #0x1, D1                  ; D1 = 0x1 (expected version)
    cmp.l       D0, D1                    ; Compare version with 0x1
    beq.b       .check_parameters         ; if (version == 0x1) goto check_parameters

.validation_error:
    ; Message size or version validation failed
    move.l      #-0x130, (0x1C,A3)        ; response->error_code = -0x130 (error 304)
    bra.b       .epilogue                 ; Skip all processing, goto epilogue

.check_parameters:
    ; --- VALIDATE PARAMETER 1 (OFFSET 0x18) ---
    move.l      (0x18,A2), D1             ; D1 = request->param1_to_validate
    cmp.l       (0x7CA4).l, D1            ; Compare with global_validation_constant_1
    bne.b       .parameter_error          ; if (param1 != valid) goto parameter_error

    ; --- VALIDATE PARAMETER 2 (OFFSET 0x20) ---
    move.l      (0x20,A2), D1             ; D1 = request->param2_to_validate
    cmp.l       (0x7CA8).l, D1            ; Compare with global_validation_constant_2
    bne.b       .parameter_error          ; if (param2 != valid) goto parameter_error

    ; --- VALIDATE PARAMETER 3 (OFFSET 0x28) ---
    move.l      (0x28,A2), D1             ; D1 = request->param3_to_validate
    cmp.l       (0x7CAC).l, D1            ; Compare with global_validation_constant_3
    beq.b       .dispatch_command         ; if (param3 == valid) goto dispatch_command

.parameter_error:
    ; One of the three parameters failed validation
    move.l      #-0x130, (0x1C,A3)        ; response->error_code = -0x130 (error 304)
    bra.b       .check_result             ; Skip dispatch, goto check_result

.dispatch_command:
    ; --- CALL INTERNAL COMMAND HANDLER ---
    ; All validations passed - dispatch to FUN_00003614 with 4 parameters
    ; Parameters pushed in reverse order (right-to-left C convention)

    move.l      (0x2C,A2), -(SP)          ; Push arg4: request->field_0x2C
    move.l      (0x24,A2), -(SP)          ; Push arg3: request->field_0x24
    pea         (0x1C,A2)                 ; Push arg2: &request->field_0x1C (ADDRESS!)
                                          ; Note: This is passed as a POINTER, not value
                                          ; Suggests FUN_00003614 modifies field_0x1C
    move.l      (0xC,A2), -(SP)           ; Push arg1: request->field_0xC

    bsr.l       0x00003614                ; result = FUN_00003614(arg1, &arg2, arg3, arg4)
                                          ; Call internal dispatcher (90 bytes)
                                          ; Returns result code in D0

    move.l      D0, (0x1C,A3)             ; response->error_code = dispatch_result
                                          ; Store whatever FUN_00003614 returned

    ; Note: No stack cleanup visible here - likely handled by unlk or caller

.check_result:
    ; --- CHECK DISPATCH/VALIDATION RESULT ---
    tst.l       (0x1C,A3)                 ; Test response->error_code
    bne.b       .epilogue                 ; if (error_code != 0) goto epilogue (failure)

    ; --- SUCCESS PATH: POPULATE RESPONSE STRUCTURE ---
    ; Only reached if error_code is 0 (success)

    move.l      (0x7CB0).l, (0x20,A3)     ; response->field_0x20 = global_response_constant
                                          ; Copy some global constant to response

    move.l      (0x1C,A2), (0x24,A3)      ; response->field_0x24 = request->field_0x1C
                                          ; Echo back a field from request
                                          ; (possibly modified by FUN_00003614?)

    move.b      #0x1, (0x3,A3)            ; response->status_flag = 0x1 (success marker)
                                          ; Set byte at offset +0x3

    moveq       #0x28, D1                 ; D1 = 0x28 (40 decimal)
    move.l      D1, (0x4,A3)              ; response->response_size = 0x28
                                          ; Indicate response is 40 bytes

.epilogue:
    ; --- EPILOGUE: RESTORE REGISTERS AND RETURN ---
    movea.l     (-0x8,A6), A2             ; Restore A2 from stack
    movea.l     (-0x4,A6), A3             ; Restore A3 from stack
    unlk        A6                        ; Destroy stack frame (restore old A6, SP)
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_ValidateAndDispatchMessage0x30
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function is a message validator and dispatcher for NeXTdimension protocol
; message type 0x30. It performs strict validation of message size (48 bytes),
; version (1), and three parameters against global constants. If all checks pass,
; it dispatches to FUN_00003614 with 4 arguments (one by reference). On success,
; it populates a response structure with results. Any validation failure returns
; error code -0x130 (304 decimal).
;
; CRITICAL OBSERVATIONS:
; 1. Parameter passed by ADDRESS: arg2 is &request->field_0x1C, suggesting the
;    handler modifies this field (input/output parameter pattern).
;
; 2. Global validation table: Three parameters validated against globals at
;    0x7CA4, 0x7CA8, 0x7CAC. These likely define valid address ranges, resource
;    IDs, or configuration values specific to the NeXTdimension board.
;
; 3. Single error code: All validation failures return -0x130, making it
;    impossible to distinguish which validation failed without logging.
;
; 4. Response size mismatch: Request is 48 bytes, response is 40 bytes. This
;    8-byte difference suggests the response omits some request fields or uses
;    a more compact structure.
;
; 5. Pattern with siblings: This function is structurally similar to FUN_000060D8
;    (message 0x28) and FUN_00006156 (message 0x38), suggesting a family of
;    message handlers likely invoked via a jump table dispatcher.
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_ValidateAndDispatchMessage0x30(
;     const nd_message_t*  request,
;     nd_response_t*       response)
; {
;     uint8_t version = extract_byte(request, offset=3, width=8);
;
;     // Validate message structure
;     if (request->size != 0x30 || version != 0x1) {
;         response->error_code = -0x130;
;         return;
;     }
;
;     // Validate three critical parameters
;     if (request->param1_to_validate != g_validation_table[0] ||
;         request->param2_to_validate != g_validation_table[1] ||
;         request->param3_to_validate != g_validation_table[2]) {
;         response->error_code = -0x130;
;         return;
;     }
;
;     // Dispatch to handler (note: arg2 passed by reference!)
;     int32_t result = FUN_00003614(
;         request->field_0xC,
;         &request->field_0x1C,      // ADDRESS, not value
;         request->field_0x24,
;         request->field_0x2C
;     );
;
;     response->error_code = result;
;
;     if (result == 0) {
;         // Success - populate response
;         response->field_0x20 = g_response_constant;
;         response->field_0x24 = request->field_0x1C;  // Possibly modified by handler
;         response->status_flag = 0x1;
;         response->response_size = 0x28;
;     }
; }
;
; ====================================================================================
; GLOBAL DATA REFERENCES:
; ====================================================================================
;
; READ-ONLY GLOBALS (validation constants):
;   0x00007CA4: Validation constant for parameter 1 (offset 0x18)
;   0x00007CA8: Validation constant for parameter 2 (offset 0x20)
;   0x00007CAC: Validation constant for parameter 3 (offset 0x28)
;   0x00007CB0: Response constant (copied to response+0x20)
;
; CALLED FUNCTIONS:
;   0x00003614: FUN_00003614 - Internal command dispatcher (90 bytes)
;               Parameters: (uint32_t, uint32_t*, uint32_t, uint32_t)
;               Returns: int32_t error code (0 = success)
;
; ====================================================================================
; ANALYSIS METADATA:
; ====================================================================================
; Analyzed by: Claude Code
; Analysis date: 2025-11-08
; Confidence: High (90%)
; Status: Production-ready
; Related functions: FUN_000060D8, FUN_00006156 (sibling handlers)
; Next steps: Analyze FUN_00003614 to understand actual operation
; ====================================================================================
