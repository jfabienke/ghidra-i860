; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateMessageType1_3Param
; ====================================================================================
; Address: 0x000060d8
; Size: 126 bytes (32 instructions)
; Purpose: Validates message type 1 (3-parameter variant) and dispatches to handler
; Analysis: docs/functions/000060d8_ND_ValidateMessageType1_3Param.md
; ====================================================================================

; FUNCTION: void ND_ValidateMessageType1_3Param(nd_message_t* message, nd_result_t* result)
;
; Validates an incoming NeXTdimension protocol message with type 1 signature before
; dispatching to a 3-parameter operation handler. This function is part of a family
; of message validators that enforce protocol compliance and security.
;
; VALIDATION SEQUENCE:
;   1. Message size must be 0x28 (40 bytes)
;   2. Message type byte must be 0x1
;   3. Authentication token 1 (field_0x18) must match global at 0x7cb4
;   4. Authentication token 2 (field_0x20) must match global at 0x7cb8
;
; PARAMETERS:
;   message (A6+0x8):  Pointer to incoming message structure (nd_message_t*)
;   result (A6+0xC):   Pointer to result structure for response (nd_result_t*)
;
; RETURNS:
;   result->error_code (field_0x1C):
;     0: Success (validation passed, operation completed)
;     -0x130 (-304 decimal): Validation or authentication failure
;     Other: Error from FUN_0000366e operation handler
;
;   On success, also sets:
;     result->response_ready_flag (field_0x03) = 0x1
;     result->response_size (field_0x04) = 0x20 (32 bytes)
;
; STACK FRAME: 0 bytes local variables
;   Saved registers: A2 (4 bytes)
;   Maximum stack: 16 bytes (saved A2 + 12 bytes call parameters)
;
; CALL GRAPH:
;   ND_ValidateMessageType1_3Param (THIS)
;     └─→ FUN_0000366e (operation handler)
;           ├─→ lib_0x0500315e (numeric conversion?)
;           └─→ lib_0x050032ba (validation/transform?)
;
; ====================================================================================

ND_ValidateMessageType1_3Param:
FUN_000060d8:

    ; ===============================================================================
    ; PROLOGUE: Stack Frame Setup
    ; ===============================================================================
    ; Create standard m68k link frame with no local variables
    ; Save callee-save register A2 (used for result pointer)

    0x000060d8:  link.w     A6, #0x0              ; Create stack frame (0 bytes locals)
                                                  ; Old A6 → stack, A6 = SP

    0x000060dc:  move.l     A2, -(SP)             ; Save A2 (callee-save register)
                                                  ; Will be used for result structure pointer


    ; ===============================================================================
    ; PARAMETER LOADING: Fetch Message and Result Pointers
    ; ===============================================================================

    0x000060de:  movea.l    (0x8,A6), A0          ; A0 = message (arg1 from stack)
                                                  ; Points to nd_message_t structure

    0x000060e2:  movea.l    (0xc,A6), A2          ; A2 = result (arg2 from stack)
                                                  ; Points to nd_result_t structure (output)


    ; ===============================================================================
    ; VALIDATION CHECK 1: Extract Message Type Byte
    ; ===============================================================================
    ; Extract type byte at offset +0x3 using bitfield operation
    ; This reads a single byte (8 bits starting at bit 0) from message+3

    0x000060e6:  bfextu     (0x3,A0), #0x0, #0x8, D0
                                                  ; D0 = message->type_byte (at offset +3)
                                                  ; bfextu = Bit Field Extract Unsigned
                                                  ; Source: (A0 + 0x3), Offset: bit 0, Width: 8 bits
                                                  ; Extracts single byte, zero-extends to D0


    ; ===============================================================================
    ; VALIDATION CHECK 2: Message Size/Signature Field
    ; ===============================================================================
    ; Verify that field_0x04 contains expected size value 0x28 (40 bytes)
    ; This distinguishes this variant from other type 1 handlers:
    ;   - This function: 0x28 (40 bytes, 3 parameters)
    ;   - FUN_00006156:  0x38 (56 bytes, 5 parameters)
    ;   - Type1_IO:      0x43c (1084 bytes, I/O operations)

    0x000060ec:  moveq      #0x28, D1             ; D1 = 0x28 (40 decimal, expected message size)
                                                  ; moveq = efficient for small constants (0-255)

    0x000060ee:  cmp.l      (0x4,A0), D1          ; Compare message->field_0x04 with 0x28
                                                  ; if (message->field_0x04 != 0x28)

    0x000060f2:  bne.b      .validation_failed    ;   goto validation_failed (size mismatch)
                                                  ; Short branch (within ±126 bytes)


    ; ===============================================================================
    ; VALIDATION CHECK 3: Message Type Must Be 1
    ; ===============================================================================
    ; Confirm that the extracted type byte equals 1 (this handler's type)

    0x000060f4:  moveq      #0x1, D1              ; D1 = 1 (expected message type)

    0x000060f6:  cmp.l      D0, D1                ; Compare message_type (D0) with 1
                                                  ; if (message_type != 1)

    0x000060f8:  beq.b      .type_valid           ;   continue to authentication checks
                                                  ; else fall through to error


.validation_failed:
    ; -------------------------------------------------------------------------------
    ; ERROR PATH: Basic Validation Failed
    ; -------------------------------------------------------------------------------
    ; Either message size (field_0x04) was wrong or type byte was not 1
    ; Set standard validation error code and exit immediately

    0x000060fa:  move.l     #-0x130, (0x1c,A2)    ; result->error_code = -0x130 (-304 decimal)
                                                  ; Standard validation failure code
                                                  ; Used by 14+ validator functions

    0x00006102:  bra.b      .epilogue             ; goto epilogue (early return)
                                                  ; Skip all authentication and operation


.type_valid:
    ; ===============================================================================
    ; VALIDATION CHECK 4: Authentication Token 1
    ; ===============================================================================
    ; Verify first authentication token against global expected value
    ; This appears to be session-based authentication (token set during init)
    ; Global at 0x7cb4 likely set by ND_RegisterBoardSlot or session establishment

    0x00006104:  move.l     (0x18,A0), D1         ; D1 = message->field_0x18 (auth token 1)
                                                  ; Could be: session ID, Mach port, security nonce

    0x00006108:  cmp.l      (0x00007cb4).l, D1    ; Compare with global expected value
                                                  ; if (message->auth_token_1 != g_auth_token_1)
                                                  ; Global at 0x7cb4 (data segment)

    0x0000610e:  bne.b      .auth_validation_failed ;   goto auth_validation_failed
                                                  ; Authentication token 1 mismatch


    ; ===============================================================================
    ; VALIDATION CHECK 5: Authentication Token 2
    ; ===============================================================================
    ; Verify second authentication token (additional security layer)
    ; Two-token authentication prevents simple replay attacks

    0x00006110:  move.l     (0x20,A0), D1         ; D1 = message->field_0x20 (auth token 2)
                                                  ; Second authentication credential

    0x00006114:  cmp.l      (0x00007cb8).l, D1    ; Compare with global expected value
                                                  ; if (message->auth_token_2 != g_auth_token_2)
                                                  ; Global at 0x7cb8 (data segment, +4 from first)

    0x0000611a:  beq.b      .all_validations_passed ;   goto all_validations_passed
                                                  ; Both tokens match - proceed to operation
                                                  ; else fall through to auth error


.auth_validation_failed:
    ; -------------------------------------------------------------------------------
    ; ERROR PATH: Authentication/Field Validation Failed
    ; -------------------------------------------------------------------------------
    ; One or both authentication tokens did not match expected values
    ; This prevents unauthorized operations or session hijacking

    0x0000611c:  move.l     #-0x130, (0x1c,A2)    ; result->error_code = -0x130
                                                  ; Same error code as basic validation
                                                  ; Client cannot distinguish auth vs. size error

    0x00006124:  bra.b      .check_error_before_exit ; goto check_error_before_exit
                                                  ; Skip to conditional response check


.all_validations_passed:
    ; ===============================================================================
    ; SUCCESS PATH: Invoke Operation Handler
    ; ===============================================================================
    ; All validations passed (size, type, 2 auth tokens)
    ; Extract 3 parameters from message and call operation handler
    ; FUN_0000366e is a 30-byte wrapper that calls library functions

    ; --- Prepare Parameters for Handler Call ---
    ; Stack layout (after pushes):
    ;   [SP+0x0]: arg1 = message->field_0x0C
    ;   [SP+0x4]: arg2 = message->field_0x1C
    ;   [SP+0x8]: arg3 = message->field_0x24

    0x00006126:  move.l     (0x24,A0), -(SP)      ; Push arg3: message->field_0x24
                                                  ; Third operation parameter
                                                  ; SP -= 4

    0x0000612a:  move.l     (0x1c,A0), -(SP)      ; Push arg2: message->field_0x1C
                                                  ; Second operation parameter
                                                  ; SP -= 4

    0x0000612e:  move.l     (0xc,A0), -(SP)       ; Push arg1: message->field_0x0C
                                                  ; First operation parameter
                                                  ; SP -= 4 (total 12 bytes pushed)

    ; --- Call Operation Handler ---
    ; FUN_0000366e(param1, param2, param3)
    ; This function internally:
    ;   result = lib_0x0500315e(param2, param3);  // Likely strtol() or conversion
    ;   return lib_0x050032ba(result);             // Likely validation/transform

    0x00006132:  bsr.l      0x0000366e            ; Call FUN_0000366e (operation handler)
                                                  ; Branch to subroutine (pushes return address)
                                                  ; Handler cleans its own stack (12 bytes)
                                                  ; Returns operation result in D0

    ; --- Store Operation Result ---

    0x00006138:  move.l     D0, (0x1c,A2)         ; result->error_code = return_value
                                                  ; Overwrites with actual operation result
                                                  ; May be 0 (success) or error code


.check_error_before_exit:
    ; ===============================================================================
    ; CONDITIONAL RESPONSE BUILDING
    ; ===============================================================================
    ; Only build response metadata if operation succeeded (error_code == 0)
    ; If error occurred, skip response building and return error code

    0x0000613c:  tst.l      (0x1c,A2)             ; Test result->error_code
                                                  ; Sets Z flag if error_code == 0

    0x00006140:  bne.b      .epilogue             ; if (error_code != 0)
                                                  ;   goto epilogue (skip response building)


    ; ===============================================================================
    ; BUILD SUCCESS RESPONSE
    ; ===============================================================================
    ; Operation succeeded (error_code == 0)
    ; Set response metadata to indicate response is ready and specify size
    ; These fields tell dispatcher to transmit 32-byte response back to client

    0x00006142:  move.b     #0x1, (0x3,A2)        ; result->response_ready_flag = 1
                                                  ; Byte write to offset +0x3
                                                  ; Indicates response is ready for transmission

    0x00006148:  moveq      #0x20, D1             ; D1 = 0x20 (32 decimal)
                                                  ; Standard response size for this message type

    0x0000614a:  move.l     D1, (0x4,A2)          ; result->response_size = 0x20 bytes
                                                  ; Tells dispatcher how many bytes to send


.epilogue:
    ; ===============================================================================
    ; EPILOGUE: Stack Frame Teardown and Return
    ; ===============================================================================
    ; Restore saved registers and return to caller
    ; Return value is implicit via result structure (not D0)

    0x0000614e:  movea.l    (-0x4,A6), A2         ; Restore A2 from stack
                                                  ; A2 = saved value (original result pointer)

    0x00006152:  unlk       A6                    ; Destroy stack frame
                                                  ; SP = A6, A6 = (A6), SP += 4
                                                  ; Restores previous frame pointer

    0x00006154:  rts                              ; Return to caller
                                                  ; PC = (SP)+, SP += 4
                                                  ; Returns to dispatcher or caller


; ====================================================================================
; END OF FUNCTION: ND_ValidateMessageType1_3Param
; ====================================================================================

; FUNCTION SUMMARY:
; This function validates incoming NeXTdimension protocol messages (type 1, 3-parameter
; variant) through a four-stage validation process:
;   1. Structural validation (size == 0x28, type == 1)
;   2. Authentication validation (2 token checks against globals)
;   3. Operation dispatch (calls FUN_0000366e with 3 extracted parameters)
;   4. Response building (sets metadata on success)
;
; The function uses early-return error handling with a standardized error code (-0x130)
; for all validation failures. This prevents information leakage about which validation
; failed, improving security against probing attacks.
;
; Integration into protocol:
;   - Called by message dispatcher (likely via function pointer table at 0x60b0)
;   - Indexed by message type (1) and size (0x28) combination
;   - Part of family including FUN_00006156 (5-param) and ND_ValidateMessageType1 (I/O)
;
; Security design:
;   - Two-factor authentication (both tokens must match)
;   - No information leakage (same error code for all failures)
;   - Early validation before expensive operations
;   - Minimal attack surface (no loops, simple control flow)
;
; ====================================================================================

; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_ValidateMessageType1_3Param(nd_message_t *message, nd_result_t *result)
; {
;     uint8_t message_type = BITFIELD_EXTRACT(message, offset=3, bit=0, len=8);
;
;     /* Stage 1: Structural validation */
;     if (message->field_0x04 != 0x28 || message_type != 0x1) {
;         result->error_code = -0x130;
;         return;
;     }
;
;     /* Stage 2: Authentication validation */
;     if (message->field_0x18 != g_auth_token_1 ||
;         message->field_0x20 != g_auth_token_2) {
;         result->error_code = -0x130;
;         return;
;     }
;
;     /* Stage 3: Operation dispatch */
;     int operation_result = FUN_0000366e(
;         message->field_0x0C,   // param1
;         message->field_0x1C,   // param2
;         message->field_0x24    // param3
;     );
;     result->error_code = operation_result;
;
;     /* Stage 4: Response building (on success) */
;     if (result->error_code == 0) {
;         result->response_ready_flag = 0x1;
;         result->response_size = 0x20;
;     }
; }
;
; ====================================================================================

; DATA STRUCTURES (from analysis):
;
; typedef struct nd_message {
;     uint8_t   field_0x00[3];       // Header
;     uint8_t   type_byte;           // +0x03: Type (1 for this handler)
;     uint32_t  field_0x04;          // +0x04: Size (0x28 for this variant)
;     uint32_t  field_0x08;          // +0x08: Unknown
;     uint32_t  param1;              // +0x0C: Operation parameter 1
;     uint8_t   field_0x10[0x8];     // +0x10-0x17: Unknown
;     uint32_t  auth_token_1;        // +0x18: Auth token 1 (vs 0x7cb4)
;     uint32_t  param2;              // +0x1C: Operation parameter 2
;     uint32_t  auth_token_2;        // +0x20: Auth token 2 (vs 0x7cb8)
;     uint32_t  param3;              // +0x24: Operation parameter 3
; } nd_message_t;
;
; typedef struct nd_result {
;     uint8_t   field_0x00[3];       // Unknown
;     uint8_t   response_ready_flag; // +0x03: 1 when ready
;     uint32_t  response_size;       // +0x04: 0x20 on success
;     uint8_t   field_0x08[0x14];    // Unknown
;     int32_t   error_code;          // +0x1C: 0, -0x130, or handler error
; } nd_result_t;
;
; extern uint32_t g_auth_token_1;    // @ 0x7cb4
; extern uint32_t g_auth_token_2;    // @ 0x7cb8
;
; ====================================================================================

; ANALYSIS METADATA:
; - Analyst: Claude Code
; - Date: 2025-11-08
; - Confidence: HIGH (85%)
; - Related functions: FUN_0000366e (handler), FUN_00006156 (5-param variant)
; - Next analysis target: FUN_0000366e (understand operation)
;
; ====================================================================================
