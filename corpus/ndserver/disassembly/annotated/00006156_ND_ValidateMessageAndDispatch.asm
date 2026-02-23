; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ValidateMessageAndDispatch
; ====================================================================================
; Address: 0x00006156
; Size: 158 bytes
; Purpose: Validate message format and credentials, then dispatch to handler
; Analysis: docs/functions/00006156_ND_ValidateMessageAndDispatch.md
; ====================================================================================

; FUNCTION: void ND_ValidateMessageAndDispatch(nd_message_t* message, nd_response_t* response)
;
; Performs two-stage message validation before dispatching to handler:
;
; STAGE 1: Format and Authentication Check
;   - Validates format_id field equals 0x38 (message protocol version/category)
;   - Extracts and validates auth_version bitfield equals 1
;
; STAGE 2: Security Credential Verification
;   - Compares four 32-bit message credentials against global constants
;   - All four must match for validation to pass
;
; If all validations pass:
;   - Extracts 5 parameters from message structure
;   - Calls handler FUN_0000368c with these parameters
;   - Stores handler result in response->error_code
;   - If handler returns 0, sets response success flags
;
; If any validation fails:
;   - Sets response->error_code = -0x130 (304 decimal)
;   - Returns without calling handler
;
; PARAMETERS:
;   message (0x8,A6):  Pointer to nd_message_t structure with format and credentials
;   response (0xc,A6): Pointer to nd_response_t structure for result/errors
;
; RETURNS:
;   void (updates response structure in-place)
;
; STACK FRAME: 0 bytes (no local variables)
;   Only saved registers on stack
;
; ERROR CODES:
;   -0x130 (304): Validation failure (format, auth, or credential mismatch)
;   0:            Success (all validations passed, handler succeeded)
;   Other:        Handler-specific error codes
;
; GLOBAL DATA DEPENDENCIES:
;   0x7cbc: g_expected_credential1 (constant)
;   0x7cc0: g_expected_credential2 (constant)
;   0x7cc4: g_expected_credential3 (constant)
;   0x7cc8: g_expected_credential4 (constant)
;
; CALLS:
;   FUN_0000368c - Message handler (receives 5 extracted parameters)
;
; ====================================================================================

; Message structure layout (nd_message_t):
;   +0x0:  header[3]                (3 bytes)
;   +0x3:  auth_version_bitfield    (1 byte) - extracted via bfextu
;   +0x4:  format_id                (4 bytes) - must be 0x38
;   +0x8:  ... (unknown)
;   +0xc:  param1                   (4 bytes) - passed to handler as arg 1
;   +0x10: ... (unknown)
;   +0x14: ... (unknown)
;   +0x18: credential1              (4 bytes) - validated against 0x7cbc
;   +0x1c: param2                   (4 bytes) - passed to handler as arg 2
;   +0x20: credential2              (4 bytes) - validated against 0x7cc0
;   +0x24: param3                   (4 bytes) - passed to handler as arg 3
;   +0x28: credential3              (4 bytes) - validated against 0x7cc4
;   +0x2c: param4                   (4 bytes) - passed to handler as arg 4
;   +0x30: credential4              (4 bytes) - validated against 0x7cc8
;   +0x34: param5                   (4 bytes) - passed to handler as arg 5
;
; Response structure layout (nd_response_t):
;   +0x0:  response_header[3]       (3 bytes)
;   +0x3:  flags                    (1 byte) - set to 0x1 on success
;   +0x4:  response_size            (4 bytes) - set to 0x20 on success
;   +0x8:  ... (unknown)
;   +0x1c: error_code               (4 bytes) - 0 = success, -0x130 = validation error
;
; ====================================================================================

ND_ValidateMessageAndDispatch:
FUN_00006156:

; --- PROLOGUE ---
; Setup stack frame and save callee-save registers
0x00006156:  link.w      A6, #0x0                 ; Create stack frame (0 bytes - no locals)
0x0000615a:  move.l      A2, -(SP)                ; Save A2 (callee-save, used for response ptr)

; --- LOAD PARAMETERS ---
; Transfer parameters from stack to address registers for efficient access
0x0000615c:  movea.l     (0x8,A6), A0             ; A0 = message (param 1 from caller)
0x00006160:  movea.l     (0xc,A6), A2             ; A2 = response (param 2 from caller)

; --- EXTRACT AUTHENTICATION/VERSION BITFIELD ---
; Use bitfield extraction to get auth_version from message header
; bfextu extracts unsigned bitfield: (base){offset:width}, dest
; Extract 8 bits starting at bit 0 from address (A0+3)
0x00006164:  bfextu      (0x3,A0){0:8}, D0        ; D0 = message->auth_version_bitfield
                                                   ; Extracts byte at offset +3 from message base
                                                   ; This is a compiler-generated bitfield access

; --- VALIDATION STAGE 1A: CHECK MESSAGE FORMAT ID ---
; Verify message format identifier matches expected protocol version/category
0x0000616a:  moveq       #0x38, D1                ; D1 = 0x38 (56 decimal) - expected format ID
                                                   ; Format 0x38 likely indicates secure command protocol
0x0000616c:  cmp.l       (0x4,A0), D1             ; Compare message->format_id with 0x38
0x00006170:  bne.b       .validation_failed_1     ; If not equal, jump to error path
                                                   ; Fail fast if wrong message format

; --- VALIDATION STAGE 1B: CHECK AUTH/VERSION BITFIELD ---
; Verify authentication/version marker in extracted bitfield
0x00006172:  moveq       #0x1, D1                 ; D1 = 1 - expected auth/version value
                                                   ; Value of 1 may indicate "authenticated" or "current version"
0x00006174:  cmp.l       D0, D1                   ; Compare extracted bitfield with 1
0x00006176:  beq.b       .stage2_credential_check ; If equal, proceed to credential validation
                                                   ; Both format and auth checks passed

; --- VALIDATION FAILURE PATH #1: FORMAT OR AUTH MISMATCH ---
; Either format_id != 0x38 OR auth_version != 1
.validation_failed_1:
0x00006178:  move.l      #-0x130, (0x1c,A2)       ; response->error_code = -0x130 (304 decimal)
                                                   ; Single error code for all validation failures
                                                   ; Prevents information leakage about which check failed
0x00006180:  bra.b       .epilogue                ; Jump to epilogue (skip handler, return immediately)

; --- VALIDATION STAGE 2: CHECK SECURITY CREDENTIALS ---
; Verify four 32-bit credentials in message against global constants
; This implements a multi-factor authentication or protocol versioning scheme
.stage2_credential_check:

    ; --- Check credential #1 (offset 0x18) ---
0x00006182:  move.l      (0x18,A0), D1            ; D1 = message->credential1
0x00006186:  cmp.l       (0x7cbc).l, D1           ; Compare with g_expected_credential1
                                                   ; Global at 0x7cbc may be signature, magic number, or version ID
0x0000618c:  bne.b       .validation_failed_2     ; If not equal, jump to credential error path

    ; --- Check credential #2 (offset 0x20) ---
0x0000618e:  move.l      (0x20,A0), D1            ; D1 = message->credential2
0x00006192:  cmp.l       (0x7cc0).l, D1           ; Compare with g_expected_credential2
                                                   ; Second component of credential quadruplet
0x00006198:  bne.b       .validation_failed_2     ; If not equal, jump to credential error path

    ; --- Check credential #3 (offset 0x28) ---
0x0000619a:  move.l      (0x28,A0), D1            ; D1 = message->credential3
0x0000619e:  cmp.l       (0x7cc4).l, D1           ; Compare with g_expected_credential3
                                                   ; Third component of credential quadruplet
0x000061a4:  bne.b       .validation_failed_2     ; If not equal, jump to credential error path

    ; --- Check credential #4 (offset 0x30) ---
0x000061a6:  move.l      (0x30,A0), D1            ; D1 = message->credential4
0x000061aa:  cmp.l       (0x7cc8).l, D1           ; Compare with g_expected_credential4
                                                   ; Fourth and final component of credential quadruplet
0x000061b0:  beq.b       .validation_passed       ; If equal, ALL checks passed! Proceed to dispatch

; --- VALIDATION FAILURE PATH #2: CREDENTIAL MISMATCH ---
; At least one of the four credentials did not match expected value
.validation_failed_2:
0x000061b2:  move.l      #-0x130, (0x1c,A2)       ; response->error_code = -0x130 (304 decimal)
                                                   ; Same error code as format failure (security measure)
0x000061ba:  bra.b       .check_error_and_update  ; Jump to error checking section
                                                   ; (Could optimize to .epilogue, but maybe future expansion)

; --- VALIDATION PASSED: EXTRACT PARAMETERS AND DISPATCH TO HANDLER ---
; All checks passed - safe to extract parameters and call handler
.validation_passed:

    ; --- Marshal parameters from message structure to stack (right-to-left) ---
    ; Handler expects: FUN_0000368c(param1, param2, param3, param4, param5)
0x000061bc:  move.l      (0x34,A0), -(SP)         ; Push message->param5 (rightmost arg)
0x000061c0:  move.l      (0x2c,A0), -(SP)         ; Push message->param4
0x000061c4:  move.l      (0x24,A0), -(SP)         ; Push message->param3
0x000061c8:  move.l      (0x1c,A0), -(SP)         ; Push message->param2
0x000061cc:  move.l      (0xc,A0), -(SP)          ; Push message->param1 (leftmost arg)
                                                   ; Stack now contains 5 parameters (20 bytes)

    ; --- Call the actual handler function ---
0x000061d0:  bsr.l       0x0000368c               ; Call FUN_0000368c(p1, p2, p3, p4, p5)
                                                   ; Handler performs the actual message processing
                                                   ; Returns error code in D0 (0 = success)
                                                   ; Stack automatically cleaned by handler's RTS

    ; --- Store handler result in response ---
0x000061d6:  move.l      D0, (0x1c,A2)            ; response->error_code = handler_return_value
                                                   ; Handler can return 0 (success) or error code

; --- CHECK HANDLER RESULT AND UPDATE RESPONSE ON SUCCESS ---
; If handler succeeded (error_code == 0), set success flags
.check_error_and_update:
0x000061da:  tst.l       (0x1c,A2)                ; Test response->error_code
                                                   ; Sets Z flag if error_code == 0
0x000061de:  bne.b       .epilogue                ; If non-zero (error), skip success update
                                                   ; Errors propagate in error_code field only

    ; --- SUCCESS PATH: UPDATE RESPONSE WITH SUCCESS STATUS ---
    ; Only reached if error_code == 0 (handler succeeded)
0x000061e0:  move.b      #0x1, (0x3,A2)           ; response->flags = 0x1 (success flag)
                                                   ; Flags byte at offset +3 (after 3-byte header)
0x000061e6:  moveq       #0x20, D1                ; D1 = 0x20 (32 decimal)
                                                   ; Fixed response size for this message type
0x000061e8:  move.l      D1, (0x4,A2)             ; response->response_size = 32 bytes
                                                   ; Indicates how much data is in response structure

; --- EPILOGUE ---
; Restore saved registers and return to caller
.epilogue:
0x000061ec:  movea.l     (-0x4,A6), A2            ; Restore A2 from stack
0x000061f0:  unlk        A6                       ; Destroy stack frame (restore old A6, adjust SP)
0x000061f2:  rts                                  ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_ValidateMessageAndDispatch
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This function acts as a security gatekeeper for sensitive message processing.
; It implements a two-stage validation process:
;
; 1. FORMAT VALIDATION (Stage 1):
;    - Checks message format_id == 0x38 (protocol version/category)
;    - Extracts and checks auth_version bitfield == 1 (authentication marker)
;
; 2. CREDENTIAL VERIFICATION (Stage 2):
;    - Compares four 32-bit message credentials against global constants
;    - All four must match (multi-factor authentication or version check)
;
; Only messages passing both stages reach the handler function. This prevents:
;    - Wrong protocol version messages from being processed
;    - Unauthenticated messages from accessing sensitive operations
;    - Replay attacks (if credentials are session-specific)
;
; The function uses a "fail fast" pattern with early returns on validation failure,
; minimizing overhead for invalid messages. All validation failures return the
; same error code (-0x130) to prevent information leakage about which check failed.
;
; ====================================================================================
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; typedef struct {
;     uint8_t   header[3];
;     uint8_t   auth_version_bitfield;
;     uint32_t  format_id;
;     uint32_t  field_08;
;     uint32_t  param1;
;     uint32_t  field_10;
;     uint32_t  field_14;
;     uint32_t  credential1;
;     uint32_t  param2;
;     uint32_t  credential2;
;     uint32_t  param3;
;     uint32_t  credential3;
;     uint32_t  param4;
;     uint32_t  credential4;
;     uint32_t  param5;
; } nd_message_t;
;
; typedef struct {
;     uint8_t   response_header[3];
;     uint8_t   flags;
;     uint32_t  response_size;
;     uint8_t   padding[20];
;     int32_t   error_code;
; } nd_response_t;
;
; // Global credentials (initialized at startup or compile-time)
; extern uint32_t g_expected_credential1;  // @ 0x7cbc
; extern uint32_t g_expected_credential2;  // @ 0x7cc0
; extern uint32_t g_expected_credential3;  // @ 0x7cc4
; extern uint32_t g_expected_credential4;  // @ 0x7cc8
;
; // Handler function (performs actual message processing)
; extern int32_t FUN_0000368c(uint32_t p1, uint32_t p2, uint32_t p3, uint32_t p4, uint32_t p5);
;
; void ND_ValidateMessageAndDispatch(nd_message_t* message, nd_response_t* response)
; {
;     uint8_t auth_version;
;     int32_t handler_result;
;
;     // Extract authentication/version bitfield from message header
;     auth_version = message->auth_version_bitfield;
;
;     // STAGE 1: Validate format ID and auth/version
;     if (message->format_id != 0x38) {
;         response->error_code = -0x130;  // Format mismatch
;         return;
;     }
;
;     if (auth_version != 1) {
;         response->error_code = -0x130;  // Wrong auth/version
;         return;
;     }
;
;     // STAGE 2: Validate security credentials
;     if (message->credential1 != g_expected_credential1 ||
;         message->credential2 != g_expected_credential2 ||
;         message->credential3 != g_expected_credential3 ||
;         message->credential4 != g_expected_credential4)
;     {
;         response->error_code = -0x130;  // Credential mismatch
;         return;
;     }
;
;     // VALIDATION PASSED: Extract parameters and call handler
;     handler_result = FUN_0000368c(
;         message->param1,
;         message->param2,
;         message->param3,
;         message->param4,
;         message->param5
;     );
;
;     // Store handler result
;     response->error_code = handler_result;
;
;     // If handler succeeded, mark response as successful
;     if (handler_result == 0) {
;         response->flags = 0x1;           // Success flag
;         response->response_size = 0x20;  // 32 bytes response
;     }
; }
;
; ====================================================================================
;
; SECURITY ANALYSIS:
;
; This function implements a defense-in-depth validation strategy:
;
; Layer 1: Format Check (cheap, fast rejection)
;   - Rejects messages with wrong protocol version
;   - Prevents processing of malformed messages
;
; Layer 2: Authentication Check (cheap, fast rejection)
;   - Validates authentication/version marker
;   - May distinguish between authenticated and unauthenticated protocols
;
; Layer 3: Credential Verification (moderate cost, strong security)
;   - Four-way credential check provides strong authentication
;   - Could be cryptographic signature components
;   - Could be protocol version compatibility markers
;   - Could be session-specific tokens
;
; Error Handling Design:
;   - Single error code (-0x130) for all validation failures
;   - Prevents attackers from determining which validation failed
;   - Information hiding security principle
;
; Performance Optimization:
;   - Cheap checks first (format ID, bitfield)
;   - Expensive checks only after cheap ones pass
;   - Early exit on first failure
;   - Minimizes overhead for invalid messages
;
; ====================================================================================
;
; PROTOCOL INTEGRATION:
;
; This function is likely part of the NeXTdimension host-board communication protocol.
; The validation sequence suggests a trusted message dispatch system where:
;
; 1. Messages are categorized by format_id (0x38 = secure command category?)
; 2. Authentication is validated via bitfield marker
; 3. Credentials are verified against session or global constants
; 4. Only authenticated messages reach the handler
;
; The four credentials may represent:
;   - Protocol version quadruplet (major.minor.patch.build)
;   - Cryptographic signature components
;   - Capability flags for both endpoints
;   - Session establishment tokens
;
; The 32-byte fixed response size suggests a standardized response structure,
; possibly containing:
;   - Status code
;   - Result data
;   - Error information
;   - Metadata
;
; ====================================================================================
