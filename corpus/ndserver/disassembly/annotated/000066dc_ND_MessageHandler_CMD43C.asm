; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD43C
; ====================================================================================
; Address: 0x000066dc
; Size: 220 bytes (110 words, ~55 instructions)
; Purpose: Process message command 0x43C with comprehensive validation
; Analysis: docs/functions/000066dc_ND_MessageHandler_CMD43C.md
; ====================================================================================

; FUNCTION: void ND_MessageHandler_CMD43C(nd_message_t* request_msg, nd_response_t* response_msg)
;
; Validates an incoming message for command 0x43C (1084 decimal), performs extensive
; field validation against global configuration values, extracts parameters, and
; delegates to worker function FUN_000062e8 for actual processing. This appears to
; handle 8KB memory transfers or DMA operations for the NeXTdimension board.
;
; VALIDATION CHECKS PERFORMED:
;   1. Command ID must be 0x43C
;   2. Message type must be 1
;   3. param1 must match global_0x7d0c
;   4. flags_byte must have bits 2&3 set (0x0C)
;   5. header_size must be 0x0C (12 bytes)
;   6. segment_count must be 1
;   7. transfer_size must be 0x2000 (8KB)
;   8. extended_param1 must match global_0x7d10
;   9. extended_param2 must match global_0x7d14
;
; PARAMETERS:
;   request_msg (0x8,A6):   Pointer to incoming message structure (1084+ bytes)
;   response_msg (0xC,A6):  Pointer to response buffer structure (48+ bytes)
;
; RETURNS:
;   void - Results written to response_msg structure
;     response_msg->error_code (0x1C): 0 = success, -0x130 = validation error
;     response_msg->result (0x24): Worker function return value on success
;     response_msg->status_value1 (0x20): Copy of global_0x7d18
;     response_msg->status_value2 (0x28): Copy of global_0x7d1c
;     response_msg->original_msg_id (0x2C): Echo of request message_id
;     response_msg->response_type (0x3): Set to 1
;     response_msg->response_size (0x4): Set to 0x30 (48 bytes)
;
; STACK FRAME: 0 bytes (no local variables)
;   Saved registers: A2, A3 (8 bytes below frame pointer)
;   Worker call uses 20 bytes on stack (5 parameters × 4 bytes)
;
; ====================================================================================

ND_MessageHandler_CMD43C:
FUN_000066dc:
    ; --- PROLOGUE ---
    ; Create stack frame and preserve callee-save registers
    link.w      A6, #0                       ; Create stack frame (no local variables)
    move.l      A3, -(SP)                    ; Save A3 (callee-save register)
    move.l      A2, -(SP)                    ; Save A2 (callee-save register)

    ; --- LOAD PARAMETERS ---
    ; A2 = request message pointer, A3 = response message pointer
    movea.l     (0x8,A6), A2                 ; A2 = request_msg (first parameter)
    movea.l     (0xC,A6), A3                 ; A3 = response_msg (second parameter)

    ; --- VALIDATION STAGE 1: Message Type and Command ID ---
    ; First, extract and validate the basic message properties

    ; Extract message type from byte at offset 0x03 using bit field extraction
    bfextu      (0x3,A2), #0, #8, D0         ; D0 = request_msg->message_type (bits 0-7)
                                             ; bfextu = extract unsigned bit field
                                             ; Source: (A2+3), Offset: 0, Width: 8 bits

    ; Validate command_id field
    cmpi.l      #0x43C, (0x4,A2)             ; Compare request_msg->command_id with 0x43C
                                             ; 0x43C = 1084 decimal (command identifier)
    bne.b       .error_invalid_command       ; Branch if not equal (wrong command)

    ; Validate message_type field
    moveq       #1, D1                       ; D1 = expected message type (1)
                                             ; moveq is optimized for small constants
    cmp.l       D0, D1                       ; Compare extracted type with expected (1)
    beq.b       .validate_parameters         ; Branch if equal (correct type, continue validation)

.error_invalid_command:
    ; ERROR EXIT 1: Command ID or message type validation failed
    ; This is the fast-fail path for malformed messages
    move.l      #-0x130, (0x1C,A3)           ; response_msg->error_code = -304 decimal
                                             ; Error code -0x130 indicates validation failure
    bra.w       .epilogue                    ; Jump to function exit (word branch, distant target)

.validate_parameters:
    ; --- VALIDATION STAGE 2: Parameter Validation Chain ---
    ; Perform extensive validation of message fields against global configuration
    ; Each validation checks critical parameters that must match expected values

    ; VALIDATION CHECK 1: param1 field
    move.l      (0x18,A2), D1                ; D1 = request_msg->param1
    cmp.l       (0x00007d0c).l, D1           ; Compare against global configuration value
                                             ; .l suffix = long addressing mode (32-bit address)
    bne.b       .error_validation_failed     ; Branch if mismatch

    ; VALIDATION CHECK 2: Control flags byte
    move.b      (0x23,A2), D0                ; D0 = request_msg->flags_byte
                                             ; Load single byte from offset 0x23
    andi.b      #0xC, D0                     ; Mask to isolate bits 2&3 (binary 00001100)
                                             ; AND immediate with byte
    cmpi.b      #0xC, D0                     ; Check if both bits 2&3 are set
                                             ; 0x0C = binary 00001100
    bne.b       .error_validation_failed     ; Branch if not 0x0C (required flags missing)

    ; VALIDATION CHECK 3: Header size
    cmpi.w      #0xC, (0x24,A2)              ; Compare request_msg->header_size with 12
                                             ; Header must be exactly 12 bytes
    bne.b       .error_validation_failed     ; Branch if not 12

    ; VALIDATION CHECK 4: Segment count
    moveq       #1, D1                       ; D1 = expected segment count (1)
    cmp.l       (0x28,A2), D1                ; Compare request_msg->segment_count with 1
                                             ; Must be single-segment transfer
    bne.b       .error_validation_failed     ; Branch if not 1

    ; VALIDATION CHECK 5: Transfer size
    cmpi.w      #0x2000, (0x26,A2)           ; Compare request_msg->transfer_size with 0x2000
                                             ; 0x2000 = 8192 bytes (8KB transfer)
                                             ; This is a fixed-size transfer constraint
    bne.b       .error_validation_failed     ; Branch if not 8KB

    ; VALIDATION CHECK 6: Extended parameter 1
    move.l      (0x42C,A2), D1               ; D1 = request_msg->extended_param1
                                             ; Offset 0x42C = 1068 decimal
    cmp.l       (0x00007d10).l, D1           ; Compare against global configuration value
    bne.b       .error_validation_failed     ; Branch if mismatch

    ; VALIDATION CHECK 7: Extended parameter 2
    move.l      (0x434,A2), D1               ; D1 = request_msg->extended_param2
                                             ; Offset 0x434 = 1076 decimal
    cmp.l       (0x00007d14).l, D1           ; Compare against global configuration value
    beq.b       .call_worker_function        ; All validations passed, proceed to worker call

.error_validation_failed:
    ; ERROR EXIT 2: One or more parameter validations failed
    ; Reached when any of the 7 parameter checks above fails
    move.l      #-0x130, (0x1C,A3)           ; response_msg->error_code = -304 decimal
                                             ; Same error code for all validation failures
    bra.b       .check_error_status          ; Jump to error status check (short branch)

.call_worker_function:
    ; --- WORKER FUNCTION CALL ---
    ; All validations passed successfully, extract parameters and delegate to worker
    ; Worker function signature: int32_t FUN_000062e8(board_id, msg_id_ptr, data_ptr, param2, param3)

    ; Push parameters onto stack in reverse order (right-to-left C calling convention)
    move.l      (0x438,A2), -(SP)            ; arg5 = request_msg->param3 (offset 1080 decimal)
                                             ; Push onto stack, decrement SP
    move.l      (0x430,A2), -(SP)            ; arg4 = request_msg->param2 (offset 1072 decimal)
    pea         (0x2C,A2)                    ; arg3 = &request_msg->data_buffer (offset 44)
                                             ; pea = push effective address
                                             ; Passes pointer to 20-byte buffer
    pea         (0x1C,A2)                    ; arg2 = &request_msg->message_id (offset 28)
                                             ; Passes pointer for tracking/correlation
    move.l      (0xC,A2), -(SP)              ; arg1 = request_msg->board_id (offset 12)
                                             ; First parameter: likely slot/device ID

    ; Call worker function to perform actual operation
    bsr.l       0x000062e8                   ; Call FUN_000062e8 (worker function)
                                             ; bsr.l = branch to subroutine, long (32-bit offset)
                                             ; Stack cleanup: 20 bytes (5 params × 4 bytes) implicit

    ; Store worker function result in response
    move.l      D0, (0x24,A3)                ; response_msg->result = worker_result
                                             ; D0 contains return value from worker

    ; Clear error code to indicate success
    clr.l       (0x1C,A3)                    ; response_msg->error_code = 0
                                             ; clr.l = clear long (set to zero)

.check_error_status:
    ; --- ERROR STATUS CHECK ---
    ; Determine whether to fill success fields or exit with error
    tst.l       (0x1C,A3)                    ; Test response_msg->error_code
                                             ; tst.l = test long (sets condition codes)
    bne.b       .epilogue                    ; If error (non-zero), skip success path

    ; --- SUCCESS PATH: Fill Response Fields ---
    ; Only executed when error_code == 0 (validation passed, worker succeeded)

    ; Copy global status values to response
    move.l      (0x00007d18).l, (0x20,A3)    ; response_msg->status_value1 = global_0x7d18
                                             ; Global at 0x7d18 (status/state value)
    move.l      (0x00007d1c).l, (0x28,A3)    ; response_msg->status_value2 = global_0x7d1c
                                             ; Global at 0x7d1c (status/state value)

    ; Echo message_id from request to response (for correlation)
    move.l      (0x1C,A2), (0x2C,A3)         ; response_msg->original_msg_id = request_msg->message_id
                                             ; Allows client to match response to request

    ; Set response header fields
    move.b      #0x1, (0x3,A3)               ; response_msg->response_type = 1
                                             ; Indicates successful response type
    moveq       #0x30, D1                    ; D1 = 48 bytes (0x30 hex)
                                             ; Response structure size
    move.l      D1, (0x4,A3)                 ; response_msg->response_size = 0x30
                                             ; Total size of response message

.epilogue:
    ; --- EPILOGUE ---
    ; Restore callee-save registers and destroy stack frame

    ; Restore preserved registers from stack
    movea.l     (-0x8,A6), A2                ; Restore A2 from stack (saved at -8 from FP)
                                             ; movea.l = move address to address register
    movea.l     (-0x4,A6), A3                ; Restore A3 from stack (saved at -4 from FP)

    ; Destroy stack frame and return
    unlk        A6                           ; Unlink: restore previous frame pointer, deallocate frame
                                             ; SP = A6, A6 = (A6), SP += 4
    rts                                      ; Return to caller
                                             ; PC = (SP)+

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD43C
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This function is a specialized message command handler for command 0x43C (1084 decimal)
; that appears to process 8KB memory transfer or DMA operations for the NeXTdimension
; graphics board. It performs comprehensive input validation (9 checks) before
; delegating to a worker function for execution.
;
; Key Constraints:
;   - Command ID must be 0x43C
;   - Message type must be 1
;   - Transfer size must be exactly 8KB (0x2000 bytes)
;   - Must be single-segment transfer
;   - Header size must be 12 bytes
;   - Control flags bits 2&3 must be set
;   - Three parameters must match global configuration values
;
; Error Handling:
;   - All validation failures return error code -0x130 (304 decimal)
;   - No retry or recovery mechanisms
;   - Worker function errors propagated via error_code field
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_MessageHandler_CMD43C(
;     nd_message_t*   request_msg,
;     nd_response_t*  response_msg)
; {
;     // VALIDATION STAGE 1: Basic Command Validation
;     uint8_t message_type = (request_msg->header[3] >> 0) & 0xFF;
;
;     if (request_msg->command_id != 0x43C || message_type != 1) {
;         response_msg->error_code = -0x130;
;         return;
;     }
;
;     // VALIDATION STAGE 2: Parameter Validation Chain
;     if (request_msg->param1 != global_0x7d0c ||
;         (request_msg->flags_byte & 0x0C) != 0x0C ||
;         request_msg->header_size != 0x0C ||
;         request_msg->segment_count != 1 ||
;         request_msg->transfer_size != 0x2000 ||
;         request_msg->extended_param1 != global_0x7d10 ||
;         request_msg->extended_param2 != global_0x7d14)
;     {
;         response_msg->error_code = -0x130;
;         goto check_error;
;     }
;
;     // WORKER FUNCTION CALL
;     int32_t result = FUN_000062e8(
;         request_msg->board_id,
;         &request_msg->message_id,
;         &request_msg->data_buffer,
;         request_msg->param2,
;         request_msg->param3
;     );
;
;     response_msg->result = result;
;     response_msg->error_code = 0;
;
; check_error:
;     if (response_msg->error_code == 0) {
;         // SUCCESS PATH: Fill in response fields
;         response_msg->status_value1 = global_0x7d18;
;         response_msg->status_value2 = global_0x7d1c;
;         response_msg->original_msg_id = request_msg->message_id;
;         response_msg->response_type = 1;
;         response_msg->response_size = 0x30;
;     }
; }
;
; ====================================================================================
; MESSAGE STRUCTURE DETAILS:
;
; Input Message (nd_message_t) - Minimum 1084 bytes (0x43C):
;   +0x00: header_byte0
;   +0x01: header_byte1
;   +0x02: header_byte2
;   +0x03: message_type (extracted via bfextu, must be 1)
;   +0x04: command_id (must be 0x43C)
;   +0x0C: board_id (passed to worker)
;   +0x18: param1 (validated against global_0x7d0c)
;   +0x1C: message_id (echoed to response)
;   +0x23: flags_byte (must have bits 2&3 set: 0x0C)
;   +0x24: header_size (must be 0x0C = 12 bytes)
;   +0x26: transfer_size (must be 0x2000 = 8KB)
;   +0x28: segment_count (must be 1)
;   +0x2C: data_buffer[20] (passed by reference to worker)
;   +0x42C: extended_param1 (validated against global_0x7d10)
;   +0x430: param2 (passed to worker)
;   +0x434: extended_param2 (validated against global_0x7d14)
;   +0x438: param3 (passed to worker)
;
; Output Response (nd_response_t) - 48 bytes (0x30):
;   +0x03: response_type (set to 1)
;   +0x04: response_size (set to 0x30)
;   +0x1C: error_code (0 = success, -0x130 = validation error)
;   +0x20: status_value1 (copied from global_0x7d18)
;   +0x24: result (worker function return value)
;   +0x28: status_value2 (copied from global_0x7d1c)
;   +0x2C: original_msg_id (echoed from request)
;
; ====================================================================================
; GLOBAL VARIABLES:
;
;   0x00007d0c: Validation constant for param1
;   0x00007d10: Validation constant for extended_param1
;   0x00007d14: Validation constant for extended_param2
;   0x00007d18: Status/result value 1 (copied to response)
;   0x00007d1c: Status/result value 2 (copied to response)
;
; ====================================================================================
; RELATED FUNCTIONS:
;
;   FUN_000062e8 (0x000062e8): Worker function (CRITICAL - not yet analyzed)
;   ND_MessageDispatcher (0x00006e6c): Likely dispatcher that invokes this handler
;   ND_MessageHandler_CMD434 (0x00006b7c): Parallel handler for command 0x434
;   ND_ValidateAndExecuteCommand (0x00006d24): Similar validation pattern
;
; ====================================================================================
; ANALYSIS METADATA:
;
;   Analyzed: 2025-11-08
;   Analyst: Claude Code
;   Confidence: High (control flow), Medium (semantics), Low (worker purpose)
;   Complexity: Medium-High (linear validation, but many checks)
;   Cyclomatic Complexity: ~15
;   Next Steps: Analyze FUN_000062e8, trace global variables 0x7d0c-0x7d1c
;
; ====================================================================================
