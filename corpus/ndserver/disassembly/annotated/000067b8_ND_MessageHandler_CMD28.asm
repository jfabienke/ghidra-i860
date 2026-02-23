; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD28
; ====================================================================================
; Address: 0x000067b8
; Size: 158 bytes (0x9e)
; Purpose: Validate and process command 0x28 message
; Analysis: docs/functions/000067b8_ND_MessageHandler_CMD28.md
; ====================================================================================
;
; FUNCTION: int32_t ND_MessageHandler_CMD28(void* message_ptr, void* response_ptr)
;
; This message handler validates incoming command 0x28 messages through a multi-stage
; validation process:
;
; VALIDATION STAGES:
;   1. Message format validation (type byte == 1, size == 0x28)
;   2. Global configuration validation (two message fields must match globals)
;   3. Helper function execution (performs core operation)
;   4. Response population (on success, write config data to response)
;
; PARAMETERS:
;   message_ptr (A6+0x8): Pointer to 40-byte incoming message structure
;   response_ptr (A6+0xc): Pointer to response structure (48 bytes on success)
;
; RETURNS:
;   Implicit via response_ptr->error_code:
;     0 = Success (all validations passed, operation completed)
;     -0x130 (decimal -304) = Validation failure
;
; STACK FRAME: 0 bytes local variables, 8 bytes saved registers
;
; GLOBAL DEPENDENCIES:
;   - global_var_7d20 (0x7d20): Validation reference for message->field_0x18
;   - global_var_7d24 (0x7d24): Validation reference for message->field_0x20
;   - global_var_7d28 (0x7d28): Response data source for response->field_0x20
;   - global_var_7d2c (0x7d2c): Response data source for response->field_0x28
;
; ====================================================================================

FUN_000067b8:
ND_MessageHandler_CMD28:

; --- PROLOGUE ---
; Standard m68k function entry: create stack frame and save callee-save registers

0x000067b8:  link.w     A6, #0x0                 ; Create stack frame (no local variables)
0x000067bc:  move.l     A3, -(SP)                ; Save A3 (will hold message pointer)
0x000067be:  move.l     A2, -(SP)                ; Save A2 (will hold response pointer)

; Load function parameters from stack into address registers
0x000067c0:  movea.l    (0x8,A6), A3             ; A3 = message_ptr (1st parameter)
0x000067c4:  movea.l    (0xc,A6), A2             ; A2 = response_ptr (2nd parameter)

; --- VALIDATION STAGE 1: Message Type and Size ---
; Verify this is a command 0x28 message with correct format
; Message must have: type_byte == 1, size_field == 0x28

; Extract message type byte from offset +3 using bitfield instruction
; bfextu extracts 8 bits starting at bit 0 of address (A3+3)
0x000067c8:  bfextu     (0x3,A3), #0, #8, D0     ; D0 = message->type_byte (unsigned byte)

0x000067ce:  moveq      #0x28, D1                ; D1 = 0x28 (expected command ID, 40 decimal)
0x000067d0:  cmp.l      (0x4,A3), D1             ; Compare message->size_field with 0x28
0x000067d4:  bne.b      .error_validation_1      ; Branch if size != 0x28 (wrong size)

0x000067d6:  moveq      #0x1, D1                 ; D1 = 1 (expected message type)
0x000067d8:  cmp.l      D0, D1                   ; Compare extracted type_byte with 1
0x000067da:  beq.b      .validation_stage_2      ; Branch if equal (validation passed)

.error_validation_1:
; Error exit path: Message format is invalid (wrong type or size)
; Set error code and jump to epilogue without processing
0x000067dc:  move.l     #-0x130, (0x1c,A2)       ; response->error_code = -0x130 (decimal -304)
0x000067e4:  bra.b      .epilogue                ; Jump to function epilogue

; --- VALIDATION STAGE 2: Global Configuration State Check ---
; Message fields must match current driver configuration stored in globals
; This ensures message is valid for current board/session state

.validation_stage_2:
; Check if message field 0x18 matches global configuration variable
0x000067e6:  move.l     (0x18,A3), D1            ; D1 = message->field_0x18
0x000067ea:  cmp.l      (0x00007d20).l, D1       ; Compare with global_var_7d20
0x000067f0:  bne.b      .error_validation_2      ; Branch if not equal (config mismatch)

; Check if message field 0x20 matches second global configuration variable
0x000067f2:  move.l     (0x20,A3), D1            ; D1 = message->field_0x20
0x000067f6:  cmp.l      (0x00007d24).l, D1       ; Compare with global_var_7d24
0x000067fc:  beq.b      .process_message         ; Branch if equal (all checks passed!)

.error_validation_2:
; Error exit path: Configuration mismatch
; Message parameters don't match current driver state
0x000067fe:  move.l     #-0x130, (0x1c,A2)       ; response->error_code = -0x130
0x00006806:  bra.b      .check_error_status      ; Jump to error status check

; --- MESSAGE PROCESSING ---
; All validations passed! Call helper function to perform core operation
; Pass three parameters from validated message structure

.process_message:
; Push parameters to stack in reverse order (m68k convention)
0x00006808:  move.l     (0x24,A3), -(SP)         ; Push message->field_0x24 (3rd parameter)
0x0000680c:  pea        (0x1c,A3)                ; Push &message->field_0x1c (2nd param - by reference)
0x00006810:  move.l     (0xc,A3), -(SP)          ; Push message->field_0xc (1st parameter)

; Call helper function FUN_00006318
; This function performs the actual hardware/system operation
; See docs/functions/0x00006318_FUN_00006318.md for details
0x00006814:  bsr.l      0x00006318               ; Call FUN_00006318(arg1, arg2_ptr, arg3)
                                                  ; Parameters auto-cleaned (12 bytes)

; Store helper function result and clear error code (success)
0x0000681a:  move.l     D0, (0x24,A2)            ; response->field_0x24 = helper_return_value
0x0000681e:  clr.l      (0x1c,A2)                ; response->error_code = 0 (SUCCESS)

; --- ERROR STATUS CHECK ---
; Determine if we should populate response fields based on error status

.check_error_status:
0x00006822:  tst.l      (0x1c,A2)                ; Test response->error_code
0x00006826:  bne.b      .epilogue                ; If error != 0, skip response population

; --- SUCCESS PATH: Populate Response Structure ---
; Copy configuration data from global variables to response
; Also echo message field back to caller for verification

; Copy global configuration values to response
0x00006828:  move.l     (0x00007d28).l, (0x20,A2)  ; response->field_0x20 = global_var_7d28
0x00006830:  move.l     (0x00007d2c).l, (0x28,A2)  ; response->field_0x28 = global_var_7d2c

; Copy message field to response (echo for correlation/verification)
0x00006838:  move.l     (0x1c,A3), (0x2c,A2)       ; response->field_0x2c = message->field_0x1c

; Set response message type and size
0x0000683e:  move.b     #0x1, (0x3,A2)             ; response->type_byte = 1
0x00006844:  moveq      #0x30, D1                  ; D1 = 0x30 (response size = 48 bytes)
0x00006846:  move.l     D1, (0x4,A2)               ; response->size_field = 0x30

; --- EPILOGUE ---
; Restore saved registers and return to caller

.epilogue:
0x0000684a:  movea.l    (-0x8,A6), A2            ; Restore A2 from stack
0x0000684e:  movea.l    (-0x4,A6), A3            ; Restore A3 from stack
0x00006852:  unlk       A6                       ; Destroy stack frame (restore old A6, SP)
0x00006854:  rts                                 ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD28
; ====================================================================================
;
; FUNCTION SUMMARY:
; This handler validates command 0x28 messages through two stages:
;   1. Format validation (type and size)
;   2. Configuration state validation (message fields vs globals)
; If validation passes, calls FUN_00006318 to perform the operation, then
; constructs a 48-byte response with operation result and configuration data.
; All validation failures return error code -0x130 (decimal -304).
;
; CONTROL FLOW SUMMARY:
; Entry → Format Check → Config Check → Process → Populate Response → Return
;           ↓ FAIL         ↓ FAIL
;           Error          Error
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; typedef struct {
;     uint8_t  header[3];        // +0x00
;     uint8_t  type_byte;        // +0x03
;     uint32_t size_field;       // +0x04
;     uint32_t unknown_0x08;     // +0x08
;     uint32_t field_0x0c;       // +0x0c
;     uint32_t unknown_0x10;     // +0x10
;     uint32_t unknown_0x14;     // +0x14
;     uint32_t field_0x18;       // +0x18
;     uint32_t field_0x1c;       // +0x1c
;     uint32_t field_0x20;       // +0x20
;     uint32_t field_0x24;       // +0x24
; } nd_message_cmd28_t;
;
; typedef struct {
;     uint8_t  header[3];        // +0x00
;     uint8_t  type_byte;        // +0x03
;     uint32_t size_field;       // +0x04
;     uint32_t unknown[5];       // +0x08 to +0x1b
;     int32_t  error_code;       // +0x1c
;     uint32_t field_0x20;       // +0x20
;     uint32_t field_0x24;       // +0x24
;     uint32_t field_0x28;       // +0x28
;     uint32_t field_0x2c;       // +0x2c
; } nd_response_cmd28_t;
;
; extern uint32_t global_var_7d20;
; extern uint32_t global_var_7d24;
; extern uint32_t global_var_7d28;
; extern uint32_t global_var_7d2c;
; extern int32_t FUN_00006318(uint32_t, uint32_t*, uint32_t);
;
; int32_t ND_MessageHandler_CMD28(
;     nd_message_cmd28_t* message_ptr,
;     nd_response_cmd28_t* response_ptr
; ) {
;     // Stage 1: Validate message format
;     uint8_t message_type = message_ptr->type_byte;
;     if (message_ptr->size_field != 0x28 || message_type != 1) {
;         response_ptr->error_code = -0x130;
;         return -0x130;
;     }
;
;     // Stage 2: Validate against global configuration
;     if (message_ptr->field_0x18 != global_var_7d20 ||
;         message_ptr->field_0x20 != global_var_7d24) {
;         response_ptr->error_code = -0x130;
;         return -0x130;
;     }
;
;     // Stage 3: Process message via helper function
;     int32_t result = FUN_00006318(
;         message_ptr->field_0x0c,
;         &message_ptr->field_0x1c,
;         message_ptr->field_0x24
;     );
;
;     response_ptr->field_0x24 = result;
;     response_ptr->error_code = 0;
;
;     // Stage 4: Populate response (only if no error)
;     if (response_ptr->error_code == 0) {
;         response_ptr->field_0x20 = global_var_7d28;
;         response_ptr->field_0x28 = global_var_7d2c;
;         response_ptr->field_0x2c = message_ptr->field_0x1c;
;         response_ptr->type_byte = 1;
;         response_ptr->size_field = 0x30;
;     }
;
;     return 0;
; }
;
; ====================================================================================
