; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD42C
; ====================================================================================
; Address: 0x00006a08
; Size: 186 bytes (0xBA)
; Purpose: Validate and process Mach IPC messages with command type 0x42C (1068 bytes)
; Analysis: docs/functions/00006a08_ND_MessageHandler_CMD42C.md
; ====================================================================================

; FUNCTION: ND_MessageHandler_CMD42C
;
; This function is a specialized message handler within NDserver's message dispatch
; system. It validates incoming Mach IPC messages of type 0x42C (1068 bytes) by
; performing 7 distinct validation checks before delegating to a low-level I/O
; operation handler. The function follows a consistent validation pattern seen across
; all message handlers in the 0x6000-0x7000 address range.
;
; The validation ensures:
;   - Message size is exactly 0x42C (1068 bytes)
;   - Message version is 1
;   - Field at offset 0x18 matches global configuration at 0x7d4c
;   - Flags at offset 0x23 have bits 2&3 set (value 0x0C)
;   - Field at offset 0x24 equals 12 (0xC)
;   - Field at offset 0x28 equals 1
;   - Field at offset 0x26 equals 0x2000 (8192 decimal)
;
; On validation success, the function calls FUN_00006398 (I/O operation handler)
; with three parameters extracted from the message, then populates the response
; structure with global configuration values and the operation result.
;
; PARAMETERS:
;   msg_in (A6+0x8):    Pointer to 1068-byte incoming message structure
;   reply_out (A6+0xC): Pointer to reply structure to populate
;
; RETURNS:
;   void (modifies reply_out structure in-place)
;
;   On success:
;     reply_out->error_code = 0
;     reply_out->result = return value from FUN_00006398
;     reply_out populated with global configuration values
;
;   On validation failure:
;     reply_out->error_code = -0x130 (304 decimal)
;
; STACK FRAME: 0 bytes (no local variables)
;   A6 - 0x4: Saved A2 (callee-save register)
;   A6 - 0x8: Saved A3 (callee-save register)
;
; REGISTERS:
;   A2: Pointer to msg_in (preserved)
;   A3: Pointer to reply_out (preserved)
;   D0: Temporary - message version byte, comparison results
;   D1: Temporary - expected values for validation
;
; GLOBAL VARIABLES:
;   0x00007D4C: Configuration value for validation of msg_in->field_0x18
;   0x00007D50: Response value copied to reply_out->field_0x20
;   0x00007D54: Response value copied to reply_out->field_0x28
;
; CALLS:
;   FUN_00006398 (0x6398): Low-level I/O operation handler (write/ioctl wrapper)
;
; COMPLEXITY:
;   Cyclomatic: 4 (Low-Medium)
;   Size: 186 bytes
;   Instructions: 47
;
; ====================================================================================

FUN_00006a08:
ND_MessageHandler_CMD42C:

    ; --- PROLOGUE: Create stack frame and save registers ---
    ; Standard m68k function entry with link frame
    link.w      A6, #0x0                    ; Create stack frame (0-byte local space)
                                             ; A6 now points to saved frame pointer
    move.l      A3, -(SP)                   ; Save A3 (callee-save register)
                                             ; Stored at A6-0x4
    move.l      A2, -(SP)                   ; Save A2 (callee-save register)
                                             ; Stored at A6-0x8

    ; --- LOAD FUNCTION PARAMETERS INTO ADDRESS REGISTERS ---
    ; Parameters passed on stack, accessed via frame pointer
    movea.l     (0x8, A6), A2               ; A2 = msg_in (1st parameter at A6+0x8)
                                             ; A2 points to 1068-byte message structure
    movea.l     (0xc, A6), A3               ; A3 = reply_out (2nd parameter at A6+0xC)
                                             ; A3 points to reply structure

    ; --- VALIDATION STEP 1: Extract message version byte ---
    ; The version field is a single byte at offset 0x3 in the message structure.
    ; Using bit field extraction for efficient unsigned byte load.
    bfextu      (0x3, A2), 0x0, 0x8, D0     ; Extract 8 bits (1 byte) from msg_in+0x3
                                             ; BFEXTU: Bit Field Extract Unsigned
                                             ; Source: (offset 0x3, base A2)
                                             ; Bit offset: 0 (start of byte)
                                             ; Width: 8 bits
                                             ; Dest: D0
                                             ; Result: D0 = message version (0-255)

    ; --- VALIDATION STEP 2: Check message size ---
    ; Message must be exactly 0x42C (1068) bytes. This is a critical check
    ; as the handler expects a specific message structure layout.
.validate_size:
    cmpi.l      #0x42c, (0x4, A2)           ; Compare msg_in->size with 0x42C
                                             ; Offset 0x4 contains 32-bit size field
                                             ; Expected: 1068 bytes
    bne.b       .error_invalid_params       ; If size != 0x42C, jump to error handler
                                             ; Branch if not equal (validation failed)

    ; --- VALIDATION STEP 3: Check message version ---
    ; Version must be 1. This ensures protocol compatibility.
.validate_version:
    moveq       #0x1, D1                    ; Load expected version (1) into D1
                                             ; MOVEQ is efficient for small constants
    cmp.l       D0, D1                      ; Compare extracted version (D0) with 1
                                             ; D0 was set by bfextu earlier
    beq.b       .validate_field_0x18        ; If version == 1, continue validation
                                             ; Branch if equal (validation passed)

    ; --- ERROR PATH 1: Invalid size or version ---
    ; This error path handles the first two validation failures.
    ; Sets error code and jumps to epilogue.
.error_invalid_params:
    move.l      #-0x130, (0x1c, A3)         ; reply_out->error_code = -304 decimal
                                             ; Offset 0x1C is error_code field
                                             ; Negative value indicates error
    bra.b       .epilogue                   ; Jump to function exit (skip all processing)
                                             ; No response fields populated on error

    ; --- VALIDATION STEP 4: Check field at offset 0x18 ---
    ; This field must match a global configuration value. Likely a board ID
    ; or configuration token that ensures the message is for the correct board.
.validate_field_0x18:
    move.l      (0x18, A2), D1              ; Load msg_in->field_0x18 into D1
                                             ; This is a 32-bit value at offset 0x18
    cmp.l       (0x00007d4c).l, D1          ; Compare with global at 0x7D4C
                                             ; .l suffix forces absolute long addressing
                                             ; Global likely set during board registration
    bne.b       .error_field_mismatch       ; If mismatch, reject message
                                             ; Security check or board identification

    ; --- VALIDATION STEP 5: Check flags at offset 0x23 ---
    ; Flags byte must have bits 2 and 3 set (binary 00001100 = 0x0C).
    ; These bits likely indicate:
    ;   - Bit 2: Operation mode or permission flag
    ;   - Bit 3: DMA enable or data ready flag
.validate_flags_0x23:
    move.b      (0x23, A2), D0b             ; Load flags byte into D0 (byte operation)
                                             ; D0b is low byte of D0
                                             ; Offset 0x23 is flags field
    andi.b      #0xc, D0b                   ; Mask to isolate bits 2&3
                                             ; 0x0C = 00001100 binary
                                             ; Clears all other bits
    cmpi.b      #0xc, D0b                   ; Check if both bits are set
                                             ; Result must be exactly 0x0C
    bne.b       .error_field_mismatch       ; If not 0x0C, validation failed
                                             ; Branch to error handler

    ; --- VALIDATION STEP 6: Check field at offset 0x24 ---
    ; This 16-bit field must equal 12 (0x000C). Possibly:
    ;   - Transfer mode indicator
    ;   - DMA channel number
    ;   - Operation type code
.validate_field_0x24:
    cmpi.w      #0xc, (0x24, A2)            ; Compare msg_in->field_0x24 with 12
                                             ; Word comparison (16-bit)
                                             ; Offset 0x24 contains operation parameter
    bne.b       .error_field_mismatch       ; If not 12, reject message
                                             ; Branch to error on mismatch

    ; --- VALIDATION STEP 7: Check field at offset 0x28 ---
    ; This 32-bit field must equal 1. Likely:
    ;   - Number of operations/buffers
    ;   - Enable flag
    ;   - Format version
.validate_field_0x28:
    moveq       #0x1, D1                    ; Expected value = 1
                                             ; MOVEQ efficient for small constants
    cmp.l       (0x28, A2), D1              ; Compare msg_in->field_0x28 with 1
                                             ; Long comparison (32-bit)
    bne.b       .error_field_mismatch       ; If not 1, validation failed
                                             ; Branch to error handler

    ; --- VALIDATION STEP 8: Check field at offset 0x26 ---
    ; This 16-bit field must equal 0x2000 (8192 decimal). Significance:
    ;   - 8KB boundary/alignment requirement
    ;   - Page size for memory operations
    ;   - VRAM bank size (NeXTdimension uses banked VRAM)
.validate_field_0x26:
    cmpi.w      #0x2000, (0x26, A2)         ; Compare msg_in->field_0x26 with 0x2000
                                             ; Word comparison (16-bit)
                                             ; 0x2000 = 8192 decimal
    beq.b       .call_operation_handler     ; If equals 0x2000, all validations passed!
                                             ; Branch to success path

    ; --- ERROR PATH 2: Field validation failed ---
    ; This error path handles failures in validation steps 4-8 (field checks).
.error_field_mismatch:
    move.l      #-0x130, (0x1c, A3)         ; reply_out->error_code = -304
                                             ; Same error code as earlier validation failures
                                             ; Unified error reporting
    bra.b       .check_error_code           ; Jump to error check section
                                             ; Skip I/O operation

    ; --- SUCCESS PATH: All validations passed, call I/O operation handler ---
    ; Prepare parameters for FUN_00006398 and invoke it.
    ; Parameters pushed right-to-left (m68k convention):
    ;   Param 1: msg_in->field_0x0C (value - likely fd or handle)
    ;   Param 2: &msg_in->field_0x1C (pointer - data buffer)
    ;   Param 3: &msg_in->field_0x2C (pointer - auxiliary data)
.call_operation_handler:
    pea         (0x2c, A2)                  ; Push parameter 3: &msg_in->field_0x2C
                                             ; PEA = Push Effective Address
                                             ; Pointer to data at offset 0x2C
    pea         (0x1c, A2)                  ; Push parameter 2: &msg_in->field_0x1C
                                             ; Pointer to data at offset 0x1C
    move.l      (0xc, A2), -(SP)            ; Push parameter 1: msg_in->field_0x0C
                                             ; Value (not pointer) at offset 0xC
                                             ; Likely file descriptor or device handle

    bsr.l       0x00006398                  ; Call FUN_00006398 (I/O operation handler)
                                             ; BSR.L = Branch to Subroutine (long offset)
                                             ; Function will:
                                             ;   - Perform write() or ioctl() system call
                                             ;   - Handle errno on error
                                             ;   - Return result in D0
                                             ; Stack cleaned by caller (12 bytes)

    move.l      D0, (0x24, A3)              ; reply_out->result = return_value
                                             ; Store I/O operation result at offset 0x24
                                             ; D0 contains return value from FUN_00006398
    clr.l       (0x1c, A3)                  ; reply_out->error_code = 0
                                             ; Clear error code (success indicator)
                                             ; Offset 0x1C is error_code field

    ; --- CHECK ERROR CODE: Determine if response should be populated ---
    ; This check allows both success and error paths to converge.
    ; Response fields are only populated if error_code is 0 (success).
.check_error_code:
    tst.l       (0x1c, A3)                  ; Test reply_out->error_code
                                             ; TST sets condition codes based on value
                                             ; Z flag set if error_code == 0
    bne.b       .epilogue                   ; If error_code != 0, skip response population
                                             ; Branch if not equal to zero
                                             ; Go directly to function exit

    ; --- POPULATE RESPONSE STRUCTURE: Success path only ---
    ; Response fields are populated from global configuration values and
    ; echoed values from the input message. This allows the host to verify
    ; that the board state matches expectations.
.populate_response:
    move.l      (0x00007d50).l, (0x20, A3)  ; reply_out->field_0x20 = global_0x7d50
                                             ; Copy global config value to response
                                             ; Offset 0x20 in reply structure
                                             ; Likely board base address or ID
    move.l      (0x00007d54).l, (0x28, A3)  ; reply_out->field_0x28 = global_0x7d54
                                             ; Copy second global config value
                                             ; Offset 0x28 in reply structure
                                             ; Likely board capabilities or flags
    move.l      (0x1c, A2), (0x2c, A3)      ; reply_out->field_0x2C = msg_in->field_0x1C
                                             ; Echo input field to response
                                             ; Allows host to correlate request/response
    move.b      #0x1, (0x3, A3)             ; reply_out->version = 1
                                             ; Set response version byte
                                             ; Offset 0x3 is version field
                                             ; Always 1 for this protocol
    moveq       #0x30, D1                   ; Prepare reply size constant
                                             ; 0x30 = 48 bytes
                                             ; MOVEQ efficient for small constants
    move.l      D1, (0x4, A3)               ; reply_out->size = 0x30
                                             ; Set response size to 48 bytes
                                             ; Fixed size regardless of input size

    ; --- EPILOGUE: Restore registers and return ---
    ; Standard function exit: restore callee-save registers and destroy frame.
.epilogue:
    movea.l     (-0x8, A6), A2              ; Restore A2 from stack
                                             ; Load saved A2 from A6-0x8
                                             ; MOVEA = Move Address (no CC update)
    movea.l     (-0x4, A6), A3              ; Restore A3 from stack
                                             ; Load saved A3 from A6-0x4
    unlk        A6                          ; Destroy stack frame
                                             ; Restores old frame pointer
                                             ; Adjusts stack pointer
    rts                                     ; Return to caller
                                             ; Pops return address and jumps

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD42C
; ====================================================================================
;
; FUNCTION SUMMARY:
;   This message handler validates a 1068-byte Mach IPC message (command type 0x42C)
;   by performing 7 distinct checks on message size, version, and parameter fields.
;   On validation success, it delegates to FUN_00006398 for the actual I/O operation
;   (likely a write() or ioctl() system call), then populates the response structure
;   with global configuration values and the operation result. On validation failure,
;   it sets error code -304 and returns immediately without performing any operation.
;
;   The function is part of a message handler family (0x6000-0x7000 address range)
;   that follows a consistent validation pattern. Similar handlers exist for command
;   types 0x434 and others, differentiated by message size and parameter count.
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_MessageHandler_CMD42C(nd_message_t *msg_in, nd_reply_t *reply_out)
; {
;     // Extract message version
;     uint8_t version = (uint8_t)(msg_in->field_0x03);
;
;     // Validation chain - fail fast on any mismatch
;     if (msg_in->size != 0x42C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (version != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x18 != g_config_value_0x7d4c) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if ((msg_in->field_0x23 & 0x0C) != 0x0C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x24 != 0xC) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x28 != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;     if (msg_in->field_0x26 != 0x2000) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // All validations passed - perform I/O operation
;     int32_t result = FUN_00006398(
;         msg_in->field_0x0C,      // fd or handle
;         &msg_in->field_0x1C,     // data buffer pointer
;         &msg_in->field_0x2C      // auxiliary data pointer
;     );
;
;     // Populate response
;     reply_out->result = result;
;     reply_out->error_code = 0;
;     reply_out->field_0x20 = g_response_value_0x7d50;
;     reply_out->field_0x28 = g_response_value_0x7d54;
;     reply_out->field_0x2C = msg_in->field_0x1C;
;     reply_out->version = 1;
;     reply_out->size = 0x30;  // 48 bytes
; }
;
; ====================================================================================
; VALIDATION REFERENCE CARD:
; ====================================================================================
;
; Field Offset | Type   | Expected Value        | Purpose
; -------------|--------|-----------------------|-----------------------------------
; 0x03         | uint8  | 1                     | Message version
; 0x04         | uint32 | 0x42C (1068)          | Message size
; 0x18         | uint32 | global_0x7d4c         | Board ID / configuration token
; 0x23         | uint8  | & 0x0C == 0x0C        | Flags (bits 2&3 must be set)
; 0x24         | uint16 | 0x000C (12)           | Operation mode / DMA channel
; 0x26         | uint16 | 0x2000 (8192)         | 8KB alignment / page size
; 0x28         | uint32 | 1                     | Buffer count / enable flag
;
; ERROR CODE: -0x130 (304 decimal) for all validation failures
;
; GLOBALS USED:
;   0x00007D4C: Validation reference (input check)
;   0x00007D50: Response field (output)
;   0x00007D54: Response field (output)
;
; ====================================================================================
