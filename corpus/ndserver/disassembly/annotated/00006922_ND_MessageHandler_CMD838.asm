; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD838
; ====================================================================================
; Address: 0x00006922
; Size: 230 bytes (0xE6)
; Purpose: Validate and process Mach IPC messages with command type 0x838 (2104 bytes)
; Analysis: docs/functions/00006922_ND_MessageHandler_CMD838.md
; ====================================================================================

; FUNCTION: ND_MessageHandler_CMD838
;
; This message handler validates incoming Mach IPC messages with command type 0x838
; (2104 decimal bytes), performing extensive dual-region parameter validation before
; delegating to a lower-level processing handler. The function checks two separate
; descriptor regions (Region 1 at offsets 0x23-0x2C, Region 2 at 0x42F-0x438) with
; identical validation criteria, suggesting it processes operations with two distinct
; data regions - likely dual-DMA transfers, bidirectional data exchange, or chained
; operations for the NeXTdimension graphics board.
;
; PARAMETERS:
;   msg_in (A6+0x8):    Pointer to incoming message structure (2104 bytes)
;   reply_out (A6+0xC): Pointer to reply structure (minimum 48 bytes)
;
; RETURNS:
;   void (modifies reply_out structure in-place)
;
; STACK FRAME: 0 bytes (no local variables)
;   -0x8: Saved A2 (msg_in pointer)
;   -0x4: Saved A3 (reply_out pointer)
;
; VALIDATION STEPS:
;   1. Message size must be 0x838 (2104 bytes)
;   2. Message version must be 1
;   3. Field at offset 0x18 must match global at 0x7d40
;   4-7. Region 1 descriptor validation (offsets 0x23-0x28)
;   8-11. Region 2 descriptor validation (offsets 0x42F-0x434)
;
; ERROR HANDLING:
;   On any validation failure: Sets reply_out->error_code = -0x130 (304 decimal)
;   On success: Clears error_code, calls handler, populates response
;
; ====================================================================================

FUN_00006922:
ND_MessageHandler_CMD838:

; --- PROLOGUE: Create stack frame and save registers ---
    link.w      A6,#0x0                   ; Create 0-byte stack frame (no locals)
    move.l      A3,-(SP)                  ; Save A3 (callee-save register)
    move.l      A2,-(SP)                  ; Save A2 (callee-save register)
                                          ; Stack: [saved A2][saved A3][saved A6][ret addr][param1][param2]

; --- PARAMETER LOADING ---
    movea.l     (0x8,A6),A2               ; A2 = msg_in (first parameter at A6+8)
    movea.l     (0xc,A6),A3               ; A3 = reply_out (second parameter at A6+12)

; --- VALIDATION STEP 1: Extract message version byte ---
; Extract 8 bits starting at bit offset 0 from byte at (A2+3)
; This uses the powerful m68k bit field extraction instruction
    bfextu      (0x3,A2),0x0,0x8,D0       ; D0 = msg_in->version (byte at offset 3)
                                          ; bfextu: Bit Field Extract Unsigned
                                          ; Source: (A2+3), bit offset 0, width 8 bits
                                          ; Destination: D0 (zero-extended)

; --- VALIDATION STEP 2: Check message size ---
; The message size field at offset 0x4 must contain exactly 0x838 (2104 decimal)
; This is significantly larger than most other message types
    cmpi.l      #0x838,(0x4,A2)           ; Compare msg_in->size with 0x838 (2104)
    bne.b       .validation_fail_early    ; If size != 0x838, branch to error handler

; --- VALIDATION STEP 3: Check version number ---
; The extracted version byte must equal 1 (protocol version)
    moveq       #0x1,D1                   ; D1 = 1 (expected version, efficient encoding)
    cmp.l       D0,D1                     ; Compare extracted version (D0) with 1 (D1)
    beq.b       .check_region1_params     ; If version == 1, continue to Region 1 checks

.validation_fail_early:
; --- ERROR PATH 1: Size or version validation failed ---
; Set error code and jump to epilogue (skip all processing)
    move.l      #-0x130,(0x1c,A3)         ; reply_out->error_code = -0x130 (304 decimal)
                                          ; This is the standard error code for validation failures
    bra.w       .epilogue                 ; Jump to function epilogue (word branch, longer distance)

.check_region1_params:
; --- VALIDATION STEP 4: Check field at offset 0x18 against global ---
; This validates a configuration-dependent value, possibly a port name or task ID
    move.l      (0x18,A2),D1              ; D1 = msg_in->field_0x18
    cmp.l       (0x00007d40).l,D1         ; Compare with global value at 0x7d40
                                          ; .l suffix indicates absolute long addressing
    bne.b       .validation_fail_region1  ; If mismatch, fail validation

; --- REGION 1 DESCRIPTOR VALIDATION (offsets 0x23-0x28) ---
; The following checks validate the first descriptor structure

; --- VALIDATION STEP 5: Check flags at offset 0x23 (Region 1) ---
; Extract byte, mask with 0xC (binary 00001100), verify both bits 2&3 are set
; These bits likely indicate permissions (read/write) or DMA enable flags
    move.b      (0x23,A2),D0b             ; D0 = msg_in->flags_region1 (byte access via D0b)
    andi.b      #0xc,D0b                  ; AND with 0x0C (mask for bits 2 & 3)
                                          ; Result: 0x0C if both set, else 0x00/0x04/0x08
    cmpi.b      #0xc,D0b                  ; Compare with 0x0C (both bits must be set)
    bne.b       .validation_fail_region1  ; If not both set, fail

; --- VALIDATION STEP 6: Check word at offset 0x24 (Region 1) ---
; This field must contain 0xC (12 decimal) - possibly a size or type indicator
    cmpi.w      #0xc,(0x24,A2)            ; Compare msg_in->field_0x24 with 12
    bne.b       .validation_fail_region1  ; If not 12, fail

; --- VALIDATION STEP 7: Check field at offset 0x28 (Region 1) ---
; This long word must equal 1 - possibly a count, enable flag, or descriptor type
    moveq       #0x1,D1                   ; D1 = 1 (expected value)
    cmp.l       (0x28,A2),D1              ; Compare msg_in->field_0x28 with 1
    bne.b       .validation_fail_region1  ; If not 1, fail

; --- VALIDATION STEP 8: Check word at offset 0x26 (Region 1) ---
; This field must contain 0x2000 (8192 decimal) - likely a size or alignment requirement
; 8192 is 2^13, suggesting page size, buffer size, or memory region alignment
    cmpi.w      #0x2000,(0x26,A2)         ; Compare msg_in->field_0x26 with 0x2000 (8192)
    bne.b       .validation_fail_region1  ; If not 0x2000, fail

; --- REGION 2 DESCRIPTOR VALIDATION (offsets 0x42F-0x434) ---
; The following checks validate the SECOND descriptor structure
; Note: Region 2 starts at offset 0x42F, which is 0x40C (1036) bytes after Region 1
; This suggests two separate data regions or operation descriptors

; --- VALIDATION STEP 9: Check flags at offset 0x42F (Region 2) ---
; Same bit pattern check as Region 1 - both regions must have identical flag settings
    move.b      (0x42f,A2),D0b            ; D0 = msg_in->flags_region2 (byte)
    andi.b      #0xc,D0b                  ; Mask with 0x0C (bits 2 & 3)
    cmpi.b      #0xc,D0b                  ; Check if both bits set
    bne.b       .validation_fail_region1  ; If not both set, fail (note: same error label)

; --- VALIDATION STEP 10: Check word at offset 0x430 (Region 2) ---
; Same value check as Region 1 offset 0x24 - both must be 12
    cmpi.w      #0xc,(0x430,A2)           ; Compare msg_in->field_0x430 with 12
    bne.b       .validation_fail_region1  ; If not 12, fail

; --- VALIDATION STEP 11: Check field at offset 0x434 (Region 2) ---
; Same value check as Region 1 offset 0x28 - both must be 1
    moveq       #0x1,D1                   ; D1 = 1 (expected value)
    cmp.l       (0x434,A2),D1             ; Compare msg_in->field_0x434 with 1
    bne.b       .validation_fail_region1  ; If not 1, fail

; --- VALIDATION STEP 12: Check word at offset 0x432 (Region 2) ---
; Same value check as Region 1 offset 0x26 - both must be 0x2000 (8192)
    cmpi.w      #0x2000,(0x432,A2)        ; Compare msg_in->field_0x432 with 0x2000
    beq.b       .all_validation_passed    ; If equal, ALL 12 checks passed! Proceed to handler

.validation_fail_region1:
; --- ERROR PATH 2: Region 1 or Region 2 validation failed ---
; Set error code and jump to error check logic
    move.l      #-0x130,(0x1c,A3)         ; reply_out->error_code = -0x130
    bra.b       .check_error_and_continue ; Jump to error check (short branch)

.all_validation_passed:
; --- SUCCESS PATH: All 12 validation checks passed ---
; Extract 4 parameters from message structure and call processing handler

; Build parameter list on stack (pushed right-to-left per C calling convention)
; Parameters are a mix of value (param 1) and pointers (params 2-4)

    pea         (0x438,A2)                ; Push &msg_in->field_0x438 (param 4 - Region 2 data base)
                                          ; pea = Push Effective Address (efficient pointer passing)
    pea         (0x2c,A2)                 ; Push &msg_in->field_0x2c (param 3 - Region 1 extended)
    pea         (0x1c,A2)                 ; Push &msg_in->field_0x1c (param 2 - Region 1 data base)
    move.l      (0xc,A2),-(SP)            ; Push msg_in->field_0xc (param 1 - value, not pointer)

; Call the processing function that will perform the actual operation
; This function is HIGH PRIORITY for analysis to understand what CMD838 does
    bsr.l       FUN_0000636c              ; Call handler at 0x0000636c (25452 decimal)
                                          ; bsr.l = Branch to Subroutine (long displacement)
                                          ; Return value will be in D0

; Note: Stack cleanup for 4 parameters (16 bytes) happens after this block
; The m68k convention leaves cleanup to caller

; Store the handler's return value in the reply structure
    move.l      D0,(0x24,A3)              ; reply_out->result = return_value from handler

; Clear error code to indicate successful processing
    clr.l       (0x1c,A3)                 ; reply_out->error_code = 0 (success)
                                          ; clr.l is more efficient than move.l #0

.check_error_and_continue:
; --- CONDITIONAL RESPONSE POPULATION ---
; Only populate response fields if error_code is still 0 (success path)
; This prevents partial responses on validation failures
    tst.l       (0x1c,A3)                 ; Test reply_out->error_code (sets flags based on value)
    bne.b       .epilogue                 ; If error set (non-zero), skip response setup

; --- RESPONSE POPULATION (Success Path Only) ---
; Copy 4 global values and 1 message field into reply structure
; These fields provide context for the client about the operation result

; Copy global value 1 - likely a port name or task identifier
    move.l      (0x00007d44).l,(0x20,A3)  ; reply_out->field_0x20 = global_0x7d44
                                          ; Absolute long addressing for global variable

; Copy global value 2 - likely related configuration or descriptor
    move.l      (0x00007d48).l,(0x28,A3)  ; reply_out->field_0x28 = global_0x7d48

; Copy message field to reply - echo back client-provided value
    move.l      (0x1c,A2),(0x2c,A3)       ; reply_out->field_0x2c = msg_in->field_0x1c

; Set response type/version byte to 1 (protocol version)
    move.b      #0x1,(0x3,A3)             ; reply_out->version = 1

; Set response size to 0x30 (48 decimal bytes)
; This indicates the reply structure contains 48 bytes of valid data
    moveq       #0x30,D1                  ; D1 = 0x30 (48 decimal, efficient encoding)
    move.l      D1,(0x4,A3)               ; reply_out->size = 48

.epilogue:
; --- EPILOGUE: Restore registers and return ---
; Clean up stack frame and restore callee-save registers
    movea.l     (-0x8,A6),A2              ; Restore A2 from stack (msg_in pointer)
    movea.l     (-0x4,A6),A3              ; Restore A3 from stack (reply_out pointer)
    unlk        A6                        ; Destroy stack frame (restore A6, adjust SP)
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD838
; ====================================================================================

; FUNCTION SUMMARY:
;
; This function is a message handler for Mach IPC command 0x838 (2104 bytes), which
; validates incoming messages through 12 distinct checks across two separate descriptor
; regions before delegating to FUN_0000636c for actual processing. The dual-region
; validation pattern is unique among observed handlers, suggesting this command handles
; complex operations with two distinct data areas - possibly dual-DMA transfers,
; bidirectional data exchange, or chained graphics operations for the NeXTdimension
; board.
;
; The function uses the standard NDserver error handling pattern (error code -0x130
; on any validation failure) and populates a 48-byte reply structure with global
; configuration values and the handler's result on success. The symmetric validation
; of Region 1 (offsets 0x23-0x2C) and Region 2 (offsets 0x42F-0x438) with identical
; criteria (same flags, same values) strongly suggests both regions represent the
; same type of descriptor or operation parameter.
;
; Key architectural insights:
; - Part of message dispatch system (likely called by ND_MessageDispatcher)
; - Uses global configuration values (0x7d40, 0x7d44, 0x7d48)
; - Delegates actual work to FUN_0000636c with 4 extracted parameters
; - Large message size (2104 bytes) indicates substantial data payload
; - No hardware interaction at this level (pure validation/delegation)

; ====================================================================================
; REVERSE-ENGINEERED C EQUIVALENT:
; ====================================================================================

; typedef struct {
;     uint8_t  reserved[3];
;     uint8_t  version;                 // 0x03 (must be 1)
;     uint32_t size;                    // 0x04 (must be 0x838 = 2104)
;     uint32_t reserved2[2];            // 0x08-0x0B
;     uint32_t field_0xc;               // 0x0C (param 1 to handler)
;     uint32_t reserved3[3];            // 0x10-0x17
;     uint32_t field_0x18;              // 0x18 (must match global_0x7d40)
;     uint32_t field_0x1c;              // 0x1C (param 2 base, copied to reply)
;
;     // REGION 1 DESCRIPTOR (0x23-0x2B)
;     uint8_t  padding1[3];             // 0x20-0x22
;     uint8_t  flags_region1;           // 0x23 (bits 2&3 must be set)
;     uint16_t field_0x24;              // 0x24 (must be 0x0C = 12)
;     uint16_t field_0x26;              // 0x26 (must be 0x2000 = 8192)
;     uint32_t field_0x28;              // 0x28 (must be 1)
;     uint32_t field_0x2c;              // 0x2C (param 3 base)
;
;     uint8_t  data[0x3FF];             // 0x30-0x42E (1023 bytes)
;
;     // REGION 2 DESCRIPTOR (0x42F-0x437)
;     uint8_t  flags_region2;           // 0x42F (bits 2&3 must be set)
;     uint16_t field_0x430;             // 0x430 (must be 0x0C = 12)
;     uint16_t field_0x432;             // 0x432 (must be 0x2000 = 8192)
;     uint32_t field_0x434;             // 0x434 (must be 1)
;     uint32_t field_0x438;             // 0x438 (param 4 base)
;
;     uint8_t  trailing_data[0x3FC];    // 0x43C-0x837 (1020 bytes)
; } nd_message_cmd838_t;
;
; typedef struct {
;     uint8_t  reserved[3];
;     uint8_t  version;                 // 0x03 (set to 1 on success)
;     uint32_t size;                    // 0x04 (set to 0x30 = 48)
;     uint8_t  reserved2[0x14];         // 0x08-0x1B
;     int32_t  error_code;              // 0x1C (0 = success, -0x130 = error)
;     uint32_t field_0x20;              // 0x20 (from global_0x7d44)
;     uint32_t result;                  // 0x24 (from handler return)
;     uint32_t field_0x28;              // 0x28 (from global_0x7d48)
;     uint32_t field_0x2c;              // 0x2C (copied from msg_in->field_0x1c)
; } nd_reply_t;
;
; extern uint32_t global_0x7d40;
; extern uint32_t global_0x7d44;
; extern uint32_t global_0x7d48;
; extern int32_t FUN_0000636c(uint32_t, void*, void*, void*);
;
; void ND_MessageHandler_CMD838(nd_message_cmd838_t *msg_in, nd_reply_t *reply_out)
; {
;     uint8_t version = msg_in->version;
;
;     // Validate size and version
;     if (msg_in->size != 0x838 || version != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate Region 1
;     if (msg_in->field_0x18 != global_0x7d40 ||
;         (msg_in->flags_region1 & 0x0C) != 0x0C ||
;         msg_in->field_0x24 != 0x0C ||
;         msg_in->field_0x28 != 1 ||
;         msg_in->field_0x26 != 0x2000) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // Validate Region 2
;     if ((msg_in->flags_region2 & 0x0C) != 0x0C ||
;         msg_in->field_0x430 != 0x0C ||
;         msg_in->field_0x434 != 1 ||
;         msg_in->field_0x432 != 0x2000) {
;         reply_out->error_code = -0x130;
;         goto check_error;
;     }
;
;     // Call handler
;     int32_t result = FUN_0000636c(
;         msg_in->field_0xc,
;         &msg_in->field_0x1c,
;         &msg_in->field_0x2c,
;         &msg_in->field_0x438
;     );
;
;     reply_out->result = result;
;     reply_out->error_code = 0;
;
; check_error:
;     if (reply_out->error_code == 0) {
;         reply_out->field_0x20 = global_0x7d44;
;         reply_out->field_0x28 = global_0x7d48;
;         reply_out->field_0x2c = msg_in->field_0x1c;
;         reply_out->version = 1;
;         reply_out->size = 0x30;
;     }
; }

; ====================================================================================
