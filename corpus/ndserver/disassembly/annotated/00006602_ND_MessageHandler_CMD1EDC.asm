; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageHandler_CMD1EDC
; ====================================================================================
; Address: 0x00006602
; Size: 218 bytes (0xDA)
; Purpose: Large memory transfer message handler with 8-step validation
; Analysis: docs/functions/00006602_ND_MessageHandler_CMD1EDC.md
; ====================================================================================

; FUNCTION: void ND_MessageHandler_CMD1EDC(nd_message_t *msg_in, nd_reply_t *reply_out)
;
; Message handler for bulk memory transfer operations (up to 7900 bytes payload).
; Validates message structure, addresses, flags, and alignment before delegating
; to FUN_000062b8 for the actual memory copy/DMA operation.
;
; PARAMETERS:
;   msg_in (A6+0x8): Pointer to incoming message (7952 bytes total)
;   reply_out (A6+0xC): Pointer to reply structure (48 bytes)
;
; RETURNS:
;   void (populates reply_out structure)
;     - reply_out->error_code = 0 on success, -0x130 on failure
;     - reply_out->result = return value from memory operation
;
; STACK FRAME: 12 bytes (3 saved registers)
;   A6-0x04: Saved A2
;   A6-0x08: Saved A3
;   A6-0x0C: Saved A4
;
; VALIDATION SEQUENCE:
;   1. Message size - 0x34 <= 0x1EDC (max 7900 bytes payload)
;   2. Version == 1
;   3. Source address matches global (0x7cfc)
;   4. Destination address matches global (0x7d00)
;   5. Flags at 0x2b have bits 2&3 set (0x0C)
;   6. Magic constant at 0x2c == 0x80008
;   7. Data size properly aligned to 4-byte boundary
;   8. Aligned size + 0x34 exactly equals message size
;
; ====================================================================================

FUN_00006602:
ND_MessageHandler_CMD1EDC:

; --- PROLOGUE ---
; Create stack frame and preserve callee-save registers
0x00006602:  link.w     A6,#0x0                   ; Create stack frame (no locals)
0x00006606:  movem.l    {A4,A3,A2},-(SP)          ; Save A2, A3, A4 (12 bytes)
0x0000660a:  movea.l    (0x8,A6),A2               ; A2 = msg_in (first parameter)
0x0000660e:  movea.l    (0xc,A6),A3               ; A3 = reply_out (second parameter)

; --- LOAD MESSAGE METADATA ---
; Extract message size and version for validation
0x00006612:  movea.l    (0x4,A2),A1               ; A1 = msg_in->size (total message bytes)

; --- VALIDATION STEP 1: Extract version byte ---
; Use bit field extract to get version from offset 0x3
0x00006616:  bfextu     (0x3,A2),0x0,0x8,D0       ; D0 = msg_in->version (byte at offset 3)
                                                   ; bfextu extracts 8 bits starting at bit 0

; --- VALIDATION STEP 2: Check size calculation ---
; Message size must fit constraint: size - 0x34 <= 0x1EDC
; This ensures payload doesn't exceed 7900 bytes
.validate_size_calculation:
0x0000661c:  lea        (-0x34,A1),A0             ; A0 = msg_size - 52 (subtract header)
0x00006620:  cmpa.l     #0x1edc,A0                ; Compare (size - 52) with 7900
0x00006626:  bhi.b      .error_invalid_params     ; Branch if (size - 52) > 7900
                                                   ; This rejects oversized messages

; --- VALIDATION STEP 3: Check message version ---
; Only version 1 is supported by this handler
.validate_version:
0x00006628:  moveq      #0x1,D1                   ; Expected version = 1
0x0000662a:  cmp.l      D0,D1                     ; Compare extracted version with 1
0x0000662c:  beq.b      .validate_addresses       ; If version == 1, continue

; --- ERROR PATH 1: Invalid parameters (size or version) ---
; Set error code and jump to epilogue
.error_invalid_params:
0x0000662e:  move.l     #-0x130,(0x1c,A3)         ; reply_out->error_code = -304
0x00006636:  bra.w      .epilogue                 ; Exit function

; --- VALIDATION STEP 4: Check source address ---
; Source address must match pre-configured global value
.validate_addresses:
0x0000663a:  movea.l    (0x18,A2),A4              ; A4 = msg_in->source_address
0x0000663e:  cmpa.l     (0x00007cfc).l,A4         ; Compare with g_valid_source_addr
0x00006644:  bne.b      .error_field_mismatch     ; Reject if mismatch

; --- VALIDATION STEP 5: Check destination address ---
; Destination address must also match global configuration
.validate_dest_address:
0x00006646:  move.l     (0x20,A2),D1              ; D1 = msg_in->dest_address
0x0000664a:  cmp.l      (0x00007d00).l,D1         ; Compare with g_valid_dest_addr
0x00006650:  bne.b      .error_field_mismatch     ; Reject if mismatch

; --- VALIDATION STEP 6: Check flags at offset 0x2b ---
; Bits 2 and 3 must both be set (likely read/write permissions)
.validate_flags_0x2b:
0x00006652:  move.b     (0x2b,A2),D0b             ; Load flags byte
0x00006656:  andi.b     #0xc,D0b                  ; Mask bits 2&3 (0x0C = 00001100b)
0x0000665a:  cmpi.b     #0xc,D0b                  ; Check if both bits set
0x0000665e:  bne.b      .error_field_mismatch     ; Reject if not 0x0C

; --- VALIDATION STEP 7: Check magic constant ---
; Field at 0x2c must contain exact value 0x80008
.validate_magic:
0x00006660:  cmpi.l     #0x80008,(0x2c,A2)        ; Check magic constant
                                                   ; 0x80008 might be memory window base
0x00006668:  bne.b      .error_field_mismatch     ; Reject if wrong value

; --- VALIDATION STEP 8: Check alignment and exact size match ---
; Data size must align to 4-byte boundary and match message size perfectly
.validate_alignment:
0x0000666a:  move.l     (0x30,A2),D0              ; D0 = msg_in->data_size (unaligned)
0x0000666e:  addq.l     #0x3,D0                   ; D0 += 3 (prepare for rounding)
0x00006670:  moveq      #-0x4,D1                  ; D1 = 0xFFFFFFFC (4-byte align mask)
0x00006672:  and.l      D1,D0                     ; D0 = (size + 3) & ~3
                                                   ; Round up to 4-byte boundary
0x00006674:  movea.l    D0,A4                     ; A4 = aligned_size

; Check that aligned size + header exactly equals message size
.validate_exact_size:
0x00006676:  lea        (0x34,A4),A0              ; A0 = aligned_size + 52 (header)
0x0000667a:  cmpa.l     A1,A0                     ; Compare with actual msg_size
                                                   ; Ensures perfect fit, no padding issues
0x0000667c:  beq.b      .call_memory_handler      ; If exact match, proceed

; --- ERROR PATH 2: Field validation failed ---
; One of the address, flag, magic, or alignment checks failed
.error_field_mismatch:
0x0000667e:  move.l     #-0x130,(0x1c,A3)         ; reply_out->error_code = -304
0x00006686:  bra.b      .check_error_code         ; Jump to response phase

; --- SUCCESS PATH: Call memory operation handler ---
; All validations passed - prepare parameters and call FUN_000062b8
.call_memory_handler:
    ; Push 5 parameters onto stack (right-to-left C calling convention)
    ; FUN_000062b8(control_word, &dest_info, flags, &data, size)

0x00006688:  move.l     (0x30,A2),-(SP)           ; Param 5: data_size
0x0000668c:  pea        (0x34,A2)                 ; Param 4: &payload_data (data pointer)
                                                   ; Offset 0x34 is where payload starts
0x00006690:  move.l     (0x24,A2),-(SP)           ; Param 3: flags_mode
0x00006694:  pea        (0x1c,A2)                 ; Param 2: &dest_info
0x00006698:  move.l     (0xc,A2),-(SP)            ; Param 1: control_word

0x0000669c:  bsr.l      0x000062b8                ; Call FUN_000062b8
                                                   ; Wraps library memory operation
                                                   ; Returns status in D0
                                                   ; Stack: 20 bytes (5 params × 4)

0x000066a2:  move.l     D0,(0x24,A3)              ; reply_out->result = operation_result
0x000066a6:  clr.l      (0x1c,A3)                 ; reply_out->error_code = 0 (success)
                                                   ; Note: Stack cleanup handled by caller

; --- CHECK ERROR CODE ---
; Determine whether to populate response fields
.check_error_code:
0x000066aa:  tst.l      (0x1c,A3)                 ; Test reply_out->error_code
0x000066ae:  bne.b      .epilogue                 ; If error, skip response population

; --- POPULATE RESPONSE STRUCTURE ---
; Success path only - fill in reply fields from globals and input
.populate_response:
0x000066b0:  move.l     (0x00007d04).l,(0x20,A3)  ; reply_out->field_0x20 = g_response_data_1
0x000066b8:  move.l     (0x00007d08).l,(0x28,A3)  ; reply_out->field_0x28 = g_response_data_2
0x000066c0:  move.l     (0x1c,A2),(0x2c,A3)       ; reply_out->field_0x2c = msg_in->dest_info
                                                   ; Echo back dest_info for client verification
0x000066c6:  move.b     #0x1,(0x3,A3)             ; reply_out->version = 1
0x000066cc:  moveq      #0x30,D1                  ; Prepare reply size constant
0x000066ce:  move.l     D1,(0x4,A3)               ; reply_out->size = 48 bytes (0x30)

; --- EPILOGUE ---
; Restore saved registers and return
.epilogue:
0x000066d2:  movem.l    -0xc(A6),{A2,A3,A4}       ; Restore A2, A3, A4 from stack
                                                   ; -0xC(A6) = FP - 12 bytes
0x000066d8:  unlk       A6                        ; Restore caller's frame pointer
0x000066da:  rts                                  ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MessageHandler_CMD1EDC
; ====================================================================================
;
; FUNCTION SUMMARY:
;   Validates and executes large memory transfer operations between host and
;   NeXTdimension i860 board. Enforces strict message format, address validation,
;   and alignment constraints before delegating to low-level memory handler.
;   Returns 48-byte reply with operation result or -304 error code.
;
; VALIDATION SUMMARY:
;   - Message size: 7952 bytes (0x1f10) with 52-byte header + 7900-byte payload
;   - Version: Must be 1
;   - Addresses: Source and dest must match pre-configured globals
;   - Flags: Bits 2&3 must be set at offset 0x2b
;   - Magic: 0x80008 constant at offset 0x2c
;   - Alignment: Data size rounds to 4-byte boundary, total size exact match
;
; CALLED FUNCTIONS:
;   FUN_000062b8 - Memory operation wrapper (5 params)
;     → Library: 0x0500330e (vm_copy/memcpy?)
;
; GLOBAL VARIABLES:
;   0x7cfc: g_valid_source_addr (source address validation)
;   0x7d00: g_valid_dest_addr (destination address validation)
;   0x7d04: g_response_data_1 (copied to reply)
;   0x7d08: g_response_data_2 (copied to reply)
;
; ERROR HANDLING:
;   All validation failures return error code -0x130 (304 decimal)
;   No partial success - operation is atomic (validate then execute)
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; void ND_MessageHandler_CMD1EDC(
;     nd_message_cmd1edc_t *msg_in,
;     nd_reply_t *reply_out
; ) {
;     // Extract metadata
;     uint32_t msg_size = msg_in->size;
;     uint8_t version = msg_in->version;
;
;     // Validate size calculation
;     if ((msg_size - 0x34) > 0x1EDC) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate version
;     if (version != 1) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate source address
;     if (msg_in->source_address != g_valid_source_addr) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate destination address
;     if (msg_in->dest_address != g_valid_dest_addr) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate flags (bits 2&3 must be set)
;     if ((msg_in->flags_0x2b & 0x0C) != 0x0C) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate magic constant
;     if (msg_in->magic_0x2c != 0x80008) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // Validate alignment - must be exact fit
;     uint32_t data_size = msg_in->data_size;
;     uint32_t aligned_size = (data_size + 3) & ~3;
;     if ((aligned_size + 0x34) != msg_size) {
;         reply_out->error_code = -0x130;
;         return;
;     }
;
;     // All validations passed - perform operation
;     int32_t result = FUN_000062b8(
;         msg_in->control_word,
;         &msg_in->dest_info,
;         msg_in->flags_mode,
;         &msg_in->payload_data[0],
;         msg_in->data_size
;     );
;
;     // Populate reply
;     reply_out->result = result;
;     reply_out->error_code = 0;
;     reply_out->field_0x20 = g_response_data_1;
;     reply_out->field_0x28 = g_response_data_2;
;     reply_out->field_0x2c = msg_in->dest_info;  // Echo back
;     reply_out->version = 1;
;     reply_out->size = 0x30;  // 48 bytes
; }
;
; ====================================================================================
