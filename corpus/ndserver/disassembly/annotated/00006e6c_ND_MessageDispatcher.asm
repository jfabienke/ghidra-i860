; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageDispatcher
; ====================================================================================
; Address: 0x00006e6c
; Size: 272 bytes (68 instructions)
; Purpose: Message type dispatcher with jump table (types 0-5)
; Analysis: docs/functions/00006e6c_ND_MessageDispatcher.md
; ====================================================================================

; FUNCTION: int ND_MessageDispatcher(nd_message_t* message, nd_result_t* result)
;
; Jump table dispatcher that routes 6 message types (0-5) to their respective
; handler functions. Implements classic m68k switch statement pattern with
; indirect jump through table at 0x6e9a.
;
; PARAMETERS:
;   message (A6+0x8):  Pointer to message structure
;                      - field_0x10: Transfer destination/handle
;                      - field_0x14: Message type (0-5)
;                      - field_0x18: Transfer source/buffer ID
;                      - field_0x20: Data value (used by some cases)
;
;   result (A6+0xC):   Pointer to result structure
;                      - field_0x1C: Error code output
;
; RETURNS:
;   D0: 0 on success, 1 on error
;   result->error_code: Set to -0x131 on failure
;
; STACK FRAME: 512 bytes
;   -0x200: 512-byte buffer for string/message operations
;
; CALLS:
;   0x0500208a - fgetc(FILE*)
;   0x050024f8 - fopen/related
;   0x05002510 - fgets(char*, int, FILE*)
;   0x0500253a - fputs/related
;   0x05003038 - strlen(char*)
;   0x050028c4 - printf(char*, ...)
;   FUN_00003eae - Transfer/send function
;   FUN_000075e2 - Error handler
;
; GLOBAL VARIABLES:
;   0x4010000 - Global buffer structure (FILE* style)
;   0x4010004 - Buffer data pointer
;   0x4010014 - Buffer name string
;   0x000081ac - Unknown global (written by case 4)
;
; ====================================================================================

FUN_00006e6c:
    ; --- PROLOGUE ---
    link.w      A6, #-0x200               ; Create 512-byte stack frame
    movem.l     {D2,A2,A3,A4}, -(SP)      ; Save preserved registers (16 bytes)

    ; --- LOAD AND BACKUP PARAMETERS ---
    movea.l     (0x8,A6), A1              ; A1 = message pointer (from stack)
    move.l      (0xc,A6), D1              ; D1 = result pointer (from stack)
    movea.l     A1, A3                    ; A3 = message (backup for later use)
    movea.l     D1, A4                    ; A4 = result (backup for later use)

    ; --- TYPE FIELD VALIDATION ---
    moveq       #0x5, D2                  ; D2 = 5 (maximum valid message type)
    cmp.l       (0x14,A1), D2             ; Compare: message->message_type vs 5
    bcs.w       .LAB_00006f74             ; if (message_type > 5) goto out_of_range

    ; --- JUMP TABLE DISPATCH ---
    ; This implements: switch (message->message_type) { ... }
    move.l      (0x14,A1), D0             ; D0 = message->message_type (0-5)
    movea.l     #0x6e9a, A0               ; A0 = &jump_table (table base address)
    movea.l     (0x0,A0,D0.l*4), A0       ; A0 = jump_table[message_type]
                                           ; Indirect load: A0 = *(jump_table + type*4)
    jmp         (A0)                      ; Jump to case handler

; ====================================================================================
; JUMP TABLE DATA - Embedded between code blocks
; ====================================================================================
; Located at: 0x00006e9a
; Size: 24 bytes (6 long-words)
;
; CRITICAL NOTE: This table is ALL ZEROS in the NDserver binary file!
; The actual case target addresses are unknown. Possible explanations:
;   1. Dynamic linker relocations (table filled at load time)
;   2. Runtime initialization by startup code
;   3. Stripped/optimized binary (Ghidra couldn't extract)
;   4. Position-independent code requiring fixups
;
; Expected structure:
;   ADDR_00006e9a:
;     DC.L  case_handler_X    ; Type 0 → Unknown target
;     DC.L  case_handler_Y    ; Type 1 → Unknown target
;     DC.L  case_handler_Z    ; Type 2 → Unknown target
;     DC.L  case_handler_W    ; Type 3 → Unknown target
;     DC.L  case_handler_V    ; Type 4 → Unknown target
;     DC.L  case_handler_U    ; Type 5 → Unknown target
;
; Identified case handlers (by control flow analysis):
;   0x6eb2 - Case handler #1: Simple library call
;   0x6ec6 - Case handler #2: Complex buffer/string operations
;   0x6f0a - Case handler #3: Single byte read/write
;   0x6f68 - Case handler #4: Write value to global 0x81ac
;
; Gap: 24 bytes (0x6e9a to 0x6eb1) matches 6 × 4-byte pointers
; ====================================================================================

    ; --- Case handlers begin at 0x6eb2 ---
    ; NOTE: Without the actual jump table data, we cannot determine which
    ; message type maps to which handler. The following labels are ordered
    ; by address, not by type value.

; ====================================================================================
; CASE HANDLER #1 (Address: 0x6eb2)
; ====================================================================================
; Simple two-parameter library call followed by error exit
;
.LAB_00006eb2:
    pea         (0x4010014).l             ; Push address of g_buffer_name
    pea         (0x20,A3)                 ; Push (message + 0x20)
    bsr.l       0x0500253a                ; Call library function
                                           ; Likely: fputs/related(message+0x20, g_buffer_name)
                                           ; D0 = result
    bra.w       .LAB_00006f80             ; goto common_error_exit

; ====================================================================================
; CASE HANDLER #2 (Address: 0x6ec6)
; ====================================================================================
; Complex string/buffer manipulation with transfer operation
; Uses:
;   - 512-byte local buffer for string storage
;   - Multiple library calls (fopen, fgets, strlen)
;   - Transfer via FUN_00003eae
;
.LAB_00006ec6:
    ; --- LIBRARY CALL: Open/Reset Buffer ---
    pea         (0x4010014).l             ; Push &g_buffer_name
    bsr.l       0x050024f8                ; result = lib_open(&g_buffer_name)
                                           ; Likely: fopen() or buffer reset

    ; --- READ STRING FROM BUFFER ---
    pea         (0x4010000).l             ; Push &global_buffer (FILE* structure)
    pea         (0x1ff).w                 ; Push 511 (max bytes to read)
    lea         (-0x200,A6), A2           ; A2 = &local_buffer (512-byte stack buffer)
    move.l      A2, -(SP)                 ; Push &local_buffer
    bsr.l       0x05002510                ; result = fgets(local_buffer, 511, global_buffer)
                                           ; Reads up to 511 chars + null terminator

    ; --- GET STRING LENGTH ---
    move.l      A2, -(SP)                 ; Push &local_buffer
    bsr.l       0x05003038                ; D0 = strlen(local_buffer)
    addq.l      #0x1, D0                  ; D0 += 1 (include null terminator in length)

    ; --- TRANSFER STRING VIA FUN_00003eae ---
    move.l      D0, -(SP)                 ; Push length (strlen + 1)
    move.l      A2, -(SP)                 ; Push &local_buffer (data to send)
    move.l      (0x18,A3), -(SP)          ; Push message->field_0x18 (source/buffer ID)
    move.l      (0x10,A3), -(SP)          ; Push message->field_0x10 (dest/handle)
    bsr.l       0x00003eae                ; D0 = FUN_00003eae(dest, src, buffer, len)
                                           ; Transfer/send function (Mach IPC or DMA?)
    adda.w      #0x24, SP                 ; Clean up 9 args (36 bytes)
                                           ; 3 from fgets + 1 from strlen + 4 from transfer
                                           ; + 1 from lib_open = 9 args
    bra.b       .LAB_00006f54             ; goto check_transfer_result

; ====================================================================================
; CASE HANDLER #3 (Address: 0x6f0a)
; ====================================================================================
; Single byte read and transfer
; Implements buffered character I/O (fgetc pattern)
;
.LAB_00006f0a:
    ; --- BUFFERED BYTE READ ---
    lea         (0x4010000).l, A0         ; A0 = &global_buffer
    subq.l      #0x1, (A0)                ; global_buffer.count--
    bmi.b       .LAB_00006f24             ; if (count < 0) goto buffer_empty

    ; Fast path: buffer has available data
    movea.l     (0x04010004).l, A0        ; A0 = global_buffer.data_ptr
    move.b      (A0), D0                  ; D0.b = *data_ptr (read byte)
    addq.l      #0x1, (0x04010004).l      ; data_ptr++ (advance to next byte)
    bra.b       .LAB_00006f32             ; goto got_byte

.LAB_00006f24:
    ; Slow path: buffer empty, refill via library call
    pea         (0x4010000).l             ; Push &global_buffer
    bsr.l       0x0500208a                ; D0 = fgetc(&global_buffer)
                                           ; Refills buffer and returns next byte
    addq.w      #0x4, SP                  ; Clean up 1 argument (4 bytes)

.LAB_00006f32:
    ; --- CREATE 2-BYTE BUFFER (byte + null) ---
    move.b      D0, (-0x200,A6)           ; local_buffer[0] = byte
    clr.b       (-0x1ff,A6)               ; local_buffer[1] = '\0' (null terminator)

    ; --- TRANSFER SINGLE BYTE ---
    pea         (0x1).w                   ; Push 1 (length = 1 byte)
    pea         (-0x200,A6)               ; Push &local_buffer
    move.l      (0x18,A3), -(SP)          ; Push message->field_0x18
    move.l      (0x10,A3), -(SP)          ; Push message->field_0x10
    bsr.l       0x00003eae                ; D0 = FUN_00003eae(dest, src, buffer, 1)
    addq.w      #0x8, SP                  ; Clean up 2 args (8 bytes)
    addq.w      #0x8, SP                  ; Clean up 2 more args (8 bytes)
                                           ; Total: 4 args cleaned

; --- COMMON: CHECK TRANSFER RESULT ---
.LAB_00006f54:
    tst.l       D0                        ; Test FUN_00003eae return value
    beq.b       .LAB_00006f80             ; if (result == 0) goto error_exit
                                           ; NOTE: 0 → error is unusual!
                                           ; Suggests inverted return semantics

    ; Transfer returned non-zero (error indicator)
    move.l      D0, -(SP)                 ; Push error_code
    pea         (0x7a39).l                ; Push format_string address
    bsr.l       0x050028c4                ; printf(format_string, error_code)
                                           ; Log error message
    bra.b       .LAB_00006f80             ; goto common_error_exit

; ====================================================================================
; CASE HANDLER #4 (Address: 0x6f68)
; ====================================================================================
; Simple global variable assignment
; Only case that returns success (D0=0)
;
.LAB_00006f68:
    move.l      (0x20,A3), (0x000081ac).l ; global_0x81ac = message->field_0x20
                                           ; Direct assignment to global variable
    clr.l       D0                        ; D0 = 0 (SUCCESS)
    bra.b       .LAB_00006f8a             ; goto epilogue (skip error handling)

; ====================================================================================
; OUT OF RANGE HANDLER (Address: 0x6f74)
; ====================================================================================
; Handles invalid message types (> 5)
; Called when: message->message_type > 5
;
.LAB_00006f74:
    move.l      D1, -(SP)                 ; Push result pointer (original D1)
    move.l      A1, -(SP)                 ; Push message pointer (original A1)
    bsr.l       0x000075e2                ; FUN_000075e2(message, result)
                                           ; Error handler for invalid types
                                           ; Likely logs error and returns status in D0
    bra.b       .LAB_00006f8a             ; goto epilogue

; ====================================================================================
; COMMON ERROR EXIT (Address: 0x6f80)
; ====================================================================================
; Sets error code in result structure and returns failure
; Used by cases 1, 2, 3 when operations fail
;
.LAB_00006f80:
    move.l      #-0x131, (0x1c,A4)        ; result->error_code = -0x131
                                           ; Error code: 305 decimal (0x131 hex)
    moveq       #0x1, D0                  ; D0 = 1 (FAILURE return value)

; --- EPILOGUE ---
.LAB_00006f8a:
    movem.l     (-0x210,A6), {D2,A2,A3,A4} ; Restore preserved registers
                                           ; -0x210 = -(0x200 + 0x10)
                                           ; Stack frame size + saved regs offset
    unlk        A6                        ; Restore frame pointer, deallocate locals
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MessageDispatcher
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This dispatcher routes 6 message types to handlers:
;   - Case #1 (0x6eb2): Simple library call → error exit
;   - Case #2 (0x6ec6): String read → transfer → check result
;   - Case #3 (0x6f0a): Byte read → transfer → check result
;   - Case #4 (0x6f68): Write to global → success return
;   - Out of range: Call error handler
;   - (2 cases unidentified - may be unreachable or duplicate targets)
;
; All cases except #4 return via error exit path (D0=1, error_code=-0x131)
; Case #4 is the only success path (D0=0)
;
; INTEGRATION WITH PROTOCOL:
;
; This function appears to handle I/O operations for NeXTdimension:
;   - String transfer (likely PostScript or display list commands)
;   - Byte-level data transfer (graphics data)
;   - Configuration updates (write to global register)
;
; The consistent use of FUN_00003eae suggests a unified transfer protocol,
; possibly Mach IPC messages or DMA requests to the i860 processor.
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int ND_MessageDispatcher(nd_message_t* message, nd_result_t* result)
; {
;     uint8_t local_buffer[512];
;     uint32_t type = message->message_type;
;
;     if (type > 5) {
;         return FUN_000075e2(message, result);
;     }
;
;     switch (type) {
;         case TYPE_UNKNOWN_1:
;             lib_func(message->field_0x20, &g_buffer_name);
;             goto error_exit;
;
;         case TYPE_STRING_TRANSFER:
;             lib_open(&g_buffer_name);
;             fgets(local_buffer, 511, &global_buffer);
;             uint32_t len = strlen(local_buffer) + 1;
;             int err = FUN_00003eae(message->field_0x10, message->field_0x18,
;                                    local_buffer, len);
;             if (err != 0) printf(fmt, err);
;             goto error_exit;
;
;         case TYPE_BYTE_TRANSFER:
;             int ch = (global_buffer.count-- < 0) ?
;                      fgetc(&global_buffer) : *global_buffer.data_ptr++;
;             local_buffer[0] = ch;
;             local_buffer[1] = '\0';
;             err = FUN_00003eae(message->field_0x10, message->field_0x18,
;                                local_buffer, 1);
;             if (err != 0) printf(fmt, err);
;             goto error_exit;
;
;         case TYPE_WRITE_GLOBAL:
;             global_0x81ac = message->field_0x20;
;             return 0;  // Success
;
;         default:
;             // Unreachable or duplicate cases
;             break;
;     }
;
; error_exit:
;     result->error_code = -0x131;
;     return 1;
; }
;
; ====================================================================================
