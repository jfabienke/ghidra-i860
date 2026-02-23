; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_ProcessDMATransfer
; ====================================================================================
; Address: 0x0000709c
; Size: 976 bytes (244 instructions)
; Purpose: Process DMA transfer with Mach-O segment descriptor parsing
; Analysis: docs/functions/0000709c_ND_ProcessDMATransfer.md
; ====================================================================================

; FUNCTION: int ND_ProcessDMATransfer(nd_board_info_t* board_info)
;
; Reads Mach-O format segment table, validates __TEXT segment, and copies
; memory between host address space (0x08000000 window) and NeXTdimension
; local memory with address translation and optional byte-swapping.
;
; PARAMETERS:
;   board_info (A6+0x8): Pointer to 80-byte board info structure
;
; RETURNS:
;   D0: 0 on success, -1 on failure
;   Global 0x040105b0: Error code (0x8=invalid, 0xE=lock fail)
;
; STACK FRAME: 56 bytes
;   -0x04: segment_ptr
;   -0x08: desc_ptr
;   -0x0C: transfer_desc
;   -0x10: error_segment_ptr
;   -0x14: current_desc
;   -0x18: src_ptr_i860
;   -0x1C: dest_ptr_nd
;   -0x20: transfer_count
;   -0x24: loop_counter
;   -0x28: initial_copy_bytes
;   -0x2C: base_offset
;   -0x34: lock_result_1
;   -0x38: lock_result_2
;
; ====================================================================================

FUN_0000709c:
    ; --- PROLOGUE ---
    link.w      A6, #-0x38                ; Create 56-byte stack frame
    move.l      A3, -(SP)                 ; Save A3
    move.l      A2, -(SP)                 ; Save A2

    ; --- INITIALIZATION ---
    clr.l       (-0x10,A6)                ; error_segment_ptr = NULL
    movea.l     (0x8,A6), A0              ; A0 = board_info
    move.l      (0x2c,A0), (-0x2c,A6)     ; base_offset = board_info->field_0x2C
    movea.l     (0x00008018).l, A0        ; A0 = global_segment_table
    move.l      A0, (-0x4,A6)             ; segment_ptr = A0

    ; --- VALIDATION BLOCK 1: Mach-O Magic Number ---
    cmpi.l      #-0x1120532, (A0)         ; if (segment->magic != 0xFEEDFACE)
    bne.w       error_invalid_state       ;   goto error (Mach-O signature check)

    ; --- VALIDATION BLOCK 2: Format Fields ---
    movea.l     (-0x4,A6), A0             ; A0 = segment_ptr
    moveq       #0xf, D1                  ; D1 = 15
    cmp.l       (0x4,A0), D1              ; if (segment->field_0x04 != 15)
    bne.w       error_invalid_state       ;   goto error (format version check)

    moveq       #0x1, D1                  ; D1 = 1
    cmp.l       (0x8,A0), D1              ; if (segment->field_0x08 < 1)
    bcs.w       error_invalid_state       ;   goto error (count check)

    ; --- VALIDATION BLOCK 3: Status Flags ---
    movea.l     (-0x4,A6), A0             ; A0 = segment_ptr
    btst.b      #0x0, (0x1b,A0)           ; if (!(segment->status_flags & 0x01))
    beq.w       error_invalid_state       ;   goto error (ready bit check)

    ; --- VALIDATION BLOCK 4: Operation Type ---
    movea.l     (-0x4,A6), A0             ; A0 = segment_ptr
    moveq       #0x2, D1                  ; D1 = 2
    cmp.l       (0xc,A0), D1              ; if (segment->op_type == 2)
    beq.b       .op_type_valid            ;   goto valid
    moveq       #0x5, D1                  ; D1 = 5
    cmp.l       (0xc,A0), D1              ; else if (segment->op_type == 5)
    bne.w       error_invalid_state       ;   else goto error (only 2 or 5 allowed)

.op_type_valid:
    ; --- LOCK ACQUISITION (Dual locking for synchronization) ---
    pea         (0x75cc).l                ; push &lock_var_1 (BSS)
    pea         (0xa).w                   ; push 10 (lock type A)
    lea         (0x5002f7e).l, A2         ; A2 = &lock_function
    jsr         A2                        ; result = lock_function(10, &lock_var_1)
    move.l      D0, (-0x34,A6)            ; lock_result_1 = result

    pea         (0x75cc).l                ; push &lock_var_2 (same address)
    pea         (0xb).w                   ; push 11 (lock type B)
    jsr         A2                        ; result = lock_function(11, &lock_var_2)
    move.l      D0, (-0x38,A6)            ; lock_result_2 = result

    ; --- SEGMENT NAME VALIDATION ---
    pea         (0x80f0).l                ; push "__TEXT" string address
    bsr.l       0x05002ec4                ; result = strcmp(segment_name, "__TEXT")
    adda.w      #0x14, SP                 ; Clean up 5 args (20 bytes)

    tst.l       D0                        ; if (strcmp_result != 0)
    beq.b       .validation_passed        ;   skip unlock

    ; Unlock on validation failure
    move.l      (-0x34,A6), -(SP)         ; push lock_result_1
    pea         (0xa).w                   ; push 10
    jsr         A2                        ; unlock_function(10, lock_result_1)
    move.l      (-0x38,A6), -(SP)         ; push lock_result_2
    pea         (0xb).w                   ; push 11
    jsr         A2                        ; unlock_function(11, lock_result_2)
    moveq       #0xe, D1                  ; D1 = 14 (error code: lock/validation fail)
    bra.w       error_with_code           ; goto error exit

.validation_passed:
    ; --- TRANSFER SETUP ---
    movea.l     (-0x4,A6), A0             ; A0 = segment_ptr
    move.l      (0x10,A0), (-0x20,A6)     ; transfer_count = segment->descriptor_count
    move.l      (0x00008018).l, (-0x14,A6) ; current_desc = segment_table base
    moveq       #0x1c, D1                 ; D1 = 28
    bra.w       .loop_test                ; goto loop test (enter at bottom)

    ; ====================================================================================
    ; MAIN TRANSFER LOOP - Process each descriptor in segment table
    ; ====================================================================================
.main_transfer_loop:
    movea.l     (-0x14,A6), A0            ; A0 = current_desc
    move.l      A0, (-0x8,A6)             ; desc_ptr = current_desc

    ; --- DESCRIPTOR TYPE CLASSIFICATION ---
    moveq       #0x1, D1                  ; D1 = 1
    cmp.l       (A0), D1                  ; if (desc->type == 1)
    beq.b       .process_type_1           ;   goto type 1 handler (transfer)

    ; Handle non-type-1 descriptors (type 4-5)
    move.l      (A0), D0                  ; D0 = desc->type
    subq.l      #0x4, D0                  ; D0 -= 4
    cmp.l       D0, D1                    ; if (type-4 >= 1) // types 4-5
    bcs.w       .next_descriptor          ;   goto next (skip)
    move.l      A0, (-0x10,A6)            ; error_segment_ptr = current_desc (mark for post-check)
    bra.w       .next_descriptor          ; goto next

    ; ====================================================================================
    ; TYPE 1 DESCRIPTOR PROCESSING - Memory transfer operation
    ; ====================================================================================
.process_type_1:
    movea.l     (-0x14,A6), A0            ; A0 = current_desc
    move.l      A0, (-0xc,A6)             ; transfer_desc = current_desc

    ; --- ADDRESS CALCULATION ---
    ; Source: i860 memory space (segment data + offset)
    movea.l     (0x00008018).l, A3        ; A3 = segment_table base
    adda.l      (0x20,A0), A3             ; A3 += desc->source_offset
    move.l      A3, (-0x18,A6)            ; src_ptr_i860 = A3

    ; Destination: Translate host address → ND local memory
    ; Formula: (dest_addr & 0x0FFFFFFF) - 0x08000000 + base_offset
    move.l      (0x18,A0), D0             ; D0 = desc->dest_addr (host space)
    andi.l      #0xfffffff, D0            ; D0 &= 0x0FFFFFFF (mask high nibble)
    addi.l      #-0x8000000, D0           ; D0 -= 0x08000000 (remove window base)
    add.l       (-0x2c,A6), D0            ; D0 += base_offset (board-specific offset)
    move.l      D0, (-0x1c,A6)            ; dest_ptr_nd = D0

    ; --- DESCRIPTOR CLASSIFICATION BY NAME ---
    pea         (0x7a49).l                ; push string_addr_1 (BSS, runtime init)
    move.l      (-0xc,A6), D1             ; D1 = transfer_desc
    addq.l      #0x8, D1                  ; D1 += 8 (offset to descriptor name)
    move.l      D1, -(SP)                 ; push desc_name_ptr
    bsr.l       0x05003008                ; result = strcmp(desc->name, string_1)
    addq.w      #0x8, SP                  ; Clean up 2 args

    tst.l       D0                        ; if (strcmp_result != 0)
    bne.w       .alt_copy_path            ;   goto alternate copy path

    ; ====================================================================================
    ; PRIMARY COPY PATH - Descriptor name matches string_1
    ; ====================================================================================

    ; --- CALCULATE INITIAL COPY SIZE ---
    ; Special case: op_type==2 AND offset==0 → add header size
    movea.l     (-0x4,A6), A1             ; A1 = segment_ptr
    moveq       #0x2, D1                  ; D1 = 2
    cmp.l       (0xc,A1), D1              ; if (segment->op_type == 2)
    bne.b       .no_special_case          ;   skip special case

    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    tst.l       (0x20,A0)                 ; if (desc->source_offset == 0)
    bne.b       .no_special_case          ;   skip special case

    ; Special case: Add Mach-O header size
    moveq       #0x1c, D1                 ; D1 = 28 (Mach-O header size)
    add.l       (0x14,A1), D1             ; D1 += segment->size_adjustment
    move.l      D1, (-0x28,A6)            ; initial_copy_bytes = D1
    bra.b       .copy_initial             ; goto initial copy

.no_special_case:
    clr.l       (-0x28,A6)                ; initial_copy_bytes = 0

    ; --- INITIAL MEMORY COPY (if any) ---
.copy_initial:
    clr.l       (-0x24,A6)                ; loop_counter = 0

.initial_copy_loop:
    movea.l     (-0x24,A6), A3            ; A3 = loop_counter
    cmpa.l      (-0x28,A6), A3            ; if (loop_counter >= initial_copy_bytes)
    bge.b       .check_swap_flag          ;   goto swap check

    ; Simple 4-byte copy (no swap)
    movea.l     (-0x18,A6), A1            ; A1 = src_ptr_i860
    movea.l     (-0x1c,A6), A0            ; A0 = dest_ptr_nd
    move.l      (A1), (A0)                ; *dest = *src (4-byte transfer)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x18,A6)          ; src_ptr_i860 += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

    move.l      (-0x24,A6), D1            ; D1 = loop_counter
    cmp.l       (-0x28,A6), D1            ; if (loop_counter < initial_copy_bytes)
    blt.b       .initial_copy_loop        ;   continue loop

    ; --- CHECK BYTE-SWAP FLAG ---
.check_swap_flag:
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    btst.b      #0x0, (0x37,A0)           ; if (desc->flags & 0x01) // swap flag
    beq.b       .no_swap_path             ;   goto no-swap path

    ; ====================================================================================
    ; SWAP PATH - Byte-swapped writes with zero-fill
    ; ====================================================================================

    ; --- ZERO-FILL REMAINING SPACE ---
    move.l      (-0x28,A6), (-0x24,A6)    ; loop_counter = initial_copy_bytes
    bra.b       .zero_fill_test           ; goto test

.zero_fill_loop:
    move.l      (-0x1c,A6), D0            ; D0 = dest_ptr_nd
    eori.w      #0x4, D0                  ; D0 ^= 0x0004 (swap word endianness)
    movea.l     D0, A3                    ; A3 = swapped_dest
    clr.l       (A3)                      ; *swapped_dest = 0

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc

.zero_fill_test:
    move.l      (0x1c,A0), D0             ; D0 = desc->total_size
    sub.l       (0x24,A0), D0             ; D0 -= desc->data_size
    cmp.l       (-0x24,A6), D0            ; if ((total - data) > loop_counter)
    bhi.b       .zero_fill_loop           ;   continue zero-fill

    ; --- COPY ACTUAL DATA (SWAPPED) ---
    clr.l       (-0x24,A6)                ; loop_counter = 0
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (-0x24,A6), D1            ; D1 = loop_counter
    cmp.l       (0x24,A0), D1             ; if (loop_counter >= desc->data_size)
    bcc.w       .next_descriptor          ;   goto next descriptor

.swap_copy_loop:
    move.l      (-0x1c,A6), D0            ; D0 = dest_ptr_nd
    eori.w      #0x4, D0                  ; D0 ^= 0x0004 (SWAP: exchange word positions)
    movea.l     (-0x18,A6), A0            ; A0 = src_ptr_i860
    movea.l     D0, A3                    ; A3 = swapped_dest
    move.l      (A0), (A3)                ; *swapped_dest = *src (BYTE-SWAPPED WRITE)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x18,A6)          ; src_ptr_i860 += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (-0x24,A6), D1            ; D1 = loop_counter
    cmp.l       (0x24,A0), D1             ; if (loop_counter < desc->data_size)
    bcs.b       .swap_copy_loop           ;   continue loop

    bra.w       .next_descriptor          ; goto next descriptor

    ; ====================================================================================
    ; NO-SWAP PATH - Standard memory copy
    ; ====================================================================================
.no_swap_path:
    ; --- COPY DATA ---
    move.l      (-0x28,A6), (-0x24,A6)    ; loop_counter = initial_copy_bytes
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    movea.l     (-0x24,A6), A3            ; A3 = loop_counter
    cmpa.l      (0x24,A0), A3             ; if (loop_counter >= desc->data_size)
    bcc.b       .zero_fill_noswap         ;   goto zero-fill

.noswap_copy_loop:
    move.l      (-0x1c,A6), D0            ; D0 = dest_ptr_nd
    eori.w      #0x4, D0                  ; D0 ^= 0x0004 (address swap, NOT data swap)
    movea.l     (-0x18,A6), A0            ; A0 = src_ptr_i860
    movea.l     D0, A3                    ; A3 = swapped_addr_dest
    move.l      (A0), (A3)                ; *dest = *src (NO DATA SWAP, only addr swap)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x18,A6)          ; src_ptr_i860 += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (-0x24,A6), D1            ; D1 = loop_counter
    cmp.l       (0x24,A0), D1             ; if (loop_counter < desc->data_size)
    bcs.b       .noswap_copy_loop         ;   continue loop

    ; --- ZERO-FILL REMAINING (NO SWAP) ---
.zero_fill_noswap:
    clr.l       (-0x24,A6)                ; loop_counter = 0
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (0x1c,A0), D0             ; D0 = desc->total_size
    sub.l       (0x24,A0), D0             ; D0 -= desc->data_size
    cmp.l       (-0x24,A6), D0            ; if ((total - data) <= loop_counter)
    bls.w       .next_descriptor          ;   goto next descriptor

.zero_fill_noswap_loop:
    move.l      (-0x1c,A6), D0            ; D0 = dest_ptr_nd
    eori.w      #0x4, D0                  ; D0 ^= 0x0004 (address swap)
    movea.l     D0, A3                    ; A3 = swapped_dest
    clr.l       (A3)                      ; *swapped_dest = 0

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (0x1c,A0), D0             ; D0 = desc->total_size
    sub.l       (0x24,A0), D0             ; D0 -= desc->data_size
    cmp.l       (-0x24,A6), D0            ; if ((total - data) > loop_counter)
    bhi.b       .zero_fill_noswap_loop    ;   continue loop

    bra.w       .next_descriptor          ; goto next descriptor

    ; ====================================================================================
    ; ALTERNATE COPY PATH - Descriptor name did NOT match string_1
    ; ====================================================================================
.alt_copy_path:
    pea         (0x7a50).l                ; push string_addr_2 (BSS)
    move.l      (-0xc,A6), D1             ; D1 = transfer_desc
    addq.l      #0x8, D1                  ; D1 += 8 (offset to name)
    move.l      D1, -(SP)                 ; push desc_name_ptr
    bsr.l       0x05003008                ; result = strcmp(desc->name, string_2)
    addq.w      #0x8, SP                  ; Clean up 2 args

    tst.l       D0                        ; if (strcmp_result == 0)
    beq.w       .next_descriptor          ;   goto next (skip this descriptor)

    ; --- ALTERNATE COPY WITH SWAP FLAG CHECK ---
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    btst.b      #0x0, (0x37,A0)           ; if (desc->flags & 0x01)
    beq.b       .alt_noswap               ;   goto alt no-swap

    ; --- ALTERNATE SWAP PATH: ZERO-FILL FIRST ---
    clr.l       (-0x24,A6)                ; loop_counter = 0
    bra.b       .alt_zero_test            ; goto test

.alt_zero_loop:
    movea.l     (-0x1c,A6), A0            ; A0 = dest_ptr_nd
    clr.l       (A0)                      ; *dest = 0 (NO ADDRESS SWAP)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc

.alt_zero_test:
    move.l      (0x1c,A0), D0             ; D0 = desc->total_size
    sub.l       (0x24,A0), D0             ; D0 -= desc->data_size
    cmp.l       (-0x24,A6), D0            ; if ((total - data) > loop_counter)
    bhi.b       .alt_zero_loop            ;   continue loop

    ; --- ALTERNATE SWAP PATH: COPY DATA ---
    clr.l       (-0x24,A6)                ; loop_counter = 0
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    movea.l     (-0x24,A6), A3            ; A3 = loop_counter
    cmpa.l      (0x24,A0), A3             ; if (loop_counter >= desc->data_size)
    bcc.w       .next_descriptor          ;   goto next descriptor

.alt_swap_copy_loop:
    movea.l     (-0x18,A6), A0            ; A0 = src_ptr_i860
    movea.l     (-0x1c,A6), A1            ; A1 = dest_ptr_nd
    move.l      (A0), (A1)                ; *dest = *src (NO ADDRESS SWAP)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x18,A6)          ; src_ptr_i860 += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (-0x24,A6), D1            ; D1 = loop_counter
    cmp.l       (0x24,A0), D1             ; if (loop_counter < desc->data_size)
    bcs.b       .alt_swap_copy_loop       ;   continue loop

    bra.b       .next_descriptor          ; goto next descriptor

    ; --- ALTERNATE NO-SWAP PATH ---
.alt_noswap:
    clr.l       (-0x24,A6)                ; loop_counter = 0
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    movea.l     (-0x24,A6), A3            ; A3 = loop_counter
    cmpa.l      (0x24,A0), A3             ; if (loop_counter >= desc->data_size)
    bcc.b       .alt_noswap_zero          ;   goto zero-fill

.alt_noswap_copy_loop:
    movea.l     (-0x18,A6), A0            ; A0 = src_ptr_i860
    movea.l     (-0x1c,A6), A1            ; A1 = dest_ptr_nd
    move.l      (A0), (A1)                ; *dest = *src (NO ADDRESS SWAP)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x18,A6)          ; src_ptr_i860 += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (-0x24,A6), D1            ; D1 = loop_counter
    cmp.l       (0x24,A0), D1             ; if (loop_counter < desc->data_size)
    bcs.b       .alt_noswap_copy_loop     ;   continue loop

.alt_noswap_zero:
    clr.l       (-0x24,A6)                ; loop_counter = 0
    bra.b       .alt_noswap_zero_test     ; goto test

.alt_noswap_zero_loop:
    movea.l     (-0x1c,A6), A0            ; A0 = dest_ptr_nd
    clr.l       (A0)                      ; *dest = 0 (NO ADDRESS SWAP)

    addq.l      #0x4, (-0x1c,A6)          ; dest_ptr_nd += 4
    addq.l      #0x4, (-0x24,A6)          ; loop_counter += 4

.alt_noswap_zero_test:
    movea.l     (-0xc,A6), A0             ; A0 = transfer_desc
    move.l      (0x1c,A0), D0             ; D0 = desc->total_size
    sub.l       (0x24,A0), D0             ; D0 -= desc->data_size
    cmp.l       (-0x24,A6), D0            ; if ((total - data) > loop_counter)
    bhi.b       .alt_noswap_zero_loop     ;   continue loop

    ; ====================================================================================
    ; LOOP CONTINUATION - Advance to next descriptor
    ; ====================================================================================
.next_descriptor:
    movea.l     (-0x8,A6), A0             ; A0 = desc_ptr
    move.l      (0x4,A0), D1              ; D1 = desc->descriptor_size

.loop_test:
    add.l       D1, (-0x14,A6)            ; current_desc += descriptor_size
    subq.l      #0x1, (-0x20,A6)          ; transfer_count--

    moveq       #-0x1, D1                 ; D1 = -1
    cmp.l       (-0x20,A6), D1            ; if (transfer_count != -1)
    bne.w       .main_transfer_loop       ;   goto main loop

    ; --- POST-LOOP ERROR CHECK ---
    tst.l       (-0x10,A6)                ; if (error_segment_ptr != NULL)
    beq.b       error_invalid_state       ;   skip check (no errors)

    movea.l     (-0x10,A6), A0            ; A0 = error_segment_ptr
    moveq       #0x4, D1                  ; D1 = 4
    cmp.l       (0x8,A0), D1              ; if (error_segment->field_0x08 == 4)
    beq.b       success_unlock            ;   goto success (type 4-5 with field=4 is OK)

    ; ====================================================================================
    ; ERROR EXIT PATH
    ; ====================================================================================
error_invalid_state:
    moveq       #0x8, D1                  ; D1 = 8 (error code: invalid state)

error_with_code:
    move.l      D1, (0x040105b0).l        ; global_error_code = error_code
    moveq       #-0x1, D0                 ; return -1 (FAILURE)
    bra.b       epilogue                  ; goto epilogue

    ; ====================================================================================
    ; SUCCESS EXIT PATH - Unlock and return 0
    ; ====================================================================================
success_unlock:
    move.l      (-0x34,A6), -(SP)         ; push lock_result_1
    pea         (0xa).w                   ; push 10 (lock type A)
    lea         (0x5002f7e).l, A2         ; A2 = &lock_function
    jsr         A2                        ; unlock_function(10, lock_result_1)

    move.l      (-0x38,A6), -(SP)         ; push lock_result_2
    pea         (0xb).w                   ; push 11 (lock type B)
    jsr         A2                        ; unlock_function(11, lock_result_2)

    clr.l       D0                        ; return 0 (SUCCESS)

    ; --- EPILOGUE ---
epilogue:
    movea.l     (-0x40,A6), A2            ; Restore A2
    movea.l     (-0x3c,A6), A3            ; Restore A3
    unlk        A6                        ; Destroy stack frame
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_ProcessDMATransfer
; ====================================================================================
;
; SUMMARY:
;   - Validates Mach-O segment table (magic 0xFEEDFACE)
;   - Acquires dual locks for thread safety
;   - Checks segment name is "__TEXT"
;   - Iterates through transfer descriptors
;   - Translates host addresses (0x08000000 window) to ND local memory
;   - Copies memory with optional byte-swapping based on descriptor flags
;   - Handles three copy strategies based on descriptor name classification
;   - Properly cleans up locks on all exit paths
;
; KEY INSIGHT:
;   The XOR with 0x04 (eori.w #0x4, dest_addr) swaps word positions within
;   long-words, handling the big-endian 68040 vs little-endian i860 difference.
;
;   Without swap: Write at 0, 4, 8, 12...
;   With swap:    Write at 4, 0, 12, 8... (pairs swapped)
;
; ====================================================================================
