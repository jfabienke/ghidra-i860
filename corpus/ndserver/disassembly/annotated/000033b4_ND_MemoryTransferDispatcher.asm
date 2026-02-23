; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MemoryTransferDispatcher
; ====================================================================================
; Address: 0x000033b4
; Size: 608 bytes (0x260)
; Purpose: DMA memory transfer dispatcher with host-to-i860 address translation
; Analysis: docs/functions/000033b4_ND_MemoryTransferDispatcher.md
; ====================================================================================

; FUNCTION: ND_MemoryTransferDispatcher
;
; This function coordinates DMA transfers between the host NeXTstation and the
; NeXTdimension i860 graphics board. It handles three command types (0x7c2, 0x7c3,
; 0x7c4) and performs critical address space translation from host memory to i860
; memory using a 4-region lookup table.
;
; PARAMETERS:
;   request (8(A6)): Pointer to nd_transfer_request_t containing:
;                    - message_type (+0x14): Command type (0x7c2/0x7c3/0x7c4)
;                    - descriptor_count (+0x24): Number of descriptors (max 32)
;                    - descriptors (+0x28): Array of 12-byte transfer descriptors
;   result (12(A6)): Pointer to nd_transfer_result_t for status output:
;                    - error_code (+0x1C): Error code (0=success, 1/4/-305=error)
;                    - field_0x18 (+0x18): Status constant
;
; RETURNS:
;   D0: 1 = handled (success or known error), 0 = failure (unsupported)
;
; STACK FRAME: 16 bytes
;   -0x04: local_success (return value)
;   -0x08: local_i860_addr_7c3 (translated address for case 0x7c3)
;   -0x0C: local_i860_addr_7c2 (translated address for case 0x7c2)
;   -0x10: loop_index (descriptor array index)
;
; ====================================================================================

FUN_000033b4:
    ; ─────────────────────────────────────────────────────────────
    ; PROLOGUE - Standard function entry
    ; ─────────────────────────────────────────────────────────────
    link.w      A6, #-0x10               ; Create 16-byte stack frame
    movem.l     {A3 A2 D2}, -(SP)        ; Save callee-save registers (12 bytes)

    ; ─────────────────────────────────────────────────────────────
    ; INITIALIZATION - Copy template data to result structure
    ; ─────────────────────────────────────────────────────────────
    ; Copies 424 bytes from request to result (likely default values)
    pea         (0x1a8).w                ; Push size: 424 bytes (0x1a8)
    move.l      (0xc,A6), -(SP)          ; Push dest: result pointer
    move.l      (0x8,A6), -(SP)          ; Push src: request pointer
    bsr.l       0x050021c8               ; CALL memcpy(request, result, 424)
    addq.w      #0x8, SP                 ; Clean 2 pointers from stack

    ; ─────────────────────────────────────────────────────────────
    ; BOARD READY CHECK - Test if board is initialized/available
    ; ─────────────────────────────────────────────────────────────
    ; This appears to be a try-lock operation on global flag at 0x8054
    move.l      #0x8054, (SP)            ; Reuse stack slot: push address
    bsr.l       0x050020de               ; CALL pthread_mutex_trylock? or test func
    addq.w      #0x4, SP                 ; Clean 1 pointer from stack
    tst.l       D0                       ; Test return value
    beq.b       .continue_processing     ; If 0 (unlocked), proceed

    ; --- Early Exit: Board Busy/Not Ready ---
.early_exit_board_busy:
    movea.l     (0xc,A6), A0             ; A0 = result pointer
    moveq       #0x1, D2                 ; D2 = 1
    move.l      D2, (0x1c,A0)            ; result->error_code = 1 (board not ready)
    move.l      (0x00007a5c).l, (0x18,A0) ; result->field_0x18 = status constant
    moveq       #0x1, D0                 ; Return 1 (handled but failed)
    bra.w       .epilogue                ; Jump to exit

    ; ─────────────────────────────────────────────────────────────
    ; MAIN PROCESSING - Set DMA-in-progress flag
    ; ─────────────────────────────────────────────────────────────
.continue_processing:
    moveq       #0x1, D2                 ; D2 = 1
    move.l      D2, (0x0000800c).l       ; g_dma_in_progress = 1 (atomic flag)

    ; ─────────────────────────────────────────────────────────────
    ; MESSAGE TYPE DISPATCH - 3-way switch on command type
    ; ─────────────────────────────────────────────────────────────
    movea.l     (0x8,A6), A0             ; A0 = request pointer
    move.l      (0x14,A0), D0            ; D0 = request->message_type (offset 0x14)

    ; Binary search tree for 3 values: 0x7c2, 0x7c3, 0x7c4
    cmpi.l      #0x7c3, D0               ; Is it 0x7c3 (1987)?
    beq.w       .case_0x7c3              ; Yes: handle destination translation
    bgt.b       .check_higher            ; If > 0x7c3, check 0x7c4
    cmpi.l      #0x7c2, D0               ; Is it 0x7c2 (1986)?
    beq.b       .case_0x7c2              ; Yes: handle source translation
    bra.w       .case_default            ; No: unknown type, delegate

.check_higher:
    cmpi.l      #0x7c4, D0               ; Is it 0x7c4 (1988)?
    beq.w       .case_0x7c4              ; Yes: unsupported command error
    bra.w       .case_default            ; No: unknown type, delegate

    ; ═════════════════════════════════════════════════════════════
    ; CASE 0x7c2: DMA Transfer with SOURCE Address Translation
    ; ═════════════════════════════════════════════════════════════
    ; This handles uploads from host to i860 (e.g., texture data)
    ; The SOURCE address (in host space) needs translation to i860 space
    ; ═════════════════════════════════════════════════════════════
.case_0x7c2:
    ; --- Validate Descriptor Count ---
    movea.l     (0x8,A6), A0             ; A0 = request
    moveq       #0x20, D2                ; D2 = 32 (max descriptors)
    cmp.l       (0x24,A0), D2            ; Compare count vs 32
    bge.b       .validate_ok_7c2         ; Branch if count <= 32 (valid)

    ; ERROR: Too many descriptors
.error_too_many_descriptors:
    movea.l     (0xc,A6), A0             ; A0 = result
    moveq       #0x4, D2                 ; D2 = 4 (error code)
    move.l      D2, (0x1c,A0)            ; result->error_code = 4
    bra.w       .success_exit            ; Exit with error set

    ; --- Descriptor Loop Setup ---
.validate_ok_7c2:
    movea.l     (0xc,A6), A0             ; A0 = result
    clr.l       (0x1c,A0)                ; result->error_code = 0 (clear)
    clr.l       (-0x10,A6)               ; loop_index = 0

    movea.l     (0x8,A6), A0             ; A0 = request
    movea.l     A0, A1                   ; A1 = request (backup for loop)

    ; --- Descriptor Processing Loop ---
.loop_descriptors_7c2:
    movea.l     (-0x10,A6), A3           ; A3 = loop_index
    cmpa.l      (0x24,A0), A3            ; Compare index vs descriptor_count
    bge.w       .success_exit            ; Exit if index >= count (done)

.loop_body_7c2:
    lea         (0x8024).l, A2           ; A2 = &g_translation_table (cache this)

    ; Calculate descriptor offset: index * 12 (3 longs per descriptor)
    ; Descriptor structure: { field_0, source_addr, field_2 }
    move.l      (-0x10,A6), D0           ; D0 = loop_index
    add.l       D0, D0                   ; D0 = index * 2
    add.l       (-0x10,A6), D0           ; D0 = index * 3
    movea.l     (0x2c,A1,D0.l*4), A0     ; A0 = descriptors[i].source_addr (+0x2C)

    ; --- Address Translation: Find Region ---
    ; Search 4 regions to find which contains this host address
    ; Table entry: { base, offset, size } * 4 regions = 48 bytes
    suba.l      A1, A1                   ; A1 = 0 (region_index)

.find_region_loop_7c2:
    lea         (0x0,A1,A1.l*2), A3      ; A3 = region_index * 3
    move.l      A3, D0                   ; D0 = index * 3
    asl.l       #0x2, D0                 ; D0 = index * 12 (bytes per region)

    ; Check if address is within this region's bounds
    move.l      A0, D1                   ; D1 = source_address
    sub.l       (0x4,A2,D0.l*1), D1      ; D1 = addr - region[i].offset
    cmp.l       (0x8,A2,D0.l*1), D1      ; Compare relative vs region[i].size
    bcs.b       .region_found_7c2        ; Branch if within range (carry = less than)

    ; Try next region
    addq.w      #0x1, A1                 ; region_index++
    moveq       #0x3, D2                 ; D2 = 3 (max index for 4 regions: 0-3)
    cmp.l       A1, D2                   ; Compare region_index vs 3
    bge.b       .find_region_loop_7c2    ; Continue if region_index <= 3

    ; --- Address Not Found in Any Region ---
.address_not_found_7c2:
    clr.l       (-0xc,A6)                ; local_i860_addr = 0 (NULL)
    tst.l       (-0xc,A6)                ; Test if NULL
    bne.b       .call_transfer_7c2       ; Branch if not NULL (won't happen)
    bra.w       .translation_failed_error ; Error: translation failed

    ; --- Region Found: Calculate Translated Address ---
.region_found_7c2:
    ; Formula: i860_addr = region[i].base + (host_addr - region[i].offset)
    add.l       (0x0,A2,D0.l*1), D1      ; D1 += region[i].base
    move.l      D1, (-0xc,A6)            ; local_i860_addr = translated address
    bra.b       .address_not_found_7c2 + 4 ; Jump to test (will be != 0)

    ; --- Call DMA Transfer Function ---
.call_transfer_7c2:
    ; Recalculate descriptor offset for field access
    move.l      (-0x10,A6), D0           ; D0 = loop_index
    add.l       D0, D0                   ; D0 = index * 2
    add.l       (-0x10,A6), D0           ; D0 = index * 3
    asl.l       #0x2, D0                 ; D0 = index * 12

    movea.l     (0x8,A6), A0             ; A0 = request

    ; Push 3 arguments in reverse order
    move.l      (0x30,A0,D0.l*1), -(SP)  ; arg3: descriptors[i].field_2
    move.l      (-0xc,A6), -(SP)         ; arg2: i860_addr (TRANSLATED)
    move.l      (0x28,A0,D0.l*1), -(SP)  ; arg1: descriptors[i].field_0

    ; Indirect call via function pointer
    movea.l     (0x00008020).l, A0       ; A0 = g_transfer_function pointer
    jsr         (A0)                     ; CALL transfer_func(field_0, i860_addr, field_2)

    addq.w      #0x8, SP                 ; Clean 2 args
    addq.w      #0x4, SP                 ; Clean 1 arg

    ; --- Loop Increment ---
    addq.l      #0x1, (-0x10,A6)         ; loop_index++
    movea.l     (0x8,A6), A1             ; A1 = request (reload)
    movea.l     (-0x10,A6), A3           ; A3 = loop_index
    cmpa.l      (0x24,A1), A3            ; Compare index vs count
    blt.b       .loop_body_7c2           ; Continue loop if index < count
    bra.w       .success_exit            ; All descriptors processed

    ; ═════════════════════════════════════════════════════════════
    ; CASE 0x7c3: DMA Transfer with DESTINATION Address Translation
    ; ═════════════════════════════════════════════════════════════
    ; This handles downloads from i860 to host (e.g., framebuffer readback)
    ; The DESTINATION address (in host space) needs translation to i860 space
    ; ═════════════════════════════════════════════════════════════
.case_0x7c3:
    ; --- Validate Descriptor Count (note: different comparison) ---
    movea.l     (0x8,A6), A0             ; A0 = request
    moveq       #0x20, D2                ; D2 = 32
    cmp.l       (0x24,A0), D2            ; Compare 32 vs count
    blt.w       .error_too_many_descriptors ; Error if count >= 32 (inverted)

    ; --- Descriptor Loop Setup ---
    movea.l     (0xc,A6), A0             ; A0 = result
    clr.l       (0x1c,A0)                ; result->error_code = 0
    clr.l       (-0x10,A6)               ; loop_index = 0

    movea.l     (0x8,A6), A0             ; A0 = request
    movea.l     A0, A1                   ; A1 = request (backup)

    ; --- Descriptor Processing Loop ---
.loop_descriptors_7c3:
    movea.l     (-0x10,A6), A3           ; A3 = loop_index
    cmpa.l      (0x24,A0), A3            ; Compare index vs count
    bge.w       .success_exit            ; Exit if index >= count

.loop_body_7c3:
    lea         (0x8024).l, A2           ; A2 = &g_translation_table

    ; Calculate descriptor offset
    move.l      (-0x10,A6), D0           ; D0 = loop_index
    add.l       D0, D0                   ; D0 = index * 2
    add.l       (-0x10,A6), D0           ; D0 = index * 3

    ; --- Pre-processing: Call Helper Function ---
    ; This may validate descriptor or prepare for transfer
    move.l      (0x28,A1,D0.l*4), -(SP)  ; Push descriptors[i].field_0
    bsr.l       0x000030c2               ; CALL FUN_000030c2 (validator/prep)

    ; Get destination address to translate
    move.l      (-0x10,A6), D0           ; D0 = loop_index (recalculate)
    add.l       D0, D0                   ; D0 = index * 2
    add.l       (-0x10,A6), D0           ; D0 = index * 3
    movea.l     (0x8,A6), A0             ; A0 = request
    movea.l     (0x2c,A0,D0.l*4), A1     ; A1 = descriptors[i].dest_addr (+0x2C)
    addq.w      #0x4, SP                 ; Clean helper function arg

    ; --- Address Translation: Find Region ---
    suba.l      A0, A0                   ; A0 = 0 (region_index)

.find_region_loop_7c3:
    lea         (0x0,A0,A0.l*2), A3      ; A3 = region_index * 3
    move.l      A3, D0                   ; D0 = index * 3
    asl.l       #0x2, D0                 ; D0 = index * 12

    ; Check if address in this region
    move.l      A1, D1                   ; D1 = dest_address
    sub.l       (0x4,A2,D0.l*1), D1      ; D1 = addr - region[i].offset
    cmp.l       (0x8,A2,D0.l*1), D1      ; Compare vs region[i].size
    bcs.b       .region_found_7c3        ; Branch if within range

    ; Try next region
    addq.w      #0x1, A0                 ; region_index++
    moveq       #0x3, D2                 ; D2 = 3
    cmp.l       A0, D2                   ; Compare index vs 3
    bge.b       .find_region_loop_7c3    ; Continue if <= 3

    ; --- Address Not Found ---
.address_not_found_7c3:
    clr.l       (-0x8,A6)                ; local_i860_addr = 0
    tst.l       (-0x8,A6)                ; Test if NULL
    bne.b       .call_transfer_7c3       ; Branch if not NULL

    ; ERROR: Address translation failed
.translation_failed_error:
    movea.l     (0xc,A6), A0             ; A0 = result
    moveq       #0x1, D2                 ; D2 = 1
    move.l      D2, (0x1c,A0)            ; result->error_code = 1 (translation failed)
    bra.b       .success_exit            ; Exit with error

    ; --- Region Found: Calculate Translated Address ---
.region_found_7c3:
    add.l       (0x0,A2,D0.l*1), D1      ; D1 += region[i].base
    move.l      D1, (-0x8,A6)            ; local_i860_addr = translated address
    bra.b       .address_not_found_7c3 + 4 ; Jump to test

    ; --- Call DMA Transfer Function (Different Argument Order!) ---
.call_transfer_7c3:
    ; Recalculate descriptor offset
    move.l      (-0x10,A6), D0           ; D0 = loop_index
    add.l       D0, D0                   ; D0 = index * 2
    add.l       (-0x10,A6), D0           ; D0 = index * 3
    asl.l       #0x2, D0                 ; D0 = index * 12

    movea.l     (0x8,A6), A0             ; A0 = request

    ; Push 3 arguments - NOTE DIFFERENT ORDER than 0x7c2
    move.l      (0x30,A0,D0.l*1), -(SP)  ; arg3: descriptors[i].field_2
    move.l      (0x28,A0,D0.l*1), -(SP)  ; arg2: descriptors[i].field_0
    move.l      (-0x8,A6), -(SP)         ; arg1: i860_addr (FIRST!)

    ; Indirect call
    movea.l     (0x00008020).l, A0       ; A0 = g_transfer_function
    jsr         (A0)                     ; CALL transfer_func(i860_addr, field_0, field_2)

    addq.w      #0x8, SP                 ; Clean 2 args
    addq.w      #0x4, SP                 ; Clean 1 arg

    ; --- Loop Increment ---
    addq.l      #0x1, (-0x10,A6)         ; loop_index++
    movea.l     (0x8,A6), A1             ; A1 = request
    movea.l     (-0x10,A6), A3           ; A3 = loop_index
    cmpa.l      (0x24,A1), A3            ; Compare index vs count
    blt.w       .loop_body_7c3           ; Continue loop if index < count
    ; Fall through to success_exit

    ; ─────────────────────────────────────────────────────────────
    ; SUCCESS EXIT - Clear DMA flag and return
    ; ─────────────────────────────────────────────────────────────
.success_exit:
    moveq       #0x1, D2                 ; D2 = 1
    move.l      D2, (-0x4,A6)            ; local_success = 1
    bra.b       .clear_flag_and_exit     ; Jump to cleanup

    ; ═════════════════════════════════════════════════════════════
    ; CASE 0x7c4: Invalid/Unsupported Command
    ; ═════════════════════════════════════════════════════════════
.case_0x7c4:
    movea.l     (0xc,A6), A0             ; A0 = result
    move.l      #-0x131, (0x1c,A0)       ; result->error_code = -305 (ENOTSUP?)
    clr.l       (-0x4,A6)                ; local_success = 0 (failure)
    bra.b       .clear_flag_and_exit     ; Jump to cleanup

    ; ═════════════════════════════════════════════════════════════
    ; CASE DEFAULT: Unknown Message Type - Delegate
    ; ═════════════════════════════════════════════════════════════
.case_default:
    clr.l       (0x0000800c).l           ; Clear g_dma_in_progress flag

    ; Call fallback handler for unknown types
    move.l      (0xc,A6), -(SP)          ; Push arg2: result
    move.l      (0x8,A6), -(SP)          ; Push arg1: request
    bsr.l       0x000061f4               ; CALL FUN_000061f4 (fallback)
    bra.b       .epilogue                ; Return with FUN_000061f4's D0

    ; ─────────────────────────────────────────────────────────────
    ; CLEANUP - Clear DMA flag and set return
    ; ─────────────────────────────────────────────────────────────
.clear_flag_and_exit:
    clr.l       (0x0000800c).l           ; g_dma_in_progress = 0 (release lock)
    movea.l     (0xc,A6), A0             ; A0 = result
    move.l      (0x00007a5c).l, (0x18,A0) ; result->field_0x18 = status constant
    move.l      (-0x4,A6), D0            ; D0 = local_success (return value)

    ; ─────────────────────────────────────────────────────────────
    ; EPILOGUE - Restore and return
    ; ─────────────────────────────────────────────────────────────
.epilogue:
    movem.l     (-0x1c,A6), {D2 A2 A3}   ; Restore saved registers
    unlk        A6                       ; Destroy stack frame
    rts                                  ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MemoryTransferDispatcher
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function is the critical DMA dispatcher for NeXTdimension memory transfers.
; It handles three command types:
;   - 0x7c2: Upload (host→i860) with SOURCE address translation
;   - 0x7c3: Download (i860→host) with DESTINATION address translation
;   - 0x7c4: Unsupported (returns error -305)
;
; The core functionality is the address translation loop that maps host addresses
; to i860 address space using a 4-region lookup table at 0x8024. Each region has
; a base, offset, and size. The algorithm:
;   1. For each descriptor in the request (up to 32)
;   2. Get the host address (source or destination depending on command)
;   3. Search the 4 regions to find which contains the address
;   4. Calculate: i860_addr = region.base + (host_addr - region.offset)
;   5. Call the transfer function (via pointer at 0x8020) with translated address
;
; The function uses two global flags for coordination:
;   - 0x8054: Board initialized/available lock
;   - 0x800c: DMA operation in progress flag
;
; ====================================================================================
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int ND_MemoryTransferDispatcher(nd_transfer_request_t *request,
;                                 nd_transfer_result_t *result)
; {
;     int i;
;     uint32_t i860_addr;
;
;     memcpy(request, result, 424);
;
;     if (pthread_mutex_trylock(&g_board_lock) != 0) {
;         result->error_code = 1;
;         result->field_0x18 = g_constant_7a5c;
;         return 1;
;     }
;
;     g_dma_in_progress = 1;
;
;     switch (request->message_type) {
;     case 0x7c2:  // Upload with source translation
;         if (request->descriptor_count > 32) {
;             result->error_code = 4;
;             break;
;         }
;         result->error_code = 0;
;         for (i = 0; i < request->descriptor_count; i++) {
;             i860_addr = translate_address(request->descriptors[i].source_addr);
;             if (!i860_addr) {
;                 result->error_code = 1;
;                 break;
;             }
;             g_transfer_function(request->descriptors[i].field_0,
;                               i860_addr,
;                               request->descriptors[i].field_2);
;         }
;         break;
;
;     case 0x7c3:  // Download with dest translation
;         if (request->descriptor_count >= 32) {
;             result->error_code = 4;
;             break;
;         }
;         result->error_code = 0;
;         for (i = 0; i < request->descriptor_count; i++) {
;             FUN_000030c2(request->descriptors[i].field_0);
;             i860_addr = translate_address(request->descriptors[i].dest_addr);
;             if (!i860_addr) {
;                 result->error_code = 1;
;                 break;
;             }
;             g_transfer_function(i860_addr,
;                               request->descriptors[i].field_0,
;                               request->descriptors[i].field_2);
;         }
;         break;
;
;     case 0x7c4:  // Unsupported
;         result->error_code = -305;
;         g_dma_in_progress = 0;
;         result->field_0x18 = g_constant_7a5c;
;         return 0;
;
;     default:     // Unknown - delegate
;         g_dma_in_progress = 0;
;         return FUN_000061f4(request, result);
;     }
;
;     g_dma_in_progress = 0;
;     result->field_0x18 = g_constant_7a5c;
;     return 1;
; }
;
; ====================================================================================
