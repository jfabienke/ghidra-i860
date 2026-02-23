; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_WriteBranchInstruction
; ====================================================================================
; Address: 0x0000746c
; Size: 352 bytes (88 instructions)
; Purpose: Write i860 branch instruction vector to high memory
; Analysis: docs/functions/0000746c_ND_WriteBranchInstruction.md
; ====================================================================================

; FUNCTION: int ND_WriteBranchInstruction(nd_board_info_t* board_info, uint32_t size)
;
; Writes an 8-instruction i860 code block to high memory consisting of:
;   - 2 NOPs
;   - 1 BRANCH instruction (calculated from kernel size)
;   - 5 NOPs
;
; This creates a jump vector/entry point for the i860 processor to branch
; to the loaded kernel after reset.
;
; PARAMETERS:
;   board_info (A6+0x8): Pointer to 80-byte board info structure
;   size (A6+0xC):       Kernel size in bytes
;
; RETURNS:
;   D0: 0 on success, -1 on failure
;   Global 0x040105b0: Error code 0xE on validation failure
;
; STACK FRAME: 24 bytes
;   -0x04: branch_instr (computed i860 branch instruction)
;   -0x08: instruction_word (26-bit offset)
;   -0x10: lock_result_1
;   -0x14: lock_result_2
;   -0x18: dest_base (destination address, evolving)
;
; ====================================================================================

FUN_0000746c:
    ; --- PROLOGUE ---
    link.w      A6, #-0x18                ; Create 24-byte stack frame
    move.l      A2, -(SP)                 ; Save A2

    ; --- DESTINATION ADDRESS CALCULATION ---
    movea.l     (0x8,A6), A0              ; A0 = board_info
    move.l      (0x2c,A0), (-0x18,A6)     ; dest_base = board_info->field_0x2C
    addi.l      #0x7ffff00, (-0x18,A6)    ; dest_base += 0x07FFFF00 (high memory)
                                           ; Result: ~top of i860 DRAM or near reset vector

    ; --- i860 BRANCH INSTRUCTION CALCULATION ---
    ; Formula: BR offset = (size + 256) / 4 - 3
    ; This calculates a PC-relative branch offset back into the loaded kernel
    move.l      (0xc,A6), D0              ; D0 = size (kernel size in bytes)
    addi.l      #0x100, D0                ; D0 += 256
    lsr.l       #0x2, D0                  ; D0 /= 4 (convert bytes → words)
    move.l      D0, (-0x8,A6)             ; instruction_word = result
    subq.l      #0x3, (-0x8,A6)           ; instruction_word -= 3 (adjustment)

    ; --- CREATE i860 BR (Branch Relative) INSTRUCTION ---
    ; i860 BR encoding: 0x68000000 | (26-bit signed offset)
    andi.l      #0x3ffffff, (-0x8,A6)     ; Mask to 26 bits
    move.l      (-0x8,A6), D0             ; D0 = masked offset
    ori.l       #0x68000000, D0           ; D0 |= 0x68 (BR opcode)
    move.l      D0, (-0x8,A6)             ; instruction_word = complete instruction
    move.l      D0, (-0x4,A6)             ; branch_instr = backup copy

    ; --- LOCK ACQUISITION (Dual locking for synchronization) ---
    pea         (0x75cc).l                ; push &lock_var_1 (BSS)
    pea         (0xa).w                   ; push 10 (lock type A)
    lea         (0x5002f7e).l, A2         ; A2 = &lock_function
    jsr         A2                        ; result = lock_function(10, &lock_var_1)
    move.l      D0, (-0x10,A6)            ; lock_result_1 = result

    pea         (0x75cc).l                ; push &lock_var_2 (same address)
    pea         (0xb).w                   ; push 11 (lock type B)
    jsr         A2                        ; result = lock_function(11, &lock_var_2)
    move.l      D0, (-0x14,A6)            ; lock_result_2 = result

    ; --- SEGMENT NAME VALIDATION ---
    pea         (0x80f0).l                ; push "__TEXT" string address
    bsr.l       0x05002ec4                ; result = strcmp(segment_name, "__TEXT")
    adda.w      #0x14, SP                 ; Clean up 5 args (20 bytes)

    tst.l       D0                        ; if (strcmp_result != 0)
    bne.w       .error_unlock             ;   goto error (validation failed)

    ; ====================================================================================
    ; WRITE i860 INSTRUCTION SEQUENCE - 8 long-words (32 bytes)
    ; Memory pattern created:
    ;   +0x00: 0xA0000000  (i860 NOP)
    ;   +0x04: 0xA0000000  (i860 NOP)
    ;   +0x08: 0x68xxxxxx  (i860 BR <offset>) ← BRANCH TO KERNEL ENTRY
    ;   +0x0C: 0xA0000000  (i860 NOP)
    ;   +0x10: 0xA0000000  (i860 NOP)
    ;   +0x14: 0xA0000000  (i860 NOP)
    ;   +0x18: 0xA0000000  (i860 NOP)
    ;   +0x1C: 0xA0000000  (i860 NOP)
    ; ====================================================================================

    ; --- INSTRUCTION 1: NOP ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04 (endian swap for i860)
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 2: NOP ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 3: BRANCH (the actual jump to kernel) ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      (-0x4,A6), (A1)           ; *A1 = branch_instr (0x68xxxxxx)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 4: NOP (branch delay slot) ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 5: NOP (branch delay slot) ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 6: NOP (pipeline safety) ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 7: NOP (pipeline safety) ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    addq.l      #0x4, (-0x18,A6)          ; dest_base += 4

    ; --- INSTRUCTION 8: NOP (final padding) ---
    move.l      (-0x18,A6), D0            ; D0 = dest_base
    eori.w      #0x4, D0                  ; D0 ^= 0x04
    movea.l     D0, A1                    ; A1 = swapped_dest
    move.l      #-0x60000000, (A1)        ; *A1 = 0xA0000000 (i860 NOP)
    ; Note: No increment - this is the last write

    ; --- UNLOCK AND SUCCESS RETURN ---
    move.l      (-0x10,A6), -(SP)         ; push lock_result_1
    pea         (0xa).w                   ; push 10
    jsr         A2                        ; unlock_function(10, lock_result_1)
    move.l      (-0x14,A6), -(SP)         ; push lock_result_2
    pea         (0xb).w                   ; push 11
    jsr         A2                        ; unlock_function(11, lock_result_2)
    clr.l       D0                        ; return 0 (SUCCESS)
    bra.b       .epilogue                 ; goto epilogue

    ; ====================================================================================
    ; ERROR EXIT PATH - Validation failed
    ; ====================================================================================
.error_unlock:
    move.l      (-0x10,A6), -(SP)         ; push lock_result_1
    pea         (0xa).w                   ; push 10
    lea         (0x5002f7e).l, A2         ; A2 = &lock_function
    jsr         A2                        ; unlock_function(10, lock_result_1)
    move.l      (-0x14,A6), -(SP)         ; push lock_result_2
    pea         (0xb).w                   ; push 11
    jsr         A2                        ; unlock_function(11, lock_result_2)
    moveq       #0xe, D1                  ; D1 = 14 (error code: validation failure)
    move.l      D1, (0x040105b0).l        ; global_error_code = 0xE
    moveq       #-0x1, D0                 ; return -1 (FAILURE)

    ; --- EPILOGUE ---
.epilogue:
    movea.l     (-0x1c,A6), A2            ; Restore A2
    unlk        A6                        ; Destroy stack frame
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_WriteBranchInstruction
; ====================================================================================
;
; BOOT SEQUENCE CONTEXT:
;
; 1. ND_RegisterBoardSlot    - Allocate board structure
; 2. ND_ProcessDMATransfer   - Load kernel to i860 DRAM (0x00000000+)
; 3. ND_WriteBranchInstruction  - Write entry vector (THIS FUNCTION)
; 4. (Unknown function)      - Release i860 from reset
; 5. i860 executes from high memory (reset vector)
; 6. i860 executes BR instruction → jumps to kernel entry point
; 7. Kernel initialization begins
;
; i860 INSTRUCTION REFERENCE:
;
; 0xA0000000 - NOP (no operation)
;   Various forms exist; this is likely fnop or standard nop
;
; 0x68xxxxxx - BR offset26 (Branch Relative)
;   Bits 31-26: 011010 (opcode)
;   Bits 25-0:  Signed 26-bit word offset
;   Target: PC + (offset * 4)
;   Range: ±64MB from current instruction
;
; BRANCH OFFSET CALCULATION EXAMPLE:
;
; If kernel size = 65536 bytes:
;   offset = ((65536 + 256) / 4) - 3
;          = (65792 / 4) - 3
;          = 16448 - 3
;          = 16445 words
;
;   instruction = 0x68000000 | 16445 = 0x6800403D
;
;   From branch location (dest_base + 0x08):
;     target = PC + (16445 * 4)
;            = PC + 65780 bytes
;
;   This points near the end or entry point of the loaded kernel
;
; ====================================================================================
