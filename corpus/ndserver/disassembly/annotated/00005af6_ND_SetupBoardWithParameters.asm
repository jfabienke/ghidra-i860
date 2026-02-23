; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_SetupBoardWithParameters
; ====================================================================================
; Address: 0x00005af6
; Size: 194 bytes (67 instructions)
; Purpose: Initialize and configure NeXTdimension board with user parameters
; Analysis: docs/functions/00005af6_ND_SetupBoardWithParameters.md
; ====================================================================================

; FUNCTION: ND_SetupBoardWithParameters
;
; This function performs high-level board setup by coordinating multiple stages:
; 1. Convert string parameter to integer (likely refresh rate, resolution, etc.)
; 2. Register board in slot via ND_RegisterBoardSlot
; 3. Initialize memory/DMA handles
; 4. Verify board is ready for configuration
; 5. Apply user-specified configuration parameters
; 6. Finalize setup with system library call
; 7. Handle errors with cleanup on all paths
;
; This is a user-facing entry point (likely from command-line or daemon configuration)
; as opposed to the low-level ND_RegisterBoardSlot which is an internal primitive.
;
; PARAMETERS:
;   board_id (8(A6), D4):  NeXTdimension board identifier
;   slot_num (12(A6), D3): NeXTBus slot number (2, 4, 6, or 8)
;   param1 (16(A6)):       Configuration parameter 1 (purpose unknown)
;   param2 (20(A6)):       Configuration parameter 2 (purpose unknown)
;   param3 (24(A6)):       Configuration parameter 3 (possibly string)
;
; RETURNS:
;   D0 = 0:     Success - board fully configured
;   D0 = 4:     Invalid slot number (from ND_RegisterBoardSlot)
;   D0 = 5:     Setup/verification/configuration failed
;   D0 = 6:     Memory allocation failed (from ND_RegisterBoardSlot)
;   D0 = other: Error from sub-initialization functions
;
; STACK FRAME: 0 bytes (no local variables)
;   Saved registers: D2-D5, A2 (20 bytes)
;
; REGISTER USAGE:
;   D2: Error code tracking across operations
;   D3: slot_num (preserved throughout)
;   D4: board_id (preserved throughout)
;   D5: Converted integer value from string parameter
;   A2: Pointer to board structure (from slot table)
;
; ====================================================================================

FUN_00005af6:
ND_SetupBoardWithParameters:

    ; ==================================================================================
    ; PROLOGUE - Standard stack frame setup
    ; ==================================================================================
    link.w      A6, #0x0                    ; Create stack frame (no local variables)
    movem.l     {A2 D5 D4 D3 D2}, -(SP)     ; Save 5 registers (20 bytes)

    ; ==================================================================================
    ; LOAD ARGUMENTS - Get board_id and slot_num from caller's stack
    ; ==================================================================================
    move.l      (0x8,A6), D4                ; D4 = board_id (arg1)
    move.l      (0xc,A6), D3                ; D3 = slot_num (arg2 - should be 2,4,6,8)

    ; ==================================================================================
    ; CONVERT STRING PARAMETER TO INTEGER
    ; ==================================================================================
    ; Library call to 0x0500315e - likely atoi() or strtol()
    ; Input: Unknown (possibly param3, or set up before call)
    ; Output: D0 = integer value
    ; Note: Which parameter is the string is unclear from this function alone
    ; ==================================================================================
    bsr.l       0x0500315e                  ; CALL atoi() or strtol()
    move.l      D0, D5                      ; D5 = converted integer value (saved)

    ; ==================================================================================
    ; REGISTER BOARD IN SLOT
    ; ==================================================================================
    ; Call ND_RegisterBoardSlot (previously analyzed function @ 0x000036b2)
    ; This allocates the 80-byte board structure, validates slot, and runs
    ; 6 initialization sub-functions. See ND_RegisterBoardSlot analysis.
    ; ==================================================================================
    move.l      D3, -(SP)                   ; Push slot_num (arg2)
    move.l      D4, -(SP)                   ; Push board_id (arg1)
    bsr.l       0x000036b2                  ; CALL ND_RegisterBoardSlot
    move.l      D0, D2                      ; D2 = registration result
    addq.w      #0x8, SP                    ; Clean stack (2 args × 4 bytes)

    ; --- Check registration result ---
    bne.w       exit_function               ; If error, return immediately (D2 in D0)

    ; ==================================================================================
    ; GET BOARD STRUCTURE FROM SLOT TABLE
    ; ==================================================================================
    ; After successful registration, retrieve the board_info structure pointer
    ; from the global slot table at 0x819C.
    ; Slot index calculation: index = slot_num / 2
    ; (slot 2 → index 0, slot 4 → index 1, slot 6 → index 2, slot 8 → index 3)
    ; ==================================================================================
    move.l      D3, D0                      ; D0 = slot_num
    asr.l       #0x1, D0                    ; D0 = slot_num / 2 (index)
    lea         (0x819c).l, A0              ; A0 = &global_slot_table
    movea.l     (0x0,A0,D0.l*4), A2         ; A2 = slot_table[index] (board_info*)

    ; ==================================================================================
    ; INITIALIZE MEMORY/DMA HANDLES
    ; ==================================================================================
    ; Call FUN_00004c88 to set up memory/DMA handles
    ; This function sets fields at +0x2C and +0x40 in the board structure
    ; Parameters:
    ;   - board_id (D4)
    ;   - board->board_port (from +0x04)
    ;   - converted_value (D5)
    ;   - slot_num (D3)
    ;   - &board->field_0x2C (output parameter 1)
    ;   - &board->field_0x40 (output parameter 2)
    ; ==================================================================================
    pea         (0x40,A2)                   ; Push &board->field_0x40 (output)
    pea         (0x2c,A2)                   ; Push &board->field_0x2C (output)
    move.l      D3, -(SP)                   ; Push slot_num
    move.l      D5, -(SP)                   ; Push converted_value
    move.l      (0x4,A2), -(SP)             ; Push board->board_port (Mach port)
    move.l      D4, -(SP)                   ; Push board_id
    bsr.l       0x00004c88                  ; CALL FUN_00004c88 (memory/DMA init)
    move.l      D0, D2                      ; D2 = memory init result
    adda.w      #0x18, SP                   ; Clean stack (6 args × 4 = 24 bytes)

    ; --- Check memory initialization result ---
    beq.b       verify_board_state          ; If success (D0 == 0), continue

    ; ==================================================================================
    ; ERROR PATH 1 - Memory/DMA initialization failed
    ; ==================================================================================
error_path_1_cleanup:
    move.l      D3, -(SP)                   ; Push slot_num
    move.l      D4, -(SP)                   ; Push board_id
    bsr.l       0x00003874                  ; CALL cleanup_board (FUN_00003874)
    move.l      D2, D0                      ; Return error code from memory init
    bra.b       exit_function               ; Jump to epilogue

    ; ==================================================================================
    ; VERIFY BOARD STATE
    ; ==================================================================================
    ; Call FUN_00005c70 to verify board is ready for configuration
    ; This checks hardware state or software initialization status
    ; Parameters:
    ;   - board_id (D4)
    ;   - slot_num (D3)
    ; Returns: 0 = ready, non-zero = not ready
    ; ==================================================================================
verify_board_state:
    move.l      D3, -(SP)                   ; Push slot_num
    move.l      D4, -(SP)                   ; Push board_id
    bsr.l       0x00005c70                  ; CALL FUN_00005c70 (verify board)
    addq.w      #0x8, SP                    ; Clean stack (2 args × 4 bytes)

    ; --- Check verification result ---
    tst.l       D0                          ; Test verification result
    bne.b       error_path_2_cleanup        ; If failed, cleanup and return error 5

    ; ==================================================================================
    ; APPLY CONFIGURATION PARAMETERS
    ; ==================================================================================
    ; Call FUN_00007032 to apply user-specified configuration to the board
    ; This function takes the board structure plus 3 additional parameters
    ; Parameters are the original arg3, arg4, arg5 passed to this function
    ; Parameters:
    ;   - board_info* (A2)
    ;   - param1 from (0x10,A6)
    ;   - param2 from (0x14,A6)
    ;   - param3 from (0x18,A6)
    ; Returns: -1 = error, other = success
    ; ==================================================================================
    move.l      (0x18,A6), -(SP)            ; Push param3 (arg5 - possibly string)
    move.l      (0x14,A6), -(SP)            ; Push param2 (arg4)
    move.l      (0x10,A6), -(SP)            ; Push param1 (arg3)
    move.l      A2, -(SP)                   ; Push board_info*
    bsr.l       0x00007032                  ; CALL FUN_00007032 (apply configuration)
    addq.w      #0x8, SP                    ; Clean stack (4 args × 4 = 16 bytes)
    addq.w      #0x8, SP                    ; (split into two for addressing mode)

    ; --- Check configuration result ---
    moveq       #-0x1, D1                   ; D1 = -1 (error sentinel)
    cmp.l       D0, D1                      ; Compare result with -1
    beq.b       error_path_2_cleanup        ; If error (-1), cleanup and return 5

    ; ==================================================================================
    ; FINALIZE SETUP WITH LIBRARY CALL
    ; ==================================================================================
    ; Library call to 0x050032ba - likely ioctl(), sysctl(), or Mach port operation
    ; Uses the handles set by FUN_00004c88 plus the converted value
    ; Parameters:
    ;   - converted_value (D5)
    ;   - board->field_0x2C (temporary handle)
    ;   - board->field_0x40 (persistent handle)
    ; Note: No error checking on this call (fire-and-forget)
    ; ==================================================================================
    move.l      (0x40,A2), -(SP)            ; Push board->field_0x40 (handle 2)
    move.l      (0x2c,A2), -(SP)            ; Push board->field_0x2C (handle 1)
    move.l      D5, -(SP)                   ; Push converted_value
    bsr.l       0x050032ba                  ; CALL library_operation (no error check!)
    ; Note: Stack not cleaned (caller will clean)

    ; ==================================================================================
    ; SUCCESS PATH - Clear temporary resources and return
    ; ==================================================================================
    clr.l       (0x2c,A2)                   ; Clear board->field_0x2C (temp handle)
                                            ; Note: field_0x40 is NOT cleared (persistent)
    clr.l       D0                          ; Return 0 (success)
    bra.b       exit_function               ; Jump to epilogue

    ; ==================================================================================
    ; ERROR PATH 2 - Verification or configuration failed
    ; ==================================================================================
    ; This path is taken if:
    ;   - FUN_00005c70 (verify) returns non-zero, OR
    ;   - FUN_00007032 (config) returns -1
    ; Both cases cleanup the board and return error code 5
    ; ==================================================================================
error_path_2_cleanup:
    move.l      D3, -(SP)                   ; Push slot_num
    move.l      D4, -(SP)                   ; Push board_id
    bsr.l       0x00003874                  ; CALL cleanup_board (FUN_00003874)
    moveq       #0x5, D0                    ; Return error code 5 (setup failed)
    ; Fall through to exit

    ; ==================================================================================
    ; EPILOGUE - Restore registers and return
    ; ==================================================================================
exit_function:
    movem.l     -0x14(A6), {D2 D3 D4 D5 A2} ; Restore saved registers
    unlk        A6                          ; Restore frame pointer
    rts                                     ; Return to caller (D0 = result)

; ====================================================================================
; END OF FUNCTION: ND_SetupBoardWithParameters
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function orchestrates the complete setup of a NeXTdimension board with
; user-specified configuration parameters. It delegates low-level registration
; to ND_RegisterBoardSlot, then adds memory/DMA initialization, board verification,
; parameter application, and finalization. Robust error handling with cleanup is
; implemented on all failure paths.
;
; CONTROL FLOW SUMMARY:
; 1. Convert string parameter → integer
; 2. Register board (ND_RegisterBoardSlot)
;    ↓ if error → return immediately
; 3. Get board structure from slot table
; 4. Initialize memory/DMA handles (FUN_00004c88)
;    ↓ if error → cleanup → return error
; 5. Verify board state (FUN_00005c70)
;    ↓ if error → cleanup → return 5
; 6. Apply configuration (FUN_00007032)
;    ↓ if error → cleanup → return 5
; 7. Library operation (finalize)
; 8. Clear temporary handle
; 9. Return 0 (success)
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int ND_SetupBoardWithParameters(
;     uint32_t board_id,
;     uint32_t slot_num,
;     void*    param1,
;     void*    param2,
;     void*    param3)
; {
;     int result;
;     int converted_value;
;     nd_board_info_t* board;
;     int slot_index;
;
;     // Convert string parameter to integer
;     converted_value = atoi(param3);  // Assumption
;
;     // Register board in slot
;     result = ND_RegisterBoardSlot(board_id, slot_num);
;     if (result != 0) {
;         return result;
;     }
;
;     // Get board structure
;     slot_index = slot_num / 2;
;     board = slot_table[slot_index];
;
;     // Initialize memory/DMA handles
;     result = init_memory_handles(
;         board_id,
;         board->board_port,
;         converted_value,
;         slot_num,
;         &board->field_0x2C,
;         &board->field_0x40
;     );
;     if (result != 0) {
;         cleanup_board(board_id, slot_num);
;         return result;
;     }
;
;     // Verify board is ready
;     result = verify_board_state(board_id, slot_num);
;     if (result != 0) {
;         cleanup_board(board_id, slot_num);
;         return 5;
;     }
;
;     // Apply configuration
;     result = apply_configuration(board, param1, param2, param3);
;     if (result == -1) {
;         cleanup_board(board_id, slot_num);
;         return 5;
;     }
;
;     // Finalize with system call
;     library_operation(converted_value, board->field_0x2C, board->field_0x40);
;
;     // Clear temporary handle
;     board->field_0x2C = NULL;
;
;     return 0;  // Success
; }
;
; ====================================================================================
; CALLED BY:
;   FUN_00002dc6 (0x00002dc6) - Main dispatcher (likely handles command routing)
;
; CALLS TO:
;   lib_0x0500315e - atoi() or strtol() (string to integer conversion)
;   FUN_000036b2   - ND_RegisterBoardSlot (basic board registration)
;   FUN_00004c88   - Memory/DMA initialization (sets handles)
;   FUN_00005c70   - Board verification (checks readiness)
;   FUN_00007032   - Apply configuration (user parameters)
;   lib_0x050032ba - Library operation (finalization, no error check)
;   FUN_00003874   - Cleanup board (on error paths)
;
; NOTES:
;   - This is a high-level entry point for board setup, likely called from
;     command-line parsing or daemon configuration
;   - Coordinates 5 internal functions plus 2 library calls
;   - Handles 3 optional configuration parameters (semantics unknown)
;   - Implements dual error paths with consistent cleanup pattern
;   - Final library call has NO error checking (assumed to always succeed)
;   - field_0x2C is temporary (cleared), field_0x40 is persistent (kept)
;
; UNKNOWNS:
;   - Which parameter is converted to integer (likely param3)
;   - Semantics of the 3 configuration parameters
;   - Purpose of field_0x2C and field_0x40 (need FUN_00004c88 analysis)
;   - What library call 0x050032ba does (ioctl? sysctl? port call?)
;   - What FUN_00005c70 verifies (hardware state? software state?)
;   - What FUN_00007032 configures (video? memory? generic?)
;
; ====================================================================================
