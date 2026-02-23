; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_LoadFirmwareAndStart
; ====================================================================================
; Address: 0x00005a3e
; Size: 184 bytes
; Purpose: Load firmware to NeXTdimension board and start i860 execution
; Analysis: docs/functions/00005a3e_ND_LoadFirmwareAndStart.md
; ====================================================================================

; FUNCTION: int ND_LoadFirmwareAndStart(uint32_t board_id, uint32_t slot_num, void* param3)
;
; This function orchestrates the complete firmware loading and startup sequence for a
; NeXTdimension graphics board. It coordinates five critical operations:
;   1. Register board slot (allocate structure, initialize subsystems)
;   2. Load firmware segments to board memory
;   3. Start i860 processor execution
;   4. Transfer program control to loaded firmware
;   5. Finalize and cleanup temporary resources
;
; The function implements comprehensive error handling with cleanup on failure paths.
; On success, the NeXTdimension board is running the loaded firmware.
;
; PARAMETERS:
;   board_id (8(A6), D4):  Board identifier from hardware detection
;   slot_num (12(A6), D3): NeXTBus slot number (2, 4, 6, or 8)
;   param3 (16(A6)):       Third parameter (likely firmware file path or FD)
;
; RETURNS:
;   D0 = 0: Success (firmware loaded and started)
;   D0 = 4: Invalid slot or board registration conflict
;   D0 = 5: Board startup or program transfer failed
;   D0 = 6: Memory allocation failed
;   D0 = Other: Error from firmware loader (FUN_00004c88)
;
; STACK FRAME: 0 bytes (no local variables)
;   Saved Registers: D2, D3, D4, D5, A2 (20 bytes)
;
; ====================================================================================

FUN_00005a3e:
ND_LoadFirmwareAndStart:

; --- PROLOGUE ---
; Set up standard stack frame and preserve registers
0x00005a3e:  link.w     A6,0x0                        ; Create stack frame (no locals)
0x00005a42:  movem.l    {A2 D5 D4 D3 D2},SP          ; Save 5 registers (20 bytes)
                                                      ; D2 = error propagation
                                                      ; D3 = slot_num
                                                      ; D4 = board_id
                                                      ; D5 = converted parameter
                                                      ; A2 = board structure pointer

; --- LOAD ARGUMENTS FROM STACK ---
; Transfer parameters from stack frame to registers for efficient access
0x00005a46:  move.l     (0x8,A6),D4                   ; D4 = board_id (argument 1)
0x00005a4a:  move.l     (0xc,A6),D3                   ; D3 = slot_num (argument 2)
                                                      ; Note: param3 at 0x10(A6) loaded later

; --- PARAMETER CONVERSION ---
; Convert/validate board_id parameter (possibly string to int conversion)
; Library function 0x0500315e likely atoi() or similar string conversion
0x00005a4e:  bsr.l      0x0500315e                    ; CALL lib_0500315e (convert parameter)
                                                      ; Input: D4 (board_id, implicit register param)
                                                      ; Output: D0 = converted integer value
0x00005a54:  move.l     D0,D5                         ; D5 = converted value (save for later use)

; --- STEP 1: REGISTER BOARD SLOT ---
; Call ND_RegisterBoardSlot to allocate board structure and initialize subsystems
; This is idempotent - handles re-registration of same board gracefully
0x00005a56:  move.l     D3,-(SP)                      ; Push slot_num (argument 2)
0x00005a58:  move.l     D4,-(SP)                      ; Push board_id (argument 1)
0x00005a5a:  bsr.l      0x000036b2                    ; CALL ND_RegisterBoardSlot
                                                      ; Returns: 0=success, 4=invalid slot, 6=no memory
0x00005a60:  move.l     D0,D2                         ; D2 = result code (save for error handling)
0x00005a62:  addq.w     0x8,SP                        ; Clean stack (2 args × 4 bytes = 8 bytes)

0x00005a64:  bne.w      0x00005aec                    ; If registration failed, jump to exit
                                                      ; (returns error code 4 or 6 directly)
                                                      ; No cleanup needed - registration handles own errors

; --- STEP 2: LOOKUP BOARD STRUCTURE IN SLOT TABLE ---
; Retrieve the board structure pointer that was just created by ND_RegisterBoardSlot
; Slot table is global array at 0x819C mapping slots 2,4,6,8 to array indices 0,1,2,3
0x00005a68:  move.l     D3,D0                         ; D0 = slot_num (2, 4, 6, or 8)
0x00005a6a:  asr.l      #0x1,D0                       ; D0 = slot_num / 2 (array index: 1, 2, 3, 4)
                                                      ; Actually maps: 2→1, 4→2, 6→3, 8→4
                                                      ; Then subtract 1: 2→0, 4→1, 6→2, 8→3
0x00005a6c:  lea        (0x819c).l,A0                 ; A0 = &global_slot_table (base address)
0x00005a72:  movea.l    (0x0,A0,D0*0x4),A2            ; A2 = slot_table[index] (board struct pointer)
                                                      ; Index scaled by 4 (pointer size)
                                                      ; A2 now points to 80-byte nd_board_info structure

; --- STEP 3: LOAD FIRMWARE SEGMENTS TO BOARD MEMORY ---
; Call FUN_00004c88 to parse firmware file and transfer segments to i860 RAM
; This is the core firmware loading operation
0x00005a76:  pea        (0x40,A2)                     ; Push &board_struct->field_0x40 (output param)
                                                      ; Likely receives firmware segment handle/pointer
0x00005a7a:  pea        (0x2c,A2)                     ; Push &board_struct->field_0x2C (output param)
                                                      ; Likely receives firmware state/descriptor
0x00005a7e:  move.l     D3,-(SP)                      ; Push slot_num (for logging/validation)
0x00005a80:  move.l     D5,-(SP)                      ; Push converted_value (from lib_0500315e)
                                                      ; Possibly firmware version or file offset
0x00005a82:  move.l     (0x4,A2),-(SP)                ; Push board_struct->board_port (Mach IPC port)
                                                      ; Used for communication during DMA transfers
0x00005a86:  move.l     D4,-(SP)                      ; Push board_id (for validation)
0x00005a88:  bsr.l      0x00004c88                    ; CALL FUN_00004c88 (load firmware segments)
                                                      ; 6 parameters total
                                                      ; Returns: 0=success, non-zero=error
0x00005a8e:  move.l     D0,D2                         ; D2 = result code (save for error handling)
0x00005a90:  adda.w     #0x18,SP                      ; Clean stack (6 args × 4 bytes = 24 bytes)

0x00005a94:  beq.b      0x00005aa4                    ; If firmware load succeeded, continue to startup
                                                      ; Otherwise fall through to error cleanup

; --- ERROR PATH: FIRMWARE LOAD FAILED ---
; Firmware loading failed - need to cleanup board registration
firmware_load_error:
0x00005a96:  move.l     D3,-(SP)                      ; Push slot_num
0x00005a98:  move.l     D4,-(SP)                      ; Push board_id
0x00005a9a:  bsr.l      0x00003874                    ; CALL cleanup_function (FUN_00003874)
                                                      ; Deallocates board structure, removes from slot table
                                                      ; Releases Mach ports, undoes initialization
0x00005aa0:  move.l     D2,D0                         ; D0 = error code from firmware loader
                                                      ; Return original error code to caller
0x00005aa2:  bra.b      0x00005aec                    ; Jump to epilogue and return

; --- STEP 4: START BOARD EXECUTION ---
; Firmware successfully loaded - now release i860 from reset and start processor
firmware_loaded:
0x00005aa4:  move.l     D3,-(SP)                      ; Push slot_num
0x00005aa6:  move.l     D4,-(SP)                      ; Push board_id
0x00005aa8:  bsr.l      0x00005c70                    ; CALL FUN_00005c70 (start board execution)
                                                      ; Likely releases i860 from reset state
                                                      ; Initializes processor registers
                                                      ; Returns: 0=success, non-zero=error
0x00005aae:  addq.w     0x8,SP                        ; Clean stack (2 args × 4 bytes = 8 bytes)

0x00005ab0:  tst.l      D0                            ; Test result code
0x00005ab2:  bne.b      0x00005ae0                    ; If startup failed, jump to error cleanup
                                                      ; Returns error code 5

; --- STEP 5: TRANSFER PROGRAM CONTROL TO LOADED FIRMWARE ---
; Board started successfully - now set i860 PC and begin firmware execution
board_started:
0x00005ab4:  move.l     (0x10,A6),-(SP)               ; Push param3 (third argument!)
                                                      ; Likely firmware file path or descriptor
                                                      ; Used to locate entry point address
0x00005ab8:  move.l     A2,-(SP)                      ; Push board_struct pointer
                                                      ; Contains board_port and other state
0x00005aba:  bsr.l      0x00006f94                    ; CALL FUN_00006f94 (transfer program control)
                                                      ; Sets i860 program counter to firmware entry point
                                                      ; Begins execution of loaded code
                                                      ; Returns: -1=error, other=success
0x00005ac0:  addq.w     0x8,SP                        ; Clean stack (2 args × 4 bytes = 8 bytes)

0x00005ac2:  moveq      -0x1,D1                       ; D1 = -1 (error indicator constant)
0x00005ac4:  cmp.l      D0,D1                         ; Compare result with -1
0x00005ac6:  beq.b      0x00005ae0                    ; If transfer failed (-1), jump to error cleanup
                                                      ; Returns error code 5

; --- SUCCESS PATH: FINALIZE AND CLEANUP TEMPORARY RESOURCES ---
; All steps succeeded - firmware is now running on i860
; Cleanup temporary resources used during loading
transfer_success:
0x00005ac8:  move.l     (0x40,A2),-(SP)               ; Push board_struct->field_0x40
                                                      ; Firmware segment handle/pointer
0x00005acc:  move.l     (0x2c,A2),-(SP)               ; Push board_struct->field_0x2C
                                                      ; Firmware state/descriptor
0x00005ad0:  move.l     D5,-(SP)                      ; Push converted_value
                                                      ; Original parameter from conversion
0x00005ad2:  bsr.l      0x050032ba                    ; CALL lib_050032ba (finalize operation)
                                                      ; Likely closes file descriptors or unmaps memory
                                                      ; Releases temporary resources no longer needed
                                                      ; Note: No stack cleanup here - library handles it?
                                                      ; Or caller expects to clean (unusual)

0x00005ad8:  clr.l      (0x2c,A2)                     ; Clear board_struct->field_0x2C
                                                      ; Mark firmware loading state as complete
                                                      ; Note: field_0x40 NOT cleared - still in use?
0x00005adc:  clr.l      D0                            ; D0 = 0 (SUCCESS return code)
0x00005ade:  bra.b      0x00005aec                    ; Jump to epilogue and return

; --- ERROR PATH: BOARD STARTUP OR PROGRAM TRANSFER FAILED ---
; Either i860 didn't start, or program control couldn't be transferred
; Need to cleanup board registration (firmware already loaded but unusable)
startup_or_transfer_error:
0x00005ae0:  move.l     D3,-(SP)                      ; Push slot_num
0x00005ae2:  move.l     D4,-(SP)                      ; Push board_id
0x00005ae4:  bsr.l      0x00003874                    ; CALL cleanup_function (FUN_00003874)
                                                      ; Deallocates board structure
                                                      ; Removes from slot table
                                                      ; Releases resources
0x00005aea:  moveq      0x5,D0                        ; D0 = 5 (ERROR_STARTUP_FAILED)
                                                      ; Specific error code for startup/transfer failures
                                                      ; Distinguishes from registration (4,6) and load errors

; --- EPILOGUE ---
; Restore registers and return to caller
exit_function:
0x00005aec:  movem.l    -0x14,A6,{D2 D3 D4 D5 A2}    ; Restore saved registers
                                                      ; -0x14 = -20 bytes (5 registers × 4 bytes)
0x00005af2:  unlk       A6                            ; Restore frame pointer
                                                      ; Deallocate stack frame
0x00005af4:  rts                                      ; Return to caller
                                                      ; D0 contains return code

; ====================================================================================
; END OF FUNCTION: ND_LoadFirmwareAndStart
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function is the primary entry point for loading and starting firmware on a
; NeXTdimension graphics board. It orchestrates a 5-step sequence:
;   1. Register board slot (ND_RegisterBoardSlot)
;   2. Load firmware segments (FUN_00004c88)
;   3. Start board execution (FUN_00005c70)
;   4. Transfer program control (FUN_00006f94)
;   5. Finalize resources (lib_050032ba)
;
; Error handling is comprehensive:
;   - Registration failure: Direct return (self-contained cleanup)
;   - Firmware load failure: Cleanup board, return loader error code
;   - Startup failure: Cleanup board, return error code 5
;   - Transfer failure: Cleanup board, return error code 5
;   - Success: Finalize resources, clear state, return 0
;
; CONTROL FLOW GRAPH:
;   Entry → Convert param → Register board
;           ↓ (success)         ↓ (fail)
;      Lookup struct → Load firmware → Exit (error 4/6)
;           ↓ (success)         ↓ (fail)
;      Start board → Cleanup → Exit (loader error)
;           ↓ (success)         ↓ (fail)
;      Transfer control → Cleanup → Exit (error 5)
;           ↓ (success)         ↓ (fail)
;      Finalize → Cleanup → Exit (error 5)
;           ↓
;      Clear state → Exit (success 0)
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int ND_LoadFirmwareAndStart(uint32_t board_id, uint32_t slot_num, void* param3)
; {
;     int result;
;     int converted_param;
;     nd_board_info_t* board_info;
;     int slot_index;
;
;     // Step 0: Convert/validate parameter
;     converted_param = lib_convert_parameter(board_id);
;
;     // Step 1: Register board in slot table
;     result = ND_RegisterBoardSlot(board_id, slot_num);
;     if (result != 0) {
;         return result;  // Error 4 or 6
;     }
;
;     // Step 2: Lookup board structure
;     slot_index = slot_num / 2;
;     board_info = slot_table[slot_index];
;
;     // Step 3: Load firmware segments
;     result = load_firmware_segments(
;         board_id, board_info->board_port, converted_param, slot_num,
;         &board_info->field_0x2C, &board_info->field_0x40
;     );
;     if (result != 0) {
;         cleanup_board(board_id, slot_num);
;         return result;
;     }
;
;     // Step 4: Start board execution
;     result = start_board_execution(board_id, slot_num);
;     if (result != 0) {
;         cleanup_board(board_id, slot_num);
;         return 5;  // ERROR_STARTUP_FAILED
;     }
;
;     // Step 5: Transfer program control
;     result = transfer_program_control(board_info, param3);
;     if (result == -1) {
;         cleanup_board(board_id, slot_num);
;         return 5;  // ERROR_STARTUP_FAILED
;     }
;
;     // Success: Finalize and cleanup
;     lib_finalize(converted_param, board_info->field_0x2C, board_info->field_0x40);
;     board_info->field_0x2C = 0;
;
;     return 0;  // SUCCESS
; }
;
; ====================================================================================
; RELATED FUNCTIONS (for further analysis):
;
; HIGH PRIORITY:
;   - FUN_00004c88 (0x00004c88): Load firmware segments - CRITICAL for understanding
;                                 firmware file format and loading protocol
;   - FUN_00005c70 (0x00005c70): Start board execution - CRITICAL for understanding
;                                 i860 initialization sequence
;   - FUN_00006f94 (0x00006f94): Transfer program control - CRITICAL for understanding
;                                 PC transfer and execution start mechanism
;
; MEDIUM PRIORITY:
;   - FUN_00003874 (0x00003874): Cleanup function - needed for error handling
;   - FUN_00007032 (0x00007032): Alternative transfer function (used by variant)
;   - FUN_00007072 (0x00007072): Another alternative transfer (used by variant)
;   - FUN_00005af6 (0x00005af6): Similar firmware loading function (variant #1)
;   - FUN_00005bb8 (0x00005bb8): Similar firmware loading function (variant #2)
;
; LIBRARY FUNCTIONS (need identification):
;   - 0x0500315e: Parameter conversion (atoi/strtol?)
;   - 0x050032ba: Resource finalization (close/munmap?)
;
; ====================================================================================
; ANALYSIS METADATA:
;
; Analyst: Claude (Manual Reverse Engineering)
; Date: November 8, 2025
; Confidence: HIGH (95% - purpose and control flow clear)
; Documentation: docs/functions/00005a3e_ND_LoadFirmwareAndStart.md
; Status: Complete analysis, ready for validation
;
; KEY DISCOVERIES:
; 1. Three-parameter function (third param passed to transfer function)
; 2. Part of family of 3 similar loading functions (firmware variants?)
; 3. Uses global slot table for board structure management
; 4. Implements asymmetric cleanup (failures only, not success)
; 5. Coordinator pattern - chains 5 operations with error handling
;
; NEXT STEPS:
; 1. Analyze FUN_00004c88 to understand firmware file format
; 2. Analyze FUN_00005c70 to understand i860 startup sequence
; 3. Analyze FUN_00006f94 to understand PC transfer mechanism
; 4. Identify library functions 0x0500315e and 0x050032ba
; 5. Compare with FUN_00005af6 and FUN_00005bb8 to identify variants
;
; ====================================================================================
