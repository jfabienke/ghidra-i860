; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_InitializeBoardWithParameters
; ====================================================================================
; Address: 0x00005bb8
; Size: 184 bytes (0xB8)
; Purpose: Complete NeXTdimension board initialization sequence coordinator
; Analysis: docs/functions/00005bb8_ND_InitializeBoardWithParameters.md
; ====================================================================================

; FUNCTION SIGNATURE:
;   int ND_InitializeBoardWithParameters(
;       uint32_t board_id_or_param,    // @ 8(A6)  - Board identifier or raw param
;       uint32_t slot_num_or_param,    // @ 12(A6) - Slot number or raw param
;       void*    config_data           // @ 16(A6) - Configuration structure
;   );
;
; DESCRIPTION:
;   Primary entry point for complete NeXTdimension board initialization. Orchestrates
;   a 5-phase initialization sequence:
;     Phase 0: Parameter conversion/validation (library_convert)
;     Phase 1: Core registration (ND_RegisterBoardSlot - 6 subsystems)
;     Phase 2: Hardware initialization (hw_init_phase1)
;     Phase 3: Board state validation (validate_board)
;     Phase 4: Firmware loading (load_firmware)
;     Phase 5: Temporary resource cleanup
;
;   Performs complete error handling with automatic cleanup on any failure.
;
; PARAMETERS:
;   board_id_or_param (8(A6)):  Board identifier (from hardware detection) or raw param
;   slot_num_or_param (12(A6)): NeXTBus slot number (2,4,6,8) or raw param
;   config_data (16(A6)):       Configuration data pointer (used in firmware loading)
;
; RETURNS:
;   D0 = Error code
;        0 = Success (board fully initialized and online)
;        4 = Invalid slot (from ND_RegisterBoardSlot)
;        5 = Initialization failed after registration
;        6 = Memory allocation failed (from ND_RegisterBoardSlot)
;        Other = Error from sub-functions
;
; STACK FRAME: No local variables (link.w A6, 0x0)
;   Saved registers: D2, D3, D4, D5, A2 (20 bytes)
;
; REGISTER USAGE:
;   D2 - Error code accumulator (tracks results across calls)
;   D3 - Slot number (preserved throughout, passed to all sub-functions)
;   D4 - Board ID (preserved throughout, passed to all sub-functions)
;   D5 - Converted parameter (from library_convert, used in hw_init)
;   A2 - Pointer to board_info structure (retrieved from slot table)
;
; CALL GRAPH:
;   THIS FUNCTION
;     ├─> library_convert (0x0500315e) - Parameter conversion
;     ├─> ND_RegisterBoardSlot (0x000036b2) - Core registration [ANALYZED]
;     ├─> hw_init_phase1 (FUN_00004c88) - Hardware initialization
;     ├─> validate_board (FUN_00005c70) - Board state validation
;     ├─> load_firmware (FUN_00007072) - Firmware loading/finalization
;     ├─> library_cleanup (0x050032ba) - Temporary resource cleanup
;     └─> cleanup_board (FUN_00003874) - Error path cleanup
;
; ====================================================================================

FUN_00005bb8:
ND_InitializeBoardWithParameters:

    ; ====================================================================================
    ; PROLOGUE
    ; ====================================================================================
    0x00005bb8:  link.w     A6,0x0                        ; Create stack frame (no locals)
    0x00005bbc:  movem.l    {A2 D5 D4 D3 D2},SP           ; Save 5 callee-save registers (20 bytes)

    ; ====================================================================================
    ; LOAD ARGUMENTS INTO PRESERVED REGISTERS
    ; ====================================================================================
    0x00005bc0:  move.l     (0x8,A6),D4                   ; D4 = param1 (board_id or raw param)
    0x00005bc4:  move.l     (0xc,A6),D3                   ; D3 = param2 (slot_num or raw param)

    ; ====================================================================================
    ; PHASE 0: PARAMETER CONVERSION/VALIDATION
    ; ====================================================================================
    ; Library function 0x0500315e - likely converts parameters
    ; Possible candidates: atoi(), strtol(), parameter parser
    ; No explicit arguments passed - may use globals or previous D4/D3 values
    0x00005bc8:  bsr.l      0x0500315e                    ; CALL library_convert_function
    0x00005bce:  move.l     D0,D5                         ; D5 = converted_param (save result)

    ; ====================================================================================
    ; PHASE 1: REGISTER BOARD IN SLOT TABLE
    ; ====================================================================================
    ; Call ND_RegisterBoardSlot(board_id=D4, slot_num=D3)
    ; This performs:
    ;   - Slot validation (must be 2,4,6,8)
    ;   - Duplicate detection
    ;   - 80-byte structure allocation
    ;   - Mach port acquisition (2 ports)
    ;   - 6 subsystem initialization
    ;   - Registration in global slot table @ 0x819C
    0x00005bd0:  move.l     D3,-(SP)                      ; Push slot_num (param 2)
    0x00005bd2:  move.l     D4,-(SP)                      ; Push board_id (param 1)
    0x00005bd4:  bsr.l      0x000036b2                    ; CALL ND_RegisterBoardSlot [ANALYZED]
    0x00005bda:  move.l     D0,D2                         ; D2 = result (save error code)
    0x00005bdc:  addq.w     0x8,SP                        ; Clean stack (2 params × 4 bytes)
    0x00005bde:  bne.w      0x00005c66                    ; If error, jump to exit (return D2)

    ; ====================================================================================
    ; RETRIEVE REGISTERED BOARD STRUCTURE FROM SLOT TABLE
    ; ====================================================================================
    ; The board was successfully registered by ND_RegisterBoardSlot
    ; Now retrieve pointer to the allocated board_info structure
registration_success:
    0x00005be2:  move.l     D3,D0                         ; D0 = slot_num (2, 4, 6, or 8)
    0x00005be4:  asr.l      #0x1,D0                       ; D0 = slot_num / 2 (convert to index)
                                                          ;   Slot 2 → 1, Slot 4 → 2, etc.
                                                          ;   Then subtract 1 for 0-based index
    0x00005be6:  lea        (0x819c).l,A0                 ; A0 = &global_slot_table (4 entries)
    0x00005bec:  movea.l    (0x0,A0,D0*0x4),A2            ; A2 = slot_table[slot/2] (board_info*)

    ; ====================================================================================
    ; PHASE 2: HARDWARE INITIALIZATION
    ; ====================================================================================
    ; FUN_00004c88 performs hardware-specific initialization
    ; Takes 6 parameters, populates fields 0x2C and 0x40 in board structure
    ; These appear to be temporary resources (buffers, mappings, etc.)
    ; that are cleaned up after successful initialization
    0x00005bf0:  pea        (0x40,A2)                     ; Push &board_info->field_0x40 (output 2)
    0x00005bf4:  pea        (0x2c,A2)                     ; Push &board_info->field_0x2C (output 1)
    0x00005bf8:  move.l     D3,-(SP)                      ; Push slot_num
    0x00005bfa:  move.l     D5,-(SP)                      ; Push converted_param (from phase 0)
    0x00005bfc:  move.l     (0x4,A2),-(SP)                ; Push board_info->board_port (Mach port)
    0x00005c00:  move.l     D4,-(SP)                      ; Push board_id
    0x00005c02:  bsr.l      0x00004c88                    ; CALL hw_init_phase1 (6 args)
    0x00005c08:  move.l     D0,D2                         ; D2 = result
    0x00005c0a:  adda.w     #0x18,SP                      ; Clean stack (6 params × 4 = 24 bytes)
    0x00005c0e:  beq.b      0x00005c1e                    ; If success (D0=0), continue to phase 3

    ; --- ERROR PATH 1: Hardware initialization failed ---
hw_init_failed:
    0x00005c10:  move.l     D3,-(SP)                      ; Push slot_num
    0x00005c12:  move.l     D4,-(SP)                      ; Push board_id
    0x00005c14:  bsr.l      0x00003874                    ; CALL cleanup_board (unregister)
    0x00005c1a:  move.l     D2,D0                         ; Return original error code from hw_init
    0x00005c1c:  bra.b      0x00005c66                    ; Jump to epilogue

    ; ====================================================================================
    ; PHASE 3: BOARD STATE VALIDATION/ACTIVATION
    ; ====================================================================================
    ; FUN_00005c70 validates that the board is responding correctly
    ; May: Poll hardware status, check register values, verify i860 boot
hw_init_success:
    0x00005c1e:  move.l     D3,-(SP)                      ; Push slot_num
    0x00005c20:  move.l     D4,-(SP)                      ; Push board_id
    0x00005c22:  bsr.l      0x00005c70                    ; CALL validate_board_state (2 args)
    0x00005c28:  addq.w     0x8,SP                        ; Clean stack (2 params × 4 bytes)
    0x00005c2a:  tst.l      D0                            ; Test result (0 = success)
    0x00005c2c:  bne.b      0x00005c5a                    ; If error, jump to error path 2

    ; ====================================================================================
    ; PHASE 4: FIRMWARE LOADING OR FINAL CONFIGURATION
    ; ====================================================================================
    ; FUN_00007072 likely loads i860 firmware binary or performs final setup
    ; Takes board structure and config_data (third parameter from 16(A6))
    ; Special return semantics: -1 indicates error (unusual for this codebase)
validation_success:
    0x00005c2e:  move.l     (0x10,A6),-(SP)               ; Push config_data (param 3 from caller)
    0x00005c32:  move.l     A2,-(SP)                      ; Push board_info* (from slot table)
    0x00005c34:  bsr.l      0x00007072                    ; CALL load_firmware_or_finalize (2 args)
    0x00005c3a:  addq.w     0x8,SP                        ; Clean stack (2 params × 4 bytes)

    ; Check for special error return value -1
    0x00005c3c:  moveq      -0x1,D1                       ; D1 = -1 (error indicator)
    0x00005c3e:  cmp.l      D0,D1                         ; Compare result with -1
    0x00005c40:  beq.b      0x00005c5a                    ; If result == -1, error path 2

    ; ====================================================================================
    ; PHASE 5: CLEANUP TEMPORARY RESOURCES
    ; ====================================================================================
    ; All phases succeeded - now cleanup temporary resources
    ; Fields 0x2C and 0x40 were created during hw_init_phase1
    ; Library function 0x050032ba deallocates/unmaps them
    ; Possible: vm_deallocate(), munmap(), IOUnmapMemory()
firmware_load_success:
    0x00005c42:  move.l     (0x40,A2),-(SP)               ; Push board_info->field_0x40 (temp resource 2)
    0x00005c46:  move.l     (0x2c,A2),-(SP)               ; Push board_info->field_0x2C (temp resource 1)
    0x00005c4a:  move.l     D5,-(SP)                      ; Push converted_param (from phase 0)
    0x00005c4c:  bsr.l      0x050032ba                    ; CALL library_resource_cleanup (3 args)
    ; Note: Stack not cleaned after library call (library handles it)

    ; Clear field_0x2C (temporary handle no longer needed)
    0x00005c52:  clr.l      (0x2c,A2)                     ; board_info->field_0x2C = 0
    ; Note: field_0x40 NOT cleared - may persist for later use

    ; ====================================================================================
    ; SUCCESS PATH - RETURN 0
    ; ====================================================================================
    0x00005c56:  clr.l      D0                            ; Return ND_SUCCESS (0)
    0x00005c58:  bra.b      0x00005c66                    ; Jump to epilogue

    ; ====================================================================================
    ; ERROR PATH 2: Validation or firmware loading failed
    ; ====================================================================================
    ; Either validate_board_state returned non-zero OR
    ; load_firmware_or_finalize returned -1
validation_or_firmware_load_failed:
    0x00005c5a:  move.l     D3,-(SP)                      ; Push slot_num
    0x00005c5c:  move.l     D4,-(SP)                      ; Push board_id
    0x00005c5e:  bsr.l      0x00003874                    ; CALL cleanup_board (unregister, free)
    0x00005c64:  moveq      0x5,D0                        ; Return ND_ERROR_INIT_FAILED (5)
    ; Falls through to epilogue

    ; ====================================================================================
    ; EPILOGUE
    ; ====================================================================================
exit_function:
    0x00005c66:  movem.l    -0x14,A6,{D2 D3 D4 D5 A2}     ; Restore 5 saved registers (from -20(A6))
    0x00005c6c:  unlk       A6                            ; Restore frame pointer
    0x00005c6e:  rts                                      ; Return to caller (D0 = error code)

; ====================================================================================
; END OF FUNCTION: ND_InitializeBoardWithParameters
; ====================================================================================

; ====================================================================================
; CONTROL FLOW SUMMARY
; ====================================================================================
;
; SUCCESS PATH (All phases complete):
;   Entry → load_args → library_convert → ND_RegisterBoardSlot (success)
;     → retrieve_board_struct → hw_init_phase1 (success) → validate_board (success)
;     → load_firmware (success, !=-1) → library_cleanup → clear_field_0x2C
;     → return 0 → epilogue
;
; ERROR PATHS:
;   1. ND_RegisterBoardSlot fails:
;      Entry → ... → ND_RegisterBoardSlot (error) → return D2 → epilogue
;
;   2. hw_init_phase1 fails:
;      Entry → ... → hw_init_phase1 (error) → cleanup_board → return D2 → epilogue
;
;   3. validate_board fails:
;      Entry → ... → validate_board (error) → cleanup_board → return 5 → epilogue
;
;   4. load_firmware returns -1:
;      Entry → ... → load_firmware (-1) → cleanup_board → return 5 → epilogue
;
; ====================================================================================

; ====================================================================================
; DATA STRUCTURE: Board Info (Partial Layout)
; ====================================================================================
;
; typedef struct nd_board_info {
;     uint32_t  board_id;          // +0x00: Board identifier
;     uint32_t  board_port;        // +0x04: Mach port for IPC (READ by hw_init)
;     uint32_t  field_0x08;        // +0x08: From ND_RegisterBoardSlot subsystem 1
;     uint32_t  field_0x0C;        // +0x0C: From ND_RegisterBoardSlot subsystem 5
;     // ... fields 0x10-0x2B ...
;     void*     field_0x2C;        // +0x2C: TEMP resource (written by hw_init, cleared at end)
;     // ... fields 0x30-0x3F ...
;     void*     field_0x40;        // +0x40: TEMP resource (written by hw_init, NOT cleared)
;     // ... fields 0x44-0x47 ...
;     uint32_t  slot_num;          // +0x48: NeXTBus slot number (2,4,6,8)
;     uint32_t  field_0x4C;        // +0x4C: Always 0
; } nd_board_info_t;  // Total size: 80 bytes (0x50)
;
; ====================================================================================

; ====================================================================================
; REVERSE-ENGINEERED C EQUIVALENT
; ====================================================================================
;
; int ND_InitializeBoardWithParameters(
;     uint32_t board_id_or_param,
;     uint32_t slot_num_or_param,
;     void* config_data)
; {
;     int result;
;     uint32_t converted_param;
;     nd_board_info_t* board_info;
;     int slot_index;
;     uint32_t board_id = board_id_or_param;
;     uint32_t slot_num = slot_num_or_param;
;
;     // Phase 0: Parameter conversion
;     converted_param = library_convert_function();
;
;     // Phase 1: Register board (allocate struct, init 6 subsystems)
;     result = ND_RegisterBoardSlot(board_id, slot_num);
;     if (result != 0) {
;         return result;  // Error: 4=invalid slot, 6=no memory
;     }
;
;     // Retrieve registered board structure from slot table
;     slot_index = (slot_num / 2) - 1;  // 2→0, 4→1, 6→2, 8→3
;     board_info = slot_table[slot_index];
;
;     // Phase 2: Hardware initialization (creates temp resources)
;     result = hw_init_phase1(
;         board_id,
;         board_info->board_port,
;         converted_param,
;         slot_num,
;         &board_info->field_0x2C,  // Temp resource 1 (output)
;         &board_info->field_0x40   // Temp resource 2 (output)
;     );
;     if (result != 0) {
;         cleanup_board(board_id, slot_num);
;         return result;
;     }
;
;     // Phase 3: Validate board state (verify hardware responding)
;     result = validate_board_state(board_id, slot_num);
;     if (result != 0) {
;         cleanup_board(board_id, slot_num);
;         return ND_ERROR_INIT_FAILED;  // 5
;     }
;
;     // Phase 4: Load firmware or finalize configuration
;     result = load_firmware_or_finalize(board_info, config_data);
;     if (result == -1) {
;         cleanup_board(board_id, slot_num);
;         return ND_ERROR_INIT_FAILED;  // 5
;     }
;
;     // Phase 5: Cleanup temporary resources
;     library_resource_cleanup(
;         converted_param,
;         board_info->field_0x2C,
;         board_info->field_0x40
;     );
;
;     // Clear temp handle (no longer needed)
;     board_info->field_0x2C = 0;
;
;     return ND_SUCCESS;  // 0
; }
;
; ====================================================================================

; ====================================================================================
; ANALYSIS NOTES
; ====================================================================================
;
; KEY INSIGHTS:
; 1. Multi-phase initialization: This function orchestrates 5 distinct phases,
;    each with specific responsibilities and error handling.
;
; 2. Temporary resources: Fields 0x2C and 0x40 are temporary (created by hw_init,
;    used during initialization, then freed/cleared at end). This suggests
;    initialization requires temporary memory mappings or buffers.
;
; 3. Robust error handling: Every phase can fail independently, and all failures
;    trigger cleanup_board() to ensure no resource leaks or partial state.
;
; 4. External entry point: No internal callers found, suggesting this is part of
;    the driver's public API (likely called from kernel, IOKit, or daemon startup).
;
; 5. Firmware loading: Phase 4 (FUN_00007072) likely downloads i860 firmware binary,
;    critical for bringing i860 processor online.
;
; NEXT ANALYSIS TARGETS (High Priority):
; - FUN_00004c88 (hw_init_phase1): What hardware features are initialized?
; - FUN_00005c70 (validate_board): How is board state validated?
; - FUN_00007072 (load_firmware): What firmware is loaded and how?
; - Library 0x0500315e: What parameter conversion is performed?
; - Library 0x050032ba: What resources are being cleaned up?
;
; ====================================================================================
