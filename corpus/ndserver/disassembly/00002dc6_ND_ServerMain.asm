; ============================================================================
; Function: ND_ServerMain
; Address: 0x00002dc6
; Size: 662 bytes
; Layer: 3 (Root - Top of Call Graph)
; Purpose: Main entry point and orchestration coordinator for NDserver daemon
; ============================================================================
;
; OVERVIEW:
; This is the root function that orchestrates the complete lifecycle of the
; NeXTdimension server daemon. It has no external callers and coordinates
; all 12 major subsystems of the driver through a strict 10-phase sequence:
;
;   Phase 1:  Parse command-line arguments (-w <slot>)
;   Phase 2:  Open NeXTdimension device via IOKit
;   Phase 3:  Discover available boards on NeXTBus
;   Phase 4:  Validate and select slot (auto or manual)
;   Phase 5:  Setup board hardware (registers, memory, DMA)
;   Phase 6:  Get handle to board structure
;   Phase 7:  Load i860 kernel from file
;   Phase 8:  Release i860 from reset (start execution)
;   Phase 9:  Validate firmware parameters (5 retries)
;   Phase 10: Enter infinite Mach IPC message loop
;
; ARGUMENTS:
;   8(A6)  = argc (int)        - Number of command-line arguments
;   12(A6) = argv (char**)     - Array of argument strings
;
; LOCALS (20-byte stack frame):
;   -4(A6)  = device_fd        - IOKit device file descriptor
;   -8(A6)  = board_bitmask    - Available boards (bit per slot)
;   -12(A6) = board_handle     - Initialized board handle
;   -16(A6) = firmware_path    - Path to firmware file
;   -20(A6) = kernel_params    - Kernel loading parameters
;
; RETURNS:
;   Does not return - infinite message loop or exit(1) on error
;
; REGISTER USAGE:
;   D2 = argc counter, then retry counter (reused)
;   D3 = Selected slot number (2, 4, 6, or 8), -1 if not selected
;   D4 = Original argv[0] (program name)
;   A2 = argv pointer (incremented during parsing)
;
; CALL GRAPH (12 internal functions):
;   Layer 0: print_usage, ND_GetAvailableBoards, ND_GetBoardHandle,
;            ND_ReleaseProcessor, ND_GetFirmwareParameter, ND_WaitForEvent,
;            ND_ConfigureKernel, ND_Cleanup
;   Layer 1: ND_LoadKernelFromFile, ND_LoadKernelSegments,
;            ND_MessageReceiveLoop
;   Layer 2: ND_SetupBoardWithParameters
;
; ERROR HANDLING:
;   Fail-fast philosophy - any error results in fprintf() + exit(1)
;   No graceful degradation or partial initialization
;   Firmware validation includes retry logic (5 attempts, 1s delay)
;
; NOTES:
;   - Never returns under normal operation (infinite message loop)
;   - Dead code section at 0x0000302a-0x0000305a (signal loop)
;   - Possible control flow anomaly at 0x00002e9c (verify with binary)
;   - No multi-instance protection (assumes singleton)
;   - Requires root privileges for IOKit device access
;
; ============================================================================

FUN_00002dc6:
ND_ServerMain:

; =======================
; === PROLOGUE ===
; =======================
  0x00002dc6:  link.w     A6,-0x14                      ; Create 20-byte stack frame
                                                         ; Stack layout:
                                                         ;   -4(A6)  = device_fd
                                                         ;   -8(A6)  = board_bitmask
                                                         ;   -12(A6) = board_handle
                                                         ;   -16(A6) = firmware_path
                                                         ;   -20(A6) = kernel_params

  0x00002dca:  movem.l    {A2 D4 D3 D2},SP              ; Save 4 registers (16 bytes)
                                                         ; A2 = argv pointer
                                                         ; D4 = program name (argv[0])
                                                         ; D3 = slot number
                                                         ; D2 = argc/retry counter

; =======================
; === INITIALIZE LOCALS AND LOAD ARGUMENTS ===
; =======================
  0x00002dce:  movea.l    (0xc,A6),A2                   ; A2 = argv (argument vector)
  0x00002dd2:  clr.l      (-0x14,A6)                    ; kernel_params = 0
  0x00002dd6:  move.l     (A2),D4                       ; D4 = argv[0] (program name)
  0x00002dd8:  moveq      -0x1,D3                       ; D3 = -1 (no slot selected)
  0x00002dda:  move.l     (0x8,A6),D2                   ; D2 = argc
  0x00002dde:  bra.b      LAB_parse_args_check          ; Jump to loop condition

; =======================
; === PHASE 1: COMMAND-LINE ARGUMENT PARSING ===
; =======================
; Supported arguments:
;   -w <slot>  : Use specific NeXTBus slot (2, 4, 6, or 8)
;
; Algorithm:
;   for (i = 1; i < argc; i++) {
;     if (argv[i][0] == '-') {
;       if (strcmp(argv[i], "-w") == 0) {
;         slot_num = atoi(argv[++i]);
;         argc--;
;       } else {
;         print_usage(); exit(1);
;       }
;     }
;   }

LAB_parse_args_loop:
  0x00002de0:  addq.w     0x4,A2                        ; A2 += 4 (next argv element)
  0x00002de2:  movea.l    (A2),A0                       ; A0 = argv[i]
  0x00002de4:  cmpi.b     #0x2d,(A0)                    ; Check if arg[0] == '-'
  0x00002de8:  bne.b      LAB_parse_args_check          ; Not a flag, continue

  ; --- Handle flag arguments (currently only "-w") ---
  0x00002dea:  pea        (0x7736).l                    ; Push string "-w"
  0x00002df0:  move.l     A0,-(SP)                      ; Push argv[i]
  0x00002df2:  bsr.l      0x05003008                    ; CALL strcmp(argv[i], "-w")
  0x00002df8:  addq.w     0x8,SP                        ; Clean 8 bytes
  0x00002dfa:  tst.l      D0                            ; Check if D0 == 0 (match)
  0x00002dfc:  bne.b      LAB_not_w_flag                ; Not "-w", error

  ; --- Handle "-w <slot>" flag ---
  0x00002dfe:  moveq      0x1,D1                        ; D1 = 1
  0x00002e00:  cmp.l      D2,D1                         ; Check if argc > 1
  0x00002e02:  bge.b      LAB_not_w_flag                ; No next arg, error

  0x00002e04:  subq.l     0x1,D2                        ; argc-- (consume slot arg)
  0x00002e06:  addq.w     0x4,A2                        ; argv++ (advance to slot)
  0x00002e08:  move.l     (A2),-(SP)                    ; Push argv[i+1]
  0x00002e0a:  bsr.l      0x0500219e                    ; CALL atoi(argv[i+1])
  0x00002e10:  move.l     D0,D3                         ; D3 = slot_num
  0x00002e12:  bra.b      LAB_parse_args_cleanup        ; Continue

LAB_not_w_flag:
  ; --- Unknown flag or missing argument ---
  0x00002e14:  move.l     D4,-(SP)                      ; Push program name
  0x00002e16:  bsr.l      0x0000305c                    ; CALL print_usage(argv[0])
                                                         ; *** DOES NOT RETURN ***
                                                         ; Prints usage and calls exit(1)

LAB_parse_args_cleanup:
  0x00002e1c:  addq.w     0x4,SP                        ; Clean stack

LAB_parse_args_check:
  0x00002e1e:  subq.l     0x1,D2                        ; argc--
  0x00002e20:  bne.b      LAB_parse_args_loop           ; Loop if more args

; =======================
; === PHASE 2: OPEN DEVICE AND GET INFO ===
; =======================
; Use IOKit to open NeXTdimension device and retrieve information.
;
; Call: ioctl(g_device_handle, NIOCGINFO, device_path, output_path, &device_fd)
;
; Expected device_path: "/dev/nd0" or "/dev/nextdimension"
; Returns device file descriptor in device_fd local variable

  0x00002e22:  pea        (-0x4,A6)                     ; Push &device_fd (output)
  0x00002e26:  pea        (0x773e).l                    ; Push device_path
                                                         ; (likely "/dev/nd0")
  0x00002e2c:  pea        (0x774c).l                    ; Push output_path
  0x00002e32:  move.l     (0x04010294).l,-(SP)          ; Push g_device_handle
  0x00002e38:  bsr.l      0x05002a14                    ; CALL ioctl(NIOCGINFO)
  0x00002e3e:  addq.w     0x8,SP                        ; Clean 8 bytes
  0x00002e40:  addq.w     0x8,SP                        ; Clean 8 bytes (16 total)
  0x00002e42:  tst.l      D0                            ; Check result
  0x00002e44:  beq.b      LAB_device_opened             ; Success, continue

  ; --- ERROR: Device open failed ---
LAB_error_device_open:
  0x00002e46:  move.l     D0,-(SP)                      ; Push error code
  0x00002e48:  pea        (0x774d).l                    ; Push error format
                                                         ; "Error opening device: %d\n"
  0x00002e4e:  bsr.l      0x050028c4                    ; CALL fprintf(stderr, ...)
  0x00002e54:  pea        (0x1).w                       ; Push exit code 1
  0x00002e58:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

; =======================
; === PHASE 3: DISCOVER AVAILABLE BOARDS ===
; =======================
; Scan NeXTBus for NeXTdimension boards and retrieve bitmask.
;
; Bitmask format:
;   bit 0 = slot 2
;   bit 2 = slot 4
;   bit 4 = slot 6
;   bit 6 = slot 8
;
; Example: 0x00000005 = boards in slots 2 and 6 (bits 0 and 2 set)

LAB_device_opened:
  0x00002e5e:  pea        (-0x8,A6)                     ; Push &board_bitmask (output)
  0x00002e62:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002e66:  bsr.l      0x000042e8                    ; CALL ND_GetAvailableBoards
  0x00002e6c:  addq.w     0x8,SP                        ; Clean 8 bytes
  0x00002e6e:  tst.l      D0                            ; Check result
  0x00002e70:  beq.b      LAB_boards_discovered         ; Success, continue

  ; --- ERROR: Board discovery failed ---
LAB_error_discovery:
  0x00002e72:  move.l     D0,-(SP)                      ; Push error code
  0x00002e74:  pea        (0x775c).l                    ; Push error format
                                                         ; "Error discovering boards: %d\n"
  0x00002e7a:  bsr.l      0x050028c4                    ; CALL fprintf(stderr, ...)
  0x00002e80:  pea        (0x1).w                       ; Push exit code 1
  0x00002e84:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

  ; --- Dead code path (see control flow anomaly note) ---
  0x00002e8a:  move.l     D2,D3                         ; D3 = D2 (overwrites slot)
  0x00002e8c:  bra.b      LAB_slot_selected             ; Jump to validation

; =======================
; === PHASE 4A: AUTO-SELECT SLOT (IF NOT SPECIFIED) ===
; =======================
; If user did not specify slot with "-w", scan bitmask to find first
; available board.

LAB_boards_discovered:
  0x00002e8e:  moveq      -0x1,D1                       ; D1 = -1
  0x00002e90:  cmp.l      D3,D1                         ; Check if D3 == -1
  0x00002e92:  bne.b      LAB_slot_specified            ; Slot already chosen

  ; --- Scan bitmask for first available slot ---
  0x00002e94:  clr.l      D2                            ; D2 = 0 (bit index)

LAB_scan_slots_loop:
  0x00002e96:  move.l     (-0x8,A6),D0                  ; D0 = board_bitmask
  0x00002e9a:  btst.l     D2,D0                         ; Test bit D2
  0x00002e9c:  bne.b      0x00002e8a                    ; Bit set, use this slot
                                                         ; *** SUSPICIOUS JUMP ***
                                                         ; This jumps to code that
                                                         ; overwrites D3 = D2 and
                                                         ; skips validation.
                                                         ; Possible disassembly error
                                                         ; or compiler bug.

  0x00002e9e:  addq.l     0x2,D2                        ; D2 += 2 (next even bit)
  0x00002ea0:  moveq      0x7,D1                        ; D1 = 7 (max bit index)
  0x00002ea2:  cmp.l      D2,D1                         ; Check if D2 <= 7
  0x00002ea4:  bge.b      LAB_scan_slots_loop           ; Continue scanning

; =======================
; === PHASE 4B: VALIDATE SLOT SELECTION ===
; =======================
; Verify that a slot was selected (either manually or automatically)

LAB_slot_selected:
  0x00002ea6:  moveq      -0x1,D1                       ; D1 = -1
  0x00002ea8:  cmp.l      D3,D1                         ; Check if D3 == -1
  0x00002eaa:  bne.b      LAB_validate_slot             ; Slot selected, validate

  ; --- ERROR: No boards available ---
LAB_error_no_boards:
  0x00002eac:  pea        (0x776c).l                    ; Push error string
                                                         ; "No NeXTdimension boards found\n"
  0x00002eb2:  bsr.l      0x05002ce4                    ; CALL fprintf(stderr, ...)
  0x00002eb8:  pea        (0x1).w                       ; Push exit code 1
  0x00002ebc:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

LAB_slot_specified:
  ; NOTE: This code appears unreachable due to control flow at 0x00002e9c
  ; The bne.b at 0x00002e9c jumps to 0x00002e8a which overwrites D3
  ; This may be a disassembly artifact or compiler optimization issue

; =======================
; === PHASE 4C: VERIFY SLOT IN BITMASK ===
; =======================
; Ensure the selected slot actually has a board present

LAB_validate_slot:
  0x00002ec2:  move.l     (-0x8,A6),D1                  ; D1 = board_bitmask
  0x00002ec6:  btst.l     D3,D1                         ; Test bit D3
  0x00002ec8:  bne.b      LAB_slot_validated            ; Bit set, valid

  ; --- ERROR: Selected slot not present ---
LAB_error_slot_invalid:
  0x00002eca:  move.l     D3,-(SP)                      ; Push slot number
  0x00002ecc:  pea        (0x778b).l                    ; Push error format
                                                         ; "Slot %d not available\n"
  0x00002ed2:  bsr.l      0x05002ce4                    ; CALL fprintf(stderr, ...)
  0x00002ed8:  pea        (0x1).w                       ; Push exit code 1
  0x00002edc:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

; =======================
; === PHASE 5: SETUP BOARD WITH PARAMETERS ===
; =======================
; Initialize board hardware including:
;   - Register board in slot
;   - Configure memory mappings
;   - Setup DMA controllers
;   - Validate board state
;
; This is a Layer 2 function that orchestrates multiple Layer 1/0 functions.

LAB_slot_validated:
  0x00002ee2:  pea        (0x77af).l                    ; Push param3 (string)
  0x00002ee8:  pea        (0x77b6).l                    ; Push param2 (string)
  0x00002eee:  pea        (0x2000).l                    ; Push param1 (0x2000 = 8192)
                                                         ; Likely buffer/page size
  0x00002ef4:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002ef6:  move.l     (-0x4,A6),-(SP)               ; Push device_fd (board_id)
  0x00002efa:  bsr.l      0x00005af6                    ; CALL ND_SetupBoardWithParameters
                                                         ; Layer 2 function (analyzed)
  0x00002f00:  adda.w     #0x14,SP                      ; Clean 20 bytes (5 args)
  0x00002f04:  tst.l      D0                            ; Check result
  0x00002f06:  beq.b      LAB_board_setup_ok            ; Success, continue

  ; --- ERROR: Setup failed ---
LAB_error_setup:
  0x00002f08:  move.l     D0,-(SP)                      ; Push error code
  0x00002f0a:  pea        (0x77bd).l                    ; Push error format
                                                         ; "Setup failed: %d\n"
  0x00002f10:  bsr.l      0x050028c4                    ; CALL fprintf(stderr, ...)
  0x00002f16:  pea        (0x1).w                       ; Push exit code 1
  0x00002f1a:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

; =======================
; === PHASE 6: GET BOARD HANDLE ===
; =======================
; Retrieve opaque handle to board structure for subsequent operations

LAB_board_setup_ok:
  0x00002f20:  pea        (-0xc,A6)                     ; Push &board_handle (output)
  0x00002f24:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002f26:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002f2a:  bsr.l      0x00003820                    ; CALL ND_GetBoardHandle
                                                         ; Returns opaque pointer to
                                                         ; board state structure

; =======================
; === PHASE 7: LOAD i860 KERNEL FROM FILE ===
; =======================
; Load i860 kernel image from file system into i860 DRAM.
;
; This is a complex operation involving:
;   - Opening kernel file
;   - Validating file format
;   - DMA transfer to i860 memory
;   - Setting up entry point

  0x00002f30:  move.l     (0x04010290).l,-(SP)          ; Push g_kernel_path
                                                         ; Global default path
  0x00002f36:  move.l     (-0xc,A6),-(SP)               ; Push board_handle
  0x00002f3a:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002f3c:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002f40:  bsr.l      0x00005178                    ; CALL ND_LoadKernelFromFile
                                                         ; Layer 1 function
  0x00002f46:  adda.w     #0x1c,SP                      ; Clean 28 bytes (7 args)
  0x00002f4a:  tst.l      D0                            ; Check result
  0x00002f4c:  beq.b      LAB_kernel_loaded             ; Success, continue

  ; --- ERROR: Kernel load failed ---
LAB_error_kernel_load:
  0x00002f4e:  move.l     D0,-(SP)                      ; Push error code
  0x00002f50:  pea        (0x77d3).l                    ; Push error format
                                                         ; "Kernel load failed: %d\n"
  0x00002f56:  bsr.l      0x050028c4                    ; CALL fprintf(stderr, ...)
  0x00002f5c:  pea        (0x1).w                       ; Push exit code 1
  0x00002f60:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

; =======================
; === PHASE 8: RELEASE i860 FROM RESET ===
; =======================
; Start i860 processor execution by releasing reset signal.
; After this point, i860 begins executing from loaded kernel.

LAB_kernel_loaded:
  0x00002f66:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002f68:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002f6c:  bsr.l      0x00005d26                    ; CALL ND_ReleaseProcessor
                                                         ; Writes to board control
                                                         ; register to clear reset
  0x00002f72:  clr.l      D2                            ; D2 = 0 (retry counter)
  0x00002f74:  addq.w     0x8,SP                        ; Clean 8 bytes

; =======================
; === PHASE 9: FIRMWARE PARAMETER VALIDATION (WITH RETRIES) ===
; =======================
; Wait for i860 to boot and respond to mailbox commands.
; Try up to 5 times with 1-second delays between attempts.
;
; This validates that the i860 kernel has started and is responding
; to host commands via the mailbox protocol.
;
; Retry algorithm:
;   for (retry = 0; retry <= 4; retry++) {  // 5 total attempts
;     if (get_firmware_parameter() == 0) {
;       if (wait_for_event(firmware_path, 10) == 0) {
;         break;  // Success
;       }
;       cleanup(); exit(1);  // Validation failed
;     }
;     sleep(1);  // Retry delay
;   }

LAB_firmware_retry_loop:
  0x00002f76:  pea        (-0x10,A6)                    ; Push &firmware_path (output)
  0x00002f7a:  pea        (0x77e3).l                    ; Push parameter name
                                                         ; Likely "firmware_path"
  0x00002f80:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002f82:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002f86:  bsr.l      0x00004a52                    ; CALL ND_GetFirmwareParameter
                                                         ; Reads parameter from i860
                                                         ; via mailbox protocol
  0x00002f8c:  addq.w     0x8,SP                        ; Clean 8 bytes
  0x00002f8e:  addq.w     0x8,SP                        ; Clean 8 bytes (16 total)
  0x00002f90:  tst.l      D0                            ; Check result
  0x00002f92:  bne.b      LAB_firmware_retry            ; Failed, retry

  ; --- Parameter retrieved successfully, validate it ---
  0x00002f94:  pea        (0xa).w                       ; Push timeout = 10 (decimal)
  0x00002f98:  move.l     (-0x10,A6),-(SP)              ; Push firmware_path
  0x00002f9c:  bsr.l      0x00003200                    ; CALL ND_WaitForEvent
                                                         ; Wait for firmware ready
  0x00002fa2:  addq.w     0x8,SP                        ; Clean 8 bytes
  0x00002fa4:  tst.l      D0                            ; Check result
  0x00002fa6:  beq.b      LAB_firmware_validated        ; Success, continue

  ; --- Firmware validation failed (timeout or error) ---
  0x00002fa8:  move.l     D0,-(SP)                      ; Push error code
  0x00002faa:  pea        (0x77ea).l                    ; Push error format
                                                         ; "Firmware validation failed: %d\n"
  0x00002fb0:  bsr.l      0x050028c4                    ; CALL fprintf(stderr, ...)

  ; --- Cleanup before exit ---
  0x00002fb6:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002fb8:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002fbc:  bsr.l      0x00003874                    ; CALL ND_Cleanup
                                                         ; Release resources
  0x00002fc2:  pea        (0x1).w                       ; Push exit code 1
  0x00002fc6:  bsr.l      0x050024b0                    ; CALL exit(1)
                                                         ; *** DOES NOT RETURN ***

; --- Firmware parameter retrieved and validated ---
LAB_firmware_validated:
  ; === LOAD KERNEL SEGMENTS ===
  0x00002fcc:  pea        (-0x14,A6)                    ; Push &kernel_params (output)
  0x00002fd0:  move.l     D3,-(SP)                      ; Push slot_num
  0x00002fd2:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x00002fd6:  bsr.l      0x00003284                    ; CALL ND_LoadKernelSegments
                                                         ; Load additional kernel
                                                         ; segments/modules

  ; === CONFIGURE KERNEL ===
  0x00002fdc:  clr.l      -(SP)                         ; Push 0 (flags)
  0x00002fde:  move.l     (-0x10,A6),-(SP)              ; Push firmware_path
  0x00002fe2:  bsr.l      0x00005d60                    ; CALL ND_ConfigureKernel
                                                         ; Send configuration to i860
  0x00002fe8:  adda.w     #0x14,SP                      ; Clean 20 bytes
  0x00002fec:  bra.b      LAB_enter_message_loop        ; Jump to message loop

; --- Retry logic: sleep and try again ---
LAB_firmware_retry:
  0x00002fee:  pea        (0x1).w                       ; Push 1 (second)
  0x00002ff2:  bsr.l      0x05002fa2                    ; CALL sleep(1)
  0x00002ff8:  addq.w     0x4,SP                        ; Clean 4 bytes
  0x00002ffa:  addq.l     0x1,D2                        ; retry_counter++
  0x00002ffc:  moveq      0x4,D1                        ; D1 = 4 (max retry index)
  0x00002ffe:  cmp.l      D2,D1                         ; Check if retry <= 4
  0x00003000:  bge.w      LAB_firmware_retry_loop       ; Retry (up to 5 attempts)

  ; --- All retries exhausted, fall through ---
  ; Note: This falls through to message loop even after 5 failed retries,
  ; which seems odd. Firmware validation may be optional for some modes.

; =======================
; === PHASE 10: ENTER INFINITE MESSAGE LOOP ===
; =======================
; Start the main Mach IPC message reception and dispatch loop.
; This function NEVER RETURNS under normal operation.
;
; The message loop:
;   - Allocates 2x 8KB message buffers
;   - Waits for Mach IPC messages
;   - Validates message types
;   - Dispatches to appropriate handlers
;   - Repeats forever

LAB_enter_message_loop:
  0x00003004:  move.l     (-0x14,A6),-(SP)              ; Push kernel_params
  0x00003008:  clr.l      -(SP)                         ; Push 0 (port_type_2)
  0x0000300a:  move.l     D3,-(SP)                      ; Push slot_num (port_type_1)
  0x0000300c:  move.l     (-0x4,A6),-(SP)               ; Push device_fd (board_id)
  0x00003010:  bsr.l      0x0000399c                    ; CALL ND_MessageReceiveLoop
                                                         ; Layer 1 function (analyzed)
                                                         ; *** NEVER RETURNS ***
                                                         ;
                                                         ; This enters an infinite loop
                                                         ; processing client requests.
                                                         ; Only exits on fatal error.

; =======================
; === UNREACHABLE CODE ===
; =======================
; The following code is never executed because ND_MessageReceiveLoop
; does not return. This may be:
;   - Defensive programming (graceful shutdown path)
;   - Dead code from earlier implementation
;   - Template code from compiler

  0x00003016:  move.l     D3,-(SP)                      ; Push slot_num
  0x00003018:  move.l     (-0x4,A6),-(SP)               ; Push device_fd
  0x0000301c:  bsr.l      0x00003874                    ; CALL ND_Cleanup
  0x00003022:  clr.l      -(SP)                         ; Push 0 (exit code)
  0x00003024:  bsr.l      0x050024b0                    ; CALL exit(0)

; =======================
; === DEAD CODE SECTION ===
; =======================
; This code appears to be completely separate from the main function.
; It may be:
;   - Start of next function (disassembly boundary error)
;   - Dead debugging code
;   - Signal-based synchronization mechanism
;
; It implements a loop that sends signals to a process ID and waits
; for the process to terminate.

  0x0000302a:  nop                                      ; Alignment padding

DEAD_CODE_signal_loop_function:
  0x0000302c:  link.w     A6,0x0                        ; New function prologue
  0x00003030:  move.l     D2,-(SP)                      ; Save D2
  0x00003032:  bsr.l      0x05002696                    ; CALL getpid()
  0x00003038:  move.l     D0,D2                         ; D2 = pid

LAB_dead_signal_loop:
  0x0000303a:  pea        (0x5).w                       ; Push 5 (signal number)
                                                         ; 5 = SIGTRAP on some systems
                                                         ; or could be sleep(5)?
  0x0000303e:  bsr.l      0x05002fa2                    ; CALL sleep(5)?
                                                         ; Address collision with sleep
  0x00003044:  clr.l      (SP)                          ; Overwrite with 0 (sig_num?)
  0x00003046:  move.l     D2,-(SP)                      ; Push pid
  0x00003048:  bsr.l      0x0500282e                    ; CALL kill(pid, 0)
                                                         ; kill(pid, 0) tests if process exists
  0x0000304e:  addq.w     0x8,SP                        ; Clean 8 bytes
  0x00003050:  tst.l      D0                            ; Check result
  0x00003052:  beq.b      LAB_dead_signal_loop          ; Loop if process alive

  0x00003054:  move.l     (-0x4,A6),D2                  ; Restore D2
  0x00003058:  unlk       A6                            ; Restore frame pointer
  0x0000305a:  rts                                      ; Return

; ============================================================================
; END OF FUNCTION
; ============================================================================
;
; EXECUTION SUMMARY:
;
; Normal execution path:
;   1. Parse arguments
;   2. Open device
;   3. Discover boards
;   4. Validate slot
;   5. Setup board
;   6. Get handle
;   7. Load kernel
;   8. Start i860
;   9. Validate firmware (with retries)
;   10. Enter message loop (never returns)
;
; Error exits (7 total):
;   - 0x00002e58: Device open failed
;   - 0x00002e84: Board discovery failed
;   - 0x00002ebc: No boards found
;   - 0x00002edc: Invalid slot
;   - 0x00002f1a: Setup failed
;   - 0x00002f60: Kernel load failed
;   - 0x00002fc6: Firmware validation failed (after 5 retries)
;
; Total size: 662 bytes
; Instruction count: ~165
; Function calls: 12 internal + 8 library
; Error handling: Fail-fast with exit(1)
; Retry logic: Firmware validation (5 attempts, 1s delay)
; Message loop: Infinite (never returns)
;
; ============================================================================
