; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageReceiveLoop
; ====================================================================================
; Address: 0x0000399c
; Size: 832 bytes (208 instructions approximately)
; Purpose: Main Mach IPC message reception and dispatch loop for NeXTdimension server
; Analysis: docs/functions/0000399c_ND_MessageReceiveLoop.md
; ====================================================================================

; FUNCTION SIGNATURE:
; int ND_MessageReceiveLoop(
;     uint32_t board_id,       // @ 8(A6)  - NeXTdimension board identifier
;     uint32_t slot_num,       // @ 12(A6) - Physical slot number (2,4,6,8)
;     uint32_t port_type_1,    // @ 16(A6) - First port type (0=debug mode)
;     uint32_t port_type_2     // @ 20(A6) - Second port type (0=skip)
; );
;
; DESCRIPTION:
; This is the MAIN MESSAGE LOOP for the NeXTdimension server. It allocates two 8KB
; message buffers (request/response), registers multiple Mach IPC ports, and enters
; an infinite loop receiving messages and dispatching them to appropriate handlers.
; The function never returns under normal operation - it only exits on fatal
; initialization errors.
;
; The loop receives messages via mach_msg_receive(), validates message types,
; routes based on port number to one of 3+ handlers, sends responses, and handles
; errors gracefully. All errors are logged but operation continues (resilient design).
;
; PARAMETERS:
;   board_id (8,A6 → D6):  Board identifier from ND_RegisterBoardSlot
;   slot_num (12,A6 → D7): NeXTBus slot number (2, 4, 6, or 8)
;   port_type_1 (16,A6 → D4): Primary port type (0 enables debug file)
;   port_type_2 (20,A6 → D5): Secondary port type (0 skips service)
;
; RETURNS:
;   D0 = Error code (only on fatal initialization failure)
;
; STACK FRAME: 12 bytes locals + 36 bytes saved registers
;   -0x4(A6): local_pid (getpid() or allocated port)
;   -0x8(A6): local_receive_port (from FUN_00004a52)
;   -0xC(A6): send_port (from mach_port_lookup)
;
; REGISTER USAGE:
;   D2: Result accumulator / current_pid
;   D3: Temporary / fd from URL open
;   D4: port_type_1 (preserved)
;   D5: port_type_2 (preserved)
;   D6: board_id (preserved)
;   D7: slot_num (preserved)
;   A2: Temporary function pointer
;   A3: request_buffer (8KB message buffer)
;   A4: response_buffer (8KB message buffer)
;
; ====================================================================================

FUN_0000399c:
ND_MessageReceiveLoop:

    ; --- PROLOGUE ---
    ; Setup stack frame and save registers
    0x0000399c:  link.w     A6,-0xc               ; Create 12-byte stack frame
    0x000039a0:  movem.l    {A4 A3 A2 D7 D6 D5 D4 D3 D2},SP  ; Save 9 registers (36 bytes)

    ; --- LOAD PARAMETERS INTO PRESERVED REGISTERS ---
    ; These parameters stay in registers throughout the entire loop
    0x000039a4:  move.l     (0x8,A6),D6           ; D6 = board_id (constant)
    0x000039a8:  move.l     (0xc,A6),D7           ; D7 = slot_num (constant)
    0x000039ac:  move.l     (0x10,A6),D4          ; D4 = port_type_1 (constant)
    0x000039b0:  move.l     (0x14,A6),D5          ; D5 = port_type_2 (constant)
    0x000039b4:  clr.l      D2                    ; D2 = 0 (result accumulator)

    ; --- ALLOCATE MESSAGE BUFFERS (2 × 8KB) ---
    ; First buffer for incoming messages (request_buffer)
    0x000039b6:  pea        (0x2000).w            ; Push size = 8192 bytes
    0x000039ba:  lea        (0x50028fa).l,A2      ; A2 = &malloc (function pointer)
    0x000039c0:  jsr        A2                    ; CALL malloc(8192)
    0x000039c2:  movea.l    D0,A3                 ; A3 = request_buffer (8KB)

    ; Second buffer for outgoing messages (response_buffer)
    0x000039c4:  pea        (0x2000).w            ; Push size = 8192 bytes
    0x000039c8:  jsr        A2                    ; CALL malloc(8192) - reuse A2
    0x000039ca:  movea.l    D0,A4                 ; A4 = response_buffer (8KB)

    ; --- GET PROCESS ID ---
    ; Used for port allocation in special case (PID=0) or fork detection
    0x000039cc:  bsr.l      0x05003152            ; CALL getpid()
    0x000039d2:  move.l     D0,(-0x4,A6)          ; local_pid = getpid() result
    0x000039d6:  addq.w     0x8,SP                ; Clean stack (2 malloc calls = 8 bytes)

    ; --- CHECK IF RUNNING AS INIT PROCESS (PID == 0) ---
    ; Unlikely condition - only true if running as system init
    0x000039d8:  bne.b      0x00003a1a            ; If PID != 0, skip port allocation

    ; === SPECIAL CASE: PID == 0 (INIT PROCESS) ===
    ; Allocate a Mach port instead of using process ID
.allocate_mach_port:
    0x000039da:  pea        (-0x4,A6)             ; Push &local_pid (output parameter)
    0x000039de:  move.l     (0x04010290).l,-(SP)  ; Push global_nd_port
    0x000039e4:  bsr.l      0x05002c54            ; CALL mach_port_allocate(global_port, &new_port)
    0x000039ea:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x000039ec:  tst.l      D0                    ; Test result
    0x000039ee:  beq.b      0x00003a02            ; If success, insert send right

    ; Error: Port allocation failed (fatal)
.error_port_allocate:
    0x000039f0:  move.l     D0,-(SP)              ; Push error code
    0x000039f2:  pea        (0x78a7).l            ; Push error string @ 0x78a7
    0x000039f8:  bsr.l      0x050028c4            ; CALL log_error(message, code)
    0x000039fe:  bra.w      0x00003cd2            ; Jump to epilogue (fatal error exit)

    ; Port allocated successfully - insert send right
.insert_send_right:
    0x00003a02:  move.l     (-0x4,A6),-(SP)       ; Push local_pid (new port)
    0x00003a06:  pea        (0x2).w               ; Push right_type = 2 (MACH_MSG_TYPE_MAKE_SEND)
    0x00003a0a:  move.l     (0x04010290).l,-(SP)  ; Push global_port
    0x00003a10:  bsr.l      0x05003164            ; CALL mach_port_insert_right(port, type, name)
    0x00003a16:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003a18:  addq.w     0x4,SP

    ; --- INITIALIZE MESSAGE RECEIVE SYSTEM ---
.init_message_receive:
    ; Get the receive port for this board/slot
    0x00003a1a:  pea        (-0x8,A6)             ; Push &local_receive_port (output)
    0x00003a1e:  pea        (0x78bc).l            ; Push port_name_string @ 0x78bc
    0x00003a24:  move.l     D7,-(SP)              ; Push slot_num
    0x00003a26:  move.l     D6,-(SP)              ; Push board_id
    0x00003a28:  bsr.l      0x00004a52            ; CALL FUN_00004a52(board_id, slot, name, &port)
    0x00003a2e:  addq.w     0x8,SP                ; Clean stack (16 bytes)
    0x00003a30:  addq.w     0x8,SP
    0x00003a32:  tst.l      D0                    ; Test result
    0x00003a34:  bne.b      0x00003a86            ; If error, skip file open section

    ; --- CHECK IF DEBUG FILE DESCRIPTOR NEEDED (PORT_TYPE_1 == 0) ---
    0x00003a36:  tst.l      D4                    ; Test port_type_1
    0x00003a38:  bne.b      0x00003a86            ; If non-zero, skip file operations

    ; === DEBUG MODE: OPEN FILE DESCRIPTOR ===
.open_debug_file:
    ; Allocate temporary buffer (16KB)
    0x00003a3a:  pea        (0x4000).w            ; Push size = 16384 bytes
    0x00003a3e:  bsr.l      0x05002f72            ; CALL malloc(16384)

    ; Open debug/log file
    0x00003a44:  clr.l      -(SP)                 ; Push flags = 0 (O_RDONLY)
    0x00003a46:  clr.l      -(SP)                 ; Push mode = 0
    0x00003a48:  pea        (0x78c8).l            ; Push filename @ 0x78c8
    0x00003a4e:  bsr.l      0x05002bc4            ; CALL open(filename, O_RDONLY, 0)
    0x00003a54:  movea.l    D0,A2                 ; A2 = file_descriptor
    0x00003a56:  addq.w     0x8,SP                ; Clean stack (16 bytes)
    0x00003a58:  addq.w     0x8,SP

    ; Check if open succeeded (fd != -1)
    0x00003a5a:  moveq      -0x1,D1               ; D1 = -1 (INVALID_FD)
    0x00003a5c:  cmp.l      A2,D1                 ; Compare fd with -1
    0x00003a5e:  beq.b      0x00003a7c            ; If open failed, skip file operations

    ; File opened successfully - perform device initialization ioctl
.ioctl_init:
    0x00003a60:  clr.l      -(SP)                 ; Push arg = NULL
    0x00003a62:  move.l     #0x20007471,-(SP)     ; Push ioctl_request = 0x20007471
    0x00003a68:  move.l     A2,-(SP)              ; Push fd
    0x00003a6a:  bsr.l      0x050027ce            ; CALL ioctl(fd, 0x20007471, NULL)

    ; Close the file descriptor (done with initialization)
.close_debug_file:
    0x00003a70:  move.l     A2,-(SP)              ; Push fd
    0x00003a72:  bsr.l      0x0500229a            ; CALL close(fd)
    0x00003a78:  addq.w     0x8,SP                ; Clean stack (16 bytes)
    0x00003a7a:  addq.w     0x8,SP

    ; Get current process ID again (fork detection?)
.get_current_pid:
    0x00003a7c:  bsr.l      0x05002696            ; CALL getpid()
    0x00003a82:  move.l     D0,D2                 ; D2 = current_pid (used later for write)
    0x00003a84:  bra.b      0x00003a8a            ; Jump to port lookup

    ; === SKIP FILE OPEN PATH ===
.skip_file_open:
    0x00003a86:  clr.l      (-0x8,A6)             ; local_receive_port = 0 (not initialized)

    ; --- LOOKUP SEND PORT ---
.port_lookup:
    0x00003a8a:  pea        (-0xc,A6)             ; Push &send_port (output parameter)
    0x00003a8e:  move.l     (0x04010290).l,-(SP)  ; Push global_port
    0x00003a94:  bsr.l      0x05002c96            ; CALL mach_port_lookup(global_port, &send_port)
    0x00003a9a:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x00003a9c:  tst.l      D0                    ; Test result
    0x00003a9e:  beq.b      0x00003ab2            ; If success, continue

    ; Error: Port lookup failed (fatal)
.error_port_lookup:
    0x00003aa0:  move.l     D0,-(SP)              ; Push error code
    0x00003aa2:  pea        (0x78d1).l            ; Push error string @ 0x78d1
    0x00003aa8:  bsr.l      0x050028c4            ; CALL log_error(message, code)
    0x00003aae:  bra.w      0x00003cd2            ; Jump to epilogue (fatal error exit)

    ; --- REGISTER PORT TYPE 1 (IF NON-ZERO) ---
.register_port_type_1:
    0x00003ab2:  tst.l      D4                    ; Test port_type_1
    0x00003ab4:  beq.b      0x00003ae2            ; If 0, skip registration

    ; Register port type 1 with Mach kernel
    0x00003ab6:  move.l     D4,-(SP)              ; Push port_type_1
    0x00003ab8:  move.l     (-0xc,A6),-(SP)       ; Push send_port
    0x00003abc:  move.l     (0x04010290).l,-(SP)  ; Push global_port
    0x00003ac2:  bsr.l      0x05002c90            ; CALL mach_port_register_type(port, send, type)
    0x00003ac8:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003aca:  addq.w     0x4,SP
    0x00003acc:  tst.l      D0                    ; Test result
    0x00003ace:  beq.b      0x00003ae2            ; If success, continue

    ; Error: Port type 1 registration failed (fatal)
.error_port_type1_register:
    0x00003ad0:  move.l     D0,-(SP)              ; Push error code
    0x00003ad2:  pea        (0x78ea).l            ; Push error string @ 0x78ea
    0x00003ad8:  bsr.l      0x050028c4            ; CALL log_error(message, code)
    0x00003ade:  bra.w      0x00003cd2            ; Jump to epilogue (fatal error exit)

    ; --- REGISTER PORT TYPE 2 (IF NON-ZERO) ---
.register_port_type_2:
    0x00003ae2:  tst.l      D5                    ; Test port_type_2
    0x00003ae4:  beq.b      0x00003b4e            ; If 0, skip registration

    ; Register port type 2 with Mach kernel
    0x00003ae6:  move.l     D5,-(SP)              ; Push port_type_2
    0x00003ae8:  move.l     (-0xc,A6),-(SP)       ; Push send_port
    0x00003aec:  move.l     (0x04010290).l,-(SP)  ; Push global_port
    0x00003af2:  bsr.l      0x05002c90            ; CALL mach_port_register_type(port, send, type)
    0x00003af8:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003afa:  addq.w     0x4,SP
    0x00003afc:  tst.l      D0                    ; Test result
    0x00003afe:  beq.b      0x00003b12            ; If success, continue

    ; Error: Port type 2 registration failed (fatal)
.error_port_type2_register:
    0x00003b00:  move.l     D0,-(SP)              ; Push error code
    0x00003b02:  pea        (0x7906).l            ; Push error string @ 0x7906
    0x00003b08:  bsr.l      0x050028c4            ; CALL log_error(message, code)
    0x00003b0e:  bra.w      0x00003cd2            ; Jump to epilogue (fatal error exit)

    ; --- OPEN FILE DESCRIPTOR FROM URL (FOR PORT_TYPE_2) ---
.open_url_fd:
    0x00003b12:  move.l     D7,-(SP)              ; Push slot_num
    0x00003b14:  move.l     D6,-(SP)              ; Push board_id
    0x00003b16:  bsr.l      0x00006474            ; CALL ND_URLFileDescriptorOpen(board_id, slot)
    0x00003b1c:  move.l     D0,D3                 ; D3 = fd (file descriptor or 0)
    0x00003b1e:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x00003b20:  beq.b      0x00003b4e            ; If fd == 0, skip fd registration

    ; File descriptor opened - register it with port
.register_url_fd:
    0x00003b22:  move.l     D3,-(SP)              ; Push fd
    0x00003b24:  move.l     (-0xc,A6),-(SP)       ; Push send_port
    0x00003b28:  move.l     (0x04010290).l,-(SP)  ; Push global_port
    0x00003b2e:  bsr.l      0x05002c90            ; CALL mach_port_register_fd(port, send, fd)
    0x00003b34:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003b36:  addq.w     0x4,SP
    0x00003b38:  tst.l      D0                    ; Test result
    0x00003b3a:  beq.b      0x00003b4e            ; If success, continue

    ; Error: FD registration failed (fatal)
.error_fd_register:
    0x00003b3c:  move.l     D0,-(SP)              ; Push error code
    0x00003b3e:  pea        (0x7922).l            ; Push error string @ 0x7922
    0x00003b44:  bsr.l      0x050028c4            ; CALL log_error(message, code)
    0x00003b4a:  bra.w      0x00003cd2            ; Jump to epilogue (fatal error exit)

    ; --- REGISTER LOCAL PID (IF NON-ZERO) ---
.register_local_pid:
    0x00003b4e:  tst.l      (-0x4,A6)             ; Test local_pid
    0x00003b52:  beq.b      0x00003b82            ; If 0, skip to main loop

    ; Register local PID with port
    0x00003b54:  move.l     (-0x4,A6),-(SP)       ; Push local_pid
    0x00003b58:  move.l     (-0xc,A6),-(SP)       ; Push send_port
    0x00003b5c:  move.l     (0x04010290).l,-(SP)  ; Push global_port
    0x00003b62:  bsr.l      0x05002c90            ; CALL mach_port_register_pid(port, send, pid)
    0x00003b68:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003b6a:  addq.w     0x4,SP
    0x00003b6c:  tst.l      D0                    ; Test result
    0x00003b6e:  beq.b      0x00003b82            ; If success, continue to main loop

    ; Error: PID registration failed (fatal)
.error_pid_register:
    0x00003b70:  move.l     D0,-(SP)              ; Push error code
    0x00003b72:  pea        (0x7942).l            ; Push error string @ 0x7942
    0x00003b78:  bsr.l      0x050028c4            ; CALL log_error(message, code)
    0x00003b7e:  bra.w      0x00003cd2            ; Jump to epilogue (fatal error exit)

    ; ==========================================================================
    ; MAIN MESSAGE RECEIVE LOOP
    ; This is the heart of the server - receives and processes messages forever
    ; ==========================================================================

.message_loop:
    ; --- SETUP REQUEST BUFFER ---
    ; Configure buffer for message receive
    0x00003b82:  move.l     #0x2000,(0x4,A3)      ; request_buffer->size = 8192
    0x00003b8a:  move.l     (-0xc,A6),(0xc,A3)    ; request_buffer->port = send_port

    ; --- RECEIVE MESSAGE (BLOCKING) ---
    ; This call blocks until a message arrives
    0x00003b90:  clr.l      -(SP)                 ; Push timeout = 0 (infinite wait)
    0x00003b92:  clr.l      -(SP)                 ; Push flags = 0
    0x00003b94:  move.l     A3,-(SP)              ; Push request_buffer
    0x00003b96:  bsr.l      0x050029ae            ; CALL mach_msg_receive(buffer, flags, timeout)
    0x00003b9c:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003b9e:  addq.w     0x4,SP
    0x00003ba0:  tst.l      D0                    ; Test result
    0x00003ba2:  beq.b      0x00003bb8            ; If success (0), process message

    ; Error: Message receive failed (fatal - can't continue without messages)
.error_receive:
    0x00003ba4:  move.l     D0,-(SP)              ; Push error code
    0x00003ba6:  bsr.l      0x050028d0            ; CALL mach_error_string(error_code)
    0x00003bac:  move.l     D0,-(SP)              ; Push error string
    0x00003bae:  pea        (0x795f).l            ; Push format string @ 0x795f
    0x00003bb4:  bra.w      0x00003cb6            ; Jump to printf and cleanup

    ; --- VALIDATE RECEIVED MESSAGE ---
.process_message:
    ; Check if message is complex (has descriptors/ports)
    0x00003bb8:  moveq      0x1,D1                ; D1 = 1 (expected complex flag)
    0x00003bba:  cmp.l      (0x8,A3),D1           ; Compare with request->complex_flag
    0x00003bbe:  bne.b      0x00003bf4            ; If not complex (simple), dispatch by port

    ; === COMPLEX MESSAGE VALIDATION ===
    ; Complex messages must be type 0x41 or 0x45
.validate_complex_message:
    0x00003bc0:  moveq      0x41,D1               ; D1 = 0x41 (message type A)
    0x00003bc2:  cmp.l      (0x14,A3),D1          ; Compare with request->msg_id
    0x00003bc6:  beq.b      0x00003bd0            ; If type A, validate remote port
    0x00003bc8:  moveq      0x45,D1               ; D1 = 0x45 (message type E)
    0x00003bca:  cmp.l      (0x14,A3),D1          ; Compare with request->msg_id
    0x00003bce:  bne.b      0x00003bde            ; If neither A nor E, log unknown type

    ; Validate remote port matches our local receive port
.validate_remote_port:
    0x00003bd0:  move.l     (0x1c,A3),D1          ; D1 = request->remote_port
    0x00003bd4:  cmp.l      (-0x8,A6),D1          ; Compare with local_receive_port
    0x00003bd8:  beq.w      0x00003cc4            ; If match, cleanup and receive next
    0x00003bdc:  bra.b      0x00003b82            ; Else retry receive (port mismatch)

    ; Unknown complex message type - log warning and continue
.unknown_message_type:
    0x00003bde:  move.l     (0x14,A3),-(SP)       ; Push request->msg_id
    0x00003be2:  pea        (0x798e).l            ; Push format string @ 0x798e
    0x00003be8:  bsr.l      0x05002ce4            ; CALL printf("Unknown message type: 0x%x", msg_id)
    0x00003bee:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x00003bf0:  bra.w      0x00003cc4            ; Cleanup buffers and receive next

    ; --- DISPATCH BASED ON PORT NUMBER ---
    ; Route simple messages to appropriate handler based on port
.dispatch_by_port:
    ; Check if message port matches port_type_1 (D4)
    0x00003bf4:  cmp.l      (0xc,A3),D4           ; Compare request->port with port_type_1
    0x00003bf8:  bne.b      0x00003c10            ; If no match, check port_type_2

    ; === HANDLER 1: PRIMARY MESSAGE DISPATCHER (PORT_TYPE_1) ===
.dispatch_to_handler_1:
    ; Initialize board_id in message if not set
    0x00003bfa:  tst.l      (0x10,A3)             ; Test request->field_0x10
    0x00003bfe:  bne.b      0x00003c04            ; If already set, skip init
    0x00003c00:  move.l     D6,(0x10,A3)          ; request->field_0x10 = board_id

    ; Call main message dispatcher
    0x00003c04:  move.l     A4,-(SP)              ; Push response_buffer
    0x00003c06:  move.l     A3,-(SP)              ; Push request_buffer
    0x00003c08:  bsr.l      0x00006e6c            ; CALL ND_MessageDispatcher(request, response)
    0x00003c0e:  bra.b      0x00003c6a            ; Jump to send response

    ; Check if message port matches port_type_2 (D5)
.check_port_type_2:
    0x00003c10:  cmp.l      (0xc,A3),D5           ; Compare request->port with port_type_2
    0x00003c14:  bne.b      0x00003c3e            ; If no match, check URL fd port (D3)

    ; === HANDLER 2: SECONDARY SERVICE (PORT_TYPE_2) ===
.dispatch_to_handler_2:
    0x00003c16:  move.l     A4,-(SP)              ; Push response_buffer
    0x00003c18:  move.l     A3,-(SP)              ; Push request_buffer
    0x00003c1a:  bsr.l      0x000033b4            ; CALL FUN_000033b4(request, response)
    0x00003c20:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x00003c22:  tst.l      D0                    ; Test handler result
    0x00003c24:  bne.b      0x00003c70            ; If error, send error response

    ; Handler succeeded - check if we should write to file descriptor
.check_write_to_fd:
    0x00003c26:  tst.l      D2                    ; Test current_pid (fd)
    0x00003c28:  ble.w      0x00003cc4            ; If <= 0, cleanup and receive next

    ; Write result to file descriptor
.write_result:
    0x00003c2c:  pea        (0x1).w               ; Push count = 1 byte
    0x00003c30:  move.l     D2,-(SP)              ; Push fd = current_pid
    0x00003c32:  bsr.l      0x0500282e            ; CALL write(fd, buffer, 1)
    0x00003c38:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x00003c3a:  bra.w      0x00003cc4            ; Cleanup and receive next

    ; Check if message port matches D3 (URL file descriptor port)
.check_url_fd_port:
    0x00003c3e:  cmp.l      (0xc,A3),D3           ; Compare request->port with D3 (URL fd)
    0x00003c42:  beq.b      0x00003c60            ; If match, dispatch to handler 3

    ; === UNKNOWN PORT - LOG ERROR ===
.unknown_port:
    0x00003c44:  move.l     (0x14,A3),-(SP)       ; Push request->msg_id
    0x00003c48:  move.l     (0xc,A3),-(SP)        ; Push request->port
    0x00003c4c:  pea        (0x79bb).l            ; Push format string @ 0x79bb
    0x00003c52:  bsr.l      0x05002ce4            ; CALL printf("Unknown port %d, msg %d", port, msg_id)
    0x00003c58:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003c5a:  addq.w     0x4,SP
    0x00003c5c:  bra.w      0x00003b82            ; Retry receive (ignore unknown port)

    ; === HANDLER 3: URL FILE DESCRIPTOR SERVICE ===
.dispatch_to_handler_3:
    0x00003c60:  move.l     A4,-(SP)              ; Push response_buffer
    0x00003c62:  move.l     A3,-(SP)              ; Push request_buffer
    0x00003c64:  bsr.l      0x00006de4            ; CALL FUN_00006de4(request, response)
    ; Fall through to send response

    ; --- SEND RESPONSE MESSAGE ---
.send_response:
    0x00003c6a:  addq.w     0x8,SP                ; Clean stack (8 bytes)
    0x00003c6c:  tst.l      D0                    ; Test handler result
    0x00003c6e:  beq.b      0x00003cc4            ; If success (0), cleanup and receive next

    ; === HANDLER RETURNED ERROR - SEND ERROR RESPONSE ===
.send_error_response:
    ; Check for special error code -305 (no response should be sent)
    0x00003c70:  cmpi.l     #-0x131,(0x1c,A4)     ; Check if response->error_code == -305
    0x00003c78:  beq.w      0x00003b82            ; If -305, retry receive (no response)

    ; Copy request context to response
.prepare_error_response:
    0x00003c7c:  move.l     (0xc,A3),(0xc,A4)     ; response->port = request->port
    0x00003c82:  move.l     (0x10,A3),(0x10,A4)   ; response->board_id = request->board_id

    ; Send error response message
.send_error_msg:
    0x00003c88:  clr.l      -(SP)                 ; Push timeout = 0 (no wait)
    0x00003c8a:  clr.l      -(SP)                 ; Push flags = 0
    0x00003c8c:  move.l     A4,-(SP)              ; Push response_buffer
    0x00003c8e:  bsr.l      0x050029d2            ; CALL mach_msg_send(response, flags, timeout)
    0x00003c94:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003c96:  addq.w     0x4,SP
    0x00003c98:  tst.l      D0                    ; Test send result
    0x00003c9a:  beq.w      0x00003b82            ; If success, retry receive

    ; Check if error is SEND_INTERRUPTED (-102) - this is normal
.check_send_interrupted:
    0x00003c9e:  moveq      -0x66,D1              ; D1 = -102 (SEND_INTERRUPTED)
    0x00003ca0:  cmp.l      D0,D1                 ; Compare with send result
    0x00003ca2:  beq.w      0x00003b82            ; If interrupted, retry (normal condition)

    ; Fatal send error - log and retry (resilient design)
.send_error:
    0x00003ca6:  move.l     D0,-(SP)              ; Push error code
    0x00003ca8:  bsr.l      0x050028d0            ; CALL mach_error_string(error_code)
    0x00003cae:  move.l     D0,-(SP)              ; Push error string
    0x00003cb0:  pea        (0x79e3).l            ; Push format string @ 0x79e3
    ; Fall through to print error

    ; --- COMMON ERROR PRINT PATH ---
.print_error:
    0x00003cb6:  bsr.l      0x05002ce4            ; CALL printf(format, error_string)
    0x00003cbc:  addq.w     0x8,SP                ; Clean stack (12 bytes)
    0x00003cbe:  addq.w     0x4,SP
    0x00003cc0:  bra.w      0x00003b82            ; Retry receive (resilient - continue despite error)

    ; --- CLEANUP BUFFERS AND LOOP AGAIN ---
    ; Free buffers and allocate fresh ones for next message
.cleanup_and_loop:
    0x00003cc4:  move.l     A3,-(SP)              ; Push request_buffer
    0x00003cc6:  lea        (0x5002546).l,A2      ; A2 = &free (function pointer)
    0x00003ccc:  jsr        A2                    ; CALL free(request_buffer)
    0x00003cce:  move.l     A4,-(SP)              ; Push response_buffer
    0x00003cd0:  jsr        A2                    ; CALL free(response_buffer)

    ; Loop back to beginning - allocate new buffers and receive next message
    ; NOTE: This jumps back to the prologue of the message loop, which will
    ; allocate fresh buffers. This prevents memory fragmentation and ensures
    ; no buffer overflow or corruption carries over between messages.
    ; Fall through to epilogue (which won't actually return - we branch back)

    ; --- EPILOGUE ---
    ; Only reached on fatal initialization errors or catastrophic receive failure
.exit_function:
    0x00003cd2:  movem.l    -0x30,A6,{D2 D3 D4 D5 D6 D7 A2 A3 A4}  ; Restore 9 registers
    0x00003cd8:  unlk       A6                    ; Destroy stack frame
    0x00003cda:  rts                              ; Return to caller (fatal error)

; ====================================================================================
; END OF FUNCTION: ND_MessageReceiveLoop
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function implements the core message reception and dispatch loop for the
; NeXTdimension server. It is designed to run indefinitely, receiving Mach IPC
; messages and routing them to appropriate handlers. The function exhibits excellent
; defensive programming with comprehensive error handling - all errors are logged
; and operation continues (except fatal initialization failures).
;
; KEY BEHAVIORAL CHARACTERISTICS:
; - Infinite loop design (only returns on fatal error)
; - Blocking message receive (no busy-wait)
; - Multi-port message routing (3+ handlers)
; - Buffer reallocation each iteration (leak prevention)
; - Resilient error handling (log and continue)
; - Complex message validation (types 0x41, 0x45)
; - Special error code handling (-305, -102)
;
; REVERSE-ENGINEERED C EQUIVALENT:
; int ND_MessageReceiveLoop(uint32_t board_id, uint32_t slot_num,
;                           uint32_t port_type_1, uint32_t port_type_2)
; {
;     nd_message_t *request, *response;
;     mach_port_t local_pid, local_rcv_port, send_port;
;     int current_pid = 0, fd = 0, result;
;
;     // Initialize (allocate buffers, get ports, register types)
;     request = malloc(8192);
;     response = malloc(8192);
;     local_pid = getpid();
;     if (local_pid == 0) {
;         mach_port_allocate(global_port, &local_pid);
;         mach_port_insert_right(global_port, 2, local_pid);
;     }
;     FUN_00004a52(board_id, slot_num, "port_name", &local_rcv_port);
;     if (port_type_1 == 0) {
;         int debug_fd = open("/debug/file", 0, 0);
;         if (debug_fd != -1) { ioctl(debug_fd, 0x20007471, NULL); close(debug_fd); }
;         current_pid = getpid();
;     }
;     mach_port_lookup(global_port, &send_port);
;     if (port_type_1) mach_port_register_type(global_port, send_port, port_type_1);
;     if (port_type_2) {
;         mach_port_register_type(global_port, send_port, port_type_2);
;         fd = ND_URLFileDescriptorOpen(board_id, slot_num);
;         if (fd) mach_port_register_fd(global_port, send_port, fd);
;     }
;     if (local_pid) mach_port_register_pid(global_port, send_port, local_pid);
;
;     // Main loop
;     while (1) {
;         request->size = 8192;
;         request->port = send_port;
;         if (mach_msg_receive(request, 0, 0) != 0) break;  // Fatal
;         if (request->complex_flag == 1) {
;             if (request->msg_id == 0x41 || request->msg_id == 0x45) {
;                 if (request->remote_port == local_rcv_port) { goto cleanup; }
;                 continue;
;             }
;             printf("Unknown message type: 0x%x\n", request->msg_id);
;             goto cleanup;
;         }
;         if (request->port == port_type_1) {
;             if (!request->board_id) request->board_id = board_id;
;             result = ND_MessageDispatcher(request, response);
;         } else if (request->port == port_type_2) {
;             result = FUN_000033b4(request, response);
;             if (result == 0 && current_pid > 0) write(current_pid, buffer, 1);
;         } else if (request->port == fd) {
;             result = FUN_00006de4(request, response);
;         } else {
;             printf("Unknown port %d, msg %d\n", request->port, request->msg_id);
;             continue;
;         }
;         if (result == 0) goto cleanup;
;         if (response->error_code == -305) continue;
;         response->port = request->port;
;         response->board_id = request->board_id;
;         result = mach_msg_send(response, 0, 0);
;         if (result == 0 || result == -102) continue;
;         printf("Send error: %s\n", mach_error_string(result));
; cleanup:
;         free(request); free(response);
;         request = malloc(8192); response = malloc(8192);
;     }
;     return -1;  // Fatal error
; }
;
; ====================================================================================
