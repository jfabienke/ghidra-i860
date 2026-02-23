; ====================================================================================
; ANNOTATED DISASSEMBLY: Callback Handler / Message Dispatcher
; ====================================================================================
; Function: FUN_000056f0
; Address: 0x000056f0
; Size: 140 bytes (35 instructions)
; Stack Frame: 548 bytes (0x224)
; Analysis: docs/functions/0x000056f0_FUN_000056f0_COMPREHENSIVE.md
;
; PURPOSE:
;   Initialize a 548-byte message/data structure buffer and dispatch it via two
;   sequential library function calls. Acts as a wrapper or callback handler in the
;   NeXTdimension device driver architecture.
;
; CALLING CONVENTION:
;   Arguments passed on stack (m68k System V ABI):
;     4(A6): arg1 - First parameter (data/handle/ID)
;     8(A6): arg2 - Second parameter (configuration/type)
;    12(A6): arg3 - Third parameter (pointer to data)
;    16(A6): arg4 - Fourth parameter (size/type value in D2)
;
;   Return value in D0:
;     0x00000000 = Success (library result)
;    -0x00000133 = Error: Size out of range (> 512)
;
; STACK FRAME LAYOUT:
;   -0x224(A6) through -0x04(A6): 548-byte local buffer/structure
;   Key fields populated before library calls:
;     -0x220: Calculated aligned size + offset
;     -0x214: Copy of arg1
;     -0x210: Max value (127)
;     -0x20c: Global config 1
;     -0x208: Copy of arg2
;     -0x204: Global config 2
;     -0x202: Bitfield insertion point (size bits)
;     -0x221: Status flag (1 = enabled)
;
; ====================================================================================

FUN_000056f0:
    ; --- PROLOGUE ---
    ; Create stack frame and save callee-preserve registers

    link.w      A6, #-0x224               ; Allocate 548 bytes for local buffer
                                          ; A6 now points to base of frame
                                          ; Local storage: A6-0x224 to A6-0x04

    movem.l     { A2 D3 D2 }, -(SP)       ; Save A2, D2, D3 (callee-preserved)
                                          ; These registers will be modified
                                          ; SP adjusted by 12 bytes (3 regs × 4)

    ; --- PARAMETER EXTRACTION AND INITIALIZATION ---

    move.l      (0x14,A6), D2             ; D2 = arg4 (size_or_type value)
                                          ; This is the fourth parameter passed by caller
                                          ; Will be used for range validation and library calls

    lea         (-0x224,A6), A2           ; A2 = base address of local buffer
                                          ; Points to bottom of stack frame
                                          ; This buffer will be populated and passed to libraries

    moveq       #0x24, D3                 ; D3 = 0x24 (constant offset)
                                          ; Used later in calculations
                                          ; 36 bytes decimal - likely message header size

    ; --- LOAD GLOBAL CONFIGURATION VALUES ---
    ; Read global variables into frame for use by library functions

    move.l      (0x00007c3c).l, (-0x20c,A6)
                                          ; Read global @ 0x7c3c
                                          ; Store in frame offset -0x20c
                                          ; Unknown purpose: config flag? state? version?

    move.l      (0xc,A6), (-0x208,A6)     ; Copy arg2 (second parameter) to frame
                                          ; Stored at frame offset -0x208
                                          ; Likely configuration or type code

    move.l      (0x00007c40).l, (-0x204,A6)
                                          ; Read global @ 0x7c40
                                          ; Store in frame offset -0x204
                                          ; Second global configuration value

    ; --- RANGE VALIDATION ---
    ; Check if size parameter is within acceptable range (0-512 bytes)

    cmpi.l      #0x200, D2                ; Compare D2 (size) with 0x200 (512 decimal)
                                          ; Sets condition codes based on comparison
                                          ; 0x200 = maximum allowed size

    bhi.b       .error_path               ; Branch if D2 > 0x200 (unsigned)
                                          ; Jump to error handling if size exceeds limit
                                          ; Normal path continues below

    ; --- LIBRARY CALL #1: FORMAT/INITIALIZE MESSAGE ---
    ; First library call to populate/format buffer structure

    move.l      D2, -(SP)                 ; Push arg3: size_or_type value
                                          ; Stack grows downward on 68000
                                          ; This is third argument to library function

    move.l      (0x10,A6), -(SP)          ; Push arg2: third parameter from caller
                                          ; From stack offset 0x10(A6)
                                          ; This is second argument to library function

    pea         (0x24,A2)                 ; Push arg1: effective address (A2 + 0x24)
                                          ; Pushes address of buffer with offset
                                          ; This is first argument to library function

    ; All three parameters now on stack (right-to-left order)
    ; Stack layout (SP points here):
    ;   SP+0: &(A2[0x24])  <- first arg
    ;   SP+4: arg3_value   <- second arg
    ;   SP+8: size_value   <- third arg

    bsr.l       0x0500294e                ; Call library function @ 0x0500294e
                                          ; Likely: memcpy, sprintf, format_message, or init
                                          ; Populates/formats the message buffer
                                          ; Return value in D0 (ignored by caller)

    ; --- BITFIELD INSERTION ---
    ; Insert low 12 bits of size into frame structure

    bfins       D2, (-0x202,A6), 0x0, 0xc
                                          ; Bitfield insert: D2 bits → memory
                                          ; Destination: frame offset -0x202
                                          ; Bit offset: 0 (start at LSB)
                                          ; Bit width: 12 (insert 12 bits)
                                          ; Inserts low 12 bits of size value into structure
                                          ; May be used for message length encoding

    ; --- POINTER ARITHMETIC AND ALIGNMENT ---
    ; Calculate aligned size and store in frame field

    move.l      D2, D0                    ; D0 = D2 (copy size value)
                                          ; Will be modified for alignment calculation

    addq.l      #0x3, D0                  ; D0 += 3 (round up by 3)
                                          ; Adding 3 prepares for 4-byte boundary rounding

    moveq       #-0x4, D1                 ; D1 = 0xFFFFFFFC (alignment mask)
                                          ; -4 in two's complement = 0xFFFFFFFC
                                          ; This masks to 4-byte alignment

    and.l       D1, D0                    ; D0 &= 0xFFFFFFFC (clear low 2 bits)
                                          ; Result: D0 now aligned to 4-byte boundary
                                          ; Example: 100 → 103 → 100 (aligned)
                                          ;          101 → 104 → 104 (aligned)

    ; --- FRAME FIELD INITIALIZATION ---
    ; Set status and control fields in message structure

    move.b      #0x1, (-0x221,A6)         ; Set byte at offset -0x221 to 0x01
                                          ; Likely status flag: enabled=1, disabled=0
                                          ; Single byte storage (not full word)

    add.l       D3, D0                    ; D0 += 0x24 (add header offset)
                                          ; D3 still contains 0x24 from earlier
                                          ; Final value: (aligned_size + 0x24)
                                          ; May represent total message size with header

    move.l      D0, (-0x220,A6)           ; Store calculated value in frame
                                          ; Frame offset -0x220 = offset field
                                          ; Used by library for size/offset information

    clr.l       (-0x21c,A6)               ; Clear 4 bytes at offset -0x21c
                                          ; Zero out frame field
                                          ; Initialization/reset of field

    move.l      (0x8,A6), (-0x214,A6)     ; Copy arg1 to frame offset -0x214
                                          ; arg1 from stack offset 0x8(A6)
                                          ; Likely: source ID, device handle, or message type

    clr.l       (-0x218,A6)               ; Clear 4 bytes at offset -0x218
                                          ; Another field initialization
                                          ; Zero out for unused or reserved field

    moveq       #0x7f, D1                 ; D1 = 0x7f (127 decimal)
                                          ; Constant limit or boundary value
                                          ; May be max count, max level, or max index

    move.l      D1, (-0x210,A6)           ; Store in frame offset -0x210
                                          ; Sets limit/max value in message structure

    ; --- LIBRARY CALL #2: SEND/ROUTE MESSAGE ---
    ; Second library call to send or dispatch the prepared message

    clr.l       -(SP)                     ; Push 0 (third parameter)
                                          ; Zero value - likely NULL or none

    clr.l       -(SP)                     ; Push 0 (second parameter)
                                          ; Zero value - likely NULL or none

    move.l      A2, -(SP)                 ; Push A2 (first parameter)
                                          ; A2 points to base of message buffer
                                          ; Prepared message with all fields initialized

    ; Stack now contains:
    ;   SP+0: A2 (message buffer pointer)   <- first arg
    ;   SP+4: 0                             <- second arg
    ;   SP+8: 0                             <- third arg

    bsr.l       0x050029d2                ; Call library function @ 0x050029d2
                                          ; Likely: mach_msg, send_event, post_rpc, or notify
                                          ; Sends/routes the prepared message
                                          ; Return value in D0 = function result/status

    ; Branch to epilogue (skip error path)
    bra.b       .epilogue                 ; Jump to cleanup and return

; --- ERROR PATH ---
; Reached if size validation fails (D2 > 0x200)

.error_path:
    move.l      #-0x133, D0               ; D0 = -0x133 = -307 (error code)
                                          ; FFFFFFFF FFFFFECD in 32-bit
                                          ; Standard error: size out of range
                                          ; Library calls skipped, return immediately

; --- EPILOGUE ---
; Clean up and return to caller

.epilogue:
    movem.l     (-0x230,A6), { D2 D3 A2 }
                                          ; Restore D2, D3, A2 from stack
                                          ; -0x230(A6) = -0x224 - 12 = address of saved regs
                                          ; Reverses the prologue movem.l

    unlk        A6                        ; Unlink frame pointer
                                          ; Restores previous A6 (caller's frame pointer)
                                          ; Removes stack frame (pops A6, resets SP)

    rts                                   ; Return to caller
                                          ; Pops return address and jumps
                                          ; D0 contains result value

; ====================================================================================
; END OF FUNCTION: FUN_000056f0
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This is a wrapper or callback function that:
; 1. Allocates a 548-byte message structure on the stack
; 2. Validates the size parameter (must be 0-512)
; 3. Loads global configuration values
; 4. Calls first library function to initialize/format message
; 5. Calls second library function to send/route message
; 6. Returns result code from second library call
;
; TYPICAL USAGE PATTERN:
;
;   // Prepare parameters
;   uint32_t result = FUN_000056f0(
;       handle_or_id,     // arg1: resource identifier
;       config_or_type,   // arg2: configuration value
;       data_ptr,         // arg3: pointer to message data
;       size              // arg4: size (must be <= 512)
;   );
;
;   if (result < 0) {
;       // Error from library call
;   } else if (result == -307) {
;       // Size validation error (handled above by function)
;   } else {
;       // Success: message sent/processed
;   }
;
; ERROR HANDLING:
;
;   Size Parameter Validation:
;   ✓ Checked against maximum (0x200 = 512)
;   ✓ Returns -307 if exceeded
;   ✓ No library calls if size invalid
;
;   Other Error Conditions:
;   ? Handled by library functions (0x0500294e, 0x050029d2)
;   ? No explicit NULL pointer checks
;   ? Library functions responsible for parameter validation
;
; OPTIMIZATION NOTES:
;
;   ✓ Uses moveq for small constants (saves instruction bytes)
;   ✓ Direct register arithmetic (no memory access except globals)
;   ✓ Minimal instruction count (35 instructions, 140 bytes)
;   ✓ Straight-line code except for single size-check branch
;   ✗ Large stack frame (548 bytes) - not suitable for recursion
;   ✗ External dependencies - performance depends on library calls
;
; CALLING CONVENTION NOTES:
;
;   m68k System V ABI (NeXTSTEP libsys_s.B.shlib):
;   • Arguments: Pushed right-to-left on stack
;   • Return: D0 register (32-bit signed int)
;   • Preserved: A2-A7, D2-D7 (this function preserves A2, D2, D3)
;   • Clobbered: A0-A1, D0-D1, D4-D6
;
; RELATED ANALYSIS:
;
;   Full 18-section analysis document:
;   docs/functions/0x000056f0_FUN_000056f0_COMPREHENSIVE.md
;
;   Related callback patterns:
;   - FUN_00003eae (140 bytes, 2 external calls, similar pattern)
;   - FUN_00006de4 (136 bytes, likely related handler)
;   - FUN_000061f4 (134 bytes, likely related handler)
;
;   Library functions (needs identification):
;   - 0x0500294e (2 call sites found) - [Identify: memcpy? sprintf? init?]
;   - 0x050029d2 (7 call sites found) - [Identify: mach_msg? send? post?]
;
; ====================================================================================

