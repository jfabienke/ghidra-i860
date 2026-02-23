; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_URLFileDescriptorOpen
; ====================================================================================
; Address: 0x00006474
; Size: 164 bytes (~41 instructions)
; Purpose: Parse URL/path and open file descriptor with port parameter
; Analysis: docs/functions/00006474_ND_URLFileDescriptorOpen.md
; ====================================================================================

; FUNCTION: int ND_URLFileDescriptorOpen(const char* url_or_path, const char* mode_or_flags)
;
; Parses a URL or file path containing a port specification (e.g., "/dev/nd0:2"),
; extracts the port number, and opens a file descriptor using that port.
; Implements dual open strategy: fdopen first, then file open fallback.
;
; PARAMETERS:
;   url_or_path (D3):   URL or file path string (loaded from A6+0x8)
;   mode_or_flags (D2): Mode string or flags (loaded from A6+0xC)
;
; RETURNS:
;   D0: File descriptor (port_number) on success, 0 on error
;
; STACK FRAME: 4 bytes
;   -0x4: port_number (extracted from URL)
;
; CALLS:
;   FUN_00004a52 - URL/path parser (sscanf-like)
;   0x0500315e - atoi/strtol
;   0x05002c54 - fdopen/socket
;   FUN_00005256 - Alternative file open
;   0x050028c4 - printf (error logging)
;   0x05002c5a - fclose/cleanup
;
; ====================================================================================

FUN_00006474:
    ; --- PROLOGUE ---
    link.w      A6, #-0x4                 ; Create 4-byte stack frame for port_number
    move.l      D3, -(SP)                 ; Save D3 (parameter register, callee-save)
    move.l      D2, -(SP)                 ; Save D2 (parameter register, callee-save)

    ; --- LOAD PARAMETERS FROM STACK INTO DATA REGISTERS ---
    move.l      (0x8,A6), D3              ; D3 = url_or_path (first parameter)
    move.l      (0xc,A6), D2              ; D2 = mode_or_flags (second parameter)

    ; --- PARSE URL/PATH TO EXTRACT PORT NUMBER ---
    ; Call signature: FUN_00004a52(url, mode, format, &port_number)
    pea         (-0x4,A6)                 ; Push &port_number (output parameter)
                                           ; Address of local variable on stack
    pea         (0x79f6).l                ; Push format_string address
                                           ; Format defines parsing pattern (e.g., "%*[^:]:%d")
    move.l      D2, -(SP)                 ; Push mode_or_flags
    move.l      D3, -(SP)                 ; Push url_or_path
    bsr.l       0x00004a52                ; result = FUN_00004a52(url, mode, fmt, &port)
                                           ; Likely: sscanf(url, fmt, &port)
                                           ; Parses URL like "/dev/nd0:1234" → port=1234
    addq.w      #0x8, SP                  ; Clean up 2 arguments (8 bytes)
    addq.w      #0x8, SP                  ; Clean up 2 more arguments (8 bytes)
                                           ; Total: 4 args cleaned (16 bytes)

    ; --- CHECK PARSE RESULT ---
    tst.l       D0                        ; Test parse result
    beq.b       .LAB_0000650a             ; if (result == 0) goto error_return_zero
                                           ; Parse failed (invalid URL format)

    ; --- CONVERT PORT STRING TO INTEGER AND OPEN FD ---
    ; Fast path: Try fdopen/socket with converted port
    pea         (-0x4,A6)                 ; Push &port_number
    bsr.l       0x0500315e                ; D0 = atoi(&port_number)
                                           ; Converts string like "1234" to int 1234
                                           ; Or: strtol(&port_number, NULL, 10)
    move.l      D0, -(SP)                 ; Push converted_port (integer)
    bsr.l       0x05002c54                ; result = fdopen_or_socket(converted_port)
                                           ; Attempts to open FD from port number
                                           ; May be: fdopen(port, mode) or socket operations
    addq.w      #0x8, SP                  ; Clean up 2 arguments (8 bytes)

    ; --- CHECK FDOPEN RESULT ---
    tst.l       D0                        ; Test fdopen result
    beq.b       .LAB_000064c8             ; if (result == 0) goto retry_with_file_open
                                           ; fdopen succeeded, try alternative method

    ; fdopen returned non-zero (error code)
    move.l      D0, -(SP)                 ; Push error_code
    pea         (0x79fb).l                ; Push error_format_string_1
    bsr.l       0x050028c4                ; printf(error_format_1, error_code)
                                           ; Log fdopen failure
    bra.b       .LAB_0000650a             ; goto error_return_zero

    ; --- RETRY WITH ALTERNATIVE FILE OPEN METHOD ---
.LAB_000064c8:
    ; Call signature: FUN_00005256(url, mode, format, port_number)
    move.l      (-0x4,A6), -(SP)          ; Push port_number (from local variable)
    pea         (0x79f6).l                ; Push format_string (same as parse step)
    move.l      D2, -(SP)                 ; Push mode_or_flags
    move.l      D3, -(SP)                 ; Push url_or_path
    bsr.l       0x00005256                ; result = FUN_00005256(url, mode, fmt, port)
                                           ; Alternative open: constructs device path and calls open()
                                           ; E.g., opens "/dev/nd0" with port=2 parameter
    addq.w      #0x8, SP                  ; Clean up 2 arguments (8 bytes)
    addq.w      #0x8, SP                  ; Clean up 2 more arguments (8 bytes)
                                           ; Total: 4 args cleaned (16 bytes)

    ; --- CHECK FILE OPEN RESULT ---
    tst.l       D0                        ; Test file open result
    bne.b       .LAB_000064ea             ; if (result != 0) goto file_open_failed
                                           ; Non-zero = error

    ; Success path: file opened successfully
    move.l      (-0x4,A6), D0             ; D0 = port_number (return value)
                                           ; Return port as file descriptor handle
    bra.b       .LAB_0000650c             ; goto epilogue

    ; --- FILE OPEN FAILED - LOG ERROR AND CLEANUP ---
.LAB_000064ea:
    ; Log the error
    move.l      D0, -(SP)                 ; Push error_code (from FUN_00005256)
    pea         (0x7a1b).l                ; Push error_format_string_2
    bsr.l       0x050028c4                ; printf(error_format_2, error_code)
                                           ; Log file open failure

    ; Cleanup: close any partially opened resources
    move.l      (-0x4,A6), -(SP)          ; Push port_number
    bsr.l       0x0500315e                ; D0 = atoi(&port_number)
                                           ; Convert port back to int (seems redundant?)
    move.l      D0, -(SP)                 ; Push fd_to_close
    bsr.l       0x05002c5a                ; fclose_or_cleanup(fd)
                                           ; Close file descriptor on error
                                           ; Prevents resource leak

    ; Fall through to error_return_zero

    ; --- ERROR RETURN PATH ---
.LAB_0000650a:
    clr.l       D0                        ; D0 = 0 (FAILURE return value)

    ; --- EPILOGUE ---
.LAB_0000650c:
    move.l      (-0xc,A6), D2             ; Restore D2 from stack
                                           ; Offset: -0xC = -4 (frame) - 8 (D3+D2 saved)
    move.l      (-0x8,A6), D3             ; Restore D3 from stack
    unlk        A6                        ; Restore frame pointer, deallocate locals
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_URLFileDescriptorOpen
; ====================================================================================
;
; FUNCTION SUMMARY:
;
; This function implements a robust URL/file opening strategy:
;   1. Parse URL to extract port number (e.g., "/dev/nd0:2" → port=2)
;   2. Try fast path: fdopen/socket with port number
;   3. If that fails, try alternative: file open with constructed path
;   4. Return port number as FD handle on success, 0 on error
;
; Error handling:
;   - Parse failure: Immediate return 0 (no cleanup needed)
;   - fdopen failure: Log error, return 0
;   - File open failure: Log error, cleanup resources, return 0
;
; INTEGRATION WITH NEXTDIMENSION:
;
; This function likely opens communication channels to the NeXTdimension board:
;   - Device file: /dev/nd0:2 (slot 2)
;   - Mach port: mach:1234
;   - Network socket: localhost:5000 (for remote/emulated boards)
;
; The dual-strategy approach provides flexibility:
;   - fdopen: For existing file descriptors or sockets
;   - FUN_00005256: For device special files requiring custom open logic
;
; The port number is returned as the FD, suggesting:
;   - Mach port numbers are used as handles
;   - Or port indexes into an FD table maintained elsewhere
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; int ND_URLFileDescriptorOpen(const char* url_or_path, const char* mode_or_flags)
; {
;     int port_number;
;     int result;
;
;     // Parse URL to extract port
;     result = FUN_00004a52(url_or_path, mode_or_flags,
;                           format_0x79f6, &port_number);
;     if (result == 0) {
;         return 0;  // Parse failed
;     }
;
;     // Try fdopen first
;     result = fdopen_or_socket(atoi(&port_number));
;     if (result != 0) {
;         printf(error_fmt_0x79fb, result);
;         return 0;
;     }
;
;     // Fallback to file open
;     result = FUN_00005256(url_or_path, mode_or_flags,
;                           format_0x79f6, port_number);
;     if (result != 0) {
;         printf(error_fmt_0x7a1b, result);
;         fclose_or_cleanup(atoi(&port_number));
;         return 0;
;     }
;
;     return port_number;  // Success
; }
;
; ====================================================================================
