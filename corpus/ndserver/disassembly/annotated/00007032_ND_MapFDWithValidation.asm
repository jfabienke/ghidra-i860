; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MapFDWithValidation
; ====================================================================================
; Address: 0x00007032
; Size: 64 bytes (18 instructions)
; Purpose: Map file descriptor into memory and validate/process the result
; Analysis: docs/functions/00007032_ND_MapFDWithValidation.md
; ====================================================================================
;
; FUNCTION SIGNATURE:
;   int ND_MapFDWithValidation(
;       void*  board_info,       // +8(A6)  - NeXTdimension board structure
;       int    file_descriptor,  // +12(A6) - FD of firmware/kernel file
;       void*  map_address,      // +16(A6) - Reserved (not currently used)
;       size_t map_size,         // +20(A6) - Size to map
;       int    map_flags         // +24(A6) - VM protection flags
;   );
;
; DESCRIPTION:
;   This function maps a file descriptor into memory using the Mach map_fd() system
;   call, stores the resulting pointer in a global variable, and then processes the
;   mapped data through FUN_0000709c (ND_ProcessDMATransfer). This is a critical
;   component in the firmware/kernel loading pipeline for NeXTdimension boards.
;
;   The function performs two main operations:
;   1. Call map_fd() to map the file into VM space
;   2. If successful, validate and process the mapped Mach-O data
;
; PARAMETERS:
;   board_info (8(A6)):       Pointer to nd_board_info structure
;   file_descriptor (12(A6)): File descriptor from open() or fdopen()
;   map_address (16(A6)):     Reserved for future use (NOT currently used)
;   map_size (20(A6)):        Number of bytes to map from file
;   map_flags (24(A6)):       Mapping flags (e.g., VM_PROT_READ)
;
; RETURNS:
;   D0 = 0:     Success (mapping and processing completed)
;   D0 = -1:    Mapping failed (error code 8 stored in global_last_error)
;   D0 = other: Processing failed (error code from ND_ProcessDMATransfer)
;
; STACK FRAME: 4 bytes
;   -4(A6): void* mapped_ptr - Output parameter from map_fd()
;
; GLOBAL VARIABLES:
;   0x00008018:   global_mapped_ptr  - Stores result of mapping for other functions
;   0x040105b0:   global_last_error  - Error code storage (runtime memory)
;
; CALLS:
;   0x05002708:   map_fd() - Mach system call to map file descriptor
;   0x0000709c:   ND_ProcessDMATransfer() - Parse and validate mapped data
;
; ====================================================================================

FUN_00007032:
ND_MapFDWithValidation:

    ; --- PROLOGUE ---
    ; Create stack frame with space for one local variable (mapped_ptr)
    0x00007032:  link.w     A6,-0x4                       ; Frame: 4 bytes for local mapped_ptr

    ; --- PREPARE LIBRARY CALL PARAMETERS ---
    ; The library function map_fd() appears to have signature:
    ;   kern_return_t map_fd(int fd, size_t size, int flags, void** result)
    ;
    ; Parameters are pushed right-to-left per m68k ABI:

    0x00007036:  pea        (-0x4,A6)                     ; Arg 5: &mapped_ptr (output parameter)
    0x0000703a:  move.l     (0x14,A6),-(SP)               ; Arg 4: map_flags (VM_PROT_READ, etc.)
    0x0000703e:  move.l     (0x10,A6),-(SP)               ; Arg 3: map_size (bytes to map)
    0x00007042:  move.l     (0xc,A6),-(SP)                ; Arg 2: file_descriptor (from open())

    ; NOTE: map_address at 0x10(A6) is NOT pushed. It appears reserved for future
    ; use but is not currently part of the library call interface.

    ; --- CALL MACH map_fd() SYSTEM CALL ---
    ; Maps the file descriptor into virtual memory. The library call will:
    ; - Allocate VM space (or use provided address)
    ; - Map file contents into that space
    ; - Return pointer via output parameter
    ; - Return error code in D0 (0 = success, non-zero = error)

    0x00007046:  bsr.l      0x05002708                    ; CALL map_fd(fd, size, flags, &result)
                                                          ; Returns: D0 = kern_return_t
                                                          ; Writes:  mapped_ptr at -4(A6)

    ; --- STORE RESULT IN GLOBAL VARIABLE ---
    ; The mapped pointer (or error code) is stored in a global variable that
    ; other functions (FUN_0000709c, FUN_00007072) will access to read the
    ; mapped Mach-O file data.

    0x0000704c:  move.l     D0,(0x00008018).l             ; global_mapped_ptr = result
                                                          ; Side effect: Sets Z flag if D0 == 0
                                                          ; (Used by subsequent beq instruction)

    ; --- CLEAN UP STACK ---
    ; Remove the 5 parameters (20 bytes total) pushed before the library call.
    ; These addq.w instructions modify SP but do NOT affect condition codes,
    ; so the Z flag from the previous move.l is preserved.

    0x00007052:  addq.w     0x8,SP                        ; Remove 8 bytes (2 params)
    0x00007054:  addq.w     0x8,SP                        ; Remove 8 bytes (2 params)
                                                          ; Total: 16 bytes removed
                                                          ; Remaining: 4 bytes (output ptr) cleaned by RTS

    ; --- CHECK FOR MAPPING ERROR ---
    ; Test if the mapping succeeded. The Z flag was set by the move.l at 0x704c.
    ; Z=1 (D0 was 0) means NULL pointer, indicating mapping failure.
    ; Z=0 (D0 non-zero) means valid pointer, indicating success.

    0x00007056:  beq.b      mapping_failed                ; Branch if D0 == 0 (mapping failed)

    ; --- SUCCESS PATH: PROCESS MAPPED DATA ---
    ; The file was successfully mapped into memory. Now call the processing
    ; function to validate the Mach-O format, parse segments, and setup DMA
    ; transfers to the i860 board.

mapping_succeeded:
    0x00007058:  move.l     (0x8,A6),-(SP)                ; Push board_info parameter
    0x0000705c:  bsr.l      0x0000709c                     ; CALL ND_ProcessDMATransfer(board_info)
                                                          ; This function:
                                                          ; - Validates Mach-O magic number
                                                          ; - Parses segment load commands
                                                          ; - Translates host→i860 addresses
                                                          ; - Sets up DMA descriptors
                                                          ; Returns: 0 on success, error code on failure
    0x00007062:  bra.b      exit_function                 ; Return with D0 from processing function

    ; --- ERROR PATH: MAPPING FAILED ---
    ; The map_fd() call returned NULL, indicating the file could not be mapped.
    ; Set error code 8 (mapping failure) and return -1 to caller.

mapping_failed:
    0x00007064:  moveq      0x8,D1                        ; D1 = 8 (ND_ERROR_MAPPING_FAILED)
    0x00007066:  move.l     D1,(0x040105b0).l             ; global_last_error = 8
                                                          ; This is in runtime memory region,
                                                          ; possibly a Mach message structure

    0x0000706c:  moveq      -0x1,D0                       ; D0 = -1 (generic failure code)
                                                          ; Caller should check global_last_error
                                                          ; for specific error details

    ; --- EPILOGUE ---
    ; Restore stack frame and return to caller.
    ; Return value in D0:
    ;   -1  = Mapping failed (check global_last_error)
    ;   0   = Complete success
    ;   >0  = Processing error (from ND_ProcessDMATransfer)

exit_function:
    0x0000706e:  unlk       A6                            ; Restore frame pointer
    0x00007070:  rts                                      ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MapFDWithValidation
; ====================================================================================
;
; FUNCTION SUMMARY:
;   This is a critical wrapper function in the NeXTdimension firmware loading
;   pipeline. It combines Mach memory mapping with data validation, providing
;   a clean interface for loading and processing firmware/kernel files.
;
;   Key design points:
;   1. Uses Mach map_fd() for efficient file-backed memory mapping
;   2. Stores mapped pointer in global variable for cross-function access
;   3. Delegates complex validation to ND_ProcessDMATransfer
;   4. Clear error handling with specific error code (8) for mapping failures
;   5. Minimal overhead (only 64 bytes, no register preservation)
;
; CONTROL FLOW:
;   START
;     |
;     v
;   [Call map_fd()]
;     |
;     v
;   [Store result in global]
;     |
;     v
;   {Check if NULL?}
;     |
;     +--YES--> [Set error 8, return -1]
;     |
;     NO
;     |
;     v
;   [Call ND_ProcessDMATransfer]
;     |
;     v
;   RETURN result
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; // Global variables
; extern void*   global_mapped_ptr;     // @ 0x8018
; extern int32_t global_last_error;     // @ 0x040105b0
;
; // External functions
; extern kern_return_t map_fd(int fd, size_t size, int flags, void** result);
; extern int ND_ProcessDMATransfer(void* board_info);
;
; int ND_MapFDWithValidation(
;     void*  board_info,
;     int    file_descriptor,
;     void*  map_address,       // Reserved for future use
;     size_t map_size,
;     int    map_flags)
; {
;     void* mapped_ptr = NULL;
;     kern_return_t kr;
;
;     // Map file descriptor into memory
;     kr = map_fd(file_descriptor, map_size, map_flags, &mapped_ptr);
;
;     // Store result in global variable for other functions to access
;     global_mapped_ptr = (void*)(uintptr_t)kr;
;
;     // Check if mapping succeeded
;     if (kr == KERN_SUCCESS) {
;         // Success - process the mapped firmware/kernel data
;         return ND_ProcessDMATransfer(board_info);
;     } else {
;         // Failure - set error code and return -1
;         global_last_error = 8;  // ND_ERROR_MAPPING_FAILED
;         return -1;
;     }
; }
;
; ====================================================================================
; USAGE EXAMPLE:
;
; // Load NeXTdimension i860 kernel
; int fd = open("/usr/lib/NextDimension/nd_i860.kernel", O_RDONLY);
; if (fd < 0) {
;     perror("Failed to open kernel");
;     return -1;
; }
;
; struct stat st;
; fstat(fd, &st);
;
; int result = ND_MapFDWithValidation(
;     board_info,
;     fd,
;     NULL,              // Reserved parameter
;     st.st_size,        // Map entire file
;     VM_PROT_READ       // Read-only mapping
; );
;
; close(fd);
;
; if (result == -1) {
;     fprintf(stderr, "Mapping failed: error code %d\n", global_last_error);
; } else if (result != 0) {
;     fprintf(stderr, "Processing failed: error code %d\n", result);
; } else {
;     printf("Firmware loaded successfully\n");
; }
;
; ====================================================================================
; RELATED FUNCTIONS:
;
;   FUN_00005af6: Caller (unknown purpose - needs analysis)
;   FUN_0000709c: ND_ProcessDMATransfer (976 bytes, previously analyzed)
;   FUN_00007072: Sibling function (also writes to global_mapped_ptr)
;
; ====================================================================================
; NOTES:
;
; 1. The map_address parameter (16(A6)) is currently unused but reserved in the
;    stack layout, suggesting future enhancement for explicit address control.
;
; 2. Error code 8 specifically indicates mapping failure. Other error codes
;    returned from ND_ProcessDMATransfer indicate validation/processing failures.
;
; 3. The global variable pattern allows multiple functions to access the mapped
;    file without passing pointers through deep call chains. This is a common
;    pattern in NeXTSTEP driver code.
;
; 4. The function assumes the caller will close the file descriptor. The mapping
;    persists independently of the FD after map_fd() returns.
;
; 5. Condition codes are cleverly preserved across stack cleanup operations,
;    allowing the error check to work correctly despite intervening addq.w
;    instructions.
;
; ====================================================================================
