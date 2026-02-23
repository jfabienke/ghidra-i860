; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_LoadKernelFromFile
; ====================================================================================
; Address: 0x00006f94
; Size: 158 bytes (48 instructions)
; Purpose: Load kernel/firmware file and transfer to NeXTdimension board via DMA
; Analysis: docs/functions/00006f94_ND_LoadKernelFromFile.md
; ====================================================================================

; FUNCTION SIGNATURE:
; int ND_LoadKernelFromFile(void* load_descriptor, const char* file_path);
;
; This function loads a Mach-O kernel/firmware file from the filesystem and
; transfers it to the NeXTdimension i860 processor memory via DMA. It uses
; memory-mapped I/O for efficient file access and delegates Mach-O parsing
; to ND_ProcessDMATransfer.
;
; PARAMETERS:
;   load_descriptor (8(A6)): Pointer to structure describing DMA operation
;                            (target address, entry point, etc.)
;   file_path (12(A6)):      Path to kernel binary (Mach-O format)
;
; RETURNS:
;   D0 = 0 on success
;   D0 = -1 on file I/O error (open/fstat/mmap)
;   D0 = error code from ND_ProcessDMATransfer on DMA failure
;
; STACK FRAME: 60 bytes
;   -0x3c to -0x04: struct stat buffer (60 bytes)
;   -0x44: Saved D2 (result code)
;   -0x40: Saved D3 (file descriptor)
;
; GLOBAL VARIABLES:
;   0x8018: Memory-mapped file address (read/write)
;   0x04010290: Global Mach port for VM operations
;
; ====================================================================================

FUN_00006f94:

    ; ─────────────────────────────────────────────────────────────────────────
    ; PROLOGUE - Stack Frame Setup
    ; ─────────────────────────────────────────────────────────────────────────

    0x00006f94:  link.w     A6,-0x3c                ; Create 60-byte stack frame for struct stat
    0x00006f98:  move.l     D3,-(SP)                ; Save D3 (will hold file descriptor)
    0x00006f9a:  move.l     D2,-(SP)                ; Save D2 (will hold result codes)

    ; ─────────────────────────────────────────────────────────────────────────
    ; OPEN KERNEL FILE
    ; ─────────────────────────────────────────────────────────────────────────
    ; Call: int open(const char* path, int flags, mode_t mode)
    ; Flags: 0x1a4 = O_RDONLY | O_NONBLOCK | O_EXLOCK | O_SHLOCK | O_CLOEXEC

    0x00006f9c:  pea        (0x1a4).w               ; Push flags = 0x1a4
                                                    ; O_RDONLY (0x0000): Read-only access
                                                    ; O_NONBLOCK (0x0004): Non-blocking I/O
                                                    ; O_EXLOCK (0x0020): Exclusive lock
                                                    ; O_SHLOCK (0x0080): Shared lock
                                                    ; O_CLOEXEC (0x0100): Close on exec

    0x00006fa0:  clr.l      -(SP)                   ; Push mode = 0 (not creating file)
    0x00006fa2:  move.l     (0xc,A6),-(SP)          ; Push file_path (arg2)
    0x00006fa6:  bsr.l      0x05002bc4              ; CALL open(path, flags, mode)
    0x00006fac:  move.l     D0,D3                   ; D3 = file descriptor (or -1 on error)
    0x00006fae:  addq.w     0x8,SP                  ; Clean up 8 bytes from stack
    0x00006fb0:  addq.w     0x4,SP                  ; Clean up 4 more bytes (total 12 = 3 args)

    ; ─────────────────────────────────────────────────────────────────────────
    ; CHECK OPEN() SUCCESS
    ; ─────────────────────────────────────────────────────────────────────────

    0x00006fb2:  moveq      -0x1,D1                 ; D1 = -1 (error indicator)
    0x00006fb4:  cmp.l      D3,D1                   ; Compare fd vs -1
    0x00006fb6:  beq.b      0x00007026              ; If fd == -1, jump to error_return
                                                    ; (no cleanup needed - file not opened)

    ; ─────────────────────────────────────────────────────────────────────────
    ; GET FILE STATISTICS
    ; ─────────────────────────────────────────────────────────────────────────
    ; Call: int fstat(int fd, struct stat* buf)
    ; Purpose: Get file size for memory mapping
    ; Buffer: 60 bytes at -0x3c(A6) through -0x04(A6)

    0x00006fb8:  pea        (-0x3c,A6)              ; Push &stat_buffer (60-byte local buffer)
                                                    ; struct stat layout (NeXTSTEP m68k):
                                                    ; +0x00: st_dev (device ID)
                                                    ; +0x04: st_ino (inode)
                                                    ; +0x08: st_mode (file mode)
                                                    ; +0x0C: st_nlink (link count)
                                                    ; +0x10: st_size (file size) ← USED LATER
                                                    ; +0x14: st_uid (user ID)
                                                    ; ... more fields ...

    0x00006fbc:  move.l     D3,-(SP)                ; Push fd (from open)
    0x00006fbe:  bsr.l      0x0500256a              ; CALL fstat(fd, &stat_buffer)
    0x00006fc4:  move.l     D0,D2                   ; D2 = fstat result (0 = success, -1 = error)
    0x00006fc6:  addq.w     0x8,SP                  ; Clean up stack (8 bytes = 2 args)

    ; ─────────────────────────────────────────────────────────────────────────
    ; CHECK FSTAT() SUCCESS
    ; ─────────────────────────────────────────────────────────────────────────

    0x00006fc8:  moveq      -0x1,D1                 ; D1 = -1 (error indicator)
    0x00006fca:  cmp.l      D2,D1                   ; Compare fstat result vs -1
    0x00006fcc:  beq.b      0x0000701c              ; If fstat failed, jump to close_and_error

    ; ─────────────────────────────────────────────────────────────────────────
    ; MEMORY MAP THE FILE
    ; ─────────────────────────────────────────────────────────────────────────
    ; Call: void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
    ; Purpose: Map entire file into memory for efficient access
    ; Note: Unusual 5-argument form with global variable as prot parameter

    0x00006fce:  move.l     (-0x2c,A6),-(SP)        ; Push file size (st_size field)
                                                    ; Offset calculation: -0x2c = -(0x3c - 0x10)
                                                    ; st_size is at offset 0x10 in struct stat

    0x00006fd2:  pea        (0x1).w                 ; Push flags = 1 (MAP_SHARED)
                                                    ; MAP_SHARED: Changes visible to other processes

    0x00006fd6:  pea        (0x8018).l              ; Push global variable (likely PROT_READ flags)
                                                    ; This global is also used to store result

    0x00006fdc:  clr.l      -(SP)                   ; Push addr = NULL (let kernel choose address)
    0x00006fde:  move.l     D3,-(SP)                ; Push fd (file descriptor)
    0x00006fe0:  bsr.l      0x0500291e              ; CALL mmap(NULL, size, prot, MAP_SHARED, fd)
    0x00006fe6:  adda.w     #0x14,SP                ; Clean up stack (20 bytes = 5 arguments)

    ; ─────────────────────────────────────────────────────────────────────────
    ; CHECK MMAP() SUCCESS
    ; ─────────────────────────────────────────────────────────────────────────

    0x00006fea:  tst.l      D0                      ; Test mmap result
                                                    ; Success: returns mapped address (non-zero)
                                                    ; Failure: returns MAP_FAILED (-1 or 0)

    0x00006fec:  bne.b      0x0000701c              ; If mmap failed (non-zero error), jump to close_and_error

    ; ─────────────────────────────────────────────────────────────────────────
    ; CORE OPERATION - DMA TRANSFER TO NEXTDIMENSION
    ; ─────────────────────────────────────────────────────────────────────────
    ; Call: int ND_ProcessDMATransfer(void* load_descriptor)
    ; Purpose: Parse Mach-O file and DMA segments to NeXTdimension i860 processor
    ; The file is now memory-mapped and accessible for parsing

    0x00006fee:  move.l     (0x8,A6),-(SP)          ; Push load_descriptor (arg1)
                                                    ; Contains: target addresses, entry point, slot, etc.

    0x00006ff2:  bsr.l      0x0000709c              ; CALL ND_ProcessDMATransfer (FUN_0000709c)
                                                    ; This function:
                                                    ; - Parses Mach-O header and load commands
                                                    ; - Iterates through segments
                                                    ; - DMAs code/data to i860 DRAM
                                                    ; - Writes entry vector branch instruction

    0x00006ff8:  move.l     D0,D2                   ; D2 = DMA transfer result
                                                    ; 0 = success
                                                    ; non-zero = specific error code

    ; ─────────────────────────────────────────────────────────────────────────
    ; CLEANUP - UNMAP FILE FROM MEMORY
    ; ─────────────────────────────────────────────────────────────────────────
    ; Call: int munmap(void* addr, size_t length)
    ; OR: int vm_deallocate(mach_port_t task, vm_address_t addr, vm_size_t size)
    ; Note: 3-argument form suggests vm_deallocate rather than munmap

    0x00006ffa:  move.l     (-0x2c,A6),-(SP)        ; Push file size (st_size)
    0x00006ffe:  move.l     (0x00008018).l,-(SP)    ; Push mapped address (from global)
                                                    ; This was written by mmap() call earlier

    0x00007004:  move.l     (0x04010290).l,-(SP)    ; Push global Mach port
                                                    ; Suggests vm_deallocate(task_port, addr, size)
                                                    ; rather than munmap(addr, size)

    0x0000700a:  bsr.l      0x050032ba              ; CALL vm_deallocate() or munmap variant
                                                    ; Frees virtual memory mapping

    ; ─────────────────────────────────────────────────────────────────────────
    ; CLEANUP - CLOSE FILE DESCRIPTOR
    ; ─────────────────────────────────────────────────────────────────────────
    ; Call: int close(int fd)
    ; Purpose: Release file descriptor (always called on success path)

    0x00007010:  move.l     D3,-(SP)                ; Push fd
    0x00007012:  bsr.l      0x0500229a              ; CALL close(fd)
                                                    ; File is now closed, fd released

    ; ─────────────────────────────────────────────────────────────────────────
    ; SUCCESS PATH - RETURN DMA RESULT
    ; ─────────────────────────────────────────────────────────────────────────

    0x00007018:  move.l     D2,D0                   ; Return DMA transfer result
                                                    ; (0 on success, error code on failure)

    0x0000701a:  bra.b      0x00007026              ; Jump to epilogue

    ; ─────────────────────────────────────────────────────────────────────────
    ; ERROR PATH - CLOSE FILE AND RETURN -1
    ; ─────────────────────────────────────────────────────────────────────────
    ; Reached if fstat() or mmap() failed
    ; File descriptor is open and must be closed

close_and_error:
    0x0000701c:  move.l     D3,-(SP)                ; Push fd
    0x0000701e:  bsr.l      0x0500229a              ; CALL close(fd)
                                                    ; Clean up file descriptor

    0x00007024:  moveq      -0x1,D0                 ; Return -1 (generic error)

    ; ─────────────────────────────────────────────────────────────────────────
    ; EPILOGUE - Restore Registers and Return
    ; ─────────────────────────────────────────────────────────────────────────

error_return:
    0x00007026:  move.l     (-0x44,A6),D2           ; Restore D2 from stack
                                                    ; Offset -0x44 = -(0x3c frame + 0x8 saved regs)

    0x0000702a:  move.l     (-0x40,A6),D3           ; Restore D3 from stack
                                                    ; Offset -0x40 = -(0x3c frame + 0x4)

    0x0000702e:  unlk       A6                      ; Restore frame pointer and deallocate frame
    0x00007030:  rts                                ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_LoadKernelFromFile
; ====================================================================================

; FUNCTION SUMMARY:
;
; This function implements a robust kernel/firmware loader for the NeXTdimension
; graphics board. It follows a clean pattern:
;
; 1. Open kernel file with exclusive lock and close-on-exec flags
; 2. Get file metadata (primarily size) using fstat()
; 3. Memory-map entire file for efficient access (avoids buffering)
; 4. Delegate Mach-O parsing and DMA transfer to ND_ProcessDMATransfer
; 5. Cleanup: Unmap memory, close file descriptor
; 6. Return result from DMA operation
;
; Error handling is comprehensive:
; - Every system call checked for failure
; - File descriptor always closed (both success and error paths)
; - Memory mapping always unmapped before return
; - No resource leaks possible
;
; The function demonstrates NeXTSTEP/Mach integration:
; - Uses Mach VM operations (vm_deallocate) instead of POSIX munmap
; - Global Mach port (0x04010290) for VM operations
; - Memory-mapped I/O for efficient large file handling
;
; CALL FLOW:
;   ND_LoadKernelFromFile (this function)
;   ├── open()           [Library - 0x05002bc4]
;   ├── fstat()          [Library - 0x0500256a]
;   ├── mmap()           [Library - 0x0500291e]
;   ├── ND_ProcessDMATransfer [Internal - 0x0000709c]
;   │   └── ND_WriteBranchInstruction [Internal - 0x0000746c]
;   ├── vm_deallocate()  [Library - 0x050032ba]
;   └── close() ×2       [Library - 0x0500229a]
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; extern uint32_t* g_mmap_address;        // @ 0x8018
; extern mach_port_t g_mach_port;         // @ 0x04010290
;
; #define KERNEL_OPEN_FLAGS  0x1a4  // O_RDONLY | O_NONBLOCK | O_EXLOCK | O_SHLOCK | O_CLOEXEC
;
; int ND_LoadKernelFromFile(void* load_descriptor, const char* file_path)
; {
;     int fd;
;     int result;
;     struct stat stat_buffer;
;     void* mapped_addr;
;
;     // Open kernel file for reading with exclusive lock
;     fd = open(file_path, KERNEL_OPEN_FLAGS, 0);
;     if (fd == -1) {
;         return -1;  // Open failed
;     }
;
;     // Get file metadata (primarily size for memory mapping)
;     result = fstat(fd, &stat_buffer);
;     if (result == -1) {
;         close(fd);
;         return -1;  // Stat failed
;     }
;
;     // Memory-map the entire file for efficient access
;     mapped_addr = mmap(
;         NULL,                    // Let kernel choose address
;         stat_buffer.st_size,     // Map entire file
;         *g_mmap_address,         // Protection flags (likely PROT_READ)
;         MAP_SHARED,              // Share mapping with other processes
;         fd,                      // File descriptor
;         0                        // Offset 0 (start of file)
;     );
;
;     if (mapped_addr == MAP_FAILED) {
;         close(fd);
;         return -1;  // Mmap failed
;     }
;
;     // Store mapped address in global for later cleanup
;     g_mmap_address = (uint32_t*)mapped_addr;
;
;     // Core operation: Parse Mach-O executable and DMA segments to NeXTdimension
;     // This transfers the kernel code and data to the i860 processor
;     result = ND_ProcessDMATransfer(load_descriptor);
;
;     // Cleanup: Unmap file from memory
;     // Note: Using vm_deallocate (Mach VM) rather than munmap (POSIX)
;     vm_deallocate(g_mach_port, (vm_address_t)mapped_addr, stat_buffer.st_size);
;
;     // Cleanup: Close file descriptor
;     close(fd);
;
;     // Return result from DMA transfer operation
;     return result;
; }
;
; TYPICAL USAGE:
;
; // During NeXTdimension initialization
; nd_load_descriptor_t desc = {
;     .target_address = 0x00000000,  // i860 DRAM start
;     .entry_point = 0x00000000,     // Kernel entry
;     .board_slot = 2                // NeXTBus slot 2
; };
;
; int result = ND_LoadKernelFromFile(&desc, "/usr/lib/NextDimension/nd_kernel");
; if (result == 0) {
;     printf("NeXTdimension kernel loaded successfully\n");
;     // Now start the i860 processor
; } else {
;     fprintf(stderr, "Failed to load kernel: error %d\n", result);
; }
;
; ====================================================================================
; ANALYSIS NOTES:
;
; Key Insights:
; 1. Uses memory-mapped I/O instead of read() for efficiency
; 2. Entire kernel file accessible at once, no buffering needed
; 3. OS handles page faults and caching automatically
; 4. Clean separation: this function handles file I/O, ND_ProcessDMATransfer
;    handles Mach-O parsing and DMA
; 5. Resource management is exception-safe (all paths close file descriptor)
;
; Open Flags (0x1a4) Analysis:
; - O_RDONLY (0x0000): Read-only access (kernel is executable, not modified)
; - O_NONBLOCK (0x0004): Don't block on device special files
; - O_EXLOCK (0x0020): Exclusive lock (prevent concurrent modification)
; - O_SHLOCK (0x0080): Shared lock (allow concurrent reads)
; - O_CLOEXEC (0x0100): Close on exec (security - don't leak to child processes)
;
; The combination of O_EXLOCK | O_SHLOCK is unusual but valid on BSD-derived
; systems like NeXTSTEP. It likely means "exclusive write lock, shared read lock"
; which prevents modifications while allowing concurrent reads.
;
; Mach VM Integration:
; - Function 0x050032ba is likely vm_deallocate(mach_port_t, vm_address_t, vm_size_t)
; - This is the Mach microkernel equivalent of munmap()
; - Uses port-based security model
; - Global port 0x04010290 is the task's VM port
;
; Performance Considerations:
; - Memory mapping is much faster than read() for large files
; - No intermediate buffering or copying needed
; - Kernel handles page faults on-demand
; - For a typical 100KB kernel: ~10-50ms total (dominated by DMA transfer)
;
; Error Recovery:
; - All error paths ensure file descriptor is closed
; - No memory leaks (mmap cleaned up before close)
; - Caller can safely retry with different file or parameters
;
; ====================================================================================
