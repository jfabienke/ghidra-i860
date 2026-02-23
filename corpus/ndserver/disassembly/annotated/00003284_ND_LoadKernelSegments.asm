; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_LoadKernelSegments
; ====================================================================================
; Address: 0x00003284
; Size: 912 bytes (0x390)
; Purpose: Load kernel segments into NeXTdimension i860 memory with address translation
; Analysis: docs/functions/00003284_ND_LoadKernelSegments.md
; ====================================================================================

; FUNCTION: int32_t ND_LoadKernelSegments(char* url_or_path, uint32_t slot_number, void* result_ptr)
;
; This function orchestrates the loading of kernel segments (likely from Mach-O format) into the
; NeXTdimension i860 processor's memory space. It performs parameter validation, segment descriptor
; parsing, address translation, and batch loading of up to 4 segments.
;
; PARAMETERS:
;   url_or_path (0x8,A6): String containing URL or path with port information
;   slot_number (0xC,A6): NeXTdimension board slot number (0-15)
;   result_ptr (0x10,A6): Pointer to result structure for output
;
; RETURNS:
;   D0: 0 on success, non-zero error code on failure
;
; STACK FRAME: 64 bytes (0x40)
;   -0x40: local_file_handle (file descriptor or handle)
;   -0x3C: local_fd (file descriptor from FUN_00003820)
;   -0x38: local_param1 (output from FUN_00004a52)
;   -0x20 to -0x40: segment_descriptors[4] (32 bytes, 4 × 8-byte entries)
;
; REGISTER USAGE:
;   D2: slot_number (preserved)
;   D3: url_or_path (preserved)
;   D4: port_number (from atoi)
;   D5: temporary constants
;   A2: loop counter / function pointer
;   A3: &g_memory_regions (0x8024)
;   A4: &segment_descriptors
;   A5: result_ptr (preserved)
;
; ====================================================================================

FUN_00003284:
ND_LoadKernelSegments:

    ; --- PROLOGUE ---
    0x00003284:  link.w     A6, #-0x40              ; Create 64-byte stack frame
    0x00003288:  movem.l    {D2-D5,A2-A5}, -(SP)    ; Save 8 callee-save registers (32 bytes)

    ; --- LOAD PARAMETERS INTO WORKING REGISTERS ---
    0x0000328c:  move.l     (0x8,A6), D3            ; D3 = url_or_path (string parameter)
    0x00003290:  move.l     (0xC,A6), D2            ; D2 = slot_number (board slot 0-15)
    0x00003294:  movea.l    (0x10,A6), A5           ; A5 = result_ptr (output parameter)

    ; --- PARSE PORT NUMBER FROM URL/PATH STRING ---
    ; Library function extracts integer from string (likely atoi or custom URL parser)
    0x00003298:  bsr.l      0x0500315e              ; atoi/strtol(url_or_path) → D0
    0x0000329e:  move.l     D0, D4                  ; D4 = port_number (saved for later use)

    ; --- PHASE 1: PARAMETER VALIDATION ---
    ; Call FUN_00004a52 to validate parameters and perform initial setup
    0x000032a0:  pea        (-0x38,A6)              ; Push &local_param1 (output parameter)
    0x000032a4:  pea        (0x77e3).l              ; Push constant/format string at 0x77e3
    0x000032aa:  move.l     D2, -(SP)               ; Push slot_number
    0x000032ac:  move.l     D3, -(SP)               ; Push url_or_path
    0x000032ae:  bsr.l      0x00004a52              ; FUN_00004a52(url, slot, const, &out)
    0x000032b4:  addq.w     #0x8, SP                ; Clean 8 bytes from stack
    0x000032b6:  addq.w     #0x8, SP                ; Clean 8 bytes from stack (16 total)
    0x000032b8:  tst.l      D0                      ; Test return value
    0x000032ba:  bne.w      .error_exit             ; If non-zero, jump to error exit

    ; --- PHASE 2: CONNECTION INITIALIZATION ---
    ; Open connection or file descriptor to data source
    0x000032be:  pea        (-0x3c,A6)              ; Push &local_fd (output parameter)
    0x000032c2:  move.l     D2, -(SP)               ; Push slot_number
    0x000032c4:  move.l     D3, -(SP)               ; Push url_or_path
    0x000032c6:  bsr.l      0x00003820              ; FUN_00003820(url, slot, &fd_out)
    0x000032cc:  addq.w     #0x8, SP                ; Clean 8 bytes from stack
    0x000032ce:  addq.w     #0x4, SP                ; Clean 4 bytes from stack (12 total)
    0x000032d0:  tst.l      D0                      ; Test return value
    0x000032d2:  bne.w      .error_exit             ; If non-zero, jump to error exit

    ; --- CONFIGURE SLOT CONTROL REGISTER ---
    ; Shift slot number left by 28 bits to create slot-specific address space selector
    ; Slot 0: 0x00000000, Slot 1: 0x10000000, Slot 2: 0x20000000, etc.
    0x000032d6:  move.l     D2, D0                  ; D0 = slot_number
    0x000032d8:  moveq      #0x1c, D5               ; D5 = 28 (0x1C decimal)
    0x000032da:  asl.l      D5, D0                  ; D0 = slot_number << 28
    0x000032dc:  move.l     D0, (0x801c).l          ; Write to global slot control register

    ; --- PHASE 3: PARSE SEGMENT DESCRIPTORS ---
    ; Extract segment information (likely from Mach-O headers)
    0x000032e2:  pea        (-0x20,A6)              ; Push &segment_descriptors[0] (32-byte array)
    0x000032e6:  move.l     (-0x38,A6), -(SP)       ; Push local_param1 (from phase 1)
    0x000032ea:  bsr.l      0x00005dea              ; FUN_00005dea(param1, &descriptors)
    0x000032f0:  addq.w     #0x8, SP                ; Clean 8 bytes from stack
    0x000032f2:  tst.l      D0                      ; Test return value
    0x000032f4:  bne.w      .error_exit             ; If non-zero, jump to error exit

    ; --- PHASE 4: SEGMENT LOADING LOOP INITIALIZATION ---
    0x000032f8:  suba.l     A2, A2                  ; A2 = 0 (segment index counter)
    0x000032fa:  lea        (-0x20,A6), A4          ; A4 = &segment_descriptors[0]
    0x000032fe:  lea        (0x8024).l, A3          ; A3 = &g_memory_regions[0] (global table)

.segment_loop:
    ; --- CHECK IF CURRENT SEGMENT IS VALID ---
    ; Each descriptor is 8 bytes: [field_0x0, field_0x4]
    ; If field_0x4 is zero, segment is invalid/empty
    0x00003304:  move.l     A2, D1                  ; D1 = segment_index
    0x00003306:  asl.l      #0x3, D1                ; D1 = segment_index * 8 (descriptor offset)
    0x00003308:  tst.l      (0x4,A4,D1*1)           ; Test descriptors[index].field_0x4 (size/flags)
    0x0000330c:  beq.b      .skip_segment           ; If zero, skip this segment (not loaded)

    ; --- CALCULATE MEMORY REGION TABLE OFFSET ---
    ; Each region entry is 12 bytes: [translated_addr, base, size]
    ; Offset = segment_index * 12 = segment_index * 3 * 4
    0x0000330e:  lea        (0x0,A2,A2*2), A0       ; A0 = segment_index * 3
    0x00003312:  move.l     A0, D0                  ; D0 = segment_index * 3
    0x00003314:  asl.l      #0x2, D0                ; D0 = (segment_index * 3) * 4 = offset in bytes

    ; --- UPDATE GLOBAL MEMORY REGION TABLE ---
    ; Copy segment descriptor fields into global region table
    0x00003316:  move.l     (0x0,A4,D1*1), (0x4,A3,D0*1)  ; region[idx].base = descriptor[idx].field_0x0
    0x0000331c:  move.l     (0x4,A4,D1*1), (0x8,A3,D0*1)  ; region[idx].size = descriptor[idx].field_0x4

    ; --- PREPARE PARAMETERS FOR SEGMENT LOADER ---
    ; FUN_000043c6(url, fd, port, region_ptr, base, size)
    0x00003322:  move.l     (0x8,A3,D0*1), -(SP)    ; Push size (region[idx].size)
    0x00003326:  move.l     (0x4,A3,D0*1), -(SP)    ; Push base (region[idx].base)
    0x0000332a:  addi.l     #0x8024, D0             ; D0 = absolute address of region[idx]
    0x00003330:  move.l     D0, -(SP)               ; Push region_ptr (for translation output)
    0x00003332:  move.l     D4, -(SP)               ; Push port_number (from atoi)
    0x00003334:  move.l     (-0x3c,A6), -(SP)       ; Push file descriptor (from phase 2)
    0x00003338:  move.l     D3, -(SP)               ; Push url_or_path

    ; --- LOAD THIS SEGMENT ---
    0x0000333a:  bsr.l      0x000043c6              ; FUN_000043c6 - Load segment with translation
    0x00003340:  adda.w     #0x18, SP               ; Clean 24 bytes (6 parameters × 4 bytes)
    0x00003344:  tst.l      D0                      ; Test return value
    0x00003346:  bne.b      .error_exit             ; If non-zero, abort (segment load failed)

.skip_segment:
    ; --- LOOP INCREMENT AND BOUNDARY CHECK ---
    0x00003348:  addq.w     #0x1, A2                ; segment_index++ (next segment)
    0x0000334a:  moveq      #0x3, D5                ; D5 = 3 (maximum segment index)
    0x0000334c:  cmp.l      A2, D5                  ; Compare segment_index with 3
    0x0000334e:  bge.b      .segment_loop           ; If index <= 3, continue loop (4 segments: 0-3)

    ; --- PHASE 5: CONFIGURE LOAD CALLBACK FUNCTION POINTER ---
    ; Store library read/recv function pointer for later use
    0x00003350:  move.l     #0x50021c8, (0x8020).l  ; Store function pointer at global 0x8020

    ; --- PHASE 6: OPEN FILE DESCRIPTOR FOR CALLBACK ---
    ; Convert local variable to integer and open as file descriptor
    0x0000335a:  pea        (-0x40,A6)              ; Push &local_file_handle
    0x0000335e:  bsr.l      0x0500315e              ; atoi/strtol(local_file_handle)
    0x00003364:  move.l     D0, -(SP)               ; Push converted integer value
    0x00003366:  bsr.l      0x05002c54              ; fdopen(int_value, ...) → D0
    0x0000336c:  addq.w     #0x8, SP                ; Clean 8 bytes from stack
    0x0000336e:  tst.l      D0                      ; Test return value
    0x00003370:  bne.b      .error_exit             ; If non-zero, error in fdopen

    ; --- PHASE 7: FINALIZE SEGMENT LOADING ---
    ; Commit loaded segments and perform final setup
    0x00003372:  move.l     (-0x40,A6), -(SP)       ; Push local_file_handle
    0x00003376:  move.l     (-0x38,A6), -(SP)       ; Push local_param1
    0x0000337a:  bsr.l      0x00005da6              ; FUN_00005da6(param1, handle) - Finalization
    0x00003380:  addq.w     #0x8, SP                ; Clean 8 bytes from stack
    0x00003382:  tst.l      D0                      ; Test return value
    0x00003384:  bne.b      .error_exit             ; If non-zero, finalization failed

    ; --- PHASE 8: STORE RESULT ---
    0x00003386:  move.l     (-0x40,A6), (A5)        ; *result_ptr = local_file_handle

    ; --- PHASE 9: DEVICE CONTROL OPERATIONS ---
    ; Issue two control commands to NeXTdimension device
    ; Likely: flush buffers, enable caches, or start i860 processor
    0x0000338a:  pea        (0x307c).l              ; Push device handle/constant 0x307C
    0x00003390:  pea        (0xa).w                 ; Push command 10 (decimal)
    0x00003394:  lea        (0x5002f7e).l, A2       ; A2 = &lib_ioctl_or_fcntl
    0x0000339a:  jsr        A2                      ; Call lib_function(10, 0x307C)

    0x0000339c:  pea        (0x307c).l              ; Push device handle/constant 0x307C
    0x000033a2:  pea        (0xb).w                 ; Push command 11 (decimal)
    0x000033a6:  jsr        A2                      ; Call lib_function(11, 0x307C)

    ; --- SUCCESS PATH ---
    0x000033a8:  clr.l      D0                      ; D0 = 0 (success return value)

.error_exit:
    ; --- EPILOGUE ---
    ; Restore saved registers and clean up stack frame
    0x000033aa:  movem.l    -0x60(A6), {D2-D5,A2-A5} ; Restore 8 saved registers
    0x000033b0:  unlk       A6                      ; Destroy stack frame, restore old FP
    0x000033b2:  rts                                ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_LoadKernelSegments
; ====================================================================================
;
; FUNCTION SUMMARY:
; This function orchestrates a 9-phase kernel loading sequence for the NeXTdimension
; i860 processor. It validates parameters, parses segment descriptors (likely from
; Mach-O format), translates addresses from host to i860 memory space, loads up to
; 4 segments via callback functions, and finalizes the load with device control
; commands. The function maintains global state in memory region table (0x8024),
; slot control register (0x801C), and callback pointer (0x8020).
;
; KEY BEHAVIORS:
; 1. Parses port number from URL/path string
; 2. Validates parameters and initializes connection
; 3. Configures slot-specific address space (slot << 28)
; 4. Extracts segment descriptors (0-3 segments)
; 5. For each valid segment:
;    - Updates global memory region table
;    - Calls loader with address translation
; 6. Stores callback function pointer for deferred operations
; 7. Opens file descriptor for callback use
; 8. Finalizes load and stores result handle
; 9. Issues device control commands (likely start i860)
;
; ERROR HANDLING:
; All internal functions return 0 on success, non-zero on error. Any error
; immediately terminates loading and returns error code to caller. Partial
; loads are not rolled back (no cleanup visible), so caller must handle
; error recovery.
;
; GLOBAL STATE MODIFIED:
; - 0x801C: Slot control register (slot << 28)
; - 0x8020: Callback function pointer (0x050021c8)
; - 0x8024+: Memory region table (up to 48 bytes for 4 regions)
;
; REVERSE-ENGINEERED C EQUIVALENT:
;
; typedef struct {
;     uint32_t base_or_offset;   // +0x0
;     uint32_t size_or_flags;    // +0x4 (0 = invalid segment)
; } segment_descriptor_t;
;
; typedef struct {
;     uint32_t translated_addr;  // +0x0
;     uint32_t base_address;     // +0x4
;     uint32_t size;             // +0x8
; } memory_region_t;
;
; extern memory_region_t g_memory_regions[4];  // At 0x8024
; extern void* g_load_callback;                // At 0x8020
; extern uint32_t g_slot_control;              // At 0x801C
;
; int32_t ND_LoadKernelSegments(char* url_or_path, uint32_t slot_number, void* result_ptr) {
;     int32_t port_number = atoi(url_or_path);
;     int32_t local_param1, local_fd, local_file_handle;
;     segment_descriptor_t segment_descriptors[4];
;     int32_t error;
;
;     // Phase 1: Validate parameters
;     error = FUN_00004a52(url_or_path, slot_number, (void*)0x77e3, &local_param1);
;     if (error != 0) return error;
;
;     // Phase 2: Initialize connection
;     error = FUN_00003820(url_or_path, slot_number, &local_fd);
;     if (error != 0) return error;
;
;     // Phase 3: Configure slot control
;     g_slot_control = slot_number << 28;
;
;     // Phase 4: Parse segment descriptors
;     error = FUN_00005dea(local_param1, segment_descriptors);
;     if (error != 0) return error;
;
;     // Phase 5: Load each valid segment
;     for (int i = 0; i <= 3; i++) {
;         if (segment_descriptors[i].size_or_flags == 0) continue;
;
;         int region_offset = i * 12;
;         g_memory_regions[i].base_address = segment_descriptors[i].base_or_offset;
;         g_memory_regions[i].size = segment_descriptors[i].size_or_flags;
;
;         error = FUN_000043c6(
;             url_or_path, local_fd, port_number,
;             (void*)((uint32_t)&g_memory_regions[0] + region_offset),
;             g_memory_regions[i].base_address,
;             g_memory_regions[i].size
;         );
;         if (error != 0) return error;
;     }
;
;     // Phase 6: Configure callback
;     g_load_callback = (void*)0x050021c8;
;
;     // Phase 7: Open file descriptor
;     int converted = atoi((char*)&local_file_handle);
;     error = fdopen(converted, &local_file_handle);
;     if (error != 0) return error;
;
;     // Phase 8: Finalize
;     error = FUN_00005da6(local_param1, local_file_handle);
;     if (error != 0) return error;
;
;     // Phase 9: Store result
;     *(uint32_t*)result_ptr = local_file_handle;
;
;     // Phase 10: Device control
;     lib_ioctl(10, (void*)0x307C);
;     lib_ioctl(11, (void*)0x307C);
;
;     return 0;  // Success
; }
;
; ====================================================================================
