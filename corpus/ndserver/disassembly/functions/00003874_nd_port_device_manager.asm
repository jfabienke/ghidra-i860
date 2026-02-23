; Function: nd_port_device_manager
; Address: 0x00003874 - 0x0000399A
; Size: 296 bytes (0x128 bytes)
; Frame: 0 bytes
; Purpose: Critical NeXTdimension port device management handler
;
; Function Signature:
;   void nd_port_device_manager(uint32_t port_device_ptr, int port_device_index)
;   A6+0x08: port_device_ptr - Device pointer
;   A6+0x0C: port_device_index - Device index (must be even: 0, 2, 4, 6)
;
; Description:
;   Manages the complete lifecycle of port devices including validation,
;   callback registration with Mach kernel, device cleanup, and finalization.
;   Critical for NeXTdimension board initialization and communication.
;
; Hardware Access:
;   - 0x04010290 (SYSTEM_PORT+0x4): Mach mailbox register (read-only)
;     Only function accessing this critical register
;
; Registers Used:
;   D0: Index calculation, temporary values
;   D1: Comparison values, device ID
;   D2: Mailbox register cache (CRITICAL - passed to all external calls)
;   A0: Table pointer, device pointer temporary
;   A2: Device structure pointer (primary working register)
;   A6: Frame pointer
;   SP: Stack pointer
;
; Data Structures:
;   0x81A0: Device pointer table (4 entries)
;   0x819C: Device registry table
;   Device structure: ~73+ bytes with callback/arg pairs
;
; External Function Calls:
;   0x050032BA: Mach callback registration (called 5x)
;   0x05002C5A: Callback cleanup handler (called 3x)
;   0x05002546: Device finalization (called 1x)
;
; Calling Functions (9 total):
;   FUN_00002dc6 (2x: 0x2FBC, 0x301C) - Initialization
;   FUN_000036B2 (1x: 0x380E) - Device setup
;   FUN_00005A3E (2x: 0x5A9A, 0x5AE4) - Port operations
;   FUN_00005AF6 (2x: 0x5B52, 0x5BA6) - Port operations
;   FUN_00005BB8 (2x: 0x5C14, 0x5C5E) - Port operations
;
; ============================================================================

0x00003874:  link.w     %fp,#0              ; Setup stack frame, no locals
0x00003878:  move.l     %a2,-(%sp)          ; Save A2 (callee-saved)
0x0000387a:  move.l     %d2,-(%sp)          ; Save D2 (callee-saved)

; ===== ENTRY AND HARDWARE ACCESS =====

0x0000387c:  move.l     (0xc,%fp),%d0       ; D0 = port_device_index (parameter @ A6+0xC)
0x00003880:  move.l     (0x04010290).l,%d2  ; D2 = mailbox register value
                                             ; *** CRITICAL HARDWARE READ ***
                                             ; Cache mailbox for entire function

; ===== VALIDATION PHASE 1: INDEX RANGE CHECK =====

0x00003886:  moveq      #0x8,%d1            ; D1 = 8 (maximum valid index)
0x00003888:  cmp.l      %d0,%d1             ; Compare: if D0 >= 8
0x0000388a:  bcs.w      0x00003990          ; Branch if unsigned overflow (index >= 8)
                                             ; FAIL: Invalid index range

; ===== VALIDATION PHASE 2: ODD INDEX CHECK =====

0x0000388e:  btst.l     #0x0,%d0            ; Test bit 0 of index (LSB)
0x00003892:  bne.w      0x00003990          ; Branch if not equal (index is odd)
                                             ; FAIL: Only even indices allowed (0, 2, 4, 6)

; ===== INDEX CALCULATION =====

0x00003896:  asr.l      #0x1,%d0            ; D0 = index >> 1 (divide by 2)
0x00003898:  subq.l     #0x1,%d0            ; D0 = (index >> 1) - 1
                                             ; Now D0 is 0-3 for table lookup

; ===== DEVICE TABLE LOOKUP =====

0x0000389a:  lea        (0x81a0).l,%a0      ; A0 = address of device table @ 0x81A0
0x000038a0:  tst.l      (0x0,%a0,%d0*0x4)   ; Test if table[D0] is non-zero
                                             ; Each entry is 4 bytes (32-bit pointer)
0x000038a4:  beq.w      0x00003990          ; Branch if NULL
                                             ; FAIL: Device not registered in table

0x000038a8:  movea.l    (0x0,%a0,%d0*0x4),%a0  ; A0 = device_table[D0]
                                             ; Load device structure pointer

; ===== DEVICE ID VALIDATION =====

0x000038ac:  move.l     (%a0),%d1           ; D1 = A0->device_id (offset +0x00)
0x000038ae:  cmp.l      (0x8,%fp),%d1       ; Compare with port_device_ptr parameter
0x000038b2:  bne.w      0x00003990          ; Branch if not equal
                                             ; FAIL: Device ID mismatch
                                             ; Device structure validation failure

0x000038b6:  movea.l    %a0,%a2             ; A2 = validated device pointer
                                             ; Move to A2 for remaining processing

; ===== CALLBACK REGISTRATION PHASE =====
; Register up to 5 callbacks with Mach kernel

; Callback Slot 1 (offset 0x1C, arg @ 0x34)
0x000038b8:  tst.l      (0x1c,%a2)          ; Test if callback @ offset 0x1C
0x000038bc:  beq.b      0x000038d2          ; Skip if NULL -> next callback

0x000038be:  move.l     (0x34,%a2),-(%sp)   ; Push arg @ offset 0x34 (stack arg 1)
0x000038c2:  move.l     (0x1c,%a2),-(%sp)   ; Push callback ptr @ 0x1C (stack arg 2)
0x000038c6:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 3)
0x000038c8:  bsr.l      0x050032ba          ; Call: mach_register_callback(mailbox, cb, arg)
0x000038ce:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)
0x000038d0:  addq.w     #0x4,%sp            ; Clean stack: pop 1 arg (4 bytes)

; Callback Slot 2 (offset 0x24, arg @ 0x38)
0x000038d2:  tst.l      (0x24,%a2)          ; Test if callback @ offset 0x24
0x000038d6:  beq.b      0x000038ec          ; Skip if NULL -> next callback

0x000038d8:  move.l     (0x38,%a2),-(%sp)   ; Push arg @ offset 0x38 (stack arg 1)
0x000038dc:  move.l     (0x24,%a2),-(%sp)   ; Push callback ptr @ 0x24 (stack arg 2)
0x000038e0:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 3)
0x000038e2:  bsr.l      0x050032ba          ; Call: mach_register_callback(mailbox, cb, arg)
0x000038e8:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)
0x000038ea:  addq.w     #0x4,%sp            ; Clean stack: pop 1 arg (4 bytes)

; Callback Slot 3 (offset 0x28, arg @ 0x3C)
0x000038ec:  tst.l      (0x28,%a2)          ; Test if callback @ offset 0x28
0x000038f0:  beq.b      0x00003906          ; Skip if NULL -> next callback

0x000038f2:  move.l     (0x3c,%a2),-(%sp)   ; Push arg @ offset 0x3C (stack arg 1)
0x000038f6:  move.l     (0x28,%a2),-(%sp)   ; Push callback ptr @ 0x28 (stack arg 2)
0x000038fa:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 3)
0x000038fc:  bsr.l      0x050032ba          ; Call: mach_register_callback(mailbox, cb, arg)
0x00003902:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)
0x00003904:  addq.w     #0x4,%sp            ; Clean stack: pop 1 arg (4 bytes)

; Callback Slot 4 (offset 0x2C, arg @ 0x40)
0x00003906:  tst.l      (0x2c,%a2)          ; Test if callback @ offset 0x2C
0x0000390a:  beq.b      0x00003920          ; Skip if NULL -> next callback

0x0000390c:  move.l     (0x40,%a2),-(%sp)   ; Push arg @ offset 0x40 (stack arg 1)
0x00003910:  move.l     (0x2c,%a2),-(%sp)   ; Push callback ptr @ 0x2C (stack arg 2)
0x00003914:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 3)
0x00003916:  bsr.l      0x050032ba          ; Call: mach_register_callback(mailbox, cb, arg)
0x0000391c:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)
0x0000391e:  addq.w     #0x4,%sp            ; Clean stack: pop 1 arg (4 bytes)

; Callback Slot 5 (offset 0x30, arg @ 0x44)
0x00003920:  tst.l      (0x30,%a2)          ; Test if callback @ offset 0x30
0x00003924:  beq.b      0x0000393a          ; Skip if NULL -> cleanup phase

0x00003926:  move.l     (0x44,%a2),-(%sp)   ; Push arg @ offset 0x44 (stack arg 1)
0x0000392a:  move.l     (0x30,%a2),-(%sp)   ; Push callback ptr @ 0x30 (stack arg 2)
0x0000392e:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 3)
0x00003930:  bsr.l      0x050032ba          ; Call: mach_register_callback(mailbox, cb, arg)
0x00003936:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)
0x00003938:  addq.w     #0x4,%sp            ; Clean stack: pop 1 arg (4 bytes)

; ===== DEVICE INVALIDATION =====

0x0000393a:  clr.l      (%a2)               ; Clear device_id @ A2+0
                                             ; *** CRITICAL: Invalidate device ***
                                             ; This marks device as no longer active

; ===== CALLBACK CLEANUP PHASE =====

; Cleanup Callback 1 (offset 0x04)
0x0000393c:  tst.l      (0x4,%a2)           ; Test if callback @ offset 0x04
0x00003940:  beq.b      0x00003950          ; Skip if NULL -> next cleanup

0x00003942:  move.l     (0x4,%a2),-(%sp)    ; Push callback ptr @ 0x04 (stack arg 1)
0x00003946:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 2)
0x00003948:  bsr.l      0x05002c5a          ; Call: mach_cleanup_callback(cb, mailbox)
0x0000394e:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)

; Cleanup Callback 2 (offset 0x08)
0x00003950:  tst.l      (0x8,%a2)           ; Test if callback @ offset 0x08
0x00003954:  beq.b      0x00003964          ; Skip if NULL -> next cleanup

0x00003956:  move.l     (0x8,%a2),-(%sp)    ; Push callback ptr @ 0x08 (stack arg 1)
0x0000395a:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 2)
0x0000395c:  bsr.l      0x05002c5a          ; Call: mach_cleanup_callback(cb, mailbox)
0x00003962:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)

; Cleanup Callback 3 (offset 0x0C)
0x00003964:  tst.l      (0xc,%a2)           ; Test if callback @ offset 0x0C
0x00003968:  beq.b      0x00003978          ; Skip if NULL -> finalization

0x0000396a:  move.l     (0xc,%a2),-(%sp)    ; Push callback ptr @ 0x0C (stack arg 1)
0x0000396e:  move.l     %d2,-(%sp)          ; Push mailbox register value (stack arg 2)
0x00003970:  bsr.l      0x05002c5a          ; Call: mach_cleanup_callback(cb, mailbox)
0x00003976:  addq.w     #0x8,%sp            ; Clean stack: pop 2 args (8 bytes)

; ===== FINALIZATION PHASE =====

0x00003978:  move.l     (0x48,%a2),%d0      ; D0 = device_id_verify @ A2+0x48
0x0000397c:  asr.l      #0x1,%d0            ; D0 = (device_id_verify >> 1)
0x0000397e:  lea        (0x819c).l,%a0      ; A0 = address of registry table @ 0x819C
0x00003984:  clr.l      (0x0,%a0,%d0*0x4)   ; Clear registry[D0]
                                             ; *** Remove device from registry ***

0x00003988:  move.l     %a2,-(%sp)          ; Push device pointer (A2) (stack arg 1)
0x0000398a:  bsr.l      0x05002546          ; Call: device_finalize(device)
                                             ; Final device teardown

; ===== EXIT (FAIL POINT) =====

0x00003990:  move.l     (-0x8,%fp),%d2      ; Restore D2
0x00003994:  movea.l    (-0x4,%fp),%a2      ; Restore A2
0x00003998:  unlk       %fp                 ; Unlink frame
0x0000399a:  rts                            ; Return to caller

; ============================================================================
; NOTES:
;
; 1. CRITICAL HARDWARE INTERFACE:
;    - Register 0x04010290 is the only hardware access point
;    - This is the ONLY function in the entire binary accessing this mailbox
;    - Value is cached in D2 and never modified
;    - All external calls receive D2 as the "context" parameter
;
; 2. FAIL-FAST VALIDATION:
;    - All 4 validation checks must pass to proceed
;    - Any validation failure jumps to 0x3990 (exit)
;    - Device is never registered if any check fails
;    - Cleanup is never called on failed validation
;
; 3. CALLBACK ARCHITECTURE:
;    - Up to 5 callbacks registered in registration phase (0x38B8-0x393A)
;    - Up to 3 callbacks cleaned up in cleanup phase (0x393C-0x3976)
;    - Registration and cleanup use different handlers
;    - Callbacks are optional (skipped if pointer is NULL)
;
; 4. DEVICE LIFECYCLE:
;    - Validation: Ensure device is legitimate
;    - Activation: Register callbacks with Mach kernel
;    - Operation: Device is active for kernel-driven operations
;    - Deactivation: Clear device_id to mark invalid
;    - Cleanup: Deregister callbacks
;    - Finalization: Remove from registry, call final handler
;
; 5. DATA STRUCTURES:
;    Device Table @ 0x81A0: 4-entry table of device pointers
;    Registry Table @ 0x819C: Device registry (parallel structure)
;    Device Structure: 73+ bytes with 8 callback/arg pairs
;
; 6. STACK FRAME:
;    Entry: [old A2][old D2][ret addr]
;    No local variables (frame size = 0)
;    All parameters passed via stack (A6-based)
;
; ============================================================================
