; ============================================================================
; Function: FUN_00005d26 (ANNOTATED)
; Address: 0x00005d26 (23846 decimal)
; Size: 58 bytes
; Architecture: Motorola 68000 (m68k)
; Complexity: Low
; Category: Callback/Device Handler
; ============================================================================
; PURPOSE: Device initialization callback that looks up a device from a static
;          table and enables it by setting control bit flags.
; ============================================================================

; --- FUNCTION PROLOGUE ---
  0x00005d26:  link.w     A6,0x0              ; Establish stack frame (no locals)
                                               ; A6 now points to return address
                                               ; Stack: [A6][retaddr][params]

  0x00005d2a:  move.l     D2,-(SP)            ; Save D2 register (callee-saved)
                                               ; Stack: [D2][A6][retaddr][params]

; --- PARAMETER LOADING ---
  0x00005d2c:  move.l     (0xc,A6),D2         ; Load parameter: D2 = M[A6+0xc]
                                               ; A6+0c points to first parameter
                                               ; D2 now contains device ID or index

; --- EXTERNAL FUNCTION CALL ---
  0x00005d30:  bsr.l      0x0500315e          ; Call external service routine
                                               ; Likely platform-specific I/O
                                               ; May modify D2 or other registers
                                               ; Purpose: TBD (context-dependent)

; --- PARAMETER SCALING ---
  0x00005d36:  asr.l      #0x1,D2             ; Arithmetic shift right D2 by 1
                                               ; Equivalent to: D2 = D2 / 2
                                               ; Scales parameter for table indexing
                                               ; Sets condition codes (affects beq/bne)

; --- TABLE LOOKUP SETUP ---
  0x00005d38:  lea        (0x819c).l,A0       ; Load effective address 0x0000819c
                                               ; A0 = pointer to device table base
                                               ; Table format: array of long pointers

; --- INDEXED TABLE LOOKUP ---
  0x00005d3e:  movea.l    (0x0,A0,D2*0x4),A0 ; Index and dereference table
                                               ; Address calc: A0 + (D2 * 4)
                                               ; A0 = table[D2] = M[0x819c + D2*4]
                                               ; Result is pointer to device structure
                                               ; Sets condition codes (affects beq)

; --- NULL POINTER CHECK ---
  0x00005d42:  tst.l      A0                  ; Test if A0 is null/zero
                                               ; Sets condition codes
                                               ; Z flag = 1 if A0 == 0

  0x00005d44:  beq.b      0x00005d56          ; Branch if A0 == null
                                               ; Jump to error case (offset +0x12)
                                               ; Falls through to success case if A0 != null

; === SUCCESS PATH (A0 != null) ===

; --- STRUCTURE DEREFERENCE ---
  0x00005d46:  movea.l    (0x1c,A0),A0        ; Dereference offset +0x1c from A0
                                               ; A0 = M[A0 + 0x1c]
                                               ; Points to bit field control register
                                               ; Likely a device control/status word

; --- BIT FIELD READ ---
  0x00005d4a:  move.l     (A0),D0             ; Load 32-bit value from memory
                                               ; D0 = M[A0] (device control flags)

; --- BIT FIELD MODIFICATION ---
  0x00005d4c:  moveq      0xc,D1              ; Load constant 0x0000000c
                                               ; 0x0c in binary: 0b00001100
                                               ; Sets bits 2 and 3
                                               ; D1 = 0x0c

  0x00005d4e:  or.l       D1,D0               ; Bitwise OR operation
                                               ; D0 = D0 | D1
                                               ; Sets bits 2 and 3 in D0
                                               ; Likely enables device features

; --- BIT FIELD WRITE ---
  0x00005d50:  move.l     D0,(A0)             ; Write modified value back to memory
                                               ; M[A0] = D0 (control flags written)
                                               ; Device control bits now active

; --- SUCCESS RETURN ---
  0x00005d52:  clr.l      D0                  ; Clear D0 register
                                               ; D0 = 0x00000000 (success code)
                                               ; Returns 0 to indicate success

  0x00005d54:  bra.b      0x00005d58          ; Branch to epilogue
                                               ; Jump over error case (offset +0x4)
                                               ; Skips "moveq 0x4,D0" instruction

; === ERROR PATH (A0 == null) ===
  0x00005d56:  moveq      0x4,D0              ; Load error code 0x00000004
                                               ; D0 = 0x04 (error status)
                                               ; Returns 4 to indicate failure

; === FUNCTION EPILOGUE ===
  0x00005d58:  move.l     (-0x4,A6),D2        ; Restore D2 register
                                               ; D2 = M[A6-0x4] (from stack save)
                                               ; Restores callee-saved register

  0x00005d5c:  unlk       A6                  ; Release stack frame
                                               ; Pops saved A6, A6 = return address
                                               ; Stack unwound to pre-call state

  0x00005d5e:  rts                            ; Return to caller
                                               ; PC = M[SP], SP += 4
                                               ; Returns to address 0x00002f72
                                               ; D0 contains return code (0 or 4)

; ============================================================================
; SUMMARY OF OPERATIONS:
; ============================================================================
; 1. Save frame and D2 register
; 2. Load parameter from stack
; 3. Call external service function
; 4. Divide parameter by 2 (scale for table access)
; 5. Load table base address (0x0000819c)
; 6. Index table with scaled parameter (D2*4)
; 7. Check if table entry is null
; 8. If null: return error code 4
; 9. If not null: dereference entry at offset 0x1c
; 10. Load 32-bit control field
; 11. OR control field with 0x0c (set bits 2-3)
; 12. Write control field back to memory
; 13. Return success code 0
; 14. Restore D2 and return to caller
; ============================================================================

; --- STACK FRAME AT ENTRY ---
; [A6-0x4]: Saved A6 (created by link.w)
; [A6+0x0]: Return address (from bsr.l 0x2f6c)
; [A6+0x4]: Parameter 1 (pushed before call) <- Caller's D3
; [A6+0x8]: Parameter 2 (pushed before call) <- Caller's local (-0x4,A6)
; [A6+0xc]: Parameter accessed at 0x5d2c <- PARAMETER 1 or 2?
;
; Note: Stack adjustment between push and link may affect offsets
;       Frame pointer setup: link.w A6,0x0 creates no local storage
;       Parameter at 0xc offset implies 2 parameters pushed (8 bytes)

; --- REGISTER USAGE ---
; Input:  A6 (frame pointer), parameters at [A6+0xc]
; Output: D0 (return code: 0=success, 4=error)
; Save:   D2 (saved and restored)
; Work:   D1 (constant 0xc)
; Addr:   A0 (table base, then structure pointer)

; --- CALLED FUNCTIONS ---
; 0x0500315e: External service (purpose unknown, modifies parameter)

; --- DATA REFERENCES ---
; 0x0000819c: Device table base (array of 4-byte pointers)

; --- ERROR CODES ---
; 0x00 (D0): Operation successful
; 0x04 (D0): Device not found in table (null pointer)

; ============================================================================
