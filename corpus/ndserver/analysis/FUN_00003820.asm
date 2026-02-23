; ============================================================================
; Function: FUN_00003820
; Address: 0x00003820
; Size: 84 bytes (21 instructions)
; Category: Callback - Table Lookup with Validation
; Complexity: Low
; Priority: HIGH
;
; Purpose: Look up entry in table, validate against parameter, return data
;
; Parameters:
;   D0: Input value (must be < 8 and even)
;   A1: Pointer to output location (32-bit)
;   Stack 0x8(A6): Secondary parameter for validation
;
; Return Value:
;   D0: Status code
;       0x0 = Success (data copied)
;       0x4 = Invalid input (bounds or odd)
;       0x8 = Entry mismatch
;       0xc = Table entry null
;
; Registers Modified:
;   D0: Return value
;   D1: Scratch (constant 8)
;   A0: Table pointer
;   A1: Output pointer (read from parameter)
;
; ============================================================================

  0x00003820:  link.w     A6, 0x0              ; Setup frame pointer
                                               ; SP and A6 form stack frame
                                               ; No local variables (0x0)

; ============================================================================
; SECTION 1: INPUT VALIDATION - LOAD PARAMETERS
; ============================================================================

  0x00003824:  move.l     (0xc,A6), D0         ; D0 = first parameter (input value)
  0x00003828:  movea.l    (0x10,A6), A1        ; A1 = second parameter (output ptr)
  0x0000382c:  moveq      0x8, D1              ; D1 = 8 (upper bounds constant)

; ============================================================================
; SECTION 2: BOUNDS CHECK - INPUT < 8
; ============================================================================

  0x0000382e:  cmp.l      D0, D1               ; Compare D1(8) against D0(input)
  0x00003830:  bcs.b      0x00003838           ; Branch if D0 >= D1 (Carry Set)
                                               ; = unsigned D0 >= 8, jump to error

; ============================================================================
; SECTION 3: ODD/EVEN CHECK - INPUT MUST BE EVEN
; ============================================================================

  0x00003832:  btst.l     #0x0, D0             ; Test bit 0 of D0 (LSB)
                                               ; 0 = even (bit clear), 1 = odd
  0x00003836:  beq.b      0x0000383c           ; Branch if bit 0 is clear (even)
                                               ; Jump to array lookup path

; ============================================================================
; SECTION 4: ERROR PATH - INPUT VALIDATION FAILED
; ============================================================================

  0x00003838:  moveq      0x4, D0              ; D0 = 0x4 (error code)
  0x0000383a:  bra.b      0x00003870           ; Jump to function exit
                                               ; Error: Input bounds fail (>= 8 or odd)

; ============================================================================
; SECTION 5: INDEX COMPUTATION - CONVERT INPUT TO TABLE INDEX
; ============================================================================

  0x0000383c:  asr.l      #0x1, D0             ; D0 = D0 >> 1 (arithmetic right shift)
                                               ; Input 2 → 1, 4 → 2, 6 → 3
  0x0000383e:  subq.l     0x1, D0              ; D0 = D0 - 1 (subtract 1)
                                               ; Index 1 → 0, 2 → 1, 3 → 2

; ============================================================================
; SECTION 6: LOAD TABLE BASE ADDRESS
; ============================================================================

  0x00003840:  lea        (0x81a0).l, A0      ; A0 = 0x81a0 (table base address)
                                               ; Table contains 32-bit pointers

; ============================================================================
; SECTION 7: CHECK TABLE ENTRY EXISTS
; ============================================================================

  0x00003846:  tst.l      (0x0,A0,D0*0x4)     ; Test value at A0 + (D0 * 4)
                                               ; Load 32-bit pointer from table[index]
  0x0000384a:  bne.b      0x00003852           ; Branch if Not Equal to zero
                                               ; Jump if table entry is not NULL

; ============================================================================
; SECTION 8: ERROR PATH - TABLE ENTRY NULL
; ============================================================================

  0x0000384c:  clr.l      (A1)                 ; *A1 = 0 (clear output location)
  0x0000384e:  moveq      0xc, D0              ; D0 = 0xc (error code)
  0x00003850:  bra.b      0x00003870           ; Jump to function exit
                                               ; Error: Table entry is NULL

; ============================================================================
; SECTION 9: ENTRY VALIDATION - LOAD AND CHECK ENTRY
; ============================================================================

  0x00003852:  lea        (0x81a0).l, A0      ; A0 = 0x81a0 (reload table base)
                                               ; (Could have been preserved from 0x3840)
  0x00003858:  movea.l    (0x0,A0,D0*0x4), A0 ; A0 = *(table[index])
                                               ; Load pointer from table entry
  0x0000385c:  move.l     (A0), D1             ; D1 = *A0 (dereference pointer)
                                               ; Load comparison value from entry

; ============================================================================
; SECTION 10: COMPARE AGAINST SECONDARY PARAMETER
; ============================================================================

  0x0000385e:  cmp.l      (0x8,A6), D1         ; Compare value at 0x8(A6) with D1
                                               ; Stack parameter 3 vs loaded value
  0x00003862:  bne.b      0x0000386c           ; Branch if Not Equal
                                               ; Jump to error if mismatch

; ============================================================================
; SECTION 11: SUCCESS PATH - COPY DATA
; ============================================================================

  0x00003864:  move.l     (0x4,A0), (A1)      ; *A1 = *(A0 + 0x4)
                                               ; Copy data from entry offset +0x4
  0x00003868:  clr.l      D0                   ; D0 = 0x0 (success code)
  0x0000386a:  bra.b      0x00003870           ; Jump to function exit
                                               ; Success: Data copied

; ============================================================================
; SECTION 12: ERROR PATH - ENTRY MISMATCH
; ============================================================================

  0x0000386c:  clr.l      (A1)                 ; *A1 = 0 (clear output location)
  0x0000386e:  moveq      0x8, D0              ; D0 = 0x8 (error code)
                                               ; Error: Entry exists but mismatch

; ============================================================================
; SECTION 13: FUNCTION EXIT - CLEANUP AND RETURN
; ============================================================================

  0x00003870:  unlk       A6                   ; Restore old A6, deallocate frame
  0x00003872:  rts                             ; Return to caller (address on stack)

; ============================================================================
; END OF FUNCTION
; ============================================================================

; ============================================================================
; DATA REFERENCE ANALYSIS
; ============================================================================
;
; Table @ 0x81a0:
;   Array of 32-bit pointers
;   Each entry points to a structure:
;     [+0x0]: 32-bit comparison key
;     [+0x4]: 32-bit output data
;
;   Valid indices: 0, 1, 2
;   (Computed from even input values 2, 4, 6)
;
; ============================================================================

; ============================================================================
; CALLER INFORMATION
; ============================================================================
;
; Called by:
;   0x00002f2a: bsr.l 0x00003820  (in FUN_00002dc6)
;   0x000032c6: bsr.l 0x00003820  (in FUN_00003284)
;
; Return code interpretation by caller:
;   D0 = 0x0: Success - data available in *A1
;   D0 = 0x4: Error - invalid input parameter
;   D0 = 0x8: Error - entry mismatch
;   D0 = 0xc: Error - table entry unavailable
;
; ============================================================================

; ============================================================================
; INSTRUCTION ENCODING NOTES
; ============================================================================
;
; link.w A6, 0x0    : 4E56 0000 (6 bytes total with displacement)
; move.l (0xc,A6),D0: 2C2E 000C (8 bytes - PC-relative addressing)
; movea.l (0x10,A6),A1: 22EE 0010 (8 bytes)
; moveq 0x8, D1     : 7208 (2 bytes)
; cmp.l D0, D1      : BC80 (2 bytes)
; bcs.b 0x3838      : 6506 (2 bytes - branch offset +6)
; btst.l #0x0, D0   : 0880 0000 (6 bytes)
; beq.b 0x383c      : 6704 (2 bytes - branch offset +4)
; moveq 0x4, D0     : 7004 (2 bytes)
; bra.b 0x3870      : 6034 (2 bytes)
; asr.l #0x1, D0    : E2C0 (2 bytes)
; subq.l 0x1, D0    : 5380 (2 bytes)
; lea (0x81a0).l,A0 : 41F9 000081A0 (6 bytes)
; tst.l (0x0,A0,D0*0x4): 4AB0 0C00 (4 bytes - indexed addressing)
; bne.b 0x3852      : 6606 (2 bytes - branch offset +6)
; clr.l (A1)        : 2259 (2 bytes)
; moveq 0xc, D0     : 700C (2 bytes)
; bra.b 0x3870      : 601E (2 bytes)
; lea (0x81a0).l,A0 : 41F9 000081A0 (6 bytes)
; movea.l (0x0,A0,D0*0x4),A0: 20B0 0C00 (4 bytes)
; move.l (A0), D1   : 2C10 (2 bytes)
; cmp.l (0x8,A6),D1 : BC2E 0008 (4 bytes)
; bne.b 0x386c      : 660A (2 bytes - branch offset +10)
; move.l (0x4,A0),(A1): 21E8 0004 (4 bytes)
; clr.l D0          : 4280 (2 bytes)
; bra.b 0x3870      : 6004 (2 bytes)
; clr.l (A1)        : 2259 (2 bytes)
; moveq 0x8, D0     : 7008 (2 bytes)
; unlk A6           : 4E5E (2 bytes)
; rts               : 4E75 (2 bytes)
;
; Total: ~84 bytes
;
; ============================================================================
