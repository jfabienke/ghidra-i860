; ============================================================================
; Function: FUN_00005d26
; Address: 0x00005d26 (23846 decimal)
; Size: 58 bytes
; Architecture: Motorola 68000 (m68k)
; Complexity: Low
; Category: Callback/Device Handler
; ============================================================================

  0x00005d26:  link.w     A6,0x0
  0x00005d2a:  move.l     D2,-(SP)
  0x00005d2c:  move.l     (0xc,A6),D2
  0x00005d30:  bsr.l      0x0500315e
  0x00005d36:  asr.l      #0x1,D2
  0x00005d38:  lea        (0x819c).l,A0
  0x00005d3e:  movea.l    (0x0,A0,D2*0x4),A0
  0x00005d42:  tst.l      A0
  0x00005d44:  beq.b      0x00005d56
  0x00005d46:  movea.l    (0x1c,A0),A0
  0x00005d4a:  move.l     (A0),D0
  0x00005d4c:  moveq      0xc,D1
  0x00005d4e:  or.l       D1,D0
  0x00005d50:  move.l     D0,(A0)
  0x00005d52:  clr.l      D0
  0x00005d54:  bra.b      0x00005d58
  0x00005d56:  moveq      0x4,D0
  0x00005d58:  move.l     (-0x4,A6),D2
  0x00005d5c:  unlk       A6
  0x00005d5e:  rts

; ============================================================================
; End of function FUN_00005d26
; ============================================================================
