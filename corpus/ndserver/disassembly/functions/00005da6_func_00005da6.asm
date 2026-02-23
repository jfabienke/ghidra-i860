; Function: func_00005da6
; Address: 0x00005da6 - 0x00005de9
; Size: 68 bytes
; Frame: 32 bytes
; Purpose: Unknown
; Description: 68 bytes, frame size 32
; Confidence: UNKNOWN
;
0x00005da6:  linkw %fp,#-32
0x00005da8:  invalid
0x00005daa:  .short 0x0000
0x00005dac:  moveq #-112,%d6
0x00005dae:  .short 0xfff8
0x00005db0:  invalid
0x00005db2:  .short 0x000c
0x00005db4:  .short 0xfffc
0x00005db6:  clrb %fp@(-29)
0x00005db8:  moveq #32,%d1
0x00005dba:  movel %d1,%fp@(-28)
0x00005dbc:  clrl %fp@(-24)
0x00005dbe:  invalid
0x00005dc0:  .short 0x0008
0x00005dc2:  .short 0xfff0
0x00005dc4:  clrl %fp@(-20)
0x00005dc6:  invalid
0x00005dc8:  .short 0x0000
0x00005dca:  bset %d2,%a5@
0x00005dcc:  .short 0xfff4
0x00005dce:  clrl %sp@-
0x00005dd0:  clrl %sp@-
0x00005dd2:  pea %fp@(-32)
0x00005dd4:  invalid
0x00005dd6:  .short 0x04ff
0x00005dd8:  mulsw %a0@(000000000000005e,%d4:l:8),%d5
0x00005dda:  rts
