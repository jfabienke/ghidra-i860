; Function: helper_0000302c
; Address: 0x0000302c - 0x0000305b
; Size: 48 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (48 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x0000302c:  linkw %fp,#0
0x0000302e:  movel %d2,%sp@-
0x00003030:  invalid
0x00003032:  .short 0x04ff
0x00003034:  .short 0xf662
0x00003036:  movel %d0,%d2
0x00003038:  pea 0x00000005
0x0000303a:  invalid
0x0000303c:  .short 0x04ff
0x0000303e:  cp1stw %d4,%a2@-,#2,#151
0x00003040:  movel %d2,%sp@-
0x00003042:  invalid
0x00003044:  .short 0x04ff
0x00003046:  .short 0xf7e4
0x00003048:  .short 0x504f
0x0000304a:  tstl %d0
0x0000304c:  beqs 0x0000000e
0x0000304e:  movel %fp@(-4),%d2
0x00003050:  unlk %fp
0x00003052:  rts
