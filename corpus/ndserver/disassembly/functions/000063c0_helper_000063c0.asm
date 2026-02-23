; Function: helper_000063c0
; Address: 0x000063c0 - 0x000063e7
; Size: 40 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (40 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x000063c0:  linkw %fp,#0
0x000063c2:  movel %a2,%sp@-
0x000063c4:  moveal %fp@(12),%a2
0x000063c6:  movel %fp@(16),%sp@-
0x000063c8:  invalid
0x000063ca:  .short 0x04ff
0x000063cc:  cmpw %a0@+,%d7
0x000063ce:  moveq #-1,%d1
0x000063d0:  cmpl %d0,%d1
0x000063d2:  bnes 0x00000020
0x000063d4:  invalid
0x000063d6:  .short 0x0401
0x000063d8:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x000063da:  .short 0xfffc
0x000063dc:  unlk %fp
0x000063de:  rts
