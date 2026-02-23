; Function: helper_00006398
; Address: 0x00006398 - 0x000063bf
; Size: 40 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (40 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00006398:  linkw %fp,#0
0x0000639a:  movel %a2,%sp@-
0x0000639c:  moveal %fp@(12),%a2
0x0000639e:  movel %fp@(16),%sp@-
0x000063a0:  invalid
0x000063a2:  .short 0x04ff
0x000063a4:  andl %fp@-,%d7
0x000063a6:  moveq #-1,%d1
0x000063a8:  cmpl %d0,%d1
0x000063aa:  bnes 0x00000020
0x000063ac:  invalid
0x000063ae:  .short 0x0401
0x000063b0:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x000063b2:  .short 0xfffc
0x000063b4:  unlk %fp
0x000063b6:  rts
