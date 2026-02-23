; Function: helper_000063e8
; Address: 0x000063e8 - 0x00006413
; Size: 44 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (44 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x000063e8:  linkw %fp,#0
0x000063ea:  movel %a2,%sp@-
0x000063ec:  moveal %fp@(12),%a2
0x000063ee:  movel %fp@(20),%sp@-
0x000063f0:  movel %fp@(16),%sp@-
0x000063f2:  invalid
0x000063f4:  .short 0x04ff
0x000063f6:  cmpb %a2@(ffffffffffffffff,%d7:w:2),%d7
0x000063f8:  cmpl %d0,%d1
0x000063fa:  bnes 0x00000024
0x000063fc:  invalid
0x000063fe:  .short 0x0401
0x00006400:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x00006402:  .short 0xfffc
0x00006404:  unlk %fp
0x00006406:  rts
