; Function: helper_000062e8
; Address: 0x000062e8 - 0x00006317
; Size: 48 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (48 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x000062e8:  linkw %fp,#0
0x000062ea:  movel %a2,%sp@-
0x000062ec:  moveal %fp@(12),%a2
0x000062ee:  movel %fp@(24),%sp@-
0x000062f0:  movel %fp@(20),%sp@-
0x000062f2:  movel %fp@(16),%sp@-
0x000062f4:  invalid
0x000062f6:  .short 0x04ff
0x000062f8:  muluw %d4,%d4
0x000062fa:  moveq #-1,%d1
0x000062fc:  cmpl %d0,%d1
0x000062fe:  bnes 0x00000028
0x00006300:  invalid
0x00006302:  .short 0x0401
0x00006304:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x00006306:  .short 0xfffc
0x00006308:  unlk %fp
0x0000630a:  rts
