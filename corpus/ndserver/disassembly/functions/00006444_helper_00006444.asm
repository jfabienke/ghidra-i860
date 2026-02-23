; Function: helper_00006444
; Address: 0x00006444 - 0x00006473
; Size: 48 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (48 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00006444:  linkw %fp,#0
0x00006446:  movel %a2,%sp@-
0x00006448:  moveal %fp@(12),%a2
0x0000644a:  movel %fp@(24),%sp@-
0x0000644c:  movel %fp@(20),%sp@-
0x0000644e:  movel %fp@(16),%sp@-
0x00006450:  invalid
0x00006452:  .short 0x04ff
0x00006454:  .short 0xc450
0x00006456:  moveq #-1,%d1
0x00006458:  cmpl %d0,%d1
0x0000645a:  bnes 0x00000028
0x0000645c:  invalid
0x0000645e:  .short 0x0401
0x00006460:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x00006462:  .short 0xfffc
0x00006464:  unlk %fp
0x00006466:  rts
