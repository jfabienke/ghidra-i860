; Function: helper_00006340
; Address: 0x00006340 - 0x0000636b
; Size: 44 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (44 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00006340:  linkw %fp,#0
0x00006342:  movel %a2,%sp@-
0x00006344:  moveal %fp@(12),%a2
0x00006346:  movel %fp@(20),%sp@-
0x00006348:  movel %fp@(16),%sp@-
0x0000634a:  invalid
0x0000634c:  .short 0x04ff
0x0000634e:  eorl %d7,%a4@
0x00006350:  moveq #-1,%d1
0x00006352:  cmpl %d0,%d1
0x00006354:  bnes 0x00000024
0x00006356:  invalid
0x00006358:  .short 0x0401
0x0000635a:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x0000635c:  .short 0xfffc
0x0000635e:  unlk %fp
0x00006360:  rts
