; Function: helper_00006414
; Address: 0x00006414 - 0x00006443
; Size: 48 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (48 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00006414:  linkw %fp,#0
0x00006416:  movel %a2,%sp@-
0x00006418:  moveal %fp@(12),%a2
0x0000641a:  movel %fp@(24),%sp@-
0x0000641c:  movel %fp@(20),%sp@-
0x0000641e:  movel %fp@(16),%sp@-
0x00006420:  invalid
0x00006422:  .short 0x04ff
0x00006424:  cmpb %a0,%d7
0x00006426:  moveq #-1,%d1
0x00006428:  cmpl %d0,%d1
0x0000642a:  bnes 0x00000028
0x0000642c:  invalid
0x0000642e:  .short 0x0401
0x00006430:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x00006432:  .short 0xfffc
0x00006434:  unlk %fp
0x00006436:  rts
