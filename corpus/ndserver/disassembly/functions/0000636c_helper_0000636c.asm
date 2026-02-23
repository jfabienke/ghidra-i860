; Function: helper_0000636c
; Address: 0x0000636c - 0x00006397
; Size: 44 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (44 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x0000636c:  linkw %fp,#0
0x0000636e:  movel %a2,%sp@-
0x00006370:  moveal %fp@(12),%a2
0x00006372:  movel %fp@(20),%sp@-
0x00006374:  movel %fp@(16),%sp@-
0x00006376:  invalid
0x00006378:  .short 0x04ff
0x0000637a:  .short 0xc4cc
0x0000637c:  moveq #-1,%d1
0x0000637e:  cmpl %d0,%d1
0x00006380:  bnes 0x00000024
0x00006382:  invalid
0x00006384:  .short 0x0401
0x00006386:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x00006388:  .short 0xfffc
0x0000638a:  unlk %fp
0x0000638c:  rts
