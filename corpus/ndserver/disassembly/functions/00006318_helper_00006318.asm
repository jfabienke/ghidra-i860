; Function: helper_00006318
; Address: 0x00006318 - 0x0000633f
; Size: 40 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (40 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00006318:  linkw %fp,#0
0x0000631a:  movel %a2,%sp@-
0x0000631c:  moveal %fp@(12),%a2
0x0000631e:  movel %fp@(16),%sp@-
0x00006320:  invalid
0x00006322:  .short 0x04ff
0x00006324:  .short 0xbf72
0x00006326:  moveq #-1,%d1
0x00006328:  cmpl %d0,%d1
0x0000632a:  bnes 0x00000020
0x0000632c:  invalid
0x0000632e:  .short 0x0401
0x00006330:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x00006332:  .short 0xfffc
0x00006334:  unlk %fp
0x00006336:  rts
