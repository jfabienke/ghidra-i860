; Function: helper_000075cc
; Address: 0x000075cc - 0x000075f7
; Size: 44 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (44 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x000075cc:  linkw %fp,#0
0x000075ce:  movel %fp@(8),%sp@-
0x000075d0:  invalid
0x000075d2:  .short 0x0000
0x000075d4:  .short 0x80f0
0x000075d6:  invalid
0x000075d8:  .short 0x04ff
0x000075da:  cmpl %a0,%d1
0x000075dc:  nop
0x000075de:  linkw %fp,#0
0x000075e0:  moveal %fp@(12),%a0
0x000075e2:  invalid
0x000075e4:  breakpoint
0x000075e6:  .short 0xfecf
0x000075e8:  .short 0x001c
0x000075ea:  moveq #1,%d0
0x000075ec:  unlk %fp
0x000075ee:  rts
