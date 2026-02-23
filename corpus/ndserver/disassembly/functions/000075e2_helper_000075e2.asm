; Function: helper_000075e2
; Address: 0x000075e2 - 0x000075f7
; Size: 22 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (22 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x000075e2:  linkw %fp,#0
0x000075e4:  moveal %fp@(12),%a0
0x000075e6:  invalid
0x000075e8:  breakpoint
0x000075ea:  .short 0xfecf
0x000075ec:  .short 0x001c
0x000075ee:  moveq #1,%d0
0x000075f0:  unlk %fp
0x000075f2:  rts
