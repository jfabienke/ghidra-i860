; Function: helper_000062b8
; Address: 0x000062b8 - 0x000062e7
; Size: 48 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (48 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x000062b8:  linkw %fp,#0
0x000062ba:  movel %a2,%sp@-
0x000062bc:  moveal %fp@(12),%a2
0x000062be:  movel %fp@(24),%sp@-
0x000062c0:  movel %fp@(20),%sp@-
0x000062c2:  movel %fp@(16),%sp@-
0x000062c4:  invalid
0x000062c6:  .short 0x04ff
0x000062c8:  .short 0xd03e
0x000062ca:  moveq #-1,%d1
0x000062cc:  cmpl %d0,%d1
0x000062ce:  bnes 0x00000028
0x000062d0:  invalid
0x000062d2:  .short 0x0401
0x000062d4:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x000062d6:  .short 0xfffc
0x000062d8:  unlk %fp
0x000062da:  rts
