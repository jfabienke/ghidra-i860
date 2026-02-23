; Function: func_00007032
; Address: 0x00007032 - 0x00007071
; Size: 64 bytes
; Frame: 4 bytes
; Purpose: Unknown
; Description: 64 bytes, frame size 4
; Confidence: UNKNOWN
;
0x00007032:  linkw %fp,#-4
0x00007034:  pea %fp@(-4)
0x00007036:  movel %fp@(20),%sp@-
0x00007038:  movel %fp@(16),%sp@-
0x0000703a:  movel %fp@(12),%sp@-
0x0000703c:  invalid
0x0000703e:  .short 0x04ff
0x00007040:  .short 0xb6c0
0x00007042:  invalid
0x00007044:  .short 0x0000
0x00007046:  .short 0x8018
0x00007048:  .short 0x504f
0x0000704a:  .short 0x504f
0x0000704c:  beqs 0x00000032
0x0000704e:  movel %fp@(8),%sp@-
0x00007050:  invalid
0x00007052:  .short 0x0000
0x00007054:  .short 0x003e
0x00007056:  bras 0x0000003c
0x00007058:  moveq #8,%d1
0x0000705a:  invalid
0x0000705c:  .short 0x0401
0x0000705e:  bclr %d2,%a0@(ffffffffffffffff,%d7:w)
0x00007060:  unlk %fp
0x00007062:  rts
