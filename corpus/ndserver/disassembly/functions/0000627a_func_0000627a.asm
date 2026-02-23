; Function: func_0000627a
; Address: 0x0000627a - 0x000062b7
; Size: 62 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 62 bytes, frame size 0
; Confidence: UNKNOWN
;
0x0000627a:  linkw %fp,#0
0x0000627c:  movel %a3,%sp@-
0x0000627e:  movel %a2,%sp@-
0x00006280:  moveal %fp@(12),%a3
0x00006282:  moveal %fp@(24),%a2
0x00006284:  movel %fp@(28),%sp@-
0x00006286:  movel %fp@(20),%sp@-
0x00006288:  movel %fp@(16),%sp@-
0x0000628a:  invalid
0x0000628c:  .short 0x04ff
0x0000628e:  .short 0xcaca
0x00006290:  tstl %d0
0x00006292:  bles 0x0000002a
0x00006294:  movel %d0,%a2@
0x00006296:  bras 0x00000032
0x00006298:  clrl %a2@
0x0000629a:  invalid
0x0000629c:  .short 0x0401
0x0000629e:  bclr %d2,%a0@(000000000000006e,%d2:w:4)
0x000062a0:  .short 0xfff8
0x000062a2:  moveal %fp@(-4),%a3
0x000062a4:  unlk %fp
0x000062a6:  rts
