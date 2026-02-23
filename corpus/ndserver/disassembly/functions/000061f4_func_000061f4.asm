; Function: func_000061f4
; Address: 0x000061f4 - 0x00006279
; Size: 134 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 134 bytes, frame size 0
; Confidence: UNKNOWN
;
0x000061f4:  linkw %fp,#0
0x000061f6:  movel %a2,%sp@-
0x000061f8:  moveal %fp@(8),%a2
0x000061fa:  moveal %fp@(12),%a1
0x000061fc:  invalid
0x000061fe:  .short 0x0001
0x00006200:  .short 0x0003
0x00006202:  moveq #32,%d1
0x00006204:  movel %d1,%a1@(4)
0x00006206:  invalid
0x00006208:  .short 0x0008
0x0000620a:  .short 0x0008
0x0000620c:  clrl %a1@(12)
0x0000620e:  invalid
0x00006210:  .short 0x0010
0x00006212:  .short 0x0010
0x00006214:  moveq #100,%d1
0x00006216:  addl %a2@(20),%d1
0x00006218:  movel %d1,%a1@(20)
0x0000621a:  invalid
0x0000621c:  .short 0x0000
0x0000621e:  moveq #-52,%d6
0x00006220:  .short 0x0018
0x00006222:  invalid
0x00006224:  breakpoint
0x00006226:  .short 0xfed1
0x00006228:  .short 0x001c
0x0000622a:  movel %a2@(20),%d0
0x0000622c:  invalid
0x0000622e:  breakpoint
0x00006230:  .short 0xf8f8
0x00006232:  moveq #2,%d1
0x00006234:  cmpl %d0,%d1
0x00006236:  bcss 0x00000064
0x00006238:  movel %a2@(20),%d0
0x0000623a:  invalid
0x0000623c:  .short 0x0000
0x0000623e:  bras 0x0000000e
0x00006240:  tstl %a0@(0000000000000000,%d0:l:4)
0x00006242:  bnes 0x00000068
0x00006244:  clrl %d0
0x00006246:  bras 0x0000007e
0x00006248:  movel %a2@(20),%d0
0x0000624a:  invalid
0x0000624c:  .short 0x0000
0x0000624e:  bras 0x00000022
0x00006250:  movel %a1,%sp@-
0x00006252:  movel %a2,%sp@-
0x00006254:  moveal %a0@(0000000000000000,%d0:l:4),%a0
0x00006256:  jsr %a0@
0x00006258:  moveq #1,%d0
0x0000625a:  moveal %fp@(-4),%a2
0x0000625c:  unlk %fp
0x0000625e:  rts
