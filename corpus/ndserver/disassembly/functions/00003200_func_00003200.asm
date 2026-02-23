; Function: func_00003200
; Address: 0x00003200 - 0x00003283
; Size: 132 bytes
; Frame: 28 bytes
; Purpose: Unknown
; Description: 132 bytes, frame size 28
; Confidence: UNKNOWN
;
0x00003200:  linkw %fp,#-28
0x00003202:  movel %a2,%sp@-
0x00003204:  movel %d2,%sp@-
0x00003206:  pea %fp@(-28)
0x00003208:  invalid
0x0000320a:  btst %d2,%d0
0x0000320c:  movew %fp@+,%a0@(20114)
0x0000320e:  movel %d0,%sp@-
0x00003210:  invalid
0x00003212:  .short 0x04ff
0x00003214:  .short 0xfa3c
0x00003216:  movel %d0,%d2
0x00003218:  .short 0x504f
0x0000321a:  bnes 0x00000076
0x0000321c:  invalid
0x0000321e:  .short 0x0008
0x00003220:  .short 0xfff8
0x00003222:  invalid
0x00003224:  .short 0xffe4
0x00003226:  .short 0xfff4
0x00003228:  moveq #2,%d1
0x0000322a:  movel %d1,%fp@(-4)
0x0000322c:  moveq #24,%d1
0x0000322e:  movel %d1,%fp@(-20)
0x00003230:  clrl %fp@(-16)
0x00003232:  invalid
0x00003234:  .short 0x0001
0x00003236:  .short 0xffeb
0x00003238:  movel %fp@(12),%d1
0x0000323a:  .short 0x4c3c
0x0000323c:  moveb %d0,%d4
0x0000323e:  .short 0x0000
0x00003240:  bset %d1,%a0@(12033)
0x00003242:  clrl %sp@-
0x00003244:  pea 0x00000018
0x00003246:  pea 0x00000100
0x00003248:  pea %fp@(-24)
0x0000324a:  invalid
0x0000324c:  .short 0x04ff
0x0000324e:  .short 0xf75e
0x00003250:  movel %d0,%d2
0x00003252:  movel %fp@(-28),%sp@-
0x00003254:  jsr %a2@
0x00003256:  movel %d0,%sp@-
0x00003258:  invalid
0x0000325a:  .short 0x04ff
0x0000325c:  .short 0xf9e8
0x0000325e:  movel %d2,%d0
0x00003260:  movel %fp@(-36),%d2
0x00003262:  moveal %fp@(-32),%a2
0x00003264:  unlk %fp
0x00003266:  rts
