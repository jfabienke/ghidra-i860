; Function: func_00006474
; Address: 0x00006474 - 0x00006517
; Size: 164 bytes
; Frame: 4 bytes
; Purpose: Unknown
; Description: 164 bytes, frame size 4
; Confidence: UNKNOWN
;
0x00006474:  linkw %fp,#-4
0x00006476:  movel %d3,%sp@-
0x00006478:  movel %d2,%sp@-
0x0000647a:  movel %fp@(8),%d3
0x0000647c:  movel %fp@(12),%d2
0x0000647e:  pea %fp@(-4)
0x00006480:  invalid
0x00006482:  .short 0x0000
0x00006484:  invalid
0x00006486:  movel %d2,%sp@-
0x00006488:  movel %d3,%sp@-
0x0000648a:  invalid
0x0000648c:  breakpoint
0x0000648e:  .short 0xe5be
0x00006490:  .short 0x504f
0x00006492:  .short 0x504f
0x00006494:  tstl %d0
0x00006496:  beqs 0x00000096
0x00006498:  pea %fp@(-4)
0x0000649a:  invalid
0x0000649c:  .short 0x04ff
0x0000649e:  andl 0x00002f00,%d6
0x000064a0:  invalid
0x000064a2:  .short 0x04ff
0x000064a4:  andl %d3,%fp@-
0x000064a6:  .short 0x504f
0x000064a8:  tstl %d0
0x000064aa:  beqs 0x00000054
0x000064ac:  movel %d0,%sp@-
0x000064ae:  invalid
0x000064b0:  .short 0x0000
0x000064b2:  invalid
0x000064b4:  invalid
0x000064b6:  .short 0x04ff
0x000064b8:  .short 0xc402
0x000064ba:  bras 0x00000096
0x000064bc:  movel %fp@(-4),%sp@-
0x000064be:  invalid
0x000064c0:  .short 0x0000
0x000064c2:  invalid
0x000064c4:  movel %d2,%sp@-
0x000064c6:  movel %d3,%sp@-
0x000064c8:  invalid
0x000064ca:  breakpoint
0x000064cc:  .short 0xed7e
0x000064ce:  .short 0x504f
0x000064d0:  .short 0x504f
0x000064d2:  tstl %d0
0x000064d4:  bnes 0x00000076
0x000064d6:  movel %fp@(-4),%d0
0x000064d8:  bras 0x00000098
0x000064da:  movel %d0,%sp@-
0x000064dc:  invalid
0x000064de:  .short 0x0000
0x000064e0:  moveq #27,%d5
0x000064e2:  invalid
0x000064e4:  .short 0x04ff
0x000064e6:  mulsw %a0@,%d1
0x000064e8:  movel %fp@(-4),%sp@-
0x000064ea:  invalid
0x000064ec:  .short 0x04ff
0x000064ee:  .short 0xcc60
0x000064f0:  movel %d0,%sp@-
0x000064f2:  invalid
0x000064f4:  .short 0x04ff
0x000064f6:  .short 0xc754
0x000064f8:  clrl %d0
0x000064fa:  movel %fp@(-12),%d2
0x000064fc:  movel %fp@(-8),%d3
0x000064fe:  unlk %fp
0x00006500:  rts
