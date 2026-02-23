; Function: func_00006518
; Address: 0x00006518 - 0x00006601
; Size: 234 bytes
; Frame: 4 bytes
; Purpose: Unknown
; Description: 234 bytes, frame size 4
; Confidence: UNKNOWN
;
0x00006518:  linkw %fp,#-4
0x0000651a:  movel %a3,%sp@-
0x0000651c:  movel %a2,%sp@-
0x0000651e:  moveal %fp@(8),%a3
0x00006520:  moveal %fp@(12),%a2
0x00006522:  clrl %d0
0x00006524:  moveb %a3@(3),%d0
0x00006526:  moveq #48,%d1
0x00006528:  cmpl %a3@(4),%d1
0x0000652a:  bnes 0x00000024
0x0000652c:  moveq #1,%d1
0x0000652e:  cmpl %d0,%d1
0x00006530:  beqs 0x00000030
0x00006532:  invalid
0x00006534:  breakpoint
0x00006536:  .short 0xfed0
0x00006538:  .short 0x001c
0x0000653a:  braw 0x000000de
0x0000653c:  movel %a3@(24),%d1
0x0000653e:  invalid
0x00006540:  .short 0x0000
0x00006542:  moveq #-36,%d6
0x00006544:  bnes 0x0000005c
0x00006546:  movel %a3@(32),%d1
0x00006548:  invalid
0x0000654a:  .short 0x0000
0x0000654c:  moveq #-32,%d6
0x0000654e:  bnes 0x0000005c
0x00006550:  invalid
0x00006552:  .short 0x0000
0x00006554:  moveb %a4@+,%sp@+
0x00006556:  .short 0xfffc
0x00006558:  movel %a3@(40),%d1
0x0000655a:  invalid
0x0000655c:  .short 0x0000
0x0000655e:  moveq #-28,%d6
0x00006560:  beqs 0x00000066
0x00006562:  invalid
0x00006564:  breakpoint
0x00006566:  .short 0xfed0
0x00006568:  .short 0x001c
0x0000656a:  bras 0x0000008c
0x0000656c:  movel %a3@(44),%sp@-
0x0000656e:  pea %fp@(-4)
0x00006570:  pea %a2@(60)
0x00006572:  movel %a3@(36),%sp@-
0x00006574:  pea %a3@(28)
0x00006576:  movel %a3@(12),%sp@-
0x00006578:  invalid
0x0000657a:  breakpoint
0x0000657c:  .short 0xfce2
0x0000657e:  movel %d0,%a2@(36)
0x00006580:  clrl %a2@(28)
0x00006582:  tstl %a2@(28)
0x00006584:  bnes 0x000000de
0x00006586:  invalid
0x00006588:  .short 0x0000
0x0000658a:  moveq #-24,%d6
0x0000658c:  .short 0x0020
0x0000658e:  invalid
0x00006590:  .short 0x0000
0x00006592:  moveq #-20,%d6
0x00006594:  .short 0x0028
0x00006596:  invalid
0x00006598:  .short 0x001c
0x0000659a:  .short 0x002c
0x0000659c:  invalid
0x0000659e:  .short 0x0000
0x000065a0:  moveq #-16,%d6
0x000065a2:  .short 0x0030
0x000065a4:  invalid
0x000065a6:  .short 0x0000
0x000065a8:  moveq #-12,%d6
0x000065aa:  .short 0x0034
0x000065ac:  invalid
0x000065ae:  .short 0x0000
0x000065b0:  moveq #-8,%d6
0x000065b2:  .short 0x0038
0x000065b4:  invalid
0x000065b6:  .short 0xfffc
0x000065b8:  .short 0x0038
0x000065ba:  movel %fp@(-4),%d0
0x000065bc:  addql #3,%d0
0x000065be:  moveq #-4,%d1
0x000065c0:  andl %d1,%d0
0x000065c2:  invalid
0x000065c4:  .short 0x0001
0x000065c6:  .short 0x0003
0x000065c8:  moveq #60,%d1
0x000065ca:  addl %d0,%d1
0x000065cc:  movel %d1,%a2@(4)
0x000065ce:  moveal %fp@(-12),%a2
0x000065d0:  moveal %fp@(-8),%a3
0x000065d2:  unlk %fp
0x000065d4:  rts
