; Function: main_logic_000033b4
; Address: 0x000033b4 - 0x00003613
; Size: 608 bytes
; Frame: 16 bytes
; Purpose: Main Logic
; Description: Large function (608 bytes) - complex logic
; Confidence: LOW
;
0x000033b4:  linkw %fp,#-16
0x000033b6:  .short 0x48e7
0x000033b8:  movel %a0@(0000000000000078,%d4:l),%d0
0x000033ba:  bclr %d0,%a0@(12078)
0x000033bc:  .short 0x000c
0x000033be:  movel %fp@(8),%sp@-
0x000033c0:  invalid
0x000033c2:  .short 0x04ff
0x000033c4:  .short 0xedfe
0x000033c6:  .short 0x504f
0x000033c8:  invalid
0x000033ca:  .short 0x0000
0x000033cc:  .short 0x8054
0x000033ce:  invalid
0x000033d0:  .short 0x04ff
0x000033d2:  .short 0xed06
0x000033d4:  .short 0x584f
0x000033d6:  tstl %d0
0x000033d8:  beqs 0x00000046
0x000033da:  moveal %fp@(12),%a0
0x000033dc:  moveq #1,%d2
0x000033de:  movel %d2,%a0@(28)
0x000033e0:  invalid
0x000033e2:  .short 0x0000
0x000033e4:  moveq #92,%d5
0x000033e6:  .short 0x0018
0x000033e8:  moveq #1,%d0
0x000033ea:  braw 0x00000256
0x000033ec:  moveq #1,%d2
0x000033ee:  invalid
0x000033f0:  .short 0x0000
0x000033f2:  .short 0x800c
0x000033f4:  moveal %fp@(8),%a0
0x000033f6:  movel %a0@(20),%d0
0x000033f8:  invalid
0x000033fa:  .short 0x0000
0x000033fc:  bset %d3,%d3
0x000033fe:  beqw 0x0000013c
0x00003400:  bgts 0x0000006e
0x00003402:  invalid
0x00003404:  .short 0x0000
0x00003406:  bset %d3,%d2
0x00003408:  beqs 0x0000007c
0x0000340a:  braw 0x0000022a
0x0000340c:  invalid
0x0000340e:  .short 0x0000
0x00003410:  bset %d3,%d4
0x00003412:  beqw 0x00000218
0x00003414:  braw 0x0000022a
0x00003416:  moveal %fp@(8),%a0
0x00003418:  moveq #32,%d2
0x0000341a:  cmpl %a0@(36),%d2
0x0000341c:  bges 0x00000096
0x0000341e:  moveal %fp@(12),%a0
0x00003420:  moveq #4,%d2
0x00003422:  movel %d2,%a0@(28)
0x00003424:  braw 0x00000210
0x00003426:  moveal %fp@(12),%a0
0x00003428:  clrl %a0@(28)
0x0000342a:  clrl %fp@(-16)
0x0000342c:  moveal %fp@(8),%a0
0x0000342e:  moveal %a0,%a1
0x00003430:  moveal %fp@(-16),%a3
0x00003432:  cmpal %a0@(36),%a3
0x00003434:  bgew 0x00000210
0x00003436:  invalid
0x00003438:  .short 0x0000
0x0000343a:  .short 0x8024
0x0000343c:  movel %fp@(-16),%d0
0x0000343e:  addl %d0,%d0
0x00003440:  addl %fp@(-16),%d0
0x00003442:  moveal %a1@(000000000000002c,%d0:l:4),%a0
0x00003444:  subal %a1,%a1
0x00003446:  lea %a1@(0000000000000000,%a1:l:2),%a3
0x00003448:  movel %a3,%d0
0x0000344a:  asll #2,%d0
0x0000344c:  movel %a0,%d1
0x0000344e:  subl %a2@(0000000000000004,%d0:l),%d1
0x00003450:  cmpl %a2@(0000000000000008,%d0:l),%d1
0x00003452:  bcss 0x000000f4
0x00003454:  .short 0x5249
0x00003456:  moveq #3,%d2
0x00003458:  cmpl %a1,%d2
0x0000345a:  bges 0x000000ca
0x0000345c:  clrl %fp@(-12)
0x0000345e:  tstl %fp@(-12)
0x00003460:  bnes 0x000000fe
0x00003462:  braw 0x000001be
0x00003464:  addl %a2@(0000000000000000,%d0:l),%d1
0x00003466:  movel %d1,%fp@(-12)
0x00003468:  bras 0x000000ea
0x0000346a:  movel %fp@(-16),%d0
0x0000346c:  addl %d0,%d0
0x0000346e:  addl %fp@(-16),%d0
0x00003470:  asll #2,%d0
0x00003472:  moveal %fp@(8),%a0
0x00003474:  movel %a0@(0000000000000030,%d0:l),%sp@-
0x00003476:  movel %fp@(-12),%sp@-
0x00003478:  movel %a0@(0000000000000028,%d0:l),%sp@-
0x0000347a:  invalid
0x0000347c:  .short 0x0000
0x0000347e:  .short 0x8020
0x00003480:  jsr %a0@
0x00003482:  .short 0x504f
0x00003484:  .short 0x584f
0x00003486:  addql #1,%fp@(-16)
0x00003488:  moveal %fp@(8),%a1
0x0000348a:  moveal %fp@(-16),%a3
0x0000348c:  cmpal %a1@(36),%a3
0x0000348e:  blts 0x000000ba
0x00003490:  braw 0x00000210
0x00003492:  moveal %fp@(8),%a0
0x00003494:  moveq #32,%d2
0x00003496:  cmpl %a0@(36),%d2
0x00003498:  bltw 0x00000088
0x0000349a:  moveal %fp@(12),%a0
0x0000349c:  clrl %a0@(28)
0x0000349e:  clrl %fp@(-16)
0x000034a0:  moveal %fp@(8),%a0
0x000034a2:  moveal %a0,%a1
0x000034a4:  moveal %fp@(-16),%a3
0x000034a6:  cmpal %a0@(36),%a3
0x000034a8:  bgew 0x00000210
0x000034aa:  invalid
0x000034ac:  .short 0x0000
0x000034ae:  .short 0x8024
0x000034b0:  movel %fp@(-16),%d0
0x000034b2:  addl %d0,%d0
0x000034b4:  addl %fp@(-16),%d0
0x000034b6:  movel %a1@(0000000000000028,%d0:l:4),%sp@-
0x000034b8:  invalid
0x000034ba:  breakpoint
0x000034bc:  wddatal %a0@
0x000034be:  movel %fp@(-16),%d0
0x000034c0:  addl %d0,%d0
0x000034c2:  addl %fp@(-16),%d0
0x000034c4:  moveal %fp@(8),%a0
0x000034c6:  moveal %a0@(000000000000002c,%d0:l:4),%a1
0x000034c8:  .short 0x584f
0x000034ca:  subal %a0,%a0
0x000034cc:  lea %a0@(0000000000000000,%a0:l:2),%a3
0x000034ce:  movel %a3,%d0
0x000034d0:  asll #2,%d0
0x000034d2:  movel %a1,%d1
0x000034d4:  subl %a2@(0000000000000004,%d0:l),%d1
0x000034d6:  cmpl %a2@(0000000000000008,%d0:l),%d1
0x000034d8:  bcss 0x000001ca
0x000034da:  .short 0x5248
0x000034dc:  moveq #3,%d2
0x000034de:  cmpl %a0,%d2
0x000034e0:  bges 0x00000198
0x000034e2:  clrl %fp@(-8)
0x000034e4:  tstl %fp@(-8)
0x000034e6:  bnes 0x000001d4
0x000034e8:  moveal %fp@(12),%a0
0x000034ea:  moveq #1,%d2
0x000034ec:  movel %d2,%a0@(28)
0x000034ee:  bras 0x00000210
0x000034f0:  addl %a2@(0000000000000000,%d0:l),%d1
0x000034f2:  movel %d1,%fp@(-8)
0x000034f4:  bras 0x000001b8
0x000034f6:  movel %fp@(-16),%d0
0x000034f8:  addl %d0,%d0
0x000034fa:  addl %fp@(-16),%d0
0x000034fc:  asll #2,%d0
0x000034fe:  moveal %fp@(8),%a0
0x00003500:  movel %a0@(0000000000000030,%d0:l),%sp@-
0x00003502:  movel %a0@(0000000000000028,%d0:l),%sp@-
0x00003504:  movel %fp@(-8),%sp@-
0x00003506:  invalid
0x00003508:  .short 0x0000
0x0000350a:  .short 0x8020
0x0000350c:  jsr %a0@
0x0000350e:  .short 0x504f
0x00003510:  .short 0x584f
0x00003512:  addql #1,%fp@(-16)
0x00003514:  moveal %fp@(8),%a1
0x00003516:  moveal %fp@(-16),%a3
0x00003518:  cmpal %a1@(36),%a3
0x0000351a:  bltw 0x0000016e
0x0000351c:  moveq #1,%d2
0x0000351e:  movel %d2,%fp@(-4)
0x00003520:  bras 0x00000240
0x00003522:  moveal %fp@(12),%a0
0x00003524:  invalid
0x00003526:  breakpoint
0x00003528:  .short 0xfecf
0x0000352a:  .short 0x001c
0x0000352c:  clrl %fp@(-4)
0x0000352e:  bras 0x00000240
0x00003530:  invalid
0x00003532:  .short 0x0000
0x00003534:  .short 0x800c
0x00003536:  movel %fp@(12),%sp@-
0x00003538:  movel %fp@(8),%sp@-
0x0000353a:  invalid
0x0000353c:  .short 0x0000
0x0000353e:  movel %d6,%d6
0x00003540:  bras 0x00000256
0x00003542:  invalid
0x00003544:  .short 0x0000
0x00003546:  .short 0x800c
0x00003548:  moveal %fp@(12),%a0
0x0000354a:  invalid
0x0000354c:  .short 0x0000
0x0000354e:  moveq #92,%d5
0x00003550:  .short 0x0018
0x00003552:  movel %fp@(-4),%d0
0x00003554:  invalid
0x00003556:  cmpib #-28,%d4
0x00003558:  unlk %fp
0x0000355a:  rts
