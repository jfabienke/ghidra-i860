; Function: func_0000746c
; Address: 0x0000746c - 0x000075cb
; Size: 352 bytes
; Frame: 24 bytes
; Purpose: Unknown
; Description: 352 bytes, frame size 24
; Confidence: UNKNOWN
;
0x0000746c:  linkw %fp,#-24
0x0000746e:  movel %a2,%sp@-
0x00007470:  moveal %fp@(8),%a0
0x00007472:  invalid
0x00007474:  .short 0x002c
0x00007476:  .short 0xffe8
0x00007478:  invalid
0x0000747a:  .short 0x07ff
0x0000747c:  cp1stb %sp,%d0,#8,#488
0x0000747e:  movel %fp@(12),%d0
0x00007480:  invalid
0x00007482:  .short 0x0000
0x00007484:  btst %d0,%d0
0x00007486:  lsrl #2,%d0
0x00007488:  movel %d0,%fp@(-8)
0x0000748a:  subql #3,%fp@(-8)
0x0000748c:  invalid
0x0000748e:  .short 0x03ff
0x00007490:  breakpoint
0x00007492:  .short 0xfff8
0x00007494:  movel %fp@(-8),%d0
0x00007496:  invalid
0x00007498:  bvcw 0x0000003c
0x0000749a:  movel %d0,%fp@(-8)
0x0000749c:  movel %d0,%fp@(-4)
0x0000749e:  invalid
0x000074a0:  .short 0x0000
0x000074a2:  mvzw %a4,%d2
0x000074a4:  pea 0x0000000a
0x000074a6:  invalid
0x000074a8:  btst %d2,%d0
0x000074aa:  .short 0x2f7e
0x000074ac:  jsr %a2@
0x000074ae:  movel %d0,%fp@(-16)
0x000074b0:  invalid
0x000074b2:  .short 0x0000
0x000074b4:  mvzw %a4,%d2
0x000074b6:  pea 0x0000000b
0x000074b8:  jsr %a2@
0x000074ba:  movel %d0,%fp@(-20)
0x000074bc:  invalid
0x000074be:  .short 0x0000
0x000074c0:  .short 0x80f0
0x000074c2:  invalid
0x000074c4:  .short 0x04ff
0x000074c6:  cmpal %a4@-,%a4
0x000074c8:  .short 0xdefc
0x000074ca:  .short 0x0014
0x000074cc:  tstl %d0
0x000074ce:  bnew 0x00000134
0x000074d0:  movel %fp@(-24),%d0
0x000074d2:  .short 0x0a40
0x000074d4:  .short 0x0004
0x000074d6:  moveal %d0,%a1
0x000074d8:  invalid
0x000074da:  .short 0xa000
0x000074dc:  .short 0x0000
0x000074de:  addql #4,%fp@(-24)
0x000074e0:  movel %fp@(-24),%d0
0x000074e2:  .short 0x0a40
0x000074e4:  .short 0x0004
0x000074e6:  moveal %d0,%a1
0x000074e8:  invalid
0x000074ea:  .short 0xa000
0x000074ec:  .short 0x0000
0x000074ee:  addql #4,%fp@(-24)
0x000074f0:  movel %fp@(-24),%d0
0x000074f2:  .short 0x0a40
0x000074f4:  .short 0x0004
0x000074f6:  moveal %d0,%a1
0x000074f8:  movel %fp@(-4),%a1@
0x000074fa:  addql #4,%fp@(-24)
0x000074fc:  movel %fp@(-24),%d0
0x000074fe:  .short 0x0a40
0x00007500:  .short 0x0004
0x00007502:  moveal %d0,%a1
0x00007504:  invalid
0x00007506:  .short 0xa000
0x00007508:  .short 0x0000
0x0000750a:  addql #4,%fp@(-24)
0x0000750c:  movel %fp@(-24),%d0
0x0000750e:  .short 0x0a40
0x00007510:  .short 0x0004
0x00007512:  moveal %d0,%a1
0x00007514:  invalid
0x00007516:  .short 0xa000
0x00007518:  .short 0x0000
0x0000751a:  addql #4,%fp@(-24)
0x0000751c:  movel %fp@(-24),%d0
0x0000751e:  .short 0x0a40
0x00007520:  .short 0x0004
0x00007522:  moveal %d0,%a1
0x00007524:  invalid
0x00007526:  .short 0xa000
0x00007528:  .short 0x0000
0x0000752a:  addql #4,%fp@(-24)
0x0000752c:  movel %fp@(-24),%d0
0x0000752e:  .short 0x0a40
0x00007530:  .short 0x0004
0x00007532:  moveal %d0,%a1
0x00007534:  invalid
0x00007536:  .short 0xa000
0x00007538:  .short 0x0000
0x0000753a:  addql #4,%fp@(-24)
0x0000753c:  movel %fp@(-24),%d0
0x0000753e:  .short 0x0a40
0x00007540:  .short 0x0004
0x00007542:  moveal %d0,%a1
0x00007544:  invalid
0x00007546:  .short 0xa000
0x00007548:  .short 0x0000
0x0000754a:  movel %fp@(-16),%sp@-
0x0000754c:  pea 0x0000000a
0x0000754e:  jsr %a2@
0x00007550:  movel %fp@(-20),%sp@-
0x00007552:  pea 0x0000000b
0x00007554:  jsr %a2@
0x00007556:  clrl %d0
0x00007558:  bras 0x00000158
0x0000755a:  movel %fp@(-16),%sp@-
0x0000755c:  pea 0x0000000a
0x0000755e:  invalid
0x00007560:  btst %d2,%d0
0x00007562:  .short 0x2f7e
0x00007564:  jsr %a2@
0x00007566:  movel %fp@(-20),%sp@-
0x00007568:  pea 0x0000000b
0x0000756a:  jsr %a2@
0x0000756c:  moveq #14,%d1
0x0000756e:  invalid
0x00007570:  .short 0x0401
0x00007572:  bclr %d2,%a0@(ffffffffffffffff,%d7:w)
0x00007574:  moveal %fp@(-28),%a2
0x00007576:  unlk %fp
0x00007578:  rts
