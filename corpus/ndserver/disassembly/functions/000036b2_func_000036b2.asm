; Function: func_000036b2
; Address: 0x000036b2 - 0x0000381f
; Size: 366 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 366 bytes, frame size 0
; Confidence: UNKNOWN
;
0x000036b2:  linkw %fp,#0
0x000036b4:  .short 0x48e7
0x000036b6:  movew #10798,%d6
0x000036b8:  .short 0x0008
0x000036ba:  movel %fp@(12),%d3
0x000036bc:  invalid
0x000036be:  .short 0x0401
0x000036c0:  invalid
0x000036c2:  moveq #8,%d1
0x000036c4:  cmpl %d3,%d1
0x000036c6:  bcss 0x00000022
0x000036c8:  btst #0,%d3
0x000036ca:  beqs 0x00000028
0x000036cc:  moveq #4,%d0
0x000036ce:  braw 0x00000164
0x000036d0:  movel %d3,%d0
0x000036d2:  asrl #1,%d0
0x000036d4:  invalid
0x000036d6:  .short 0x0000
0x000036d8:  orl %d0,%a4@+
0x000036da:  tstl %a0@(0000000000000000,%d0:l:4)
0x000036dc:  beqs 0x00000048
0x000036de:  moveal %a0@(0000000000000000,%d0:l:4),%a0
0x000036e0:  cmpl %a0@,%d5
0x000036e2:  sne %d0
0x000036e4:  moveq #4,%d1
0x000036e6:  andl %d1,%d0
0x000036e8:  braw 0x00000164
0x000036ea:  pea 0x00000050
0x000036ec:  pea 0x00000001
0x000036ee:  invalid
0x000036f0:  .short 0x04ff
0x000036f2:  .short 0xeb06
0x000036f4:  moveal %d0,%a2
0x000036f6:  .short 0x504f
0x000036f8:  tstl %a2
0x000036fa:  bnes 0x00000064
0x000036fc:  moveq #6,%d0
0x000036fe:  braw 0x00000164
0x00003700:  movel %d3,%d0
0x00003702:  asrl #1,%d0
0x00003704:  invalid
0x00003706:  .short 0x0000
0x00003708:  orl %d0,%a4@+
0x0000370a:  movel %a2,%a0@(0000000000000000,%d0:l:4)
0x0000370c:  movel %d3,%a2@(72)
0x0000370e:  clrl %a2@(76)
0x00003710:  movel %d5,%a2@
0x00003712:  lea %a2@(8),%a4
0x00003714:  movel %a4,%sp@-
0x00003716:  movel %d4,%sp@-
0x00003718:  invalid
0x0000371a:  btst %d2,%d0
0x0000371c:  moveal %a4@,%fp
0x0000371e:  jsr %a5@
0x00003720:  movel %d0,%d2
0x00003722:  .short 0x504f
0x00003724:  bnew 0x0000014a
0x00003726:  lea %a2@(4),%a3
0x00003728:  movel %a3,%sp@-
0x0000372a:  movel %d4,%sp@-
0x0000372c:  jsr %a5@
0x0000372e:  movel %d0,%d2
0x00003730:  .short 0x504f
0x00003732:  bnew 0x0000014a
0x00003734:  movel %a4,%sp@-
0x00003736:  movel %a3@,%sp@-
0x00003738:  movel %d3,%sp@-
0x0000373a:  movel %d5,%sp@-
0x0000373c:  invalid
0x0000373e:  .short 0x0000
0x00003740:  .short 0x057a
0x00003742:  movel %d0,%d2
0x00003744:  .short 0x504f
0x00003746:  .short 0x504f
0x00003748:  bnew 0x0000014a
0x0000374a:  pea %a2@(52)
0x0000374c:  pea %a2@(28)
0x0000374e:  movel %d3,%sp@-
0x00003750:  movel %d4,%sp@-
0x00003752:  movel %a3@,%sp@-
0x00003754:  movel %d5,%sp@-
0x00003756:  invalid
0x00003758:  .short 0x0000
0x0000375a:  .short 0x0e70
0x0000375c:  movel %d0,%d2
0x0000375e:  .short 0xdefc
0x00003760:  .short 0x0018
0x00003762:  bnes 0x0000014a
0x00003764:  lea %a2@(60),%a5
0x00003766:  movel %a5,%sp@-
0x00003768:  lea %a2@(40),%a4
0x0000376a:  movel %a4,%sp@-
0x0000376c:  movel %d3,%sp@-
0x0000376e:  movel %d4,%sp@-
0x00003770:  movel %a3@,%sp@-
0x00003772:  movel %d5,%sp@-
0x00003774:  invalid
0x00003776:  .short 0x0000
0x00003778:  .short 0x107e
0x0000377a:  movel %d0,%d2
0x0000377c:  .short 0xdefc
0x0000377e:  .short 0x0018
0x00003780:  bnes 0x0000014a
0x00003782:  movel %a5,%sp@-
0x00003784:  movel %a4,%sp@-
0x00003786:  movel %d3,%sp@-
0x00003788:  movel %d4,%sp@-
0x0000378a:  movel %a3@,%sp@-
0x0000378c:  movel %d5,%sp@-
0x0000378e:  invalid
0x00003790:  .short 0x0000
0x00003792:  invalid
0x00003794:  movel %d0,%d2
0x00003796:  .short 0xdefc
0x00003798:  .short 0x0018
0x0000379a:  bnes 0x0000014a
0x0000379c:  lea %a2@(12),%a3
0x0000379e:  movel %a3,%sp@-
0x000037a0:  movel %d3,%sp@-
0x000037a2:  movel %d5,%sp@-
0x000037a4:  invalid
0x000037a6:  .short 0x0000
0x000037a8:  .short 0x0a28
0x000037aa:  movel %d0,%d2
0x000037ac:  .short 0x504f
0x000037ae:  .short 0x584f
0x000037b0:  bnes 0x0000014a
0x000037b2:  pea %a2@(24)
0x000037b4:  movel %a3@,%sp@-
0x000037b6:  movel %d5,%sp@-
0x000037b8:  invalid
0x000037ba:  .short 0x0000
0x000037bc:  .short 0x074e
0x000037be:  movel %d0,%d2
0x000037c0:  .short 0x504f
0x000037c2:  .short 0x584f
0x000037c4:  bnes 0x0000014a
0x000037c6:  clrl %d0
0x000037c8:  bras 0x00000164
0x000037ca:  movel %d2,%sp@-
0x000037cc:  invalid
0x000037ce:  .short 0x0000
0x000037d0:  moveq #-97,%d4
0x000037d2:  invalid
0x000037d4:  .short 0x04ff
0x000037d6:  .short 0xf0be
0x000037d8:  movel %d3,%sp@-
0x000037da:  movel %d5,%sp@-
0x000037dc:  invalid
0x000037de:  .short 0x0000
0x000037e0:  .short 0x0064
0x000037e2:  movel %d2,%d0
0x000037e4:  invalid
0x000037e6:  movew #-32,%d6
0x000037e8:  unlk %fp
0x000037ea:  rts
