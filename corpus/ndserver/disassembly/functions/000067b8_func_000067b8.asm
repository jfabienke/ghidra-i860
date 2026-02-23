; Function: func_000067b8
; Address: 0x000067b8 - 0x00006855
; Size: 158 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 158 bytes, frame size 0
; Confidence: UNKNOWN
;
0x000067b8:  linkw %fp,#0
0x000067ba:  movel %a3,%sp@-
0x000067bc:  movel %a2,%sp@-
0x000067be:  moveal %fp@(8),%a3
0x000067c0:  moveal %fp@(12),%a2
0x000067c2:  .short 0xe9eb
0x000067c4:  .short 0x0008
0x000067c6:  .short 0x0003
0x000067c8:  moveq #40,%d1
0x000067ca:  cmpl %a3@(4),%d1
0x000067cc:  bnes 0x00000024
0x000067ce:  moveq #1,%d1
0x000067d0:  cmpl %d0,%d1
0x000067d2:  beqs 0x0000002e
0x000067d4:  invalid
0x000067d6:  breakpoint
0x000067d8:  .short 0xfed0
0x000067da:  .short 0x001c
0x000067dc:  bras 0x00000092
0x000067de:  movel %a3@(24),%d1
0x000067e0:  invalid
0x000067e2:  .short 0x0000
0x000067e4:  mvsb %a0@-,%d6
0x000067e6:  bnes 0x00000046
0x000067e8:  movel %a3@(32),%d1
0x000067ea:  invalid
0x000067ec:  .short 0x0000
0x000067ee:  mvsb %a4@-,%d6
0x000067f0:  beqs 0x00000050
0x000067f2:  invalid
0x000067f4:  breakpoint
0x000067f6:  .short 0xfed0
0x000067f8:  .short 0x001c
0x000067fa:  bras 0x0000006a
0x000067fc:  movel %a3@(36),%sp@-
0x000067fe:  pea %a3@(28)
0x00006800:  movel %a3@(12),%sp@-
0x00006802:  invalid
0x00006804:  breakpoint
0x00006806:  .short 0xfb02
0x00006808:  movel %d0,%a2@(36)
0x0000680a:  clrl %a2@(28)
0x0000680c:  tstl %a2@(28)
0x0000680e:  bnes 0x00000092
0x00006810:  invalid
0x00006812:  .short 0x0000
0x00006814:  mvsb %a0@(32),%d6
0x00006816:  invalid
0x00006818:  .short 0x0000
0x0000681a:  mvsb %a4@(40),%d6
0x0000681c:  invalid
0x0000681e:  .short 0x001c
0x00006820:  .short 0x002c
0x00006822:  invalid
0x00006824:  .short 0x0001
0x00006826:  .short 0x0003
0x00006828:  moveq #48,%d1
0x0000682a:  movel %d1,%a2@(4)
0x0000682c:  moveal %fp@(-8),%a2
0x0000682e:  moveal %fp@(-4),%a3
0x00006830:  unlk %fp
0x00006832:  rts
