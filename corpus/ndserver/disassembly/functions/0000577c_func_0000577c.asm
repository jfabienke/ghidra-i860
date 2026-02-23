; Function: func_0000577c
; Address: 0x0000577c - 0x00005949
; Size: 462 bytes
; Frame: 120 bytes
; Purpose: Unknown
; Description: 462 bytes, frame size 120
; Confidence: UNKNOWN
;
0x0000577c:  linkw %fp,#-120
0x0000577e:  .short 0x48e7
0x00005780:  movew #9838,%d0
0x00005782:  .short 0x0010
0x00005784:  moveal %fp@(20),%a4
0x00005786:  moveal %fp@(24),%a5
0x00005788:  lea %fp@(-120),%a2
0x0000578a:  invalid
0x0000578c:  .short 0x0000
0x0000578e:  moveq #68,%d6
0x00005790:  cp1stl %d2,%a0@-,#7,#366
0x00005792:  .short 0x000c
0x00005794:  cp1stl %d1,%a4@-,#7,#380
0x00005796:  .short 0x0001
0x00005798:  cp1stl %d7,%a3,#4,#32
0x0000579a:  movel %d3,%fp@(-116)
0x0000579c:  invalid
0x0000579e:  .short 0x0000
0x000057a0:  btst %d0,%d0
0x000057a2:  cp1stl %d2,%a0@,#7,#366
0x000057a4:  .short 0x0008
0x000057a6:  cp1stl %d6,%a0@+,#1,#511
0x000057a8:  .short 0x04ff
0x000057aa:  addl %d0,%a2@-
0x000057ac:  movel %d0,%fp@(-108)
0x000057ae:  invalid
0x000057b0:  .short 0x0000
0x000057b2:  invalid
0x000057b4:  cp1stl %d4,%a4@+,#2,#167
0x000057b6:  clrl %sp@-
0x000057b8:  pea 0x00000078
0x000057ba:  clrl %sp@-
0x000057bc:  movel %a2,%sp@-
0x000057be:  invalid
0x000057c0:  .short 0x04ff
0x000057c2:  addal %a4@-,%a0
0x000057c4:  movel %d0,%d2
0x000057c6:  .short 0xdefc
0x000057c8:  .short 0x0014
0x000057ca:  beqs 0x00000080
0x000057cc:  invalid
0x000057ce:  breakpoint
0x000057d0:  .short 0xff36
0x000057d2:  bnes 0x0000007a
0x000057d4:  invalid
0x000057d6:  .short 0x04ff
0x000057d8:  .short 0xd168
0x000057da:  movel %d2,%d0
0x000057dc:  braw 0x000001c4
0x000057de:  movel %a2@(4),%d0
0x000057e0:  .short 0xe9ea
0x000057e2:  .short 0x1008
0x000057e4:  .short 0x0003
0x000057e6:  invalid
0x000057e8:  .short 0x0000
0x000057ea:  .short 0x00e4
0x000057ec:  .short 0x0014
0x000057ee:  beqs 0x0000009e
0x000057f0:  invalid
0x000057f2:  breakpoint
0x000057f4:  .short 0xfed3
0x000057f6:  braw 0x000001c4
0x000057f8:  moveq #120,%d3
0x000057fa:  cmpl %d0,%d3
0x000057fc:  bnes 0x000000aa
0x000057fe:  moveq #1,%d3
0x00005800:  cmpl %d1,%d3
0x00005802:  beqs 0x000000c2
0x00005804:  moveq #32,%d3
0x00005806:  cmpl %d0,%d3
0x00005808:  bnew 0x000001be
0x0000580a:  moveq #1,%d3
0x0000580c:  cmpl %d1,%d3
0x0000580e:  bnew 0x000001be
0x00005810:  tstl %a2@(28)
0x00005812:  beqw 0x000001be
0x00005814:  moveal %a2@(24),%a0
0x00005816:  invalid
0x00005818:  .short 0x0000
0x0000581a:  moveq #72,%d6
0x0000581c:  bnew 0x000001be
0x0000581e:  tstl %a2@(28)
0x00005820:  beqs 0x000000de
0x00005822:  movel %a2@(28),%d0
0x00005824:  braw 0x000001c4
0x00005826:  movel %a2@(32),%d3
0x00005828:  invalid
0x0000582a:  .short 0x0000
0x0000582c:  moveq #76,%d6
0x0000582e:  bnew 0x000001be
0x00005830:  movel %a2@(36),%a3@
0x00005832:  moveal %a2@(40),%a0
0x00005834:  invalid
0x00005836:  .short 0x0000
0x00005838:  moveq #80,%d6
0x0000583a:  bnew 0x000001be
0x0000583c:  movel %a2@(44),%a4@
0x0000583e:  movel %a2@(48),%d3
0x00005840:  invalid
0x00005842:  .short 0x0000
0x00005844:  moveq #84,%d6
0x00005846:  bnew 0x000001be
0x00005848:  movel %a2@(52),%a5@
0x0000584a:  moveal %a2@(56),%a0
0x0000584c:  invalid
0x0000584e:  .short 0x0000
0x00005850:  moveq #88,%d6
0x00005852:  bnew 0x000001be
0x00005854:  moveal %fp@(28),%a0
0x00005856:  movel %a2@(60),%a0@
0x00005858:  movel %a2@(64),%d3
0x0000585a:  invalid
0x0000585c:  .short 0x0000
0x0000585e:  moveq #92,%d6
0x00005860:  bnew 0x000001be
0x00005862:  moveal %fp@(32),%a0
0x00005864:  movel %a2@(68),%a0@
0x00005866:  movel %a2@(72),%d3
0x00005868:  invalid
0x0000586a:  .short 0x0000
0x0000586c:  moveq #96,%d6
0x0000586e:  bnes 0x000001be
0x00005870:  moveal %fp@(36),%a0
0x00005872:  movel %a2@(76),%a0@
0x00005874:  movel %a2@(80),%d3
0x00005876:  invalid
0x00005878:  .short 0x0000
0x0000587a:  moveq #100,%d6
0x0000587c:  bnes 0x000001be
0x0000587e:  moveal %fp@(40),%a0
0x00005880:  movel %a2@(84),%a0@
0x00005882:  movel %a2@(88),%d3
0x00005884:  invalid
0x00005886:  .short 0x0000
0x00005888:  moveq #104,%d6
0x0000588a:  bnes 0x000001be
0x0000588c:  moveal %fp@(44),%a0
0x0000588e:  movel %a2@(92),%a0@
0x00005890:  movel %a2@(96),%d3
0x00005892:  invalid
0x00005894:  .short 0x0000
0x00005896:  moveq #108,%d6
0x00005898:  bnes 0x000001be
0x0000589a:  moveal %fp@(48),%a0
0x0000589c:  movel %a2@(100),%a0@
0x0000589e:  movel %a2@(104),%d3
0x000058a0:  invalid
0x000058a2:  .short 0x0000
0x000058a4:  moveq #112,%d6
0x000058a6:  bnes 0x000001be
0x000058a8:  moveal %fp@(52),%a0
0x000058aa:  movel %a2@(108),%a0@
0x000058ac:  movel %a2@(112),%d3
0x000058ae:  invalid
0x000058b0:  .short 0x0000
0x000058b2:  moveq #116,%d6
0x000058b4:  bnes 0x000001be
0x000058b6:  moveal %fp@(56),%a0
0x000058b8:  movel %a2@(116),%a0@
0x000058ba:  movel %a2@(28),%d0
0x000058bc:  bras 0x000001c4
0x000058be:  invalid
0x000058c0:  breakpoint
0x000058c2:  .short 0xfed4
0x000058c4:  invalid
0x000058c6:  movew %a4,%d6
0x000058c8:  .short 0xff70
0x000058ca:  unlk %fp
0x000058cc:  rts
