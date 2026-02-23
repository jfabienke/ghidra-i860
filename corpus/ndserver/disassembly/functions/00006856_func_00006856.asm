; Function: func_00006856
; Address: 0x00006856 - 0x00006921
; Size: 204 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 204 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006856:  linkw %fp,#0
0x00006858:  movel %a3,%sp@-
0x0000685a:  movel %a2,%sp@-
0x0000685c:  moveal %fp@(8),%a2
0x0000685e:  moveal %fp@(12),%a3
0x00006860:  .short 0xe9ea
0x00006862:  .short 0x0008
0x00006864:  .short 0x0003
0x00006866:  invalid
0x00006868:  .short 0x0000
0x0000686a:  .short 0x0434
0x0000686c:  .short 0x0004
0x0000686e:  bnes 0x00000026
0x00006870:  moveq #1,%d1
0x00006872:  cmpl %d0,%d1
0x00006874:  beqs 0x00000032
0x00006876:  invalid
0x00006878:  breakpoint
0x0000687a:  .short 0xfed0
0x0000687c:  .short 0x001c
0x0000687e:  braw 0x000000c0
0x00006880:  movel %a2@(24),%d1
0x00006882:  invalid
0x00006884:  .short 0x0000
0x00006886:  mvsb %a0@(0000000000000032,%d6:w:8),%d6
0x00006888:  moveb %a2@(35),%d0
0x0000688a:  .short 0x0200
0x0000688c:  .short 0x000c
0x0000688e:  cmpib #12,%d0
0x00006890:  bnes 0x00000070
0x00006892:  cmpiw #12,%d2
0x00006894:  .short 0x0024
0x00006896:  bnes 0x00000070
0x00006898:  moveq #1,%d1
0x0000689a:  cmpl %a2@(40),%d1
0x0000689c:  bnes 0x00000070
0x0000689e:  cmpiw #8192,%d2
0x000068a0:  .short 0x0026
0x000068a2:  bnes 0x00000070
0x000068a4:  movel %a2@(1068),%d1
0x000068a6:  invalid
0x000068a8:  .short 0x0000
0x000068aa:  invalid
0x000068ac:  beqs 0x0000007a
0x000068ae:  invalid
0x000068b0:  breakpoint
0x000068b2:  .short 0xfed0
0x000068b4:  .short 0x001c
0x000068b6:  bras 0x00000098
0x000068b8:  movel %a2@(1072),%sp@-
0x000068ba:  pea %a2@(44)
0x000068bc:  pea %a2@(28)
0x000068be:  movel %a2@(12),%sp@-
0x000068c0:  invalid
0x000068c2:  breakpoint
0x000068c4:  .short 0xfa5e
0x000068c6:  movel %d0,%a3@(36)
0x000068c8:  clrl %a3@(28)
0x000068ca:  tstl %a3@(28)
0x000068cc:  bnes 0x000000c0
0x000068ce:  invalid
0x000068d0:  .short 0x0000
0x000068d2:  mvsb 0x00000020,%d6
0x000068d4:  invalid
0x000068d6:  .short 0x0000
0x000068d8:  mvsb #40,%d6
0x000068da:  invalid
0x000068dc:  .short 0x001c
0x000068de:  .short 0x002c
0x000068e0:  invalid
0x000068e2:  .short 0x0001
0x000068e4:  .short 0x0003
0x000068e6:  moveq #48,%d1
0x000068e8:  movel %d1,%a3@(4)
0x000068ea:  moveal %fp@(-8),%a2
0x000068ec:  moveal %fp@(-4),%a3
0x000068ee:  unlk %fp
0x000068f0:  rts
