; Function: func_000066dc
; Address: 0x000066dc - 0x000067b7
; Size: 220 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 220 bytes, frame size 0
; Confidence: UNKNOWN
;
0x000066dc:  linkw %fp,#0
0x000066de:  movel %a3,%sp@-
0x000066e0:  movel %a2,%sp@-
0x000066e2:  moveal %fp@(8),%a2
0x000066e4:  moveal %fp@(12),%a3
0x000066e6:  .short 0xe9ea
0x000066e8:  .short 0x0008
0x000066ea:  .short 0x0003
0x000066ec:  invalid
0x000066ee:  .short 0x0000
0x000066f0:  .short 0x043c
0x000066f2:  .short 0x0004
0x000066f4:  bnes 0x00000026
0x000066f6:  moveq #1,%d1
0x000066f8:  cmpl %d0,%d1
0x000066fa:  beqs 0x00000032
0x000066fc:  invalid
0x000066fe:  breakpoint
0x00006700:  .short 0xfed0
0x00006702:  .short 0x001c
0x00006704:  braw 0x000000d0
0x00006706:  movel %a2@(24),%d1
0x00006708:  invalid
0x0000670a:  .short 0x0000
0x0000670c:  mvsb %a4,%d6
0x0000670e:  bnes 0x0000007c
0x00006710:  moveb %a2@(35),%d0
0x00006712:  .short 0x0200
0x00006714:  .short 0x000c
0x00006716:  cmpib #12,%d0
0x00006718:  bnes 0x0000007c
0x0000671a:  cmpiw #12,%d2
0x0000671c:  .short 0x0024
0x0000671e:  bnes 0x0000007c
0x00006720:  moveq #1,%d1
0x00006722:  cmpl %a2@(40),%d1
0x00006724:  bnes 0x0000007c
0x00006726:  cmpiw #8192,%d2
0x00006728:  .short 0x0026
0x0000672a:  bnes 0x0000007c
0x0000672c:  movel %a2@(1068),%d1
0x0000672e:  invalid
0x00006730:  .short 0x0000
0x00006732:  mvsb %a0@,%d6
0x00006734:  bnes 0x0000007c
0x00006736:  movel %a2@(1076),%d1
0x00006738:  invalid
0x0000673a:  .short 0x0000
0x0000673c:  mvsb %a4@,%d6
0x0000673e:  beqs 0x00000086
0x00006740:  invalid
0x00006742:  breakpoint
0x00006744:  .short 0xfed0
0x00006746:  .short 0x001c
0x00006748:  bras 0x000000a8
0x0000674a:  movel %a2@(1080),%sp@-
0x0000674c:  movel %a2@(1072),%sp@-
0x0000674e:  pea %a2@(44)
0x00006750:  pea %a2@(28)
0x00006752:  movel %a2@(12),%sp@-
0x00006754:  invalid
0x00006756:  breakpoint
0x00006758:  wddataw %a0@(0000000000000000)
0x0000675a:  .short 0x0024
0x0000675c:  clrl %a3@(28)
0x0000675e:  tstl %a3@(28)
0x00006760:  bnes 0x000000d0
0x00006762:  invalid
0x00006764:  .short 0x0000
0x00006766:  mvsb %a0@+,%d6
0x00006768:  .short 0x0020
0x0000676a:  invalid
0x0000676c:  .short 0x0000
0x0000676e:  mvsb %a4@+,%d6
0x00006770:  .short 0x0028
0x00006772:  invalid
0x00006774:  .short 0x001c
0x00006776:  .short 0x002c
0x00006778:  invalid
0x0000677a:  .short 0x0001
0x0000677c:  .short 0x0003
0x0000677e:  moveq #48,%d1
0x00006780:  movel %d1,%a3@(4)
0x00006782:  moveal %fp@(-8),%a2
0x00006784:  moveal %fp@(-4),%a3
0x00006786:  unlk %fp
0x00006788:  rts
