; Function: func_00006602
; Address: 0x00006602 - 0x000066db
; Size: 218 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 218 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006602:  linkw %fp,#0
0x00006604:  .short 0x48e7
0x00006606:  .short 0x0038
0x00006608:  moveal %fp@(8),%a2
0x0000660a:  moveal %fp@(12),%a3
0x0000660c:  moveal %a2@(4),%a1
0x0000660e:  .short 0xe9ea
0x00006610:  .short 0x0008
0x00006612:  .short 0x0003
0x00006614:  lea %a1@(-52),%a0
0x00006616:  invalid
0x00006618:  .short 0x0000
0x0000661a:  moveb %a4@+,%sp@+
0x0000661c:  bhis 0x0000002c
0x0000661e:  moveq #1,%d1
0x00006620:  cmpl %d0,%d1
0x00006622:  beqs 0x00000038
0x00006624:  invalid
0x00006626:  breakpoint
0x00006628:  .short 0xfed0
0x0000662a:  .short 0x001c
0x0000662c:  braw 0x000000d0
0x0000662e:  moveal %a2@(24),%a4
0x00006630:  invalid
0x00006632:  .short 0x0000
0x00006634:  moveq #-4,%d6
0x00006636:  bnes 0x0000007c
0x00006638:  movel %a2@(32),%d1
0x0000663a:  invalid
0x0000663c:  .short 0x0000
0x0000663e:  mvsb %d0,%d6
0x00006640:  bnes 0x0000007c
0x00006642:  moveb %a2@(43),%d0
0x00006644:  .short 0x0200
0x00006646:  .short 0x000c
0x00006648:  cmpib #12,%d0
0x0000664a:  bnes 0x0000007c
0x0000664c:  invalid
0x0000664e:  .short 0x0008
0x00006650:  .short 0x0008
0x00006652:  .short 0x002c
0x00006654:  bnes 0x0000007c
0x00006656:  movel %a2@(48),%d0
0x00006658:  addql #3,%d0
0x0000665a:  moveq #-4,%d1
0x0000665c:  andl %d1,%d0
0x0000665e:  moveal %d0,%a4
0x00006660:  lea %a4@(52),%a0
0x00006662:  cmpal %a1,%a0
0x00006664:  beqs 0x00000086
0x00006666:  invalid
0x00006668:  breakpoint
0x0000666a:  .short 0xfed0
0x0000666c:  .short 0x001c
0x0000666e:  bras 0x000000a8
0x00006670:  movel %a2@(48),%sp@-
0x00006672:  pea %a2@(52)
0x00006674:  movel %a2@(36),%sp@-
0x00006676:  pea %a2@(28)
0x00006678:  movel %a2@(12),%sp@-
0x0000667a:  invalid
0x0000667c:  breakpoint
0x0000667e:  cp0ldb %a2@+,%d2,#4,#320
0x00006680:  .short 0x0024
0x00006682:  clrl %a3@(28)
0x00006684:  tstl %a3@(28)
0x00006686:  bnes 0x000000d0
0x00006688:  invalid
0x0000668a:  .short 0x0000
0x0000668c:  mvsb %d4,%d6
0x0000668e:  .short 0x0020
0x00006690:  invalid
0x00006692:  .short 0x0000
0x00006694:  mvsb %a0,%d6
0x00006696:  .short 0x0028
0x00006698:  invalid
0x0000669a:  .short 0x001c
0x0000669c:  .short 0x002c
0x0000669e:  invalid
0x000066a0:  .short 0x0001
0x000066a2:  .short 0x0003
0x000066a4:  moveq #48,%d1
0x000066a6:  movel %d1,%a3@(4)
0x000066a8:  invalid
0x000066aa:  moveb %d0,%d6
0x000066ac:  .short 0xfff4
0x000066ae:  unlk %fp
0x000066b0:  rts
