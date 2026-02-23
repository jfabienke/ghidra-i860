; Function: func_00003614
; Address: 0x00003614 - 0x0000366d
; Size: 90 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 90 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00003614:  linkw %fp,#0
0x00003616:  .short 0x48e7
0x00003618:  movew %a0@-,%d4
0x0000361a:  moveal %fp@(12),%a2
0x0000361c:  movel %fp@(16),%d4
0x0000361e:  movel %fp@(20),%d3
0x00003620:  movel %d3,%sp@-
0x00003622:  movel %d4,%sp@-
0x00003624:  movel %a2,%sp@-
0x00003626:  invalid
0x00003628:  .short 0x04ff
0x0000362a:  wddatab %fp@(12032)
0x0000362c:  invalid
0x0000362e:  .short 0x04ff
0x00003630:  .short 0xfc70
0x00003632:  movel %d0,%d2
0x00003634:  .short 0x504f
0x00003636:  .short 0x504f
0x00003638:  bnes 0x00000034
0x0000363a:  tstl %a2@
0x0000363c:  bnes 0x0000004e
0x0000363e:  moveq #1,%d1
0x00003640:  cmpl %d3,%d1
0x00003642:  bnes 0x0000004e
0x00003644:  movel %d3,%sp@-
0x00003646:  movel %d4,%sp@-
0x00003648:  movel %a2@,%sp@-
0x0000364a:  movel %d2,%sp@-
0x0000364c:  invalid
0x0000364e:  .short 0x0000
0x00003650:  moveq #111,%d4
0x00003652:  invalid
0x00003654:  .short 0x04ff
0x00003656:  .short 0xf686
0x00003658:  movel %d2,%d0
0x0000365a:  invalid
0x0000365c:  .short 0x041c
0x0000365e:  .short 0xfff0
0x00003660:  unlk %fp
0x00003662:  rts
