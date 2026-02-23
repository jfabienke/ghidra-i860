; Function: func_00003874
; Address: 0x00003874 - 0x0000399b
; Size: 296 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 296 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00003874:  linkw %fp,#0
0x00003876:  movel %a2,%sp@-
0x00003878:  movel %d2,%sp@-
0x0000387a:  movel %fp@(12),%d0
0x0000387c:  invalid
0x0000387e:  .short 0x0401
0x00003880:  invalid
0x00003882:  moveq #8,%d1
0x00003884:  cmpl %d0,%d1
0x00003886:  bcsw 0x0000011c
0x00003888:  btst #0,%d0
0x0000388a:  bnew 0x0000011c
0x0000388c:  asrl #1,%d0
0x0000388e:  subql #1,%d0
0x00003890:  invalid
0x00003892:  .short 0x0000
0x00003894:  orl %d0,%a0@-
0x00003896:  tstl %a0@(0000000000000000,%d0:l:4)
0x00003898:  beqw 0x0000011c
0x0000389a:  moveal %a0@(0000000000000000,%d0:l:4),%a0
0x0000389c:  movel %a0@,%d1
0x0000389e:  cmpl %fp@(8),%d1
0x000038a0:  bnew 0x0000011c
0x000038a2:  moveal %a0,%a2
0x000038a4:  tstl %a2@(28)
0x000038a6:  beqs 0x0000005e
0x000038a8:  movel %a2@(52),%sp@-
0x000038aa:  movel %a2@(28),%sp@-
0x000038ac:  movel %d2,%sp@-
0x000038ae:  invalid
0x000038b0:  .short 0x04ff
0x000038b2:  .short 0xf9f0
0x000038b4:  .short 0x504f
0x000038b6:  .short 0x584f
0x000038b8:  tstl %a2@(36)
0x000038ba:  beqs 0x00000078
0x000038bc:  movel %a2@(56),%sp@-
0x000038be:  movel %a2@(36),%sp@-
0x000038c0:  movel %d2,%sp@-
0x000038c2:  invalid
0x000038c4:  .short 0x04ff
0x000038c6:  .short 0xf9d6
0x000038c8:  .short 0x504f
0x000038ca:  .short 0x584f
0x000038cc:  tstl %a2@(40)
0x000038ce:  beqs 0x00000092
0x000038d0:  movel %a2@(60),%sp@-
0x000038d2:  movel %a2@(40),%sp@-
0x000038d4:  movel %d2,%sp@-
0x000038d6:  invalid
0x000038d8:  .short 0x04ff
0x000038da:  .short 0xf9bc
0x000038dc:  .short 0x504f
0x000038de:  .short 0x584f
0x000038e0:  tstl %a2@(44)
0x000038e2:  beqs 0x000000ac
0x000038e4:  movel %a2@(64),%sp@-
0x000038e6:  movel %a2@(44),%sp@-
0x000038e8:  movel %d2,%sp@-
0x000038ea:  invalid
0x000038ec:  .short 0x04ff
0x000038ee:  .short 0xf9a2
0x000038f0:  .short 0x504f
0x000038f2:  .short 0x584f
0x000038f4:  tstl %a2@(48)
0x000038f6:  beqs 0x000000c6
0x000038f8:  movel %a2@(68),%sp@-
0x000038fa:  movel %a2@(48),%sp@-
0x000038fc:  movel %d2,%sp@-
0x000038fe:  invalid
0x00003900:  .short 0x04ff
0x00003902:  .short 0xf988
0x00003904:  .short 0x504f
0x00003906:  .short 0x584f
0x00003908:  clrl %a2@
0x0000390a:  tstl %a2@(4)
0x0000390c:  beqs 0x000000dc
0x0000390e:  movel %a2@(4),%sp@-
0x00003910:  movel %d2,%sp@-
0x00003912:  invalid
0x00003914:  .short 0x04ff
0x00003916:  .short 0xf310
0x00003918:  .short 0x504f
0x0000391a:  tstl %a2@(8)
0x0000391c:  beqs 0x000000f0
0x0000391e:  movel %a2@(8),%sp@-
0x00003920:  movel %d2,%sp@-
0x00003922:  invalid
0x00003924:  .short 0x04ff
0x00003926:  .short 0xf2fc
0x00003928:  .short 0x504f
0x0000392a:  tstl %a2@(12)
0x0000392c:  beqs 0x00000104
0x0000392e:  movel %a2@(12),%sp@-
0x00003930:  movel %d2,%sp@-
0x00003932:  invalid
0x00003934:  .short 0x04ff
0x00003936:  .short 0xf2e8
0x00003938:  .short 0x504f
0x0000393a:  movel %a2@(72),%d0
0x0000393c:  asrl #1,%d0
0x0000393e:  invalid
0x00003940:  .short 0x0000
0x00003942:  orl %d0,%a4@+
0x00003944:  clrl %a0@(0000000000000000,%d0:l:4)
0x00003946:  movel %a2,%sp@-
0x00003948:  invalid
0x0000394a:  .short 0x04ff
0x0000394c:  .short 0xebba
0x0000394e:  movel %fp@(-8),%d2
0x00003950:  moveal %fp@(-4),%a2
0x00003952:  unlk %fp
0x00003954:  rts
