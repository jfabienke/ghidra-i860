; Function: func_0000594a
; Address: 0x0000594a - 0x000059f7
; Size: 174 bytes
; Frame: 812 bytes
; Purpose: Unknown
; Description: 174 bytes, frame size 812
; Confidence: UNKNOWN
;
0x0000594a:  linkw %fp,#-812
0x0000594c:  .short 0x48e7
0x0000594e:  movew %a0@(000000000000002e,%d2:l),%d4
0x00005950:  .short 0x0008
0x00005952:  movel %fp@(20),%d2
0x00005954:  movel %fp@(24),%d3
0x00005956:  lea %fp@(-812),%a3
0x00005958:  invalid
0x0000595a:  .short 0x0000
0x0000595c:  moveq #120,%d6
0x0000595e:  .short 0xfcec
0x00005960:  invalid
0x00005962:  .short 0x000c
0x00005964:  .short 0xfcf0
0x00005966:  invalid
0x00005968:  .short 0x0000
0x0000596a:  moveq #124,%d6
0x0000596c:  .short 0xfcf4
0x0000596e:  pea 0x00000100
0x00005970:  pea %a3@(36)
0x00005972:  movel %fp@(16),%sp@-
0x00005974:  invalid
0x00005976:  btst %d2,%d0
0x00005978:  movel %a0,0x00004e92
0x0000597a:  .short 0x504f
0x0000597c:  .short 0x584f
0x0000597e:  invalid
0x00005980:  .short 0x0000
0x00005982:  moveq #-128,%d6
0x00005984:  .short 0xfdf8
0x00005986:  pea 0x00000100
0x00005988:  pea %fp@(-516)
0x0000598a:  movel %d2,%sp@-
0x0000598c:  jsr %a2@
0x0000598e:  .short 0x504f
0x00005990:  .short 0x584f
0x00005992:  invalid
0x00005994:  .short 0x0000
0x00005996:  moveq #-124,%d6
0x00005998:  .short 0xfefc
0x0000599a:  pea 0x00000100
0x0000599c:  pea %fp@(-256)
0x0000599e:  movel %d3,%sp@-
0x000059a0:  jsr %a2@
0x000059a2:  .short 0x504f
0x000059a4:  .short 0x584f
0x000059a6:  invalid
0x000059a8:  .short 0x0001
0x000059aa:  .short 0xfcd7
0x000059ac:  invalid
0x000059ae:  .short 0x0000
0x000059b0:  btst %d1,%a4@(-808)
0x000059b2:  clrl %fp@(-804)
0x000059b4:  movel %d4,%fp@(-796)
0x000059b6:  clrl %fp@(-800)
0x000059b8:  invalid
0x000059ba:  .short 0x0000
0x000059bc:  invalid
0x000059be:  .short 0xfce8
0x000059c0:  clrl %sp@-
0x000059c2:  clrl %sp@-
0x000059c4:  movel %a3,%sp@-
0x000059c6:  invalid
0x000059c8:  .short 0x04ff
0x000059ca:  mulsw %a0@(19694),%d7
0x000059cc:  cmpib #-64,%d4
0x000059ce:  unlk %fp
0x000059d0:  rts
