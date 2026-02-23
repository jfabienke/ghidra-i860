; Function: func_000060d8
; Address: 0x000060d8 - 0x00006155
; Size: 126 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 126 bytes, frame size 0
; Confidence: UNKNOWN
;
0x000060d8:  linkw %fp,#0
0x000060da:  movel %a2,%sp@-
0x000060dc:  moveal %fp@(8),%a0
0x000060de:  moveal %fp@(12),%a2
0x000060e0:  .short 0xe9e8
0x000060e2:  .short 0x0008
0x000060e4:  .short 0x0003
0x000060e6:  moveq #40,%d1
0x000060e8:  cmpl %a0@(4),%d1
0x000060ea:  bnes 0x00000022
0x000060ec:  moveq #1,%d1
0x000060ee:  cmpl %d0,%d1
0x000060f0:  beqs 0x0000002c
0x000060f2:  invalid
0x000060f4:  breakpoint
0x000060f6:  .short 0xfed0
0x000060f8:  .short 0x001c
0x000060fa:  bras 0x00000076
0x000060fc:  movel %a0@(24),%d1
0x000060fe:  invalid
0x00006100:  .short 0x0000
0x00006102:  moveq #-76,%d6
0x00006104:  bnes 0x00000044
0x00006106:  movel %a0@(32),%d1
0x00006108:  invalid
0x0000610a:  .short 0x0000
0x0000610c:  moveq #-72,%d6
0x0000610e:  beqs 0x0000004e
0x00006110:  invalid
0x00006112:  breakpoint
0x00006114:  .short 0xfed0
0x00006116:  .short 0x001c
0x00006118:  bras 0x00000064
0x0000611a:  movel %a0@(36),%sp@-
0x0000611c:  movel %a0@(28),%sp@-
0x0000611e:  movel %a0@(12),%sp@-
0x00006120:  invalid
0x00006122:  breakpoint
0x00006124:  .short 0xd53a
0x00006126:  movel %d0,%a2@(28)
0x00006128:  tstl %a2@(28)
0x0000612a:  bnes 0x00000076
0x0000612c:  invalid
0x0000612e:  .short 0x0001
0x00006130:  .short 0x0003
0x00006132:  moveq #32,%d1
0x00006134:  movel %d1,%a2@(4)
0x00006136:  moveal %fp@(-4),%a2
0x00006138:  unlk %fp
0x0000613a:  rts
