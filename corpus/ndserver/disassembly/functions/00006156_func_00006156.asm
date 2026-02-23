; Function: func_00006156
; Address: 0x00006156 - 0x000061f3
; Size: 158 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 158 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006156:  linkw %fp,#0
0x00006158:  movel %a2,%sp@-
0x0000615a:  moveal %fp@(8),%a0
0x0000615c:  moveal %fp@(12),%a2
0x0000615e:  .short 0xe9e8
0x00006160:  .short 0x0008
0x00006162:  .short 0x0003
0x00006164:  moveq #56,%d1
0x00006166:  cmpl %a0@(4),%d1
0x00006168:  bnes 0x00000022
0x0000616a:  moveq #1,%d1
0x0000616c:  cmpl %d0,%d1
0x0000616e:  beqs 0x0000002c
0x00006170:  invalid
0x00006172:  breakpoint
0x00006174:  .short 0xfed0
0x00006176:  .short 0x001c
0x00006178:  bras 0x00000096
0x0000617a:  movel %a0@(24),%d1
0x0000617c:  invalid
0x0000617e:  .short 0x0000
0x00006180:  moveq #-68,%d6
0x00006182:  bnes 0x0000005c
0x00006184:  movel %a0@(32),%d1
0x00006186:  invalid
0x00006188:  .short 0x0000
0x0000618a:  moveq #-64,%d6
0x0000618c:  bnes 0x0000005c
0x0000618e:  movel %a0@(40),%d1
0x00006190:  invalid
0x00006192:  .short 0x0000
0x00006194:  moveq #-60,%d6
0x00006196:  bnes 0x0000005c
0x00006198:  movel %a0@(48),%d1
0x0000619a:  invalid
0x0000619c:  .short 0x0000
0x0000619e:  moveq #-56,%d6
0x000061a0:  beqs 0x00000066
0x000061a2:  invalid
0x000061a4:  breakpoint
0x000061a6:  .short 0xfed0
0x000061a8:  .short 0x001c
0x000061aa:  bras 0x00000084
0x000061ac:  movel %a0@(52),%sp@-
0x000061ae:  movel %a0@(44),%sp@-
0x000061b0:  movel %a0@(36),%sp@-
0x000061b2:  movel %a0@(28),%sp@-
0x000061b4:  movel %a0@(12),%sp@-
0x000061b6:  invalid
0x000061b8:  breakpoint
0x000061ba:  addl %pc@(0x000025c0),%d2
0x000061bc:  .short 0x001c
0x000061be:  tstl %a2@(28)
0x000061c0:  bnes 0x00000096
0x000061c2:  invalid
0x000061c4:  .short 0x0001
0x000061c6:  .short 0x0003
0x000061c8:  moveq #32,%d1
0x000061ca:  movel %d1,%a2@(4)
0x000061cc:  moveal %fp@(-4),%a2
0x000061ce:  unlk %fp
0x000061d0:  rts
