; Function: func_00006036
; Address: 0x00006036 - 0x000060d7
; Size: 162 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 162 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006036:  linkw %fp,#0
0x00006038:  movel %a3,%sp@-
0x0000603a:  movel %a2,%sp@-
0x0000603c:  moveal %fp@(8),%a2
0x0000603e:  moveal %fp@(12),%a3
0x00006040:  .short 0xe9ea
0x00006042:  .short 0x0008
0x00006044:  .short 0x0003
0x00006046:  moveq #48,%d1
0x00006048:  cmpl %a2@(4),%d1
0x0000604a:  bnes 0x00000024
0x0000604c:  moveq #1,%d1
0x0000604e:  cmpl %d0,%d1
0x00006050:  beqs 0x0000002e
0x00006052:  invalid
0x00006054:  breakpoint
0x00006056:  .short 0xfed0
0x00006058:  .short 0x001c
0x0000605a:  bras 0x00000096
0x0000605c:  movel %a2@(24),%d1
0x0000605e:  invalid
0x00006060:  .short 0x0000
0x00006062:  moveq #-92,%d6
0x00006064:  bnes 0x00000052
0x00006066:  movel %a2@(32),%d1
0x00006068:  invalid
0x0000606a:  .short 0x0000
0x0000606c:  moveq #-88,%d6
0x0000606e:  bnes 0x00000052
0x00006070:  movel %a2@(40),%d1
0x00006072:  invalid
0x00006074:  .short 0x0000
0x00006076:  moveq #-84,%d6
0x00006078:  beqs 0x0000005c
0x0000607a:  invalid
0x0000607c:  breakpoint
0x0000607e:  .short 0xfed0
0x00006080:  .short 0x001c
0x00006082:  bras 0x00000076
0x00006084:  movel %a2@(44),%sp@-
0x00006086:  movel %a2@(36),%sp@-
0x00006088:  pea %a2@(28)
0x0000608a:  movel %a2@(12),%sp@-
0x0000608c:  invalid
0x0000608e:  breakpoint
0x00006090:  .short 0xd570
0x00006092:  movel %d0,%a3@(28)
0x00006094:  tstl %a3@(28)
0x00006096:  bnes 0x00000096
0x00006098:  invalid
0x0000609a:  .short 0x0000
0x0000609c:  moveq #-80,%d6
0x0000609e:  .short 0x0020
0x000060a0:  invalid
0x000060a2:  .short 0x001c
0x000060a4:  .short 0x0024
0x000060a6:  invalid
0x000060a8:  .short 0x0001
0x000060aa:  .short 0x0003
0x000060ac:  moveq #40,%d1
0x000060ae:  movel %d1,%a3@(4)
0x000060b0:  moveal %fp@(-8),%a2
0x000060b2:  moveal %fp@(-4),%a3
0x000060b4:  unlk %fp
0x000060b6:  rts
