; Function: func_00006de4
; Address: 0x00006de4 - 0x00006e6b
; Size: 136 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 136 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006de4:  linkw %fp,#0
0x00006de6:  movel %a2,%sp@-
0x00006de8:  moveal %fp@(8),%a2
0x00006dea:  moveal %fp@(12),%a1
0x00006dec:  invalid
0x00006dee:  .short 0x0001
0x00006df0:  .short 0x0003
0x00006df2:  moveq #32,%d1
0x00006df4:  movel %d1,%a1@(4)
0x00006df6:  invalid
0x00006df8:  .short 0x0008
0x00006dfa:  .short 0x0008
0x00006dfc:  clrl %a1@(12)
0x00006dfe:  invalid
0x00006e00:  .short 0x0010
0x00006e02:  .short 0x0010
0x00006e04:  moveq #100,%d1
0x00006e06:  addl %a2@(20),%d1
0x00006e08:  movel %d1,%a1@(20)
0x00006e0a:  invalid
0x00006e0c:  .short 0x0000
0x00006e0e:  mvzb %a0@-,%d6
0x00006e10:  .short 0x0018
0x00006e12:  invalid
0x00006e14:  breakpoint
0x00006e16:  .short 0xfed1
0x00006e18:  .short 0x001c
0x00006e1a:  movel %a2@(20),%d0
0x00006e1c:  invalid
0x00006e1e:  breakpoint
0x00006e20:  .short 0xd508
0x00006e22:  invalid
0x00006e24:  .short 0x0000
0x00006e26:  invalid
0x00006e28:  bhis 0x00000066
0x00006e2a:  movel %a2@(20),%d0
0x00006e2c:  invalid
0x00006e2e:  breakpoint
0x00006e30:  addal %d4,%a0
0x00006e32:  tstl %a0@(0000000000000000,%d0:l:4)
0x00006e34:  bnes 0x0000006a
0x00006e36:  clrl %d0
0x00006e38:  bras 0x00000080
0x00006e3a:  movel %a2@(20),%d0
0x00006e3c:  invalid
0x00006e3e:  breakpoint
0x00006e40:  addal %d4,%a0
0x00006e42:  movel %a1,%sp@-
0x00006e44:  movel %a2,%sp@-
0x00006e46:  moveal %a0@(0000000000000000,%d0:l:4),%a0
0x00006e48:  jsr %a0@
0x00006e4a:  moveq #1,%d0
0x00006e4c:  moveal %fp@(-4),%a2
0x00006e4e:  unlk %fp
0x00006e50:  rts
