; Function: func_00006d24
; Address: 0x00006d24 - 0x00006de3
; Size: 192 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 192 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006d24:  linkw %fp,#0
0x00006d26:  movel %a3,%sp@-
0x00006d28:  movel %a2,%sp@-
0x00006d2a:  moveal %fp@(8),%a3
0x00006d2c:  moveal %fp@(12),%a2
0x00006d2e:  .short 0xe9eb
0x00006d30:  .short 0x0008
0x00006d32:  .short 0x0003
0x00006d34:  moveq #56,%d1
0x00006d36:  cmpl %a3@(4),%d1
0x00006d38:  bnes 0x00000024
0x00006d3a:  moveq #1,%d1
0x00006d3c:  cmpl %d0,%d1
0x00006d3e:  beqs 0x00000030
0x00006d40:  invalid
0x00006d42:  breakpoint
0x00006d44:  .short 0xfed0
0x00006d46:  .short 0x001c
0x00006d48:  braw 0x000000b4
0x00006d4a:  movel %a3@(24),%d1
0x00006d4c:  invalid
0x00006d4e:  .short 0x0000
0x00006d50:  mvzb %a0,%d6
0x00006d52:  bnes 0x00000060
0x00006d54:  movel %a3@(32),%d1
0x00006d56:  invalid
0x00006d58:  .short 0x0000
0x00006d5a:  mvzb %a4,%d6
0x00006d5c:  bnes 0x00000060
0x00006d5e:  movel %a3@(40),%d1
0x00006d60:  invalid
0x00006d62:  .short 0x0000
0x00006d64:  mvzb %a0@,%d6
0x00006d66:  bnes 0x00000060
0x00006d68:  movel %a3@(48),%d1
0x00006d6a:  invalid
0x00006d6c:  .short 0x0000
0x00006d6e:  mvzb %a4@,%d6
0x00006d70:  beqs 0x0000006a
0x00006d72:  invalid
0x00006d74:  breakpoint
0x00006d76:  .short 0xfed0
0x00006d78:  .short 0x001c
0x00006d7a:  bras 0x0000008c
0x00006d7c:  movel %a3@(52),%sp@-
0x00006d7e:  movel %a3@(44),%sp@-
0x00006d80:  movel %a3@(36),%sp@-
0x00006d82:  pea %a3@(28)
0x00006d84:  movel %a3@(12),%sp@-
0x00006d86:  invalid
0x00006d88:  breakpoint
0x00006d8a:  .short 0xf6a0
0x00006d8c:  movel %d0,%a2@(36)
0x00006d8e:  clrl %a2@(28)
0x00006d90:  tstl %a2@(28)
0x00006d92:  bnes 0x000000b4
0x00006d94:  invalid
0x00006d96:  .short 0x0000
0x00006d98:  mvzb %a0@+,%d6
0x00006d9a:  .short 0x0020
0x00006d9c:  invalid
0x00006d9e:  .short 0x0000
0x00006da0:  mvzb %a4@+,%d6
0x00006da2:  .short 0x0028
0x00006da4:  invalid
0x00006da6:  .short 0x001c
0x00006da8:  .short 0x002c
0x00006daa:  invalid
0x00006dac:  .short 0x0001
0x00006dae:  .short 0x0003
0x00006db0:  moveq #48,%d1
0x00006db2:  movel %d1,%a2@(4)
0x00006db4:  moveal %fp@(-8),%a2
0x00006db6:  moveal %fp@(-4),%a3
0x00006db8:  unlk %fp
0x00006dba:  rts
