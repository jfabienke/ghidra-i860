; Function: func_00006c48
; Address: 0x00006c48 - 0x00006d23
; Size: 220 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 220 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006c48:  linkw %fp,#0
0x00006c4a:  movel %a3,%sp@-
0x00006c4c:  movel %a2,%sp@-
0x00006c4e:  moveal %fp@(8),%a2
0x00006c50:  moveal %fp@(12),%a3
0x00006c52:  .short 0xe9ea
0x00006c54:  .short 0x0008
0x00006c56:  .short 0x0003
0x00006c58:  invalid
0x00006c5a:  .short 0x0000
0x00006c5c:  .short 0x043c
0x00006c5e:  .short 0x0004
0x00006c60:  bnes 0x00000026
0x00006c62:  moveq #1,%d1
0x00006c64:  cmpl %d0,%d1
0x00006c66:  beqs 0x00000032
0x00006c68:  invalid
0x00006c6a:  breakpoint
0x00006c6c:  .short 0xfed0
0x00006c6e:  .short 0x001c
0x00006c70:  braw 0x000000d0
0x00006c72:  movel %a2@(24),%d1
0x00006c74:  invalid
0x00006c76:  .short 0x0000
0x00006c78:  mvsw %a4@(000000000000003e,%d6:w:8),%d6
0x00006c7a:  moveb %a2@(35),%d0
0x00006c7c:  .short 0x0200
0x00006c7e:  .short 0x000c
0x00006c80:  cmpib #12,%d0
0x00006c82:  bnes 0x0000007c
0x00006c84:  cmpiw #12,%d2
0x00006c86:  .short 0x0024
0x00006c88:  bnes 0x0000007c
0x00006c8a:  moveq #1,%d1
0x00006c8c:  cmpl %a2@(40),%d1
0x00006c8e:  bnes 0x0000007c
0x00006c90:  cmpiw #8192,%d2
0x00006c92:  .short 0x0026
0x00006c94:  bnes 0x0000007c
0x00006c96:  movel %a2@(1068),%d1
0x00006c98:  invalid
0x00006c9a:  .short 0x0000
0x00006c9c:  mvsw 0x0000660c,%d6
0x00006c9e:  movel %a2@(1076),%d1
0x00006ca0:  invalid
0x00006ca2:  .short 0x0000
0x00006ca4:  mvsw #26378,%d6
0x00006ca6:  invalid
0x00006ca8:  breakpoint
0x00006caa:  .short 0xfed0
0x00006cac:  .short 0x001c
0x00006cae:  bras 0x000000a8
0x00006cb0:  movel %a2@(1080),%sp@-
0x00006cb2:  movel %a2@(1072),%sp@-
0x00006cb4:  pea %a2@(44)
0x00006cb6:  pea %a2@(28)
0x00006cb8:  movel %a2@(12),%sp@-
0x00006cba:  invalid
0x00006cbc:  breakpoint
0x00006cbe:  .short 0xf730
0x00006cc0:  movel %d0,%a3@(36)
0x00006cc2:  clrl %a3@(28)
0x00006cc4:  tstl %a3@(28)
0x00006cc6:  bnes 0x000000d0
0x00006cc8:  invalid
0x00006cca:  .short 0x0000
0x00006ccc:  mvzb %d0,%d6
0x00006cce:  .short 0x0020
0x00006cd0:  invalid
0x00006cd2:  .short 0x0000
0x00006cd4:  mvzb %d4,%d6
0x00006cd6:  .short 0x0028
0x00006cd8:  invalid
0x00006cda:  .short 0x001c
0x00006cdc:  .short 0x002c
0x00006cde:  invalid
0x00006ce0:  .short 0x0001
0x00006ce2:  .short 0x0003
0x00006ce4:  moveq #48,%d1
0x00006ce6:  movel %d1,%a3@(4)
0x00006ce8:  moveal %fp@(-8),%a2
0x00006cea:  moveal %fp@(-4),%a3
0x00006cec:  unlk %fp
0x00006cee:  rts
