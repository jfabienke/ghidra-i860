; Function: func_00005c70
; Address: 0x00005c70 - 0x00005d25
; Size: 182 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 182 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00005c70:  linkw %fp,#0
0x00005c72:  movel %a2,%sp@-
0x00005c74:  movel %d2,%sp@-
0x00005c76:  movel %fp@(12),%d0
0x00005c78:  asrl #1,%d0
0x00005c7a:  invalid
0x00005c7c:  .short 0x0000
0x00005c7e:  orl %d0,%a4@+
0x00005c80:  moveal %a0@(0000000000000000,%d0:l:4),%a2
0x00005c82:  tstl %a2
0x00005c84:  bnes 0x00000022
0x00005c86:  moveq #4,%d0
0x00005c88:  braw 0x000000aa
0x00005c8a:  moveal %a2@(28),%a0
0x00005c8c:  movel %a0@,%d0
0x00005c8e:  moveq #6,%d1
0x00005c90:  andl %d1,%d0
0x00005c92:  cmpl %d0,%d1
0x00005c94:  beqs 0x0000006c
0x00005c96:  moveq #1,%d1
0x00005c98:  movel %d1,%a0@
0x00005c9a:  clrl %d2
0x00005c9c:  moveal %a2@(28),%a0
0x00005c9e:  movel %a0@,%d0
0x00005ca0:  moveq #6,%d1
0x00005ca2:  andl %d1,%d0
0x00005ca4:  cmpl %d0,%d1
0x00005ca6:  beqs 0x0000006c
0x00005ca8:  invalid
0x00005caa:  .short 0x0001
0x00005cac:  orl %a0@-,%d3
0x00005cae:  invalid
0x00005cb0:  .short 0x04ff
0x00005cb2:  addl %d2,%a4@-
0x00005cb4:  moveal %a2@(28),%a0
0x00005cb6:  movel %a0@,%d0
0x00005cb8:  .short 0x584f
0x00005cba:  btst #1,%d0
0x00005cbc:  bnes 0x00000062
0x00005cbe:  moveq #1,%d1
0x00005cc0:  movel %d1,%a0@
0x00005cc2:  addql #1,%d2
0x00005cc4:  invalid
0x00005cc6:  .short 0x0000
0x00005cc8:  invalid
0x00005cca:  bles 0x00000036
0x00005ccc:  moveal %a2@(28),%a0
0x00005cce:  movel %a0@,%d0
0x00005cd0:  moveq #6,%d1
0x00005cd2:  andl %d1,%d0
0x00005cd4:  cmpl %d0,%d1
0x00005cd6:  beqs 0x0000007e
0x00005cd8:  moveq #5,%d0
0x00005cda:  bras 0x000000aa
0x00005cdc:  tstl %a2@(44)
0x00005cde:  beqs 0x000000a8
0x00005ce0:  movel %a2@(64),%d0
0x00005ce2:  subql #1,%d0
0x00005ce4:  invalid
0x00005ce6:  .short 0x083f
0x00005ce8:  .short 0xe800
0x00005cea:  moveal %a2@(44),%a2
0x00005cec:  addal %d0,%a2
0x00005cee:  pea 0x00000414
0x00005cf0:  clrl %sp@-
0x00005cf2:  movel %a2,%sp@-
0x00005cf4:  invalid
0x00005cf6:  .short 0x04ff
0x00005cf8:  .short 0xcc44
0x00005cfa:  moveq #-1,%d1
0x00005cfc:  movel %d1,%a2@
0x00005cfe:  clrl %d0
0x00005d00:  movel %fp@(-8),%d2
0x00005d02:  moveal %fp@(-4),%a2
0x00005d04:  unlk %fp
0x00005d06:  rts
