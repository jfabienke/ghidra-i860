; Function: func_00005dea
; Address: 0x00005dea - 0x00005ee9
; Size: 256 bytes
; Frame: 68 bytes
; Purpose: Unknown
; Description: 256 bytes, frame size 68
; Confidence: UNKNOWN
;
0x00005dea:  linkw %fp,#-68
0x00005dec:  .short 0x48e7
0x00005dee:  movew %a0@(000000000000006e,%d2:w:8),%d0
0x00005df0:  .short 0x000c
0x00005df2:  lea %fp@(-68),%a2
0x00005df4:  invalid
0x00005df6:  .short 0x0001
0x00005df8:  .short 0xffbf
0x00005dfa:  moveq #24,%d3
0x00005dfc:  movel %d3,%fp@(-64)
0x00005dfe:  invalid
0x00005e00:  .short 0x0000
0x00005e02:  btst %d0,%d0
0x00005e04:  .short 0xffc4
0x00005e06:  invalid
0x00005e08:  .short 0x0008
0x00005e0a:  .short 0xffcc
0x00005e0c:  invalid
0x00005e0e:  .short 0x04ff
0x00005e10:  .short 0xcb4a
0x00005e12:  movel %d0,%fp@(-56)
0x00005e14:  invalid
0x00005e16:  .short 0x0000
0x00005e18:  bset %d2,%fp@
0x00005e1a:  .short 0xffd0
0x00005e1c:  clrl %sp@-
0x00005e1e:  clrl %sp@-
0x00005e20:  pea 0x00000044
0x00005e22:  clrl %sp@-
0x00005e24:  movel %a2,%sp@-
0x00005e26:  invalid
0x00005e28:  .short 0x04ff
0x00005e2a:  .short 0xcb8c
0x00005e2c:  movel %d0,%d2
0x00005e2e:  .short 0xdefc
0x00005e30:  .short 0x0014
0x00005e32:  beqs 0x0000006a
0x00005e34:  invalid
0x00005e36:  breakpoint
0x00005e38:  .short 0xff36
0x00005e3a:  bnes 0x00000064
0x00005e3c:  invalid
0x00005e3e:  .short 0x04ff
0x00005e40:  .short 0xcb10
0x00005e42:  movel %d2,%d0
0x00005e44:  braw 0x000000f6
0x00005e46:  movel %a2@(4),%d0
0x00005e48:  .short 0xe9ea
0x00005e4a:  .short 0x1008
0x00005e4c:  .short 0x0003
0x00005e4e:  invalid
0x00005e50:  .short 0x0000
0x00005e52:  .short 0x063a
0x00005e54:  .short 0x0014
0x00005e56:  beqs 0x00000086
0x00005e58:  invalid
0x00005e5a:  breakpoint
0x00005e5c:  .short 0xfed3
0x00005e5e:  bras 0x000000f6
0x00005e60:  moveq #68,%d3
0x00005e62:  cmpl %d0,%d3
0x00005e64:  bnes 0x00000092
0x00005e66:  moveq #1,%d3
0x00005e68:  cmpl %d1,%d3
0x00005e6a:  beqs 0x000000a4
0x00005e6c:  moveq #32,%d3
0x00005e6e:  cmpl %d0,%d3
0x00005e70:  bnes 0x000000f0
0x00005e72:  moveq #1,%d3
0x00005e74:  cmpl %d1,%d3
0x00005e76:  bnes 0x000000f0
0x00005e78:  tstl %a2@(28)
0x00005e7a:  beqs 0x000000f0
0x00005e7c:  movel %a2@(24),%d3
0x00005e7e:  invalid
0x00005e80:  .short 0x0000
0x00005e82:  moveq #-108,%d6
0x00005e84:  bnes 0x000000f0
0x00005e86:  tstl %a2@(28)
0x00005e88:  beqs 0x000000bc
0x00005e8a:  movel %a2@(28),%d0
0x00005e8c:  bras 0x000000f6
0x00005e8e:  movel %a2@(32),%d3
0x00005e90:  invalid
0x00005e92:  .short 0x0000
0x00005e94:  moveq #-104,%d6
0x00005e96:  bnes 0x000000f0
0x00005e98:  movel %a2@(36),%a3@+
0x00005e9a:  moveal %a3,%a0
0x00005e9c:  movel %a2@(40),%a0@+
0x00005e9e:  movel %a2@(44),%a0@+
0x00005ea0:  movel %a2@(48),%a0@+
0x00005ea2:  movel %a2@(52),%a0@+
0x00005ea4:  movel %a2@(56),%a0@+
0x00005ea6:  movel %a2@(60),%a0@+
0x00005ea8:  movel %a2@(64),%a0@
0x00005eaa:  movel %a2@(28),%d0
0x00005eac:  bras 0x000000f6
0x00005eae:  invalid
0x00005eb0:  breakpoint
0x00005eb2:  .short 0xfed4
0x00005eb4:  invalid
0x00005eb6:  cmpib #-84,%d4
0x00005eb8:  unlk %fp
0x00005eba:  rts
