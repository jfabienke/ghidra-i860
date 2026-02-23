; Function: func_00005af6
; Address: 0x00005af6 - 0x00005bb7
; Size: 194 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 194 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00005af6:  linkw %fp,#0
0x00005af8:  .short 0x48e7
0x00005afa:  movew %a0@-,%d6
0x00005afc:  movel %fp@(8),%d4
0x00005afe:  movel %fp@(12),%d3
0x00005b00:  invalid
0x00005b02:  .short 0x04ff
0x00005b04:  .short 0xd656
0x00005b06:  movel %d0,%d5
0x00005b08:  movel %d3,%sp@-
0x00005b0a:  movel %d4,%sp@-
0x00005b0c:  invalid
0x00005b0e:  breakpoint
0x00005b10:  addl %d5,%fp@+
0x00005b12:  movel %d0,%d2
0x00005b14:  .short 0x504f
0x00005b16:  bnew 0x000000b8
0x00005b18:  movel %d3,%d0
0x00005b1a:  asrl #1,%d0
0x00005b1c:  invalid
0x00005b1e:  .short 0x0000
0x00005b20:  orl %d0,%a4@+
0x00005b22:  moveal %a0@(0000000000000000,%d0:l:4),%a2
0x00005b24:  pea %a2@(64)
0x00005b26:  pea %a2@(44)
0x00005b28:  movel %d3,%sp@-
0x00005b2a:  movel %d5,%sp@-
0x00005b2c:  movel %a2@(4),%sp@-
0x00005b2e:  movel %d4,%sp@-
0x00005b30:  invalid
0x00005b32:  breakpoint
0x00005b34:  .short 0xf146
0x00005b36:  movel %d0,%d2
0x00005b38:  .short 0xdefc
0x00005b3a:  .short 0x0018
0x00005b3c:  beqs 0x00000066
0x00005b3e:  movel %d3,%sp@-
0x00005b40:  movel %d4,%sp@-
0x00005b42:  invalid
0x00005b44:  breakpoint
0x00005b46:  .short 0xdd20
0x00005b48:  movel %d2,%d0
0x00005b4a:  bras 0x000000b8
0x00005b4c:  movel %d3,%sp@-
0x00005b4e:  movel %d4,%sp@-
0x00005b50:  invalid
0x00005b52:  .short 0x0000
0x00005b54:  .short 0x010e
0x00005b56:  .short 0x504f
0x00005b58:  tstl %d0
0x00005b5a:  bnes 0x000000ac
0x00005b5c:  movel %fp@(24),%sp@-
0x00005b5e:  movel %fp@(20),%sp@-
0x00005b60:  movel %fp@(16),%sp@-
0x00005b62:  movel %a2,%sp@-
0x00005b64:  invalid
0x00005b66:  .short 0x0000
0x00005b68:  moveb %fp@(000000000000004f,%d5:w),%a2@
0x00005b6a:  .short 0x504f
0x00005b6c:  moveq #-1,%d1
0x00005b6e:  cmpl %d0,%d1
0x00005b70:  beqs 0x000000ac
0x00005b72:  movel %a2@(64),%sp@-
0x00005b74:  movel %a2@(44),%sp@-
0x00005b76:  movel %d5,%sp@-
0x00005b78:  invalid
0x00005b7a:  .short 0x04ff
0x00005b7c:  .short 0xd724
0x00005b7e:  clrl %a2@(44)
0x00005b80:  clrl %d0
0x00005b82:  bras 0x000000b8
0x00005b84:  movel %d3,%sp@-
0x00005b86:  movel %d4,%sp@-
0x00005b88:  invalid
0x00005b8a:  breakpoint
0x00005b8c:  .short 0xdccc
0x00005b8e:  moveq #5,%d0
0x00005b90:  invalid
0x00005b92:  .short 0x043c
0x00005b94:  .short 0xffec
0x00005b96:  unlk %fp
0x00005b98:  rts
