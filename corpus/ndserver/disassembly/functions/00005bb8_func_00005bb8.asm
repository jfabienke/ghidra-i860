; Function: func_00005bb8
; Address: 0x00005bb8 - 0x00005c6f
; Size: 184 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 184 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00005bb8:  linkw %fp,#0
0x00005bba:  .short 0x48e7
0x00005bbc:  movew %a0@-,%d6
0x00005bbe:  movel %fp@(8),%d4
0x00005bc0:  movel %fp@(12),%d3
0x00005bc2:  invalid
0x00005bc4:  .short 0x04ff
0x00005bc6:  addl %d2,%a4@
0x00005bc8:  movel %d0,%d5
0x00005bca:  movel %d3,%sp@-
0x00005bcc:  movel %d4,%sp@-
0x00005bce:  invalid
0x00005bd0:  breakpoint
0x00005bd2:  .short 0xdadc
0x00005bd4:  movel %d0,%d2
0x00005bd6:  .short 0x504f
0x00005bd8:  bnew 0x000000ae
0x00005bda:  movel %d3,%d0
0x00005bdc:  asrl #1,%d0
0x00005bde:  invalid
0x00005be0:  .short 0x0000
0x00005be2:  orl %d0,%a4@+
0x00005be4:  moveal %a0@(0000000000000000,%d0:l:4),%a2
0x00005be6:  pea %a2@(64)
0x00005be8:  pea %a2@(44)
0x00005bea:  movel %d3,%sp@-
0x00005bec:  movel %d5,%sp@-
0x00005bee:  movel %a2@(4),%sp@-
0x00005bf0:  movel %d4,%sp@-
0x00005bf2:  invalid
0x00005bf4:  breakpoint
0x00005bf6:  .short 0xf084
0x00005bf8:  movel %d0,%d2
0x00005bfa:  .short 0xdefc
0x00005bfc:  .short 0x0018
0x00005bfe:  beqs 0x00000066
0x00005c00:  movel %d3,%sp@-
0x00005c02:  movel %d4,%sp@-
0x00005c04:  invalid
0x00005c06:  breakpoint
0x00005c08:  .short 0xdc5e
0x00005c0a:  movel %d2,%d0
0x00005c0c:  bras 0x000000ae
0x00005c0e:  movel %d3,%sp@-
0x00005c10:  movel %d4,%sp@-
0x00005c12:  invalid
0x00005c14:  .short 0x0000
0x00005c16:  .short 0x004c
0x00005c18:  .short 0x504f
0x00005c1a:  tstl %d0
0x00005c1c:  bnes 0x000000a2
0x00005c1e:  movel %fp@(16),%sp@-
0x00005c20:  movel %a2,%sp@-
0x00005c22:  invalid
0x00005c24:  .short 0x0000
0x00005c26:  moveb #79,%d2
0x00005c28:  moveq #-1,%d1
0x00005c2a:  cmpl %d0,%d1
0x00005c2c:  beqs 0x000000a2
0x00005c2e:  movel %a2@(64),%sp@-
0x00005c30:  movel %a2@(44),%sp@-
0x00005c32:  movel %d5,%sp@-
0x00005c34:  invalid
0x00005c36:  .short 0x04ff
0x00005c38:  .short 0xd66c
0x00005c3a:  clrl %a2@(44)
0x00005c3c:  clrl %d0
0x00005c3e:  bras 0x000000ae
0x00005c40:  movel %d3,%sp@-
0x00005c42:  movel %d4,%sp@-
0x00005c44:  invalid
0x00005c46:  breakpoint
0x00005c48:  .short 0xdc14
0x00005c4a:  moveq #5,%d0
0x00005c4c:  invalid
0x00005c4e:  .short 0x043c
0x00005c50:  .short 0xffec
0x00005c52:  unlk %fp
0x00005c54:  rts
