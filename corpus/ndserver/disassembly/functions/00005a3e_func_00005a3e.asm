; Function: func_00005a3e
; Address: 0x00005a3e - 0x00005af5
; Size: 184 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 184 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00005a3e:  linkw %fp,#0
0x00005a40:  .short 0x48e7
0x00005a42:  movew %a0@-,%d6
0x00005a44:  movel %fp@(8),%d4
0x00005a46:  movel %fp@(12),%d3
0x00005a48:  invalid
0x00005a4a:  .short 0x04ff
0x00005a4c:  .short 0xd70e
0x00005a4e:  movel %d0,%d5
0x00005a50:  movel %d3,%sp@-
0x00005a52:  movel %d4,%sp@-
0x00005a54:  invalid
0x00005a56:  breakpoint
0x00005a58:  .short 0xdc56
0x00005a5a:  movel %d0,%d2
0x00005a5c:  .short 0x504f
0x00005a5e:  bnew 0x000000ae
0x00005a60:  movel %d3,%d0
0x00005a62:  asrl #1,%d0
0x00005a64:  invalid
0x00005a66:  .short 0x0000
0x00005a68:  orl %d0,%a4@+
0x00005a6a:  moveal %a0@(0000000000000000,%d0:l:4),%a2
0x00005a6c:  pea %a2@(64)
0x00005a6e:  pea %a2@(44)
0x00005a70:  movel %d3,%sp@-
0x00005a72:  movel %d5,%sp@-
0x00005a74:  movel %a2@(4),%sp@-
0x00005a76:  movel %d4,%sp@-
0x00005a78:  invalid
0x00005a7a:  breakpoint
0x00005a7c:  .short 0xf1fe
0x00005a7e:  movel %d0,%d2
0x00005a80:  .short 0xdefc
0x00005a82:  .short 0x0018
0x00005a84:  beqs 0x00000066
0x00005a86:  movel %d3,%sp@-
0x00005a88:  movel %d4,%sp@-
0x00005a8a:  invalid
0x00005a8c:  breakpoint
0x00005a8e:  addal %a0@+,%fp
0x00005a90:  movel %d2,%d0
0x00005a92:  bras 0x000000ae
0x00005a94:  movel %d3,%sp@-
0x00005a96:  movel %d4,%sp@-
0x00005a98:  invalid
0x00005a9a:  .short 0x0000
0x00005a9c:  bset %d0,%d6
0x00005a9e:  .short 0x504f
0x00005aa0:  tstl %d0
0x00005aa2:  bnes 0x000000a2
0x00005aa4:  movel %fp@(16),%sp@-
0x00005aa6:  movel %a2,%sp@-
0x00005aa8:  invalid
0x00005aaa:  .short 0x0000
0x00005aac:  moveb %a0@+,%a2@+
0x00005aae:  .short 0x504f
0x00005ab0:  moveq #-1,%d1
0x00005ab2:  cmpl %d0,%d1
0x00005ab4:  beqs 0x000000a2
0x00005ab6:  movel %a2@(64),%sp@-
0x00005ab8:  movel %a2@(44),%sp@-
0x00005aba:  movel %d5,%sp@-
0x00005abc:  invalid
0x00005abe:  .short 0x04ff
0x00005ac0:  addal %fp@-,%a3
0x00005ac2:  clrl %a2@(44)
0x00005ac4:  clrl %d0
0x00005ac6:  bras 0x000000ae
0x00005ac8:  movel %d3,%sp@-
0x00005aca:  movel %d4,%sp@-
0x00005acc:  invalid
0x00005ace:  breakpoint
0x00005ad0:  .short 0xdd8e
0x00005ad2:  moveq #5,%d0
0x00005ad4:  invalid
0x00005ad6:  .short 0x043c
0x00005ad8:  .short 0xffec
0x00005ada:  unlk %fp
0x00005adc:  rts
