; Function: func_00006b7c
; Address: 0x00006b7c - 0x00006c47
; Size: 204 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 204 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00006b7c:  linkw %fp,#0
0x00006b7e:  movel %a3,%sp@-
0x00006b80:  movel %a2,%sp@-
0x00006b82:  moveal %fp@(8),%a2
0x00006b84:  moveal %fp@(12),%a3
0x00006b86:  .short 0xe9ea
0x00006b88:  .short 0x0008
0x00006b8a:  .short 0x0003
0x00006b8c:  invalid
0x00006b8e:  .short 0x0000
0x00006b90:  .short 0x0434
0x00006b92:  .short 0x0004
0x00006b94:  bnes 0x00000026
0x00006b96:  moveq #1,%d1
0x00006b98:  cmpl %d0,%d1
0x00006b9a:  beqs 0x00000032
0x00006b9c:  invalid
0x00006b9e:  breakpoint
0x00006ba0:  .short 0xfed0
0x00006ba2:  .short 0x001c
0x00006ba4:  braw 0x000000c0
0x00006ba6:  movel %a2@(24),%d1
0x00006ba8:  invalid
0x00006baa:  .short 0x0000
0x00006bac:  mvsw %a4@-,%d6
0x00006bae:  bnes 0x00000070
0x00006bb0:  moveb %a2@(35),%d0
0x00006bb2:  .short 0x0200
0x00006bb4:  .short 0x000c
0x00006bb6:  cmpib #12,%d0
0x00006bb8:  bnes 0x00000070
0x00006bba:  cmpiw #12,%d2
0x00006bbc:  .short 0x0024
0x00006bbe:  bnes 0x00000070
0x00006bc0:  moveq #1,%d1
0x00006bc2:  cmpl %a2@(40),%d1
0x00006bc4:  bnes 0x00000070
0x00006bc6:  cmpiw #8192,%d2
0x00006bc8:  .short 0x0026
0x00006bca:  bnes 0x00000070
0x00006bcc:  movel %a2@(1068),%d1
0x00006bce:  invalid
0x00006bd0:  .short 0x0000
0x00006bd2:  mvsw %a0@(26378),%d6
0x00006bd4:  invalid
0x00006bd6:  breakpoint
0x00006bd8:  .short 0xfed0
0x00006bda:  .short 0x001c
0x00006bdc:  bras 0x00000098
0x00006bde:  movel %a2@(1072),%sp@-
0x00006be0:  pea %a2@(44)
0x00006be2:  pea %a2@(28)
0x00006be4:  movel %a2@(12),%sp@-
0x00006be6:  invalid
0x00006be8:  breakpoint
0x00006bea:  .short 0xf7e0
0x00006bec:  movel %d0,%a3@(36)
0x00006bee:  clrl %a3@(28)
0x00006bf0:  tstl %a3@(28)
0x00006bf2:  bnes 0x000000c0
0x00006bf4:  invalid
0x00006bf6:  .short 0x0000
0x00006bf8:  mvsw %a4@(32),%d6
0x00006bfa:  invalid
0x00006bfc:  .short 0x0000
0x00006bfe:  mvsw %a0@(0000000000000028,%d0:w),%d6
0x00006c00:  invalid
0x00006c02:  .short 0x001c
0x00006c04:  .short 0x002c
0x00006c06:  invalid
0x00006c08:  .short 0x0001
0x00006c0a:  .short 0x0003
0x00006c0c:  moveq #48,%d1
0x00006c0e:  movel %d1,%a3@(4)
0x00006c10:  moveal %fp@(-8),%a2
0x00006c12:  moveal %fp@(-4),%a3
0x00006c14:  unlk %fp
0x00006c16:  rts
