; Function: func_00004a52
; Address: 0x00004a52 - 0x00004b6f
; Size: 286 bytes
; Frame: 300 bytes
; Purpose: Unknown
; Description: 286 bytes, frame size 300
; Confidence: UNKNOWN
;
0x00004a52:  linkw %fp,#-300
0x00004a54:  .short 0x48e7
0x00004a56:  movew %a0@(000000000000002e,%d2:w:4),%d0
0x00004a58:  .short 0x0008
0x00004a5a:  moveal %fp@(20),%a3
0x00004a5c:  lea %fp@(-300),%a2
0x00004a5e:  invalid
0x00004a60:  .short 0x0000
0x00004a62:  btst %d0,%a4@(11641)
0x00004a64:  .short 0x0000
0x00004a66:  mvsw %a0@-,%d5
0x00004a68:  .short 0xfeec
0x00004a6a:  invalid
0x00004a6c:  .short 0x000c
0x00004a6e:  .short 0xfef0
0x00004a70:  invalid
0x00004a72:  .short 0x0000
0x00004a74:  mvsw %a4@-,%d5
0x00004a76:  .short 0x0020
0x00004a78:  invalid
0x00004a7a:  .short 0x0000
0x00004a7c:  mvsw %a0@(36),%d5
0x00004a7e:  invalid
0x00004a80:  .short 0x0000
0x00004a82:  mvsw %a4@(40),%d5
0x00004a84:  pea 0x00000100
0x00004a86:  movel %fp@(16),%sp@-
0x00004a88:  pea %a2@(44)
0x00004a8a:  invalid
0x00004a8c:  .short 0x04ff
0x00004a8e:  lsll %d2,%d2
0x00004a90:  clrb %fp@(-1)
0x00004a92:  invalid
0x00004a94:  .short 0x0001
0x00004a96:  .short 0xfed7
0x00004a98:  movel %d3,%fp@(-296)
0x00004a9a:  invalid
0x00004a9c:  .short 0x0000
0x00004a9e:  btst %d0,%d0
0x00004aa0:  .short 0xfedc
0x00004aa2:  movel %d2,%fp@(-284)
0x00004aa4:  invalid
0x00004aa6:  .short 0x04ff
0x00004aa8:  addl %a0@-,%d7
0x00004aaa:  movel %d0,%fp@(-288)
0x00004aac:  moveq #114,%d1
0x00004aae:  movel %d1,%fp@(-280)
0x00004ab0:  clrl %sp@-
0x00004ab2:  clrl %sp@-
0x00004ab4:  pea 0x00000028
0x00004ab6:  clrl %sp@-
0x00004ab8:  movel %a2,%sp@-
0x00004aba:  invalid
0x00004abc:  .short 0x04ff
0x00004abe:  .short 0xdee4
0x00004ac0:  movel %d0,%d2
0x00004ac2:  .short 0xdefc
0x00004ac4:  .short 0x0020
0x00004ac6:  beqs 0x000000a8
0x00004ac8:  invalid
0x00004aca:  breakpoint
0x00004acc:  .short 0xff36
0x00004ace:  bnes 0x000000a4
0x00004ad0:  invalid
0x00004ad2:  .short 0x04ff
0x00004ad4:  .short 0xde68
0x00004ad6:  movel %d2,%d0
0x00004ad8:  bras 0x00000114
0x00004ada:  movel %a2@(4),%d3
0x00004adc:  .short 0xe9ea
0x00004ade:  .short 0x0008
0x00004ae0:  .short 0x0003
0x00004ae2:  invalid
0x00004ae4:  .short 0x0000
0x00004ae6:  .short 0x00d6
0x00004ae8:  .short 0x0014
0x00004aea:  beqs 0x000000c4
0x00004aec:  invalid
0x00004aee:  breakpoint
0x00004af0:  .short 0xfed3
0x00004af2:  bras 0x00000114
0x00004af4:  moveq #40,%d1
0x00004af6:  cmpl %d3,%d1
0x00004af8:  bnes 0x000000ce
0x00004afa:  tstl %d0
0x00004afc:  beqs 0x000000e0
0x00004afe:  moveq #32,%d1
0x00004b00:  cmpl %d3,%d1
0x00004b02:  bnes 0x0000010e
0x00004b04:  moveq #1,%d1
0x00004b06:  cmpl %d0,%d1
0x00004b08:  bnes 0x0000010e
0x00004b0a:  tstl %a2@(28)
0x00004b0c:  beqs 0x0000010e
0x00004b0e:  movel %a2@(24),%d1
0x00004b10:  invalid
0x00004b12:  .short 0x0000
0x00004b14:  mvsw %a0@(0000000000000022,%d6:w:8),%d5
0x00004b16:  tstl %a2@(28)
0x00004b18:  beqs 0x000000f8
0x00004b1a:  movel %a2@(28),%d0
0x00004b1c:  bras 0x00000114
0x00004b1e:  movel %a2@(32),%d1
0x00004b20:  invalid
0x00004b22:  .short 0x0000
0x00004b24:  mvsw %a4@(000000000000000a,%d6:w:8),%d5
0x00004b26:  movel %a2@(36),%a3@
0x00004b28:  movel %a2@(28),%d0
0x00004b2a:  bras 0x00000114
0x00004b2c:  invalid
0x00004b2e:  breakpoint
0x00004b30:  .short 0xfed4
0x00004b32:  invalid
0x00004b34:  cmpib #-60,%d4
0x00004b36:  unlk %fp
0x00004b38:  rts
