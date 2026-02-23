; Function: func_00003eae
; Address: 0x00003eae - 0x00003f39
; Size: 140 bytes
; Frame: 548 bytes
; Purpose: Unknown
; Description: 140 bytes, frame size 548
; Confidence: UNKNOWN
;
0x00003eae:  linkw %fp,#-548
0x00003eb0:  .short 0x48e7
0x00003eb2:  movew %a0@-,%d0
0x00003eb4:  movel %fp@(20),%d2
0x00003eb6:  lea %fp@(-548),%a2
0x00003eb8:  moveq #36,%d3
0x00003eba:  invalid
0x00003ebc:  .short 0x0000
0x00003ebe:  moveq #-128,%d5
0x00003ec0:  .short 0xfdf4
0x00003ec2:  invalid
0x00003ec4:  .short 0x000c
0x00003ec6:  .short 0xfdf8
0x00003ec8:  invalid
0x00003eca:  .short 0x0000
0x00003ecc:  moveq #-124,%d5
0x00003ece:  .short 0xfdfc
0x00003ed0:  invalid
0x00003ed2:  .short 0x0000
0x00003ed4:  .short 0x0200
0x00003ed6:  bhis 0x0000007c
0x00003ed8:  movel %d2,%sp@-
0x00003eda:  movel %fp@(16),%sp@-
0x00003edc:  pea %a2@(36)
0x00003ede:  invalid
0x00003ee0:  .short 0x04ff
0x00003ee2:  .short 0xea64
0x00003ee4:  .short 0xefee
0x00003ee6:  movel %a4,%d0
0x00003ee8:  .short 0xfdfe
0x00003eea:  movel %d2,%d0
0x00003eec:  addql #3,%d0
0x00003eee:  moveq #-4,%d1
0x00003ef0:  andl %d1,%d0
0x00003ef2:  invalid
0x00003ef4:  .short 0x0001
0x00003ef6:  .short 0xfddf
0x00003ef8:  addl %d3,%d0
0x00003efa:  movel %d0,%fp@(-544)
0x00003efc:  clrl %fp@(-540)
0x00003efe:  invalid
0x00003f00:  .short 0x0008
0x00003f02:  .short 0xfdec
0x00003f04:  clrl %fp@(-536)
0x00003f06:  moveq #102,%d1
0x00003f08:  movel %d1,%fp@(-528)
0x00003f0a:  clrl %sp@-
0x00003f0c:  clrl %sp@-
0x00003f0e:  movel %a2,%sp@-
0x00003f10:  invalid
0x00003f12:  .short 0x04ff
0x00003f14:  lsrl %d5,%d6
0x00003f16:  bras 0x00000082
0x00003f18:  invalid
0x00003f1a:  breakpoint
0x00003f1c:  .short 0xfecd
0x00003f1e:  invalid
0x00003f20:  .short 0x040c
0x00003f22:  .short 0xfdd0
0x00003f24:  unlk %fp
0x00003f26:  rts
