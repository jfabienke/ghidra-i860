; Function: func_00006f94
; Address: 0x00006f94 - 0x00007031
; Size: 158 bytes
; Frame: 60 bytes
; Purpose: Unknown
; Description: 158 bytes, frame size 60
; Confidence: UNKNOWN
;
0x00006f94:  linkw %fp,#-60
0x00006f96:  movel %d3,%sp@-
0x00006f98:  movel %d2,%sp@-
0x00006f9a:  pea 0x000001a4
0x00006f9c:  clrl %sp@-
0x00006f9e:  movel %fp@(12),%sp@-
0x00006fa0:  invalid
0x00006fa2:  .short 0x04ff
0x00006fa4:  cmpb %a4@+,%d6
0x00006fa6:  movel %d0,%d3
0x00006fa8:  .short 0x504f
0x00006faa:  .short 0x584f
0x00006fac:  moveq #-1,%d1
0x00006fae:  cmpl %d3,%d1
0x00006fb0:  beqs 0x00000092
0x00006fb2:  pea %fp@(-60)
0x00006fb4:  movel %d3,%sp@-
0x00006fb6:  invalid
0x00006fb8:  .short 0x04ff
0x00006fba:  eorl %d2,%a2@(9216)
0x00006fbc:  .short 0x504f
0x00006fbe:  moveq #-1,%d1
0x00006fc0:  cmpl %d2,%d1
0x00006fc2:  beqs 0x00000088
0x00006fc4:  movel %fp@(-44),%sp@-
0x00006fc6:  pea 0x00000001
0x00006fc8:  invalid
0x00006fca:  .short 0x0000
0x00006fcc:  .short 0x8018
0x00006fce:  clrl %sp@-
0x00006fd0:  movel %d3,%sp@-
0x00006fd2:  invalid
0x00006fd4:  .short 0x04ff
0x00006fd6:  .short 0xb93c
0x00006fd8:  .short 0xdefc
0x00006fda:  .short 0x0014
0x00006fdc:  tstl %d0
0x00006fde:  bnes 0x00000088
0x00006fe0:  movel %fp@(8),%sp@-
0x00006fe2:  invalid
0x00006fe4:  .short 0x0000
0x00006fe6:  invalid
0x00006fe8:  movel %d0,%d2
0x00006fea:  movel %fp@(-44),%sp@-
0x00006fec:  invalid
0x00006fee:  .short 0x0000
0x00006ff0:  .short 0x8018
0x00006ff2:  invalid
0x00006ff4:  .short 0x0401
0x00006ff6:  invalid
0x00006ff8:  invalid
0x00006ffa:  .short 0x04ff
0x00006ffc:  andl %fp@(12035),%d1
0x00006ffe:  invalid
0x00007000:  .short 0x04ff
0x00007002:  cmpl %d6,%d1
0x00007004:  movel %d2,%d0
0x00007006:  bras 0x00000092
0x00007008:  movel %d3,%sp@-
0x0000700a:  invalid
0x0000700c:  .short 0x04ff
0x0000700e:  cmpw %pc@(0x0000718f),%d1
0x00007010:  movel %fp@(-68),%d2
0x00007012:  movel %fp@(-64),%d3
0x00007014:  unlk %fp
0x00007016:  rts
