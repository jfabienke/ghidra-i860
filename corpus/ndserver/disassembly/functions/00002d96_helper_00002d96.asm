; Function: helper_00002d96
; Address: 0x00002d96 - 0x00002dc5
; Size: 48 bytes
; Frame: 4 bytes
; Purpose: Utility/Helper
; Description: Small function (48 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00002d96:  linkw %fp,#-4
0x00002d98:  invalid
0x00002d9a:  .short 0x0000
0x00002d9c:  mvzw 0xfffffffffffffffc,%d2
0x00002d9e:  nop
0x00002da0:  invalid
0x00002da2:  .short 0x0000
0x00002da4:  invalid
0x00002da6:  .short 0xfffc
0x00002da8:  bccs 0x0000002c
0x00002daa:  moveal %fp@(-4),%a0
0x00002dac:  moveal %a0@(4),%a1
0x00002dae:  moveal %fp@(-4),%a0
0x00002db0:  movel %a0@,%a1@
0x00002db2:  addql #8,%fp@(-4)
0x00002db4:  bras 0x0000000e
0x00002db6:  unlk %fp
0x00002db8:  rts
