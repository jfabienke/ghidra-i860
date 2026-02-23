; Function: func_00005d26
; Address: 0x00005d26 - 0x00005d5f
; Size: 58 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 58 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00005d26:  linkw %fp,#0
0x00005d28:  movel %d2,%sp@-
0x00005d2a:  movel %fp@(12),%d2
0x00005d2c:  invalid
0x00005d2e:  .short 0x04ff
0x00005d30:  .short 0xd42c
0x00005d32:  asrl #1,%d2
0x00005d34:  invalid
0x00005d36:  .short 0x0000
0x00005d38:  orl %d0,%a4@+
0x00005d3a:  moveal %a0@(0000000000000000,%d2:l:4),%a0
0x00005d3c:  tstl %a0
0x00005d3e:  beqs 0x00000030
0x00005d40:  moveal %a0@(28),%a0
0x00005d42:  movel %a0@,%d0
0x00005d44:  moveq #12,%d1
0x00005d46:  orl %d1,%d0
0x00005d48:  movel %d0,%a0@
0x00005d4a:  clrl %d0
0x00005d4c:  bras 0x00000032
0x00005d4e:  moveq #4,%d0
0x00005d50:  movel %fp@(-4),%d2
0x00005d52:  unlk %fp
0x00005d54:  rts
