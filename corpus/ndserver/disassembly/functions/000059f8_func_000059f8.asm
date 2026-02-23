; Function: func_000059f8
; Address: 0x000059f8 - 0x00005a3d
; Size: 70 bytes
; Frame: 32 bytes
; Purpose: Unknown
; Description: 70 bytes, frame size 32
; Confidence: UNKNOWN
;
0x000059f8:  linkw %fp,#-32
0x000059fa:  invalid
0x000059fc:  .short 0x0000
0x000059fe:  moveq #-120,%d6
0x00005a00:  .short 0xfff8
0x00005a02:  invalid
0x00005a04:  .short 0x000c
0x00005a06:  .short 0xfffc
0x00005a08:  invalid
0x00005a0a:  .short 0x0001
0x00005a0c:  .short 0xffe3
0x00005a0e:  moveq #32,%d1
0x00005a10:  movel %d1,%fp@(-28)
0x00005a12:  clrl %fp@(-24)
0x00005a14:  invalid
0x00005a16:  .short 0x0008
0x00005a18:  .short 0xfff0
0x00005a1a:  clrl %fp@(-20)
0x00005a1c:  invalid
0x00005a1e:  .short 0x0000
0x00005a20:  invalid
0x00005a22:  .short 0xfff4
0x00005a24:  clrl %sp@-
0x00005a26:  clrl %sp@-
0x00005a28:  pea %fp@(-32)
0x00005a2a:  invalid
0x00005a2c:  .short 0x04ff
0x00005a2e:  andl %d7,%a4@+
0x00005a30:  unlk %fp
0x00005a32:  rts
