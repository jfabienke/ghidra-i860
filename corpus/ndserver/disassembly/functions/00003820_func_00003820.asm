; Function: func_00003820
; Address: 0x00003820 - 0x00003873
; Size: 84 bytes
; Frame: 0 bytes
; Purpose: Unknown
; Description: 84 bytes, frame size 0
; Confidence: UNKNOWN
;
0x00003820:  linkw %fp,#0
0x00003822:  movel %fp@(12),%d0
0x00003824:  moveal %fp@(16),%a1
0x00003826:  moveq #8,%d1
0x00003828:  cmpl %d0,%d1
0x0000382a:  bcss 0x00000018
0x0000382c:  btst #0,%d0
0x0000382e:  beqs 0x0000001c
0x00003830:  moveq #4,%d0
0x00003832:  bras 0x00000050
0x00003834:  asrl #1,%d0
0x00003836:  subql #1,%d0
0x00003838:  invalid
0x0000383a:  .short 0x0000
0x0000383c:  orl %d0,%a0@-
0x0000383e:  tstl %a0@(0000000000000000,%d0:l:4)
0x00003840:  bnes 0x00000032
0x00003842:  clrl %a1@
0x00003844:  moveq #12,%d0
0x00003846:  bras 0x00000050
0x00003848:  invalid
0x0000384a:  .short 0x0000
0x0000384c:  orl %d0,%a0@-
0x0000384e:  moveal %a0@(0000000000000000,%d0:l:4),%a0
0x00003850:  movel %a0@,%d1
0x00003852:  cmpl %fp@(8),%d1
0x00003854:  bnes 0x0000004c
0x00003856:  movel %a0@(4),%a1@
0x00003858:  clrl %d0
0x0000385a:  bras 0x00000050
0x0000385c:  clrl %a1@
0x0000385e:  moveq #8,%d0
0x00003860:  unlk %fp
0x00003862:  rts
