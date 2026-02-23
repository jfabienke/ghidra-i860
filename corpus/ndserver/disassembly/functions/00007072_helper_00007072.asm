; Function: helper_00007072
; Address: 0x00007072 - 0x0000709b
; Size: 42 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (42 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x00007072:  linkw %fp,#0
0x00007074:  movel %fp@(12),%d0
0x00007076:  invalid
0x00007078:  .short 0x0000
0x0000707a:  .short 0x8018
0x0000707c:  beqs 0x0000001c
0x0000707e:  movel %fp@(8),%sp@-
0x00007080:  invalid
0x00007082:  .short 0x0000
0x00007084:  .short 0x0014
0x00007086:  bras 0x00000026
0x00007088:  moveq #8,%d1
0x0000708a:  invalid
0x0000708c:  .short 0x0401
0x0000708e:  bclr %d2,%a0@(ffffffffffffffff,%d7:w)
0x00007090:  unlk %fp
0x00007092:  rts
