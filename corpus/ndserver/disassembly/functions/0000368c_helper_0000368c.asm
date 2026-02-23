; Function: helper_0000368c
; Address: 0x0000368c - 0x000036b1
; Size: 38 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (38 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x0000368c:  linkw %fp,#0
0x0000368e:  movel %fp@(24),%sp@-
0x00003690:  movel %fp@(20),%sp@-
0x00003692:  movel %fp@(16),%sp@-
0x00003694:  movel %fp@(12),%sp@-
0x00003696:  invalid
0x00003698:  .short 0x04ff
0x0000369a:  .short 0xfabc
0x0000369c:  movel %d0,%sp@-
0x0000369e:  invalid
0x000036a0:  .short 0x04ff
0x000036a2:  cp0ldb %a4@+,%d4,#8,#94
0x000036a4:  rts
