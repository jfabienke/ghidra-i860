; Function: helper_0000366e
; Address: 0x0000366e - 0x0000368b
; Size: 30 bytes
; Frame: 0 bytes
; Purpose: Utility/Helper
; Description: Small function (30 bytes) - likely helper/wrapper
; Confidence: LOW
;
0x0000366e:  linkw %fp,#0
0x00003670:  movel %fp@(16),%sp@-
0x00003672:  movel %fp@(12),%sp@-
0x00003674:  invalid
0x00003676:  .short 0x04ff
0x00003678:  .short 0xfae2
0x0000367a:  movel %d0,%sp@-
0x0000367c:  invalid
0x0000367e:  .short 0x04ff
0x00003680:  .short 0xfc36
0x00003682:  unlk %fp
0x00003684:  rts
