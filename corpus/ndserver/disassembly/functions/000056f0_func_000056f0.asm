; Function: func_000056f0
; Address: 0x000056f0 - 0x0000577b
; Size: 140 bytes
; Frame: 548 bytes
; Purpose: Unknown
; Description: 140 bytes, frame size 548
; Confidence: UNKNOWN
;
0x000056f0:  linkw %fp,#-548
0x000056f2:  .short 0x48e7
0x000056f4:  movew %a0@-,%d0
0x000056f6:  movel %fp@(20),%d2
0x000056f8:  lea %fp@(-548),%a2
0x000056fa:  moveq #36,%d3
0x000056fc:  invalid
0x000056fe:  .short 0x0000
0x00005700:  moveq #60,%d6
0x00005702:  .short 0xfdf4
0x00005704:  invalid
0x00005706:  .short 0x000c
0x00005708:  .short 0xfdf8
0x0000570a:  invalid
0x0000570c:  .short 0x0000
0x0000570e:  moveq #64,%d6
0x00005710:  .short 0xfdfc
0x00005712:  invalid
0x00005714:  .short 0x0000
0x00005716:  .short 0x0200
0x00005718:  bhis 0x0000007c
0x0000571a:  movel %d2,%sp@-
0x0000571c:  movel %fp@(16),%sp@-
0x0000571e:  pea %a2@(36)
0x00005720:  invalid
0x00005722:  .short 0x04ff
0x00005724:  .short 0xd222
0x00005726:  .short 0xefee
0x00005728:  movel %a4,%d0
0x0000572a:  .short 0xfdfe
0x0000572c:  movel %d2,%d0
0x0000572e:  addql #3,%d0
0x00005730:  moveq #-4,%d1
0x00005732:  andl %d1,%d0
0x00005734:  invalid
0x00005736:  .short 0x0001
0x00005738:  .short 0xfddf
0x0000573a:  addl %d3,%d0
0x0000573c:  movel %d0,%fp@(-544)
0x0000573e:  clrl %fp@(-540)
0x00005740:  invalid
0x00005742:  .short 0x0008
0x00005744:  .short 0xfdec
0x00005746:  clrl %fp@(-536)
0x00005748:  moveq #127,%d1
0x0000574a:  movel %d1,%fp@(-528)
0x0000574c:  clrl %sp@-
0x0000574e:  clrl %sp@-
0x00005750:  movel %a2,%sp@-
0x00005752:  invalid
0x00005754:  .short 0x04ff
0x00005756:  .short 0xd26c
0x00005758:  bras 0x00000082
0x0000575a:  invalid
0x0000575c:  breakpoint
0x0000575e:  .short 0xfecd
0x00005760:  invalid
0x00005762:  .short 0x040c
0x00005764:  .short 0xfdd0
0x00005766:  unlk %fp
0x00005768:  rts
