# NDserver m68k Disassembly
# Entry Point: 0x00002d10
# Size: 18664 bytes
# Disassembler: rasm2 (m68k.gnu)
# Date: Fri Nov  7 23:18:09 CET 2025

moveal %sp,%a0
.short 0x9efc
.short 0x000c
movel %a0@+,%d0
movel %d0,%sp@
invalid
.short 0x0000
.short 0x8004
movel %a0,%sp@(4)
invalid
.short 0x0000
.short 0x8008
addql #1,%d0
asll #2,%d0
addal %d0,%a0
movel %a0,%sp@(8)
invalid
.short 0x0000
.short 0x8000
invalid
.short 0x0000
.short 0x005a
invalid
.short 0x0401
invalid
beqs 0x00000050
invalid
.short 0x0401
invalid
jsr %a0@
invalid
.short 0x0401
bclr %d0,%a4@-
beqs 0x00000050
invalid
.short 0x0401
bclr %d0,%a4@-
jsr %a0@
invalid
.short 0x0000
orl %d0,%a4@
beqs 0x0000005e
invalid
.short 0x0000
.short 0x542a
invalid
.short 0x0401
bclr %d2,%a0@(ffffffffffffffb9,%d4:l:2)
.short 0x0000
orl %d0,%a0@
beqs 0x00000072
invalid
.short 0x0000
.short 0x5412
invalid
.short 0x0000
.short 0x0042
movel %d0,%sp@
invalid
.short 0x04ff
.short 0xf724
.short 0x50fb
invalid
.short 0xface
linkw %fp,#-4
invalid
.short 0x0000
mvzw 0xfffffffffffffffc,%d2
nop
invalid
.short 0x0000
invalid
.short 0xfffc
bccs 0x000000b2
moveal %fp@(-4),%a0
moveal %a0@(4),%a1
moveal %fp@(-4),%a0
movel %a0@,%a1@
addql #8,%fp@(-4)
bras 0x00000094
unlk %fp
rts
linkw %fp,#-20
.short 0x48e7
movew %a0@-,%d4
moveal %fp@(12),%a2
clrl %fp@(-20)
movel %a2@,%d4
moveq #-1,%d3
movel %fp@(8),%d2
bras 0x0000010e
.short 0x584a
moveal %a2@,%a0
cmpib #45,%d0
bnes 0x0000010e
invalid
.short 0x0000
mvsb %fp@(0000000000000000,%d2:l:8),%d3
invalid
btst %d2,%d0
.short 0x0214
.short 0x504f
tstl %d0
bnes 0x00000104
moveq #1,%d1
cmpl %d2,%d1
bges 0x00000104
subql #1,%d2
.short 0x584a
movel %a2@,%sp@-
invalid
.short 0x04ff
.short 0xf392
movel %d0,%d3
bras 0x0000010c
movel %d4,%sp@-
invalid
.short 0x0000
.short 0x0244
.short 0x584f
subql #1,%d2
bnes 0x000000d0
pea %fp@(-4)
invalid
.short 0x0000
.short 0x773e
invalid
.short 0x0000
mvsw %a4,%d3
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xfbda
.short 0x504f
.short 0x504f
tstl %d0
beqs 0x0000014e
movel %d0,%sp@-
invalid
.short 0x0000
mvsw %a5,%d3
invalid
.short 0x04ff
.short 0xfa74
pea 0x00000001
invalid
.short 0x04ff
.short 0xf656
pea %fp@(-8)
movel %fp@(-4),%sp@-
invalid
.short 0x0000
moveb %d0,%a2@
.short 0x504f
tstl %d0
beqs 0x0000017e
movel %d0,%sp@-
invalid
.short 0x0000
mvsw %a4@+,%d3
invalid
.short 0x04ff
.short 0xfa48
pea 0x00000001
invalid
.short 0x04ff
.short 0xf62a
movel %d2,%d3
bras 0x00000196
moveq #-1,%d1
cmpl %d3,%d1
bnes 0x000001b2
clrl %d2
movel %fp@(-8),%d0
btst %d2,%d0
bnes 0x0000017a
addql #2,%d2
moveq #7,%d1
cmpl %d2,%d1
bges 0x0000018a
moveq #-1,%d1
cmpl %d3,%d1
bnes 0x000001d2
invalid
.short 0x0000
mvsw %a4@(25087),%d3
.short 0x04ff
.short 0xfe30
pea 0x00000001
invalid
.short 0x04ff
.short 0xf5f2
movel %fp@(-8),%d1
btst %d3,%d1
bnes 0x000001d2
movel %d3,%sp@-
invalid
.short 0x0000
mvzb %a3,%d3
invalid
.short 0x04ff
cp1ldb %a0@,%d4,#5,#120
.short 0x0001
invalid
.short 0x04ff
.short 0xf5d2
invalid
.short 0x0000
mvzb %sp@(18553),%d3
.short 0x0000
mvzb %fp@(0000000000000079,%d4:l),%d3
.short 0x0000
movel %d0,%d0
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
.short 0x2bfa
.short 0xdefc
.short 0x0014
tstl %d0
beqs 0x00000210
movel %d0,%sp@-
invalid
.short 0x0000
.short 0x77bd
invalid
.short 0x04ff
.short 0xf9b2
pea 0x00000001
invalid
.short 0x04ff
.short 0xf594
pea %fp@(-12)
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
.short 0x08f4
invalid
.short 0x0401
invalid
movel %fp@(-12),%sp@-
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
movel %fp@(fffffffffffffffc,%a5:l:8),%d1
.short 0x001c
tstl %d0
beqs 0x00000256
movel %d0,%sp@-
invalid
.short 0x0000
mvzw %a3@,%d3
invalid
.short 0x04ff
.short 0xf96c
pea 0x00000001
invalid
.short 0x04ff
.short 0xf54e
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
.short 0x2db8
clrl %d2
.short 0x504f
pea %fp@(-16)
invalid
.short 0x0000
mvzw %a3@-,%d3
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
.short 0x1aca
.short 0x504f
.short 0x504f
tstl %d0
bnes 0x000002de
pea 0x0000000a
movel %fp@(-16),%sp@-
invalid
.short 0x0000
.short 0x0262
.short 0x504f
tstl %d0
beqs 0x000002bc
movel %d0,%sp@-
invalid
.short 0x0000
mvzw %a2@(25087),%d3
.short 0x04ff
.short 0xf912
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
.short 0x08b6
pea 0x00000001
invalid
.short 0x04ff
cpushl bc,%a0@
pea %fp@(-20)
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
invalid
clrl %sp@-
movel %fp@(-16),%sp@-
invalid
.short 0x0000
invalid
.short 0xdefc
.short 0x0014
bras 0x000002f4
pea 0x00000001
invalid
.short 0x04ff
invalid
.short 0x584f
addql #1,%d2
moveq #4,%d1
cmpl %d2,%d1
bgew 0x00000266
movel %fp@(-20),%sp@-
clrl %sp@-
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
.short 0x098a
movel %d3,%sp@-
movel %fp@(-4),%sp@-
invalid
.short 0x0000
bchg #-89,%fp@
invalid
.short 0x04ff
.short 0xf48a
nop
linkw %fp,#0
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf662
movel %d0,%d2
pea 0x00000005
invalid
.short 0x04ff
cp1stw %d4,%a2@-,#2,#151
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf7e4
.short 0x504f
tstl %d0
beqs 0x0000032a
movel %fp@(-4),%d2
unlk %fp
rts
linkw %fp,#0
movel %fp@(8),%sp@-
invalid
.short 0x0000
invalid
invalid
.short 0x04ff
.short 0xfc78
pea 0x00000001
invalid
.short 0x04ff
.short 0xf43a
nop
linkw %fp,#0
invalid
.short 0x0000
.short 0x800c
beqs 0x00000398
invalid
.short 0x0000
moveaw #12078,%a0
.short 0x0008
invalid
.short 0x04ff
.short 0xfeea
pea 0x00000001
invalid
.short 0x0000
.short 0x8054
invalid
.short 0x04ff
.short 0xf010
invalid
.short 0x0000
moveq #12,%d4
invalid
.short 0x0401
.short 0x0028
invalid
.short 0x04ff
.short 0xf478
invalid
.short 0x04ff
.short 0xf06a
nop
linkw %fp,#-28
movel %d2,%sp@-
movel %fp@(8),%d2
invalid
.short 0x0000
.short 0x8010
bcss 0x000003d6
invalid
.short 0x0000
.short 0x8010
invalid
.short 0x0000
.short 0x8014
cmpl %d2,%d0
bhiw 0x000004e8
invalid
.short 0x0000
.short 0x8010
pea %fp@(-24)
pea %fp@(-20)
pea %fp@(-16)
pea %fp@(-12)
pea %fp@(-8)
pea %fp@(-4)
invalid
.short 0x0000
.short 0x8014
invalid
.short 0x0000
.short 0x8010
invalid
btst %d2,%d0
.short 0x004c
movel %d0,%sp@-
invalid
btst %d2,%d0
bclr %d0,0xffffffffffffdefc
.short 0x0024
tstl %d0
beqs 0x00000428
movel %d0,%sp@-
invalid
.short 0x0000
moveq #36,%d4
invalid
.short 0x04ff
.short 0xf794
braw 0x000004e8
invalid
.short 0x0000
.short 0x8010
bcsw 0x000004e8
invalid
.short 0x0000
.short 0x8010
invalid
.short 0x0000
.short 0x8014
cmpl %d2,%d0
blsw 0x000004e8
invalid
.short 0x0001
breakpoint
bnew 0x000004e8
pea 0x00000001
invalid
.short 0x0000
.short 0x8014
pea %fp@(-28)
invalid
.short 0x04ff
.short 0xfff0
movel %d0,%sp@-
invalid
btst %d2,%d0
btst %d0,%a2@(000000000000004f,%d5:w)
.short 0x504f
tstl %d0
beqs 0x00000482
movel %d0,%sp@-
invalid
.short 0x0000
moveq #63,%d4
invalid
.short 0x04ff
.short 0xf738
bras 0x000004e8
invalid
.short 0x0000
.short 0x8014
movel %fp@(-28),%sp@-
invalid
.short 0x0000
.short 0x8010
invalid
.short 0x0000
.short 0x8020
jsr %a0@
invalid
.short 0x0000
.short 0x8010
invalid
.short 0x0000
.short 0x8014
movel %fp@(-28),%sp@-
invalid
.short 0x04ff
cp1stl %d2,%a2@-,#8,#256
invalid
btst %d2,%d0
.short 0x00f0
.short 0xdefc
.short 0x001c
tstl %d0
beqs 0x000004d0
movel %d0,%sp@-
invalid
.short 0x0000
moveq #88,%d4
invalid
.short 0x04ff
.short 0xf6ea
bras 0x000004e8
invalid
.short 0x0000
.short 0x8014
movel %fp@(-28),%sp@-
invalid
.short 0x04ff
.short 0xff72
movel %d0,%sp@-
invalid
btst %d2,%d0
bitrev %d6
movel %fp@(-32),%d2
unlk %fp
rts
linkw %fp,#-28
movel %a2,%sp@-
movel %d2,%sp@-
pea %fp@(-28)
invalid
btst %d2,%d0
movew %fp@+,%a0@(20114)
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xfa3c
movel %d0,%d2
.short 0x504f
bnes 0x00000566
invalid
.short 0x0008
.short 0xfff8
invalid
.short 0xffe4
.short 0xfff4
moveq #2,%d1
movel %d1,%fp@(-4)
moveq #24,%d1
movel %d1,%fp@(-20)
clrl %fp@(-16)
invalid
.short 0x0001
.short 0xffeb
movel %fp@(12),%d1
.short 0x4c3c
moveb %d0,%d4
.short 0x0000
bset %d1,%a0@(12033)
clrl %sp@-
pea 0x00000018
pea 0x00000100
pea %fp@(-24)
invalid
.short 0x04ff
.short 0xf75e
movel %d0,%d2
movel %fp@(-28),%sp@-
jsr %a2@
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xf9e8
movel %d2,%d0
movel %fp@(-36),%d2
moveal %fp@(-32),%a2
unlk %fp
rts
linkw %fp,#-64
.short 0x48e7
movew #9774,%d6
.short 0x0008
movel %fp@(12),%d2
moveal %fp@(16),%a5
invalid
.short 0x04ff
cp1bcbusy 0x00002d8e
pea %fp@(-56)
invalid
.short 0x0000
mvzw %a3@-,%d3
movel %d2,%sp@-
movel %d3,%sp@-
invalid
.short 0x0000
moveb %a2@-,%a3@(000000000000004f,%d5:w)
.short 0x504f
tstl %d0
bnew 0x0000069a
pea %fp@(-60)
movel %d2,%sp@-
movel %d3,%sp@-
invalid
.short 0x0000
bchg %d2,%a0@+
.short 0x504f
.short 0x584f
tstl %d0
bnew 0x0000069a
movel %d2,%d0
moveq #28,%d5
asll %d5,%d0
invalid
.short 0x0000
.short 0x801c
pea %fp@(-32)
movel %fp@(-56),%sp@-
invalid
.short 0x0000
.short 0x2afe
.short 0x504f
tstl %d0
bnew 0x0000069a
subal %a2,%a2
lea %fp@(-32),%a4
invalid
.short 0x0000
.short 0x8024
movel %a2,%d1
asll #3,%d1
tstl %a4@(0000000000000004,%d1:l)
beqs 0x00000638
lea %a2@(0000000000000000,%a2:l:2),%a0
movel %a0,%d0
asll #2,%d0
.short 0x27b4
moveb %d0,%d4
btst #-76,%d4
moveb %d4,%d4
.short 0x0808
movel %a3@(0000000000000008,%d0:l),%sp@-
movel %a3@(0000000000000004,%d0:l),%sp@-
invalid
.short 0x0000
.short 0x8024
movel %d0,%sp@-
movel %d4,%sp@-
movel %fp@(-60),%sp@-
movel %d3,%sp@-
invalid
.short 0x0000
.short 0x108a
.short 0xdefc
.short 0x0018
tstl %d0
bnes 0x0000069a
.short 0x524a
moveq #3,%d5
cmpl %a2,%d5
bges 0x000005f4
invalid
btst %d2,%d0
movel %a0,0x00000000
.short 0x8020
pea %fp@(-64)
invalid
.short 0x04ff
.short 0xfdfe
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xf8ec
.short 0x504f
tstl %d0
bnes 0x0000069a
movel %fp@(-64),%sp@-
movel %fp@(-56),%sp@-
invalid
.short 0x0000
movel %a2@(20559),%d5
tstl %d0
bnes 0x0000069a
movel %fp@(-64),%a5@
invalid
.short 0x0000
moveaw #18552,%a0
.short 0x000a
invalid
btst %d2,%d0
.short 0x2f7e
jsr %a2@
invalid
.short 0x0000
moveaw #18552,%a0
.short 0x000b
jsr %a2@
clrl %d0
invalid
movew #-96,%d6
unlk %fp
rts
linkw %fp,#-16
.short 0x48e7
movel %a0@(0000000000000078,%d4:l),%d0
bclr %d0,%a0@(12078)
.short 0x000c
movel %fp@(8),%sp@-
invalid
.short 0x04ff
.short 0xedfe
.short 0x504f
invalid
.short 0x0000
.short 0x8054
invalid
.short 0x04ff
.short 0xed06
.short 0x584f
tstl %d0
beqs 0x000006ea
moveal %fp@(12),%a0
moveq #1,%d2
movel %d2,%a0@(28)
invalid
.short 0x0000
moveq #92,%d5
.short 0x0018
moveq #1,%d0
braw 0x000008fa
moveq #1,%d2
invalid
.short 0x0000
.short 0x800c
moveal %fp@(8),%a0
movel %a0@(20),%d0
invalid
.short 0x0000
bset %d3,%d3
beqw 0x000007e0
bgts 0x00000712
invalid
.short 0x0000
bset %d3,%d2
beqs 0x00000720
braw 0x000008ce
invalid
.short 0x0000
bset %d3,%d4
beqw 0x000008bc
braw 0x000008ce
moveal %fp@(8),%a0
moveq #32,%d2
cmpl %a0@(36),%d2
bges 0x0000073a
moveal %fp@(12),%a0
moveq #4,%d2
movel %d2,%a0@(28)
braw 0x000008b4
moveal %fp@(12),%a0
clrl %a0@(28)
clrl %fp@(-16)
moveal %fp@(8),%a0
moveal %a0,%a1
moveal %fp@(-16),%a3
cmpal %a0@(36),%a3
bgew 0x000008b4
invalid
.short 0x0000
.short 0x8024
movel %fp@(-16),%d0
addl %d0,%d0
addl %fp@(-16),%d0
moveal %a1@(000000000000002c,%d0:l:4),%a0
subal %a1,%a1
lea %a1@(0000000000000000,%a1:l:2),%a3
movel %a3,%d0
asll #2,%d0
movel %a0,%d1
subl %a2@(0000000000000004,%d0:l),%d1
cmpl %a2@(0000000000000008,%d0:l),%d1
bcss 0x00000798
.short 0x5249
moveq #3,%d2
cmpl %a1,%d2
bges 0x0000076e
clrl %fp@(-12)
tstl %fp@(-12)
bnes 0x000007a2
braw 0x00000862
addl %a2@(0000000000000000,%d0:l),%d1
movel %d1,%fp@(-12)
bras 0x0000078e
movel %fp@(-16),%d0
addl %d0,%d0
addl %fp@(-16),%d0
asll #2,%d0
moveal %fp@(8),%a0
movel %a0@(0000000000000030,%d0:l),%sp@-
movel %fp@(-12),%sp@-
movel %a0@(0000000000000028,%d0:l),%sp@-
invalid
.short 0x0000
.short 0x8020
jsr %a0@
.short 0x504f
.short 0x584f
addql #1,%fp@(-16)
moveal %fp@(8),%a1
moveal %fp@(-16),%a3
cmpal %a1@(36),%a3
blts 0x0000075e
braw 0x000008b4
moveal %fp@(8),%a0
moveq #32,%d2
cmpl %a0@(36),%d2
bltw 0x0000072c
moveal %fp@(12),%a0
clrl %a0@(28)
clrl %fp@(-16)
moveal %fp@(8),%a0
moveal %a0,%a1
moveal %fp@(-16),%a3
cmpal %a0@(36),%a3
bgew 0x000008b4
invalid
.short 0x0000
.short 0x8024
movel %fp@(-16),%d0
addl %d0,%d0
addl %fp@(-16),%d0
movel %a1@(0000000000000028,%d0:l:4),%sp@-
invalid
breakpoint
wddatal %a0@
movel %fp@(-16),%d0
addl %d0,%d0
addl %fp@(-16),%d0
moveal %fp@(8),%a0
moveal %a0@(000000000000002c,%d0:l:4),%a1
.short 0x584f
subal %a0,%a0
lea %a0@(0000000000000000,%a0:l:2),%a3
movel %a3,%d0
asll #2,%d0
movel %a1,%d1
subl %a2@(0000000000000004,%d0:l),%d1
cmpl %a2@(0000000000000008,%d0:l),%d1
bcss 0x0000086e
.short 0x5248
moveq #3,%d2
cmpl %a0,%d2
bges 0x0000083c
clrl %fp@(-8)
tstl %fp@(-8)
bnes 0x00000878
moveal %fp@(12),%a0
moveq #1,%d2
movel %d2,%a0@(28)
bras 0x000008b4
addl %a2@(0000000000000000,%d0:l),%d1
movel %d1,%fp@(-8)
bras 0x0000085c
movel %fp@(-16),%d0
addl %d0,%d0
addl %fp@(-16),%d0
asll #2,%d0
moveal %fp@(8),%a0
movel %a0@(0000000000000030,%d0:l),%sp@-
movel %a0@(0000000000000028,%d0:l),%sp@-
movel %fp@(-8),%sp@-
invalid
.short 0x0000
.short 0x8020
jsr %a0@
.short 0x504f
.short 0x584f
addql #1,%fp@(-16)
moveal %fp@(8),%a1
moveal %fp@(-16),%a3
cmpal %a1@(36),%a3
bltw 0x00000812
moveq #1,%d2
movel %d2,%fp@(-4)
bras 0x000008e4
moveal %fp@(12),%a0
invalid
breakpoint
.short 0xfecf
.short 0x001c
clrl %fp@(-4)
bras 0x000008e4
invalid
.short 0x0000
.short 0x800c
movel %fp@(12),%sp@-
movel %fp@(8),%sp@-
invalid
.short 0x0000
movel %d6,%d6
bras 0x000008fa
invalid
.short 0x0000
.short 0x800c
moveal %fp@(12),%a0
invalid
.short 0x0000
moveq #92,%d5
.short 0x0018
movel %fp@(-4),%d0
invalid
cmpib #-28,%d4
unlk %fp
rts
linkw %fp,#0
.short 0x48e7
movew %a0@-,%d4
moveal %fp@(12),%a2
movel %fp@(16),%d4
movel %fp@(20),%d3
movel %d3,%sp@-
movel %d4,%sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
wddatab %fp@(12032)
invalid
.short 0x04ff
.short 0xfc70
movel %d0,%d2
.short 0x504f
.short 0x504f
bnes 0x00000938
tstl %a2@
bnes 0x00000952
moveq #1,%d1
cmpl %d3,%d1
bnes 0x00000952
movel %d3,%sp@-
movel %d4,%sp@-
movel %a2@,%sp@-
movel %d2,%sp@-
invalid
.short 0x0000
moveq #111,%d4
invalid
.short 0x04ff
.short 0xf686
movel %d2,%d0
invalid
.short 0x041c
.short 0xfff0
unlk %fp
rts
linkw %fp,#0
movel %fp@(16),%sp@-
movel %fp@(12),%sp@-
invalid
.short 0x04ff
.short 0xfae2
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xfc36
unlk %fp
rts
linkw %fp,#0
movel %fp@(24),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
movel %fp@(12),%sp@-
invalid
.short 0x04ff
.short 0xfabc
movel %d0,%sp@-
invalid
.short 0x04ff
cp0ldb %a4@+,%d4,#8,#94
rts
linkw %fp,#0
.short 0x48e7
movew #10798,%d6
.short 0x0008
movel %fp@(12),%d3
invalid
.short 0x0401
invalid
moveq #8,%d1
cmpl %d3,%d1
bcss 0x000009c4
btst #0,%d3
beqs 0x000009ca
moveq #4,%d0
braw 0x00000b06
movel %d3,%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
tstl %a0@(0000000000000000,%d0:l:4)
beqs 0x000009ea
moveal %a0@(0000000000000000,%d0:l:4),%a0
cmpl %a0@,%d5
sne %d0
moveq #4,%d1
andl %d1,%d0
braw 0x00000b06
pea 0x00000050
pea 0x00000001
invalid
.short 0x04ff
.short 0xeb06
moveal %d0,%a2
.short 0x504f
tstl %a2
bnes 0x00000a06
moveq #6,%d0
braw 0x00000b06
movel %d3,%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
movel %a2,%a0@(0000000000000000,%d0:l:4)
movel %d3,%a2@(72)
clrl %a2@(76)
movel %d5,%a2@
lea %a2@(8),%a4
movel %a4,%sp@-
movel %d4,%sp@-
invalid
btst %d2,%d0
moveal %a4@,%fp
jsr %a5@
movel %d0,%d2
.short 0x504f
bnew 0x00000aec
lea %a2@(4),%a3
movel %a3,%sp@-
movel %d4,%sp@-
jsr %a5@
movel %d0,%d2
.short 0x504f
bnew 0x00000aec
movel %a4,%sp@-
movel %a3@,%sp@-
movel %d3,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
.short 0x057a
movel %d0,%d2
.short 0x504f
.short 0x504f
bnew 0x00000aec
pea %a2@(52)
pea %a2@(28)
movel %d3,%sp@-
movel %d4,%sp@-
movel %a3@,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
.short 0x0e70
movel %d0,%d2
.short 0xdefc
.short 0x0018
bnes 0x00000aec
lea %a2@(60),%a5
movel %a5,%sp@-
lea %a2@(40),%a4
movel %a4,%sp@-
movel %d3,%sp@-
movel %d4,%sp@-
movel %a3@,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
.short 0x107e
movel %d0,%d2
.short 0xdefc
.short 0x0018
bnes 0x00000aec
movel %a5,%sp@-
movel %a4,%sp@-
movel %d3,%sp@-
movel %d4,%sp@-
movel %a3@,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
invalid
movel %d0,%d2
.short 0xdefc
.short 0x0018
bnes 0x00000aec
lea %a2@(12),%a3
movel %a3,%sp@-
movel %d3,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
.short 0x0a28
movel %d0,%d2
.short 0x504f
.short 0x584f
bnes 0x00000aec
pea %a2@(24)
movel %a3@,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
.short 0x074e
movel %d0,%d2
.short 0x504f
.short 0x584f
bnes 0x00000aec
clrl %d0
bras 0x00000b06
movel %d2,%sp@-
invalid
.short 0x0000
moveq #-97,%d4
invalid
.short 0x04ff
.short 0xf0be
movel %d3,%sp@-
movel %d5,%sp@-
invalid
.short 0x0000
.short 0x0064
movel %d2,%d0
invalid
movew #-32,%d6
unlk %fp
rts
linkw %fp,#0
movel %fp@(12),%d0
moveal %fp@(16),%a1
moveq #8,%d1
cmpl %d0,%d1
bcss 0x00000b28
btst #0,%d0
beqs 0x00000b2c
moveq #4,%d0
bras 0x00000b60
asrl #1,%d0
subql #1,%d0
invalid
.short 0x0000
orl %d0,%a0@-
tstl %a0@(0000000000000000,%d0:l:4)
bnes 0x00000b42
clrl %a1@
moveq #12,%d0
bras 0x00000b60
invalid
.short 0x0000
orl %d0,%a0@-
moveal %a0@(0000000000000000,%d0:l:4),%a0
movel %a0@,%d1
cmpl %fp@(8),%d1
bnes 0x00000b5c
movel %a0@(4),%a1@
clrl %d0
bras 0x00000b60
clrl %a1@
moveq #8,%d0
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
movel %d2,%sp@-
movel %fp@(12),%d0
invalid
.short 0x0401
invalid
moveq #8,%d1
cmpl %d0,%d1
bcsw 0x00000c80
btst #0,%d0
bnew 0x00000c80
asrl #1,%d0
subql #1,%d0
invalid
.short 0x0000
orl %d0,%a0@-
tstl %a0@(0000000000000000,%d0:l:4)
beqw 0x00000c80
moveal %a0@(0000000000000000,%d0:l:4),%a0
movel %a0@,%d1
cmpl %fp@(8),%d1
bnew 0x00000c80
moveal %a0,%a2
tstl %a2@(28)
beqs 0x00000bc2
movel %a2@(52),%sp@-
movel %a2@(28),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf9f0
.short 0x504f
.short 0x584f
tstl %a2@(36)
beqs 0x00000bdc
movel %a2@(56),%sp@-
movel %a2@(36),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf9d6
.short 0x504f
.short 0x584f
tstl %a2@(40)
beqs 0x00000bf6
movel %a2@(60),%sp@-
movel %a2@(40),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf9bc
.short 0x504f
.short 0x584f
tstl %a2@(44)
beqs 0x00000c10
movel %a2@(64),%sp@-
movel %a2@(44),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf9a2
.short 0x504f
.short 0x584f
tstl %a2@(48)
beqs 0x00000c2a
movel %a2@(68),%sp@-
movel %a2@(48),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf988
.short 0x504f
.short 0x584f
clrl %a2@
tstl %a2@(4)
beqs 0x00000c40
movel %a2@(4),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf310
.short 0x504f
tstl %a2@(8)
beqs 0x00000c54
movel %a2@(8),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf2fc
.short 0x504f
tstl %a2@(12)
beqs 0x00000c68
movel %a2@(12),%sp@-
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xf2e8
.short 0x504f
movel %a2@(72),%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
clrl %a0@(0000000000000000,%d0:l:4)
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xebba
movel %fp@(-8),%d2
moveal %fp@(-4),%a2
unlk %fp
rts
linkw %fp,#-12
.short 0x48e7
movew 0x00002c2e,%sp@-
.short 0x0008
movel %fp@(12),%d7
movel %fp@(16),%d4
movel %fp@(20),%d5
clrl %d2
pea 0x00002000
invalid
btst %d2,%d0
movel %pc@(0x00005b42),%a4@+
moveal %d0,%a3
pea 0x00002000
jsr %a2@
moveal %d0,%a4
invalid
.short 0x04ff
.short 0xf784
movel %d0,%fp@(-4)
.short 0x504f
bnes 0x00000d0a
pea %fp@(-4)
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf26e
.short 0x504f
tstl %d0
beqs 0x00000cf2
movel %d0,%sp@-
invalid
.short 0x0000
moveq #-89,%d4
invalid
.short 0x04ff
.short 0xeeca
braw 0x00000fc2
movel %fp@(-4),%sp@-
pea 0x00000002
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf752
.short 0x504f
.short 0x584f
pea %fp@(-8)
invalid
.short 0x0000
moveq #-68,%d4
movel %d7,%sp@-
movel %d6,%sp@-
invalid
.short 0x0000
moveb %a0@(20559),%d0
.short 0x504f
tstl %d0
bnes 0x00000d76
tstl %d4
bnes 0x00000d76
pea 0x00004000
invalid
.short 0x04ff
.short 0xf532
clrl %sp@-
clrl %sp@-
invalid
.short 0x0000
moveq #-56,%d4
invalid
.short 0x04ff
.short 0xf174
moveal %d0,%a2
.short 0x504f
.short 0x504f
moveq #-1,%d1
cmpl %a2,%d1
beqs 0x00000d6c
clrl %sp@-
invalid
movel %d0,%d0
moveq #113,%d2
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xed62
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe826
.short 0x504f
.short 0x504f
invalid
.short 0x04ff
.short 0xec18
movel %d0,%d2
bras 0x00000d7a
clrl %fp@(-8)
pea %fp@(-12)
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf200
.short 0x504f
tstl %d0
beqs 0x00000da2
movel %d0,%sp@-
invalid
.short 0x0000
moveq #-47,%d4
invalid
.short 0x04ff
.short 0xee1a
braw 0x00000fc2
tstl %d4
beqs 0x00000dd2
movel %d4,%sp@-
movel %fp@(-12),%sp@-
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf1cc
.short 0x504f
.short 0x584f
tstl %d0
beqs 0x00000dd2
movel %d0,%sp@-
invalid
.short 0x0000
moveq #-22,%d4
invalid
.short 0x04ff
.short 0xedea
braw 0x00000fc2
tstl %d5
beqs 0x00000e3e
movel %d5,%sp@-
movel %fp@(-12),%sp@-
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf19c
.short 0x504f
.short 0x584f
tstl %d0
beqs 0x00000e02
movel %d0,%sp@-
invalid
.short 0x0000
mvsb %d6,%d4
invalid
.short 0x04ff
.short 0xedba
braw 0x00000fc2
movel %d7,%sp@-
movel %d6,%sp@-
invalid
.short 0x0000
movel %a4@+,%a4@(9728)
.short 0x504f
beqs 0x00000e3e
movel %d3,%sp@-
movel %fp@(-12),%sp@-
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf160
.short 0x504f
.short 0x584f
tstl %d0
beqs 0x00000e3e
movel %d0,%sp@-
invalid
.short 0x0000
mvsb %a2@-,%d4
invalid
.short 0x04ff
.short 0xed7e
braw 0x00000fc2
tstl %fp@(-4)
beqs 0x00000e72
movel %fp@(-4),%sp@-
movel %fp@(-12),%sp@-
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
.short 0xf12c
.short 0x504f
.short 0x584f
tstl %d0
beqs 0x00000e72
movel %d0,%sp@-
invalid
.short 0x0000
mvsw %d2,%d4
invalid
.short 0x04ff
.short 0xed4a
braw 0x00000fc2
invalid
.short 0x0000
movel %d0,%d0
.short 0x0004
invalid
.short 0xfff4
.short 0x000c
clrl %sp@-
clrl %sp@-
movel %a3,%sp@-
invalid
.short 0x04ff
.short 0xee16
.short 0x504f
.short 0x584f
tstl %d0
beqs 0x00000ea8
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xed28
movel %d0,%sp@-
invalid
.short 0x0000
mvsw %sp@+,%d4
braw 0x00000fa6
moveq #1,%d1
cmpl %a3@(8),%d1
bnes 0x00000ee4
moveq #65,%d1
cmpl %a3@(20),%d1
beqs 0x00000ec0
moveq #69,%d1
cmpl %a3@(20),%d1
bnes 0x00000ece
movel %a3@(28),%d1
cmpl %fp@(-8),%d1
beqw 0x00000fb4
bras 0x00000e72
movel %a3@(20),%sp@-
invalid
.short 0x0000
mvzb %fp,%d4
invalid
.short 0x04ff
.short 0xf0fa
.short 0x504f
braw 0x00000fb4
cmpl %a3@(12),%d4
bnes 0x00000f00
tstl %a3@(16)
bnes 0x00000ef4
movel %d6,%a3@(16)
movel %a4,%sp@-
movel %a3,%sp@-
invalid
.short 0x0000
moveaw %a2@-,%a1
bras 0x00000f5a
cmpl %a3@(12),%d5
bnes 0x00000f2e
movel %a4,%sp@-
movel %a3,%sp@-
invalid
breakpoint
.short 0xf798
.short 0x504f
tstl %d0
bnes 0x00000f60
tstl %d2
blew 0x00000fb4
pea 0x00000001
movel %d2,%sp@-
invalid
.short 0x04ff
.short 0xebfa
.short 0x504f
braw 0x00000fb4
cmpl %a3@(12),%d3
beqs 0x00000f50
movel %a3@(20),%sp@-
movel %a3@(12),%sp@-
invalid
.short 0x0000
invalid
invalid
.short 0x04ff
.short 0xf090
.short 0x504f
.short 0x584f
braw 0x00000e72
movel %a4,%sp@-
movel %a3,%sp@-
invalid
.short 0x0000
.short 0x317e
.short 0x504f
tstl %d0
beqs 0x00000fb4
invalid
breakpoint
.short 0xfecf
.short 0x001c
beqw 0x00000e72
invalid
.short 0x000c
.short 0x000c
invalid
.short 0x0010
.short 0x0010
clrl %sp@-
clrl %sp@-
movel %a4,%sp@-
invalid
.short 0x04ff
.short 0xed42
.short 0x504f
.short 0x584f
tstl %d0
beqw 0x00000e72
moveq #-102,%d1
cmpl %d0,%d1
beqw 0x00000e72
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xec26
movel %d0,%sp@-
invalid
.short 0x0000
mvzw %a3@-,%d4
invalid
.short 0x04ff
.short 0xf02c
.short 0x504f
.short 0x584f
braw 0x00000e72
movel %a3,%sp@-
invalid
btst %d2,%d0
movel %d6,%a2@(20114)
movel %a4,%sp@-
jsr %a2@
invalid
moveb #-48,%fp@+
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x0014
lea %fp@(-48),%a2
invalid
.short 0x0000
moveq #96,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
moveq #100,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
moveq #104,%d5
.short 0xfff8
movel %a3@,%fp@(-4)
clrb %fp@(-45)
moveq #48,%d3
movel %d3,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
.short 0xec32
movel %d0,%fp@(-36)
moveq #100,%d3
movel %d3,%fp@(-28)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xec76
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001058
invalid
breakpoint
.short 0xff36
bnes 0x00001054
invalid
.short 0x04ff
.short 0xebfa
movel %d2,%d0
bras 0x000010c4
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00c8
.short 0x0014
beqs 0x00001074
invalid
breakpoint
.short 0xfed3
bras 0x000010c4
moveq #40,%d3
cmpl %d0,%d3
bnes 0x0000107e
tstl %d1
beqs 0x00001090
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000010be
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000010be
tstl %a2@(28)
beqs 0x000010be
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #108,%d5
bnes 0x000010be
tstl %a2@(28)
beqs 0x000010a8
movel %a2@(28),%d0
bras 0x000010c4
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #112,%d5
bnes 0x000010be
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x000010c4
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-64,%d4
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@-,%d0
lea %fp@(-40),%a2
invalid
.short 0x0000
moveq #116,%d5
.short 0xfff0
invalid
.short 0x000c
.short 0xfff4
invalid
.short 0x0000
moveq #120,%d5
.short 0xfff8
invalid
.short 0x0010
.short 0xfffc
clrb %fp@(-37)
moveq #40,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xeb40
movel %d0,%fp@(-28)
moveq #101,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
asll #5,%d4
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x0000114a
invalid
breakpoint
.short 0xff36
bnes 0x00001146
invalid
.short 0x04ff
.short 0xeb08
movel %d2,%d0
bras 0x00001194
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00c9
.short 0x0014
beqs 0x00001166
invalid
breakpoint
.short 0xfed3
bras 0x00001194
moveq #32,%d3
cmpl %d0,%d3
bnes 0x0000117e
moveq #1,%d3
cmpl %d1,%d3
bnes 0x0000117e
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #124,%d5
beqs 0x00001186
invalid
breakpoint
.short 0xfed4
bras 0x00001194
tstl %a2@(28)
bnes 0x00001190
clrl %d0
bras 0x00001194
movel %a2@(28),%d0
invalid
.short 0x040c
.short 0xffcc
unlk %fp
rts
linkw %fp,#-548
.short 0x48e7
movew %a0@-,%d0
movel %fp@(20),%d2
lea %fp@(-548),%a2
moveq #36,%d3
invalid
.short 0x0000
moveq #-128,%d5
.short 0xfdf4
invalid
.short 0x000c
.short 0xfdf8
invalid
.short 0x0000
moveq #-124,%d5
.short 0xfdfc
invalid
.short 0x0000
.short 0x0200
bhis 0x0000121a
movel %d2,%sp@-
movel %fp@(16),%sp@-
pea %a2@(36)
invalid
.short 0x04ff
.short 0xea64
.short 0xefee
movel %a4,%d0
.short 0xfdfe
movel %d2,%d0
addql #3,%d0
moveq #-4,%d1
andl %d1,%d0
invalid
.short 0x0001
.short 0xfddf
addl %d3,%d0
movel %d0,%fp@(-544)
clrl %fp@(-540)
invalid
.short 0x0008
.short 0xfdec
clrl %fp@(-536)
moveq #102,%d1
movel %d1,%fp@(-528)
clrl %sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
lsrl %d5,%d6
bras 0x00001220
invalid
breakpoint
.short 0xfecd
invalid
.short 0x040c
.short 0xfdd0
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x0010
lea %fp@(-40),%a2
invalid
.short 0x0000
moveq #-120,%d5
.short 0xfff0
invalid
.short 0x000c
.short 0xfff4
clrb %fp@(-37)
moveq #32,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xe9ee
movel %d0,%fp@(-28)
moveq #103,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xea32
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x0000129c
invalid
breakpoint
.short 0xff36
bnes 0x00001298
invalid
.short 0x04ff
.short 0xe9b6
movel %d2,%d0
bras 0x0000130a
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00cb
.short 0x0014
beqs 0x000012b8
invalid
breakpoint
.short 0xfed3
bras 0x0000130a
moveq #40,%d3
cmpl %d0,%d3
bnes 0x000012c4
moveq #1,%d3
cmpl %d1,%d3
beqs 0x000012d6
moveq #32,%d3
cmpl %d0,%d3
bnes 0x00001304
moveq #1,%d3
cmpl %d1,%d3
bnes 0x00001304
tstl %a2@(28)
beqs 0x00001304
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-116,%d5
bnes 0x00001304
tstl %a2@(28)
beqs 0x000012ee
movel %a2@(28),%d0
bras 0x0000130a
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #-112,%d5
bnes 0x00001304
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x0000130a
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-56,%d4
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@-,%d0
lea %fp@(-40),%a2
invalid
.short 0x0000
moveq #-108,%d5
.short 0xfff0
invalid
.short 0x000c
.short 0xfff4
invalid
.short 0x0000
moveq #-104,%d5
.short 0xfff8
invalid
.short 0x0010
.short 0xfffc
clrb %fp@(-37)
moveq #40,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xe8fa
movel %d0,%fp@(-28)
moveq #104,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe93e
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001390
invalid
breakpoint
.short 0xff36
bnes 0x0000138c
invalid
.short 0x04ff
.short 0xe8c2
movel %d2,%d0
bras 0x000013da
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00cc
.short 0x0014
beqs 0x000013ac
invalid
breakpoint
.short 0xfed3
bras 0x000013da
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000013c4
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000013c4
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-100,%d5
beqs 0x000013cc
invalid
breakpoint
.short 0xfed4
bras 0x000013da
tstl %a2@(28)
bnes 0x000013d6
clrl %d0
bras 0x000013da
movel %a2@(28),%d0
invalid
.short 0x040c
.short 0xffcc
unlk %fp
rts
linkw %fp,#-72
.short 0x48e7
movew %a0@-,%d0
lea %fp@(-72),%a2
invalid
.short 0x0000
moveq #-96,%d5
.short 0xffd0
invalid
.short 0x000c
.short 0xffd4
invalid
.short 0x0000
moveq #-92,%d5
.short 0xffd8
invalid
.short 0x0010
.short 0xffdc
invalid
.short 0x0000
moveq #-88,%d5
.short 0xffe0
invalid
.short 0x0014
.short 0xffe4
invalid
.short 0x0000
moveq #-84,%d5
.short 0xffe8
invalid
.short 0x0018
.short 0xffec
invalid
.short 0x0000
moveq #-80,%d5
.short 0xfff0
invalid
.short 0x001c
.short 0xfff4
invalid
.short 0x0000
moveq #-76,%d5
.short 0xfff8
invalid
.short 0x0020
.short 0xfffc
invalid
.short 0x0001
.short 0xffbb
moveq #72,%d3
movel %d3,%fp@(-68)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffc0
invalid
.short 0x0008
.short 0xffc8
invalid
.short 0x04ff
.short 0xe7f0
movel %d0,%fp@(-60)
moveq #105,%d3
movel %d3,%fp@(-52)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe834
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x0000149a
invalid
breakpoint
.short 0xff36
bnes 0x00001496
invalid
.short 0x04ff
.short 0xe7b8
movel %d2,%d0
bras 0x000014e4
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00cd
.short 0x0014
beqs 0x000014b6
invalid
breakpoint
.short 0xfed3
bras 0x000014e4
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000014ce
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000014ce
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-72,%d5
beqs 0x000014d6
invalid
breakpoint
.short 0xfed4
bras 0x000014e4
tstl %a2@(28)
bnes 0x000014e0
clrl %d0
bras 0x000014e4
movel %a2@(28),%d0
invalid
.short 0x040c
invalid
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x0010
lea %fp@(-40),%a2
invalid
.short 0x0000
moveq #-68,%d5
.short 0xfff0
invalid
.short 0x000c
.short 0xfff4
invalid
.short 0x0001
.short 0xffdb
moveq #32,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xe728
movel %d0,%fp@(-28)
moveq #106,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe76c
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001562
invalid
breakpoint
.short 0xff36
bnes 0x0000155e
invalid
.short 0x04ff
.short 0xe6f0
movel %d2,%d0
bras 0x000015ce
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00ce
.short 0x0014
beqs 0x0000157e
invalid
breakpoint
.short 0xfed3
bras 0x000015ce
moveq #40,%d3
cmpl %d0,%d3
bnes 0x00001588
tstl %d1
beqs 0x0000159a
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000015c8
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000015c8
tstl %a2@(28)
beqs 0x000015c8
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-64,%d5
bnes 0x000015c8
tstl %a2@(28)
beqs 0x000015b2
movel %a2@(28),%d0
bras 0x000015ce
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #-60,%d5
bnes 0x000015c8
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x000015ce
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-56,%d4
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x000c
lea %fp@(-40),%a2
invalid
.short 0x0001
.short 0xffdb
moveq #24,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xe64c
movel %d0,%fp@(-28)
moveq #107,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe690
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x0000163e
invalid
breakpoint
.short 0xff36
bnes 0x0000163a
invalid
.short 0x04ff
.short 0xe614
movel %d2,%d0
bras 0x000016ac
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00cf
.short 0x0014
beqs 0x0000165a
invalid
breakpoint
.short 0xfed3
bras 0x000016ac
moveq #40,%d3
cmpl %d0,%d3
bnes 0x00001666
moveq #1,%d3
cmpl %d1,%d3
beqs 0x00001678
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000016a6
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000016a6
tstl %a2@(28)
beqs 0x000016a6
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-56,%d5
bnes 0x000016a6
tstl %a2@(28)
beqs 0x00001690
movel %a2@(28),%d0
bras 0x000016ac
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #-52,%d5
bnes 0x000016a6
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x000016ac
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-56,%d4
unlk %fp
rts
linkw %fp,#-56
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x0014
lea %fp@(-56),%a2
invalid
.short 0x0000
moveq #-48,%d5
.short 0xffe0
invalid
.short 0x000c
.short 0xffe4
invalid
.short 0x0000
moveq #-44,%d5
.short 0xffe8
invalid
.short 0x0010
.short 0xffec
invalid
.short 0x0000
moveq #-40,%d5
.short 0xfff0
invalid
.short 0x0018
.short 0xfff4
invalid
.short 0x0000
moveq #-36,%d5
.short 0xfff8
invalid
.short 0x001c
.short 0xfffc
clrb %fp@(-53)
moveq #56,%d3
movel %d3,%fp@(-52)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd0
invalid
.short 0x0008
.short 0xffd8
invalid
.short 0x04ff
.short 0xe538
movel %d0,%fp@(-44)
moveq #108,%d3
movel %d3,%fp@(-36)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe57c
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001752
invalid
breakpoint
.short 0xff36
bnes 0x0000174e
invalid
.short 0x04ff
.short 0xe500
movel %d2,%d0
bras 0x000017c0
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00d0
.short 0x0014
beqs 0x0000176e
invalid
breakpoint
.short 0xfed3
bras 0x000017c0
moveq #40,%d3
cmpl %d0,%d3
bnes 0x0000177a
moveq #1,%d3
cmpl %d1,%d3
beqs 0x0000178c
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000017ba
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000017ba
tstl %a2@(28)
beqs 0x000017ba
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-32,%d5
bnes 0x000017ba
tstl %a2@(28)
beqs 0x000017a4
movel %a2@(28),%d0
bras 0x000017c0
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #-28,%d5
bnes 0x000017ba
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x000017c0
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-72,%d4
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
moveq #-24,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
moveq #-20,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
moveq #-16,%d5
.short 0xfff8
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
.short 0xe42e
movel %d0,%fp@(-36)
moveq #109,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe474
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x0000185a
invalid
breakpoint
.short 0xff36
bnes 0x00001856
invalid
.short 0x04ff
.short 0xe3f8
movel %d2,%d0
bras 0x000018d8
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d1
.short 0x0014
beqs 0x00001876
invalid
breakpoint
.short 0xfed3
bras 0x000018d8
moveq #48,%d1
cmpl %d2,%d1
bnes 0x00001882
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00001894
moveq #32,%d1
cmpl %d2,%d1
bnes 0x000018d2
moveq #1,%d1
cmpl %d0,%d1
bnes 0x000018d2
tstl %a2@(28)
beqs 0x000018d2
movel %a2@(24),%d1
invalid
.short 0x0000
moveq #-12,%d5
bnes 0x000018d2
tstl %a2@(28)
beqs 0x000018ac
movel %a2@(28),%d0
bras 0x000018d8
movel %a2@(32),%d1
invalid
.short 0x0000
moveq #-8,%d5
bnes 0x000018d2
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
moveq #-4,%d5
bnes 0x000018d2
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x000018d8
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
mvsb %d0,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
mvsb %d4,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvsb %a0,%d5
.short 0xfff8
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
.short 0xe316
movel %d0,%fp@(-36)
moveq #110,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe35c
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001972
invalid
breakpoint
.short 0xff36
bnes 0x0000196e
invalid
.short 0x04ff
.short 0xe2e0
movel %d2,%d0
bras 0x000019f0
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d2
.short 0x0014
beqs 0x0000198e
invalid
breakpoint
.short 0xfed3
bras 0x000019f0
moveq #48,%d1
cmpl %d2,%d1
bnes 0x0000199a
moveq #1,%d1
cmpl %d0,%d1
beqs 0x000019ac
moveq #32,%d1
cmpl %d2,%d1
bnes 0x000019ea
moveq #1,%d1
cmpl %d0,%d1
bnes 0x000019ea
tstl %a2@(28)
beqs 0x000019ea
movel %a2@(24),%d1
invalid
.short 0x0000
mvsb %a4,%d5
bnes 0x000019ea
tstl %a2@(28)
beqs 0x000019c4
movel %a2@(28),%d0
bras 0x000019f0
movel %a2@(32),%d1
invalid
.short 0x0000
mvsb %a0@,%d5
bnes 0x000019ea
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
mvsb %a4@,%d5
bnes 0x000019ea
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x000019f0
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
mvsb %a0@+,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
mvsb %a4@+,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvsb %a0@-,%d5
.short 0xfff8
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
.short 0xe1fe
movel %d0,%fp@(-36)
moveq #111,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe244
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001a8a
invalid
breakpoint
.short 0xff36
bnes 0x00001a86
invalid
.short 0x04ff
.short 0xe1c8
movel %d2,%d0
bras 0x00001b08
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d3
.short 0x0014
beqs 0x00001aa6
invalid
breakpoint
.short 0xfed3
bras 0x00001b08
moveq #48,%d1
cmpl %d2,%d1
bnes 0x00001ab2
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00001ac4
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00001b02
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00001b02
tstl %a2@(28)
beqs 0x00001b02
movel %a2@(24),%d1
invalid
.short 0x0000
mvsb %a4@-,%d5
bnes 0x00001b02
tstl %a2@(28)
beqs 0x00001adc
movel %a2@(28),%d0
bras 0x00001b08
movel %a2@(32),%d1
invalid
.short 0x0000
mvsb %a0@(26138),%d5
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
mvsb %a4@(26122),%d5
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x00001b08
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
invalid
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
invalid
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvsb 0xfffffffffffffff8,%d5
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
.short 0xe0e6
movel %d0,%fp@(-36)
moveq #112,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe12c
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001ba2
invalid
breakpoint
.short 0xff36
bnes 0x00001b9e
invalid
.short 0x04ff
.short 0xe0b0
movel %d2,%d0
bras 0x00001c20
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d4
.short 0x0014
beqs 0x00001bbe
invalid
breakpoint
.short 0xfed3
bras 0x00001c20
moveq #48,%d1
cmpl %d2,%d1
bnes 0x00001bca
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00001bdc
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00001c1a
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00001c1a
tstl %a2@(28)
beqs 0x00001c1a
movel %a2@(24),%d1
invalid
.short 0x0000
mvsb #50,%d5
tstl %a2@(28)
beqs 0x00001bf4
movel %a2@(28),%d0
bras 0x00001c20
movel %a2@(32),%d1
invalid
.short 0x0000
mvsw %d0,%d5
bnes 0x00001c1a
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
mvsw %d4,%d5
bnes 0x00001c1a
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x00001c20
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
mvsw %a0,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
mvsw %a4,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvsw %a0@,%d5
.short 0xfff8
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
addal %fp,%sp
movel %d0,%fp@(-36)
moveq #113,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xe014
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001cba
invalid
breakpoint
.short 0xff36
bnes 0x00001cb6
invalid
.short 0x04ff
addl %d7,%a0@+
movel %d2,%d0
bras 0x00001d38
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d5
.short 0x0014
beqs 0x00001cd6
invalid
breakpoint
.short 0xfed3
bras 0x00001d38
moveq #48,%d1
cmpl %d2,%d1
bnes 0x00001ce2
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00001cf4
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00001d32
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00001d32
tstl %a2@(28)
beqs 0x00001d32
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %a4@,%d5
bnes 0x00001d32
tstl %a2@(28)
beqs 0x00001d0c
movel %a2@(28),%d0
bras 0x00001d38
movel %a2@(32),%d1
invalid
.short 0x0000
mvsw %a0@+,%d5
bnes 0x00001d32
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
mvsw %a4@+,%d5
bnes 0x00001d32
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x00001d38
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-300
.short 0x48e7
movew %a0@(000000000000002e,%d2:w:4),%d0
.short 0x0008
moveal %fp@(20),%a3
lea %fp@(-300),%a2
invalid
.short 0x0000
btst %d0,%a4@(11641)
.short 0x0000
mvsw %a0@-,%d5
.short 0xfeec
invalid
.short 0x000c
.short 0xfef0
invalid
.short 0x0000
mvsw %a4@-,%d5
.short 0x0020
invalid
.short 0x0000
mvsw %a0@(36),%d5
invalid
.short 0x0000
mvsw %a4@(40),%d5
pea 0x00000100
movel %fp@(16),%sp@-
pea %a2@(44)
invalid
.short 0x04ff
lsll %d2,%d2
clrb %fp@(-1)
invalid
.short 0x0001
.short 0xfed7
movel %d3,%fp@(-296)
invalid
.short 0x0000
btst %d0,%d0
.short 0xfedc
movel %d2,%fp@(-284)
invalid
.short 0x04ff
addl %a0@-,%d7
movel %d0,%fp@(-288)
moveq #114,%d1
movel %d1,%fp@(-280)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xdee4
movel %d0,%d2
.short 0xdefc
.short 0x0020
beqs 0x00001dea
invalid
breakpoint
.short 0xff36
bnes 0x00001de6
invalid
.short 0x04ff
.short 0xde68
movel %d2,%d0
bras 0x00001e56
movel %a2@(4),%d3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d6
.short 0x0014
beqs 0x00001e06
invalid
breakpoint
.short 0xfed3
bras 0x00001e56
moveq #40,%d1
cmpl %d3,%d1
bnes 0x00001e10
tstl %d0
beqs 0x00001e22
moveq #32,%d1
cmpl %d3,%d1
bnes 0x00001e50
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00001e50
tstl %a2@(28)
beqs 0x00001e50
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %a0@(0000000000000022,%d6:w:8),%d5
tstl %a2@(28)
beqs 0x00001e3a
movel %a2@(28),%d0
bras 0x00001e56
movel %a2@(32),%d1
invalid
.short 0x0000
mvsw %a4@(000000000000000a,%d6:w:8),%d5
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x00001e56
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-60,%d4
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
mvsw 0xffffffffffffffe8,%d5
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
mvsw #-16,%d5
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvzb %d0,%d5
.short 0xfff8
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
addl %d6,%a0@+
movel %d0,%fp@(-36)
moveq #115,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
addal %fp@+,%fp
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00001ef0
invalid
breakpoint
.short 0xff36
bnes 0x00001eec
invalid
.short 0x04ff
.short 0xdd62
movel %d2,%d0
bras 0x00001f6e
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d7
.short 0x0014
beqs 0x00001f0c
invalid
breakpoint
.short 0xfed3
bras 0x00001f6e
moveq #48,%d1
cmpl %d2,%d1
bnes 0x00001f18
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00001f2a
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00001f68
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00001f68
tstl %a2@(28)
beqs 0x00001f68
movel %a2@(24),%d1
invalid
.short 0x0000
mvzb %d4,%d5
bnes 0x00001f68
tstl %a2@(28)
beqs 0x00001f42
movel %a2@(28),%d0
bras 0x00001f6e
movel %a2@(32),%d1
invalid
.short 0x0000
mvzb %a0,%d5
bnes 0x00001f68
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
mvzb %a4,%d5
bnes 0x00001f68
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x00001f6e
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movel 0x0000266e,%d0
.short 0x0018
moveal %fp@(28),%a4
lea %fp@(-48),%a2
moveq #48,%d2
invalid
.short 0x0000
mvzb %a0@,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
mvzb %a4@,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvzb %a0@+,%d5
.short 0xfff8
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
movel %d2,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
addl %d0,%d6
movel %d0,%fp@(-36)
moveq #116,%d1
movel %d1,%fp@(-28)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xdcc6
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00002008
invalid
breakpoint
.short 0xff36
bnes 0x00002004
invalid
.short 0x04ff
.short 0xdc4a
movel %d2,%d0
bras 0x00002086
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00d8
.short 0x0014
beqs 0x00002024
invalid
breakpoint
.short 0xfed3
bras 0x00002086
moveq #48,%d1
cmpl %d2,%d1
bnes 0x00002030
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00002042
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00002080
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00002080
tstl %a2@(28)
beqs 0x00002080
movel %a2@(24),%d1
invalid
.short 0x0000
mvzb %a4@+,%d5
bnes 0x00002080
tstl %a2@(28)
beqs 0x0000205a
movel %a2@(28),%d0
bras 0x00002086
movel %a2@(32),%d1
invalid
.short 0x0000
mvzb %a0@-,%d5
bnes 0x00002080
movel %a2@(36),%a3@
movel %a2@(40),%d1
invalid
.short 0x0000
mvzb %a4@-,%d5
bnes 0x00002080
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x00002086
invalid
breakpoint
.short 0xfed4
invalid
moveb %d4,%d6
.short 0xffc0
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movew 0x0000266e,%d0
.short 0x0010
moveal %fp@(20),%a4
lea %fp@(-48),%a2
invalid
.short 0x0000
mvzb %a0@(-24),%d5
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0001
.short 0xffd3
moveq #32,%d3
movel %d3,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
addxl %d2,%d5
movel %d0,%fp@(-36)
moveq #117,%d3
movel %d3,%fp@(-28)
clrl %sp@-
clrl %sp@-
pea 0x00000030
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
addal %d6,%a5
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00002108
invalid
breakpoint
.short 0xff36
bnes 0x00002104
invalid
.short 0x04ff
.short 0xdb4a
movel %d2,%d0
bras 0x00002186
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00d9
.short 0x0014
beqs 0x00002124
invalid
breakpoint
.short 0xfed3
bras 0x00002186
moveq #48,%d3
cmpl %d0,%d3
bnes 0x00002130
moveq #1,%d3
cmpl %d1,%d3
beqs 0x00002142
moveq #32,%d3
cmpl %d0,%d3
bnes 0x00002180
moveq #1,%d3
cmpl %d1,%d3
bnes 0x00002180
tstl %a2@(28)
beqs 0x00002180
movel %a2@(24),%d3
invalid
.short 0x0000
mvzb %a4@(26162),%d5
tstl %a2@(28)
beqs 0x0000215a
movel %a2@(28),%d0
bras 0x00002186
movel %a2@(32),%d3
invalid
.short 0x0000
mvzb %a0@(000000000000001a,%d6:w:8),%d5
movel %a2@(36),%a3@
movel %a2@(40),%d3
invalid
.short 0x0000
mvzb %a4@(000000000000000a,%d6:w:8),%d5
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x00002186
invalid
breakpoint
.short 0xfed4
invalid
.short 0x1c0c
.short 0xffbc
unlk %fp
rts
linkw %fp,#-32
movel %a2,%sp@-
movel %d2,%sp@-
lea %fp@(-32),%a2
moveq #32,%d2
invalid
.short 0x0000
mvzb 0xfffffffffffffff8,%d5
invalid
.short 0x000c
.short 0xfffc
invalid
.short 0x0001
.short 0xffe3
movel %d2,%fp@(-28)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe8
invalid
.short 0x0008
.short 0xfff0
invalid
.short 0x04ff
addl %a2,%d5
movel %d0,%fp@(-20)
moveq #118,%d1
movel %d1,%fp@(-12)
clrl %sp@-
clrl %sp@-
movel %d2,%sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xdad0
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x000021fe
invalid
breakpoint
.short 0xff36
bnes 0x000021fa
invalid
.short 0x04ff
.short 0xda54
movel %d2,%d0
bras 0x00002248
movel %a2@(4),%d2
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00da
.short 0x0014
beqs 0x0000221a
invalid
breakpoint
.short 0xfed3
bras 0x00002248
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00002232
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00002232
movel %a2@(24),%d1
invalid
.short 0x0000
mvzb #8,%d5
invalid
breakpoint
.short 0xfed4
bras 0x00002248
tstl %a2@(28)
bnes 0x00002244
clrl %d0
bras 0x00002248
movel %a2@(28),%d0
movel %fp@(-40),%d2
moveal %fp@(-36),%a2
unlk %fp
rts
linkw %fp,#-1068
.short 0x48e7
movew %a0@(000000000000002e,%d2:w:8),%d0
.short 0x0018
lea %fp@(-1068),%a3
moveal %a3,%a2
moveq #44,%d2
invalid
.short 0x0000
mvzw %d0,%d5
.short 0xfbec
invalid
.short 0x000c
.short 0xfbf0
invalid
.short 0x0000
mvzw %d4,%d5
.short 0xfbf4
invalid
.short 0x0010
.short 0xfbf8
invalid
.short 0x0000
mvzw %a0,%d5
.short 0xfbfc
invalid
.short 0x0000
.short 0x0400
blss 0x0000229e
invalid
breakpoint
.short 0xfecd
braw 0x0000235e
movel %d3,%sp@-
movel %fp@(20),%sp@-
pea %a2@(44)
invalid
.short 0x04ff
addl %d4,%a4@
.short 0xefea
movew %a4,%d0
.short 0x002a
movel %d3,%d0
addql #3,%d0
moveq #-4,%d1
andl %d1,%d0
invalid
.short 0x0001
.short 0x0003
addl %d0,%d2
movel %d2,%a2@(4)
invalid
.short 0x0000
btst %d0,%d0
.short 0x0008
invalid
.short 0x0008
.short 0x0010
invalid
.short 0x04ff
.short 0xd978
movel %d0,%a2@(12)
moveq #119,%d1
movel %d1,%a2@(20)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd9bc
moveal %d0,%a2
.short 0xdefc
.short 0x0020
tstl %a2
beqs 0x00002314
invalid
breakpoint
.short 0xff36
bnes 0x00002310
invalid
.short 0x04ff
.short 0xd93e
movel %a2,%d0
bras 0x0000235e
movel %a3@(4),%d2
.short 0xe9eb
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00db
.short 0x0014
beqs 0x00002330
invalid
breakpoint
.short 0xfed3
bras 0x0000235e
moveq #32,%d1
cmpl %d2,%d1
bnes 0x00002348
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00002348
movel %a3@(24),%d1
invalid
.short 0x0000
mvzw %a4,%d5
beqs 0x00002350
invalid
breakpoint
.short 0xfed4
bras 0x0000235e
tstl %a3@(28)
bnes 0x0000235a
clrl %d0
bras 0x0000235e
movel %a3@(28),%d0
invalid
cmpib #-60,%d4
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movew 0x0000266e,%d0
.short 0x0010
moveal %fp@(20),%a4
lea %fp@(-48),%a2
invalid
.short 0x0000
mvzw %a0@,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0001
.short 0xffd3
moveq #32,%d3
movel %d3,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
addl %a2@(11584),%d4
.short 0xffdc
moveq #120,%d3
movel %d3,%fp@(-28)
clrl %sp@-
clrl %sp@-
pea 0x00000030
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd8ee
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x000023e0
invalid
breakpoint
.short 0xff36
bnes 0x000023dc
invalid
.short 0x04ff
.short 0xd872
movel %d2,%d0
bras 0x0000245e
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00dc
.short 0x0014
beqs 0x000023fc
invalid
breakpoint
.short 0xfed3
bras 0x0000245e
moveq #48,%d3
cmpl %d0,%d3
bnes 0x00002408
moveq #1,%d3
cmpl %d1,%d3
beqs 0x0000241a
moveq #32,%d3
cmpl %d0,%d3
bnes 0x00002458
moveq #1,%d3
cmpl %d1,%d3
bnes 0x00002458
tstl %a2@(28)
beqs 0x00002458
movel %a2@(24),%d3
invalid
.short 0x0000
mvzw %a4@,%d5
bnes 0x00002458
tstl %a2@(28)
beqs 0x00002432
movel %a2@(28),%d0
bras 0x0000245e
movel %a2@(32),%d3
invalid
.short 0x0000
mvzw %a0@+,%d5
bnes 0x00002458
movel %a2@(36),%a3@
movel %a2@(40),%d3
invalid
.short 0x0000
mvzw %a4@+,%d5
bnes 0x00002458
movel %a2@(44),%a4@
movel %a2@(28),%d0
bras 0x0000245e
invalid
breakpoint
.short 0xfed4
invalid
.short 0x1c0c
.short 0xffbc
unlk %fp
rts
linkw %fp,#-48
.short 0x48e7
movew %a0@-,%d0
lea %fp@(-48),%a2
invalid
.short 0x0000
mvzw %a0@-,%d5
.short 0xffe8
invalid
.short 0x000c
.short 0xffec
invalid
.short 0x0000
mvzw %a4@-,%d5
.short 0xfff0
invalid
.short 0x0010
.short 0xfff4
invalid
.short 0x0000
mvzw %a0@(-8),%d5
invalid
.short 0x0014
.short 0xfffc
clrb %fp@(-45)
moveq #48,%d3
movel %d3,%fp@(-44)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffd8
invalid
.short 0x0008
.short 0xffe0
invalid
.short 0x04ff
addl %d3,%a0@+
movel %d0,%fp@(-36)
moveq #121,%d3
movel %d3,%fp@(-28)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
addal %a4@+,%a3
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x000024f2
invalid
breakpoint
.short 0xff36
bnes 0x000024ee
invalid
.short 0x04ff
.short 0xd760
movel %d2,%d0
bras 0x0000253c
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00dd
.short 0x0014
beqs 0x0000250e
invalid
breakpoint
.short 0xfed3
bras 0x0000253c
moveq #32,%d3
cmpl %d0,%d3
bnes 0x00002526
moveq #1,%d3
cmpl %d1,%d3
bnes 0x00002526
movel %a2@(24),%d3
invalid
.short 0x0000
mvzw %a4@(26376),%d5
invalid
breakpoint
.short 0xfed4
bras 0x0000253c
tstl %a2@(28)
bnes 0x00002538
clrl %d0
bras 0x0000253c
movel %a2@(28),%d0
invalid
.short 0x040c
.short 0xffc4
unlk %fp
rts
linkw %fp,#-308
.short 0x48e7
movew %a0@-,%d4
movel %fp@(8),%d3
movel %fp@(20),%d2
lea %fp@(-308),%a2
invalid
.short 0x0000
invalid
invalid
.short 0x0000
mvzw %a0@(ffffffffffffffe4,%sp:l:8),%d5
invalid
.short 0x000c
.short 0xfee8
invalid
.short 0x0000
mvzw %a4@(0000000000000020,%d0:w),%d5
invalid
.short 0x0000
mvzw 0x00000024,%d5
invalid
.short 0x0000
mvzw #40,%d5
pea 0x00000100
movel %fp@(16),%sp@-
pea %a2@(44)
invalid
.short 0x04ff
addl %d6,%fp@-
clrb %fp@(-9)
invalid
.short 0x0000
moveq #0,%d6
.short 0xfff8
movel %d2,%fp@(-4)
clrb %fp@(-305)
movel %d4,%fp@(-304)
invalid
.short 0x0000
btst %d0,%d0
.short 0xfed4
movel %d3,%fp@(-292)
invalid
.short 0x04ff
addl %a2@,%d3
movel %d0,%fp@(-296)
moveq #122,%d1
movel %d1,%fp@(-288)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd6d6
movel %d0,%d2
.short 0xdefc
.short 0x0020
beqs 0x000025f8
invalid
breakpoint
.short 0xff36
bnes 0x000025f4
invalid
.short 0x04ff
.short 0xd65a
movel %d2,%d0
bras 0x00002642
movel %a2@(4),%d4
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00de
.short 0x0014
beqs 0x00002614
invalid
breakpoint
.short 0xfed3
bras 0x00002642
moveq #32,%d1
cmpl %d4,%d1
bnes 0x0000262c
moveq #1,%d1
cmpl %d0,%d1
bnes 0x0000262c
movel %a2@(24),%d1
invalid
.short 0x0000
moveq #4,%d6
beqs 0x00002634
invalid
breakpoint
.short 0xfed4
bras 0x00002642
tstl %a2@(28)
bnes 0x0000263e
clrl %d0
bras 0x00002642
movel %a2@(28),%d0
invalid
.short 0x041c
.short 0xfebc
unlk %fp
rts
linkw %fp,#-300
.short 0x48e7
movew %a0@-,%d0
movel %fp@(8),%d2
lea %fp@(-300),%a2
invalid
.short 0x0000
btst %d0,%a4@(11641)
.short 0x0000
moveq #8,%d6
.short 0xfeec
invalid
.short 0x000c
.short 0xfef0
invalid
.short 0x0000
moveq #12,%d6
.short 0x0020
invalid
.short 0x0000
moveq #16,%d6
.short 0x0024
invalid
.short 0x0000
moveq #20,%d6
.short 0x0028
pea 0x00000100
movel %fp@(16),%sp@-
pea %a2@(44)
invalid
.short 0x04ff
addl %a4@-,%d6
clrb %fp@(-1)
invalid
.short 0x0001
.short 0xfed7
movel %d3,%fp@(-296)
invalid
.short 0x0000
btst %d0,%d0
.short 0xfedc
movel %d2,%fp@(-284)
invalid
.short 0x04ff
addl %d2,%a2@+
movel %d0,%fp@(-288)
moveq #123,%d1
movel %d1,%fp@(-280)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
addal %fp@+,%a2
movel %d0,%d2
.short 0xdefc
.short 0x0020
beqs 0x000026f0
invalid
breakpoint
.short 0xff36
bnes 0x000026ec
invalid
.short 0x04ff
.short 0xd562
movel %d2,%d0
bras 0x0000273a
movel %a2@(4),%d3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x00df
.short 0x0014
beqs 0x0000270c
invalid
breakpoint
.short 0xfed3
bras 0x0000273a
moveq #32,%d1
cmpl %d3,%d1
bnes 0x00002724
moveq #1,%d1
cmpl %d0,%d1
bnes 0x00002724
movel %a2@(24),%d1
invalid
.short 0x0000
moveq #24,%d6
beqs 0x0000272c
invalid
breakpoint
.short 0xfed4
bras 0x0000273a
tstl %a2@(28)
bnes 0x00002736
clrl %d0
bras 0x0000273a
movel %a2@(28),%d0
invalid
.short 0x040c
.short 0xfec8
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x0010
lea %fp@(-40),%a2
invalid
.short 0x0000
moveq #28,%d6
.short 0xfff0
invalid
.short 0x000c
.short 0xfff4
invalid
.short 0x0001
.short 0xffdb
moveq #32,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xd4d2
movel %d0,%fp@(-28)
moveq #124,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd516
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x000027b8
invalid
breakpoint
.short 0xff36
bnes 0x000027b4
invalid
.short 0x04ff
addl %a2@+,%d2
movel %d2,%d0
bras 0x00002826
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00e0
.short 0x0014
beqs 0x000027d4
invalid
breakpoint
.short 0xfed3
bras 0x00002826
moveq #40,%d3
cmpl %d0,%d3
bnes 0x000027e0
moveq #1,%d3
cmpl %d1,%d3
beqs 0x000027f2
moveq #32,%d3
cmpl %d0,%d3
bnes 0x00002820
moveq #1,%d3
cmpl %d1,%d3
bnes 0x00002820
tstl %a2@(28)
beqs 0x00002820
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #32,%d6
bnes 0x00002820
tstl %a2@(28)
beqs 0x0000280a
movel %a2@(28),%d0
bras 0x00002826
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #36,%d6
bnes 0x00002820
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x00002826
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-56,%d4
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x000c
lea %fp@(-40),%a2
invalid
.short 0x0001
.short 0xffdb
moveq #24,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
addal %a4@(0000000000000000),%a1
.short 0xffe4
moveq #125,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000028
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd438
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00002896
invalid
breakpoint
.short 0xff36
bnes 0x00002892
invalid
.short 0x04ff
.short 0xd3bc
movel %d2,%d0
bras 0x00002904
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00e1
.short 0x0014
beqs 0x000028b2
invalid
breakpoint
.short 0xfed3
bras 0x00002904
moveq #40,%d3
cmpl %d0,%d3
bnes 0x000028be
moveq #1,%d3
cmpl %d1,%d3
beqs 0x000028d0
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000028fe
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000028fe
tstl %a2@(28)
beqs 0x000028fe
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #40,%d6
bnes 0x000028fe
tstl %a2@(28)
beqs 0x000028e8
movel %a2@(28),%d0
bras 0x00002904
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #44,%d6
bnes 0x000028fe
movel %a2@(36),%a3@
movel %a2@(28),%d0
bras 0x00002904
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-56,%d4
unlk %fp
rts
linkw %fp,#-40
.short 0x48e7
movew %a0@-,%d0
lea %fp@(-40),%a2
invalid
.short 0x0000
moveq #48,%d6
.short 0xfff0
invalid
.short 0x000c
.short 0xfff4
invalid
.short 0x0000
moveq #52,%d6
.short 0xfff8
invalid
.short 0x0010
.short 0xfffc
invalid
.short 0x0001
.short 0xffdb
moveq #40,%d3
movel %d3,%fp@(-36)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffe0
invalid
.short 0x0008
.short 0xffe8
invalid
.short 0x04ff
.short 0xd2fe
movel %d0,%fp@(-28)
moveq #126,%d3
movel %d3,%fp@(-20)
clrl %sp@-
clrl %sp@-
pea 0x00000020
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd342
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x0000298c
invalid
breakpoint
.short 0xff36
bnes 0x00002988
invalid
.short 0x04ff
.short 0xd2c6
movel %d2,%d0
bras 0x000029d6
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00e2
.short 0x0014
beqs 0x000029a8
invalid
breakpoint
.short 0xfed3
bras 0x000029d6
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000029c0
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000029c0
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #56,%d6
beqs 0x000029c8
invalid
breakpoint
.short 0xfed4
bras 0x000029d6
tstl %a2@(28)
bnes 0x000029d2
clrl %d0
bras 0x000029d6
movel %a2@(28),%d0
invalid
.short 0x040c
.short 0xffcc
unlk %fp
rts
linkw %fp,#-548
.short 0x48e7
movew %a0@-,%d0
movel %fp@(20),%d2
lea %fp@(-548),%a2
moveq #36,%d3
invalid
.short 0x0000
moveq #60,%d6
.short 0xfdf4
invalid
.short 0x000c
.short 0xfdf8
invalid
.short 0x0000
moveq #64,%d6
.short 0xfdfc
invalid
.short 0x0000
.short 0x0200
bhis 0x00002a5c
movel %d2,%sp@-
movel %fp@(16),%sp@-
pea %a2@(36)
invalid
.short 0x04ff
.short 0xd222
.short 0xefee
movel %a4,%d0
.short 0xfdfe
movel %d2,%d0
addql #3,%d0
moveq #-4,%d1
andl %d1,%d0
invalid
.short 0x0001
.short 0xfddf
addl %d3,%d0
movel %d0,%fp@(-544)
clrl %fp@(-540)
invalid
.short 0x0008
.short 0xfdec
clrl %fp@(-536)
moveq #127,%d1
movel %d1,%fp@(-528)
clrl %sp@-
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xd26c
bras 0x00002a62
invalid
breakpoint
.short 0xfecd
invalid
.short 0x040c
.short 0xfdd0
unlk %fp
rts
linkw %fp,#-120
.short 0x48e7
movew #9838,%d0
.short 0x0010
moveal %fp@(20),%a4
moveal %fp@(24),%a5
lea %fp@(-120),%a2
invalid
.short 0x0000
moveq #68,%d6
cp1stl %d2,%a0@-,#7,#366
.short 0x000c
cp1stl %d1,%a4@-,#7,#380
.short 0x0001
cp1stl %d7,%a3,#4,#32
movel %d3,%fp@(-116)
invalid
.short 0x0000
btst %d0,%d0
cp1stl %d2,%a0@,#7,#366
.short 0x0008
cp1stl %d6,%a0@+,#1,#511
.short 0x04ff
addl %d0,%a2@-
movel %d0,%fp@(-108)
invalid
.short 0x0000
invalid
cp1stl %d4,%a4@+,#2,#167
clrl %sp@-
pea 0x00000078
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
addal %a4@-,%a0
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00002aec
invalid
breakpoint
.short 0xff36
bnes 0x00002ae6
invalid
.short 0x04ff
.short 0xd168
movel %d2,%d0
braw 0x00002c30
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x00e4
.short 0x0014
beqs 0x00002b0a
invalid
breakpoint
.short 0xfed3
braw 0x00002c30
moveq #120,%d3
cmpl %d0,%d3
bnes 0x00002b16
moveq #1,%d3
cmpl %d1,%d3
beqs 0x00002b2e
moveq #32,%d3
cmpl %d0,%d3
bnew 0x00002c2a
moveq #1,%d3
cmpl %d1,%d3
bnew 0x00002c2a
tstl %a2@(28)
beqw 0x00002c2a
moveal %a2@(24),%a0
invalid
.short 0x0000
moveq #72,%d6
bnew 0x00002c2a
tstl %a2@(28)
beqs 0x00002b4a
movel %a2@(28),%d0
braw 0x00002c30
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #76,%d6
bnew 0x00002c2a
movel %a2@(36),%a3@
moveal %a2@(40),%a0
invalid
.short 0x0000
moveq #80,%d6
bnew 0x00002c2a
movel %a2@(44),%a4@
movel %a2@(48),%d3
invalid
.short 0x0000
moveq #84,%d6
bnew 0x00002c2a
movel %a2@(52),%a5@
moveal %a2@(56),%a0
invalid
.short 0x0000
moveq #88,%d6
bnew 0x00002c2a
moveal %fp@(28),%a0
movel %a2@(60),%a0@
movel %a2@(64),%d3
invalid
.short 0x0000
moveq #92,%d6
bnew 0x00002c2a
moveal %fp@(32),%a0
movel %a2@(68),%a0@
movel %a2@(72),%d3
invalid
.short 0x0000
moveq #96,%d6
bnes 0x00002c2a
moveal %fp@(36),%a0
movel %a2@(76),%a0@
movel %a2@(80),%d3
invalid
.short 0x0000
moveq #100,%d6
bnes 0x00002c2a
moveal %fp@(40),%a0
movel %a2@(84),%a0@
movel %a2@(88),%d3
invalid
.short 0x0000
moveq #104,%d6
bnes 0x00002c2a
moveal %fp@(44),%a0
movel %a2@(92),%a0@
movel %a2@(96),%d3
invalid
.short 0x0000
moveq #108,%d6
bnes 0x00002c2a
moveal %fp@(48),%a0
movel %a2@(100),%a0@
movel %a2@(104),%d3
invalid
.short 0x0000
moveq #112,%d6
bnes 0x00002c2a
moveal %fp@(52),%a0
movel %a2@(108),%a0@
movel %a2@(112),%d3
invalid
.short 0x0000
moveq #116,%d6
bnes 0x00002c2a
moveal %fp@(56),%a0
movel %a2@(116),%a0@
movel %a2@(28),%d0
bras 0x00002c30
invalid
breakpoint
.short 0xfed4
invalid
movew %a4,%d6
.short 0xff70
unlk %fp
rts
linkw %fp,#-812
.short 0x48e7
movew %a0@(000000000000002e,%d2:l),%d4
.short 0x0008
movel %fp@(20),%d2
movel %fp@(24),%d3
lea %fp@(-812),%a3
invalid
.short 0x0000
moveq #120,%d6
.short 0xfcec
invalid
.short 0x000c
.short 0xfcf0
invalid
.short 0x0000
moveq #124,%d6
.short 0xfcf4
pea 0x00000100
pea %a3@(36)
movel %fp@(16),%sp@-
invalid
btst %d2,%d0
movel %a0,0x00004e92
.short 0x504f
.short 0x584f
invalid
.short 0x0000
moveq #-128,%d6
.short 0xfdf8
pea 0x00000100
pea %fp@(-516)
movel %d2,%sp@-
jsr %a2@
.short 0x504f
.short 0x584f
invalid
.short 0x0000
moveq #-124,%d6
.short 0xfefc
pea 0x00000100
pea %fp@(-256)
movel %d3,%sp@-
jsr %a2@
.short 0x504f
.short 0x584f
invalid
.short 0x0001
.short 0xfcd7
invalid
.short 0x0000
btst %d1,%a4@(-808)
clrl %fp@(-804)
movel %d4,%fp@(-796)
clrl %fp@(-800)
invalid
.short 0x0000
invalid
.short 0xfce8
clrl %sp@-
clrl %sp@-
movel %a3,%sp@-
invalid
.short 0x04ff
mulsw %a0@(19694),%d7
cmpib #-64,%d4
unlk %fp
rts
linkw %fp,#-32
invalid
.short 0x0000
moveq #-120,%d6
.short 0xfff8
invalid
.short 0x000c
.short 0xfffc
invalid
.short 0x0001
.short 0xffe3
moveq #32,%d1
movel %d1,%fp@(-28)
clrl %fp@(-24)
invalid
.short 0x0008
.short 0xfff0
clrl %fp@(-20)
invalid
.short 0x0000
invalid
.short 0xfff4
clrl %sp@-
clrl %sp@-
pea %fp@(-32)
invalid
.short 0x04ff
andl %d7,%a4@+
unlk %fp
rts
linkw %fp,#0
.short 0x48e7
movew %a0@-,%d6
movel %fp@(8),%d4
movel %fp@(12),%d3
invalid
.short 0x04ff
.short 0xd70e
movel %d0,%d5
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdc56
movel %d0,%d2
.short 0x504f
bnew 0x00002ddc
movel %d3,%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
moveal %a0@(0000000000000000,%d0:l:4),%a2
pea %a2@(64)
pea %a2@(44)
movel %d3,%sp@-
movel %d5,%sp@-
movel %a2@(4),%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xf1fe
movel %d0,%d2
.short 0xdefc
.short 0x0018
beqs 0x00002d94
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
addal %a0@+,%fp
movel %d2,%d0
bras 0x00002ddc
movel %d3,%sp@-
movel %d4,%sp@-
invalid
.short 0x0000
bset %d0,%d6
.short 0x504f
tstl %d0
bnes 0x00002dd0
movel %fp@(16),%sp@-
movel %a2,%sp@-
invalid
.short 0x0000
moveb %a0@+,%a2@+
.short 0x504f
moveq #-1,%d1
cmpl %d0,%d1
beqs 0x00002dd0
movel %a2@(64),%sp@-
movel %a2@(44),%sp@-
movel %d5,%sp@-
invalid
.short 0x04ff
addal %fp@-,%a3
clrl %a2@(44)
clrl %d0
bras 0x00002ddc
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdd8e
moveq #5,%d0
invalid
.short 0x043c
.short 0xffec
unlk %fp
rts
linkw %fp,#0
.short 0x48e7
movew %a0@-,%d6
movel %fp@(8),%d4
movel %fp@(12),%d3
invalid
.short 0x04ff
.short 0xd656
movel %d0,%d5
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
addl %d5,%fp@+
movel %d0,%d2
.short 0x504f
bnew 0x00002e9e
movel %d3,%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
moveal %a0@(0000000000000000,%d0:l:4),%a2
pea %a2@(64)
pea %a2@(44)
movel %d3,%sp@-
movel %d5,%sp@-
movel %a2@(4),%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xf146
movel %d0,%d2
.short 0xdefc
.short 0x0018
beqs 0x00002e4c
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdd20
movel %d2,%d0
bras 0x00002e9e
movel %d3,%sp@-
movel %d4,%sp@-
invalid
.short 0x0000
.short 0x010e
.short 0x504f
tstl %d0
bnes 0x00002e92
movel %fp@(24),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
movel %a2,%sp@-
invalid
.short 0x0000
moveb %fp@(000000000000004f,%d5:w),%a2@
.short 0x504f
moveq #-1,%d1
cmpl %d0,%d1
beqs 0x00002e92
movel %a2@(64),%sp@-
movel %a2@(44),%sp@-
movel %d5,%sp@-
invalid
.short 0x04ff
.short 0xd724
clrl %a2@(44)
clrl %d0
bras 0x00002e9e
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdccc
moveq #5,%d0
invalid
.short 0x043c
.short 0xffec
unlk %fp
rts
linkw %fp,#0
.short 0x48e7
movew %a0@-,%d6
movel %fp@(8),%d4
movel %fp@(12),%d3
invalid
.short 0x04ff
addl %d2,%a4@
movel %d0,%d5
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdadc
movel %d0,%d2
.short 0x504f
bnew 0x00002f56
movel %d3,%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
moveal %a0@(0000000000000000,%d0:l:4),%a2
pea %a2@(64)
pea %a2@(44)
movel %d3,%sp@-
movel %d5,%sp@-
movel %a2@(4),%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xf084
movel %d0,%d2
.short 0xdefc
.short 0x0018
beqs 0x00002f0e
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdc5e
movel %d2,%d0
bras 0x00002f56
movel %d3,%sp@-
movel %d4,%sp@-
invalid
.short 0x0000
.short 0x004c
.short 0x504f
tstl %d0
bnes 0x00002f4a
movel %fp@(16),%sp@-
movel %a2,%sp@-
invalid
.short 0x0000
moveb #79,%d2
moveq #-1,%d1
cmpl %d0,%d1
beqs 0x00002f4a
movel %a2@(64),%sp@-
movel %a2@(44),%sp@-
movel %d5,%sp@-
invalid
.short 0x04ff
.short 0xd66c
clrl %a2@(44)
clrl %d0
bras 0x00002f56
movel %d3,%sp@-
movel %d4,%sp@-
invalid
breakpoint
.short 0xdc14
moveq #5,%d0
invalid
.short 0x043c
.short 0xffec
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
movel %d2,%sp@-
movel %fp@(12),%d0
asrl #1,%d0
invalid
.short 0x0000
orl %d0,%a4@+
moveal %a0@(0000000000000000,%d0:l:4),%a2
tstl %a2
bnes 0x00002f82
moveq #4,%d0
braw 0x0000300a
moveal %a2@(28),%a0
movel %a0@,%d0
moveq #6,%d1
andl %d1,%d0
cmpl %d0,%d1
beqs 0x00002fcc
moveq #1,%d1
movel %d1,%a0@
clrl %d2
moveal %a2@(28),%a0
movel %a0@,%d0
moveq #6,%d1
andl %d1,%d0
cmpl %d0,%d1
beqs 0x00002fcc
invalid
.short 0x0001
orl %a0@-,%d3
invalid
.short 0x04ff
addl %d2,%a4@-
moveal %a2@(28),%a0
movel %a0@,%d0
.short 0x584f
btst #1,%d0
bnes 0x00002fc2
moveq #1,%d1
movel %d1,%a0@
addql #1,%d2
invalid
.short 0x0000
invalid
bles 0x00002f96
moveal %a2@(28),%a0
movel %a0@,%d0
moveq #6,%d1
andl %d1,%d0
cmpl %d0,%d1
beqs 0x00002fde
moveq #5,%d0
bras 0x0000300a
tstl %a2@(44)
beqs 0x00003008
movel %a2@(64),%d0
subql #1,%d0
invalid
.short 0x083f
.short 0xe800
moveal %a2@(44),%a2
addal %d0,%a2
pea 0x00000414
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xcc44
moveq #-1,%d1
movel %d1,%a2@
clrl %d0
movel %fp@(-8),%d2
moveal %fp@(-4),%a2
unlk %fp
rts
linkw %fp,#0
movel %d2,%sp@-
movel %fp@(12),%d2
invalid
.short 0x04ff
.short 0xd42c
asrl #1,%d2
invalid
.short 0x0000
orl %d0,%a4@+
moveal %a0@(0000000000000000,%d2:l:4),%a0
tstl %a0
beqs 0x00003046
moveal %a0@(28),%a0
movel %a0@,%d0
moveq #12,%d1
orl %d1,%d0
movel %d0,%a0@
clrl %d0
bras 0x00003048
moveq #4,%d0
movel %fp@(-4),%d2
unlk %fp
rts
linkw %fp,#-32
invalid
.short 0x0000
moveq #-116,%d6
.short 0xfff8
invalid
.short 0x000c
.short 0xfffc
invalid
.short 0x0001
.short 0xffe3
moveq #32,%d1
movel %d1,%fp@(-28)
clrl %fp@(-24)
invalid
.short 0x0008
.short 0xfff0
clrl %fp@(-20)
invalid
.short 0x0000
bset %d2,%a4@
.short 0xfff4
clrl %sp@-
clrl %sp@-
pea %fp@(-32)
invalid
.short 0x04ff
.short 0xcc34
unlk %fp
rts
linkw %fp,#-32
invalid
.short 0x0000
moveq #-112,%d6
.short 0xfff8
invalid
.short 0x000c
.short 0xfffc
clrb %fp@(-29)
moveq #32,%d1
movel %d1,%fp@(-28)
clrl %fp@(-24)
invalid
.short 0x0008
.short 0xfff0
clrl %fp@(-20)
invalid
.short 0x0000
bset %d2,%a5@
.short 0xfff4
clrl %sp@-
clrl %sp@-
pea %fp@(-32)
invalid
.short 0x04ff
mulsw %a0@(000000000000005e,%d4:l:8),%d5
rts
linkw %fp,#-68
.short 0x48e7
movew %a0@(000000000000006e,%d2:w:8),%d0
.short 0x000c
lea %fp@(-68),%a2
invalid
.short 0x0001
.short 0xffbf
moveq #24,%d3
movel %d3,%fp@(-64)
invalid
.short 0x0000
btst %d0,%d0
.short 0xffc4
invalid
.short 0x0008
.short 0xffcc
invalid
.short 0x04ff
.short 0xcb4a
movel %d0,%fp@(-56)
invalid
.short 0x0000
bset %d2,%fp@
.short 0xffd0
clrl %sp@-
clrl %sp@-
pea 0x00000044
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xcb8c
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00003144
invalid
breakpoint
.short 0xff36
bnes 0x0000313e
invalid
.short 0x04ff
.short 0xcb10
movel %d2,%d0
braw 0x000031d0
movel %a2@(4),%d0
.short 0xe9ea
.short 0x1008
.short 0x0003
invalid
.short 0x0000
.short 0x063a
.short 0x0014
beqs 0x00003160
invalid
breakpoint
.short 0xfed3
bras 0x000031d0
moveq #68,%d3
cmpl %d0,%d3
bnes 0x0000316c
moveq #1,%d3
cmpl %d1,%d3
beqs 0x0000317e
moveq #32,%d3
cmpl %d0,%d3
bnes 0x000031ca
moveq #1,%d3
cmpl %d1,%d3
bnes 0x000031ca
tstl %a2@(28)
beqs 0x000031ca
movel %a2@(24),%d3
invalid
.short 0x0000
moveq #-108,%d6
bnes 0x000031ca
tstl %a2@(28)
beqs 0x00003196
movel %a2@(28),%d0
bras 0x000031d0
movel %a2@(32),%d3
invalid
.short 0x0000
moveq #-104,%d6
bnes 0x000031ca
movel %a2@(36),%a3@+
moveal %a3,%a0
movel %a2@(40),%a0@+
movel %a2@(44),%a0@+
movel %a2@(48),%a0@+
movel %a2@(52),%a0@+
movel %a2@(56),%a0@+
movel %a2@(60),%a0@+
movel %a2@(64),%a0@
movel %a2@(28),%d0
bras 0x000031d0
invalid
breakpoint
.short 0xfed4
invalid
cmpib #-84,%d4
unlk %fp
rts
linkw %fp,#-7944
.short 0x48e7
movew 0x0000262e,%d0
.short 0x0010
moveal %fp@(20),%a3
lea %fp@(-7944),%a2
invalid
.short 0x0000
moveq #-100,%d6
.short 0xe110
invalid
.short 0x000c
.short 0xe114
invalid
.short 0x0001
.short 0xe0fb
moveq #32,%d1
movel %d1,%fp@(-7940)
invalid
.short 0x0000
btst %d0,%d0
.short 0xe100
invalid
.short 0x0008
.short 0xe108
invalid
.short 0x04ff
.short 0xca38
movel %d0,%fp@(-7932)
invalid
.short 0x0000
bset %d2,%sp@
.short 0xe10c
clrl %sp@-
clrl %sp@-
pea 0x00001f08
clrl %sp@-
movel %a2,%sp@-
invalid
.short 0x04ff
.short 0xca7a
movel %d0,%d2
.short 0xdefc
.short 0x0014
beqs 0x00003256
invalid
breakpoint
.short 0xff36
bnes 0x00003250
invalid
.short 0x04ff
.short 0xc9fe
movel %d2,%d0
braw 0x0000331c
moveal %a2@(4),%a1
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x063b
.short 0x0014
beqs 0x00003274
invalid
breakpoint
.short 0xfed3
braw 0x0000331c
lea %a1@(-44),%a0
invalid
.short 0x0000
moveb %a4@+,%sp@+
bhis 0x00003286
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003298
moveq #32,%d1
cmpl %a1,%d1
bnes 0x000032dc
moveq #1,%d1
cmpl %d0,%d1
bnes 0x000032dc
tstl %a2@(28)
beqs 0x000032dc
moveal %a2@(24),%a4
invalid
.short 0x0000
moveq #-96,%d6
bnes 0x000032dc
tstl %a2@(28)
beqs 0x000032b0
movel %a2@(28),%d0
bras 0x0000331c
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x000032dc
invalid
.short 0x0008
.short 0x0008
.short 0x0024
bnes 0x000032dc
movel %a2@(40),%d0
addql #3,%d0
moveq #-4,%d1
andl %d1,%d0
moveal %d0,%a4
lea %a4@(44),%a0
cmpal %a1,%a0
beqs 0x000032e4
invalid
breakpoint
.short 0xfed4
bras 0x0000331c
movel %a2@(40),%d1
cmpl %a3@,%d1
bhis 0x00003304
movel %d1,%sp@-
pea %a2@(44)
movel %d3,%sp@-
invalid
.short 0x04ff
.short 0xc948
movel %a2@(40),%a3@
movel %fp@(-7916),%d0
bras 0x0000331c
movel %a3@,%sp@-
pea %a2@(44)
movel %d3,%sp@-
invalid
.short 0x04ff
.short 0xc930
movel %a2@(40),%a3@
invalid
breakpoint
.short 0xfecd
invalid
.short 0x1c0c
.short 0xe0e4
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
moveq #48,%d1
cmpl %a2@(4),%d1
bnes 0x0000334a
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003354
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x000033bc
movel %a2@(24),%d1
invalid
.short 0x0000
moveq #-92,%d6
bnes 0x00003378
movel %a2@(32),%d1
invalid
.short 0x0000
moveq #-88,%d6
bnes 0x00003378
movel %a2@(40),%d1
invalid
.short 0x0000
moveq #-84,%d6
beqs 0x00003382
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x0000339c
movel %a2@(44),%sp@-
movel %a2@(36),%sp@-
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xd570
movel %d0,%a3@(28)
tstl %a3@(28)
bnes 0x000033bc
invalid
.short 0x0000
moveq #-80,%d6
.short 0x0020
invalid
.short 0x001c
.short 0x0024
invalid
.short 0x0001
.short 0x0003
moveq #40,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(8),%a0
moveal %fp@(12),%a2
.short 0xe9e8
.short 0x0008
.short 0x0003
moveq #40,%d1
cmpl %a0@(4),%d1
bnes 0x000033ea
moveq #1,%d1
cmpl %d0,%d1
beqs 0x000033f4
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x0000343e
movel %a0@(24),%d1
invalid
.short 0x0000
moveq #-76,%d6
bnes 0x0000340c
movel %a0@(32),%d1
invalid
.short 0x0000
moveq #-72,%d6
beqs 0x00003416
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x0000342c
movel %a0@(36),%sp@-
movel %a0@(28),%sp@-
movel %a0@(12),%sp@-
invalid
breakpoint
.short 0xd53a
movel %d0,%a2@(28)
tstl %a2@(28)
bnes 0x0000343e
invalid
.short 0x0001
.short 0x0003
moveq #32,%d1
movel %d1,%a2@(4)
moveal %fp@(-4),%a2
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(8),%a0
moveal %fp@(12),%a2
.short 0xe9e8
.short 0x0008
.short 0x0003
moveq #56,%d1
cmpl %a0@(4),%d1
bnes 0x00003468
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003472
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x000034dc
movel %a0@(24),%d1
invalid
.short 0x0000
moveq #-68,%d6
bnes 0x000034a2
movel %a0@(32),%d1
invalid
.short 0x0000
moveq #-64,%d6
bnes 0x000034a2
movel %a0@(40),%d1
invalid
.short 0x0000
moveq #-60,%d6
bnes 0x000034a2
movel %a0@(48),%d1
invalid
.short 0x0000
moveq #-56,%d6
beqs 0x000034ac
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x000034ca
movel %a0@(52),%sp@-
movel %a0@(44),%sp@-
movel %a0@(36),%sp@-
movel %a0@(28),%sp@-
movel %a0@(12),%sp@-
invalid
breakpoint
addl %pc@(0x00005a06),%d2
.short 0x001c
tstl %a2@(28)
bnes 0x000034dc
invalid
.short 0x0001
.short 0x0003
moveq #32,%d1
movel %d1,%a2@(4)
moveal %fp@(-4),%a2
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a1
invalid
.short 0x0001
.short 0x0003
moveq #32,%d1
movel %d1,%a1@(4)
invalid
.short 0x0008
.short 0x0008
clrl %a1@(12)
invalid
.short 0x0010
.short 0x0010
moveq #100,%d1
addl %a2@(20),%d1
movel %d1,%a1@(20)
invalid
.short 0x0000
moveq #-52,%d6
.short 0x0018
invalid
breakpoint
.short 0xfed1
.short 0x001c
movel %a2@(20),%d0
invalid
breakpoint
.short 0xf8f8
moveq #2,%d1
cmpl %d0,%d1
bcss 0x00003548
movel %a2@(20),%d0
invalid
.short 0x0000
bras 0x000034f2
tstl %a0@(0000000000000000,%d0:l:4)
bnes 0x0000354c
clrl %d0
bras 0x00003562
movel %a2@(20),%d0
invalid
.short 0x0000
bras 0x00003506
movel %a1,%sp@-
movel %a2,%sp@-
moveal %a0@(0000000000000000,%d0:l:4),%a0
jsr %a0@
moveq #1,%d0
moveal %fp@(-4),%a2
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(12),%a3
moveal %fp@(24),%a2
movel %fp@(28),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
.short 0xcaca
tstl %d0
bles 0x00003594
movel %d0,%a2@
bras 0x0000359c
clrl %a2@
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfff8
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(24),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
.short 0xd03e
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x000035d0
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(24),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
muluw %d4,%d4
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x00003600
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(16),%sp@-
invalid
.short 0x04ff
.short 0xbf72
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x00003628
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
eorl %d7,%a4@
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x00003654
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
.short 0xc4cc
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x00003680
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(16),%sp@-
invalid
.short 0x04ff
andl %fp@-,%d7
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x000036a8
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(16),%sp@-
invalid
.short 0x04ff
cmpw %a0@+,%d7
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x000036d0
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
cmpb %a2@(ffffffffffffffff,%d7:w:2),%d7
cmpl %d0,%d1
bnes 0x000036fc
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(24),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
cmpb %a0,%d7
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x0000372c
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(12),%a2
movel %fp@(24),%sp@-
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
invalid
.short 0x04ff
.short 0xc450
moveq #-1,%d1
cmpl %d0,%d1
bnes 0x0000375c
invalid
.short 0x0401
bclr %d2,%a0@(000000000000006e,%d2:w:4)
.short 0xfffc
unlk %fp
rts
linkw %fp,#-4
movel %d3,%sp@-
movel %d2,%sp@-
movel %fp@(8),%d3
movel %fp@(12),%d2
pea %fp@(-4)
invalid
.short 0x0000
invalid
movel %d2,%sp@-
movel %d3,%sp@-
invalid
breakpoint
.short 0xe5be
.short 0x504f
.short 0x504f
tstl %d0
beqs 0x000037fa
pea %fp@(-4)
invalid
.short 0x04ff
andl 0x00002f00,%d6
invalid
.short 0x04ff
andl %d3,%fp@-
.short 0x504f
tstl %d0
beqs 0x000037b8
movel %d0,%sp@-
invalid
.short 0x0000
invalid
invalid
.short 0x04ff
.short 0xc402
bras 0x000037fa
movel %fp@(-4),%sp@-
invalid
.short 0x0000
invalid
movel %d2,%sp@-
movel %d3,%sp@-
invalid
breakpoint
.short 0xed7e
.short 0x504f
.short 0x504f
tstl %d0
bnes 0x000037da
movel %fp@(-4),%d0
bras 0x000037fc
movel %d0,%sp@-
invalid
.short 0x0000
moveq #27,%d5
invalid
.short 0x04ff
mulsw %a0@,%d1
movel %fp@(-4),%sp@-
invalid
.short 0x04ff
.short 0xcc60
movel %d0,%sp@-
invalid
.short 0x04ff
.short 0xc754
clrl %d0
movel %fp@(-12),%d2
movel %fp@(-8),%d3
unlk %fp
rts
linkw %fp,#-4
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a3
moveal %fp@(12),%a2
clrl %d0
moveb %a3@(3),%d0
moveq #48,%d1
cmpl %a3@(4),%d1
bnes 0x0000382c
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003838
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x000038e6
movel %a3@(24),%d1
invalid
.short 0x0000
moveq #-36,%d6
bnes 0x00003864
movel %a3@(32),%d1
invalid
.short 0x0000
moveq #-32,%d6
bnes 0x00003864
invalid
.short 0x0000
moveb %a4@+,%sp@+
.short 0xfffc
movel %a3@(40),%d1
invalid
.short 0x0000
moveq #-28,%d6
beqs 0x0000386e
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003894
movel %a3@(44),%sp@-
pea %fp@(-4)
pea %a2@(60)
movel %a3@(36),%sp@-
pea %a3@(28)
movel %a3@(12),%sp@-
invalid
breakpoint
.short 0xfce2
movel %d0,%a2@(36)
clrl %a2@(28)
tstl %a2@(28)
bnes 0x000038e6
invalid
.short 0x0000
moveq #-24,%d6
.short 0x0020
invalid
.short 0x0000
moveq #-20,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0000
moveq #-16,%d6
.short 0x0030
invalid
.short 0x0000
moveq #-12,%d6
.short 0x0034
invalid
.short 0x0000
moveq #-8,%d6
.short 0x0038
invalid
.short 0xfffc
.short 0x0038
movel %fp@(-4),%d0
addql #3,%d0
moveq #-4,%d1
andl %d1,%d0
invalid
.short 0x0001
.short 0x0003
moveq #60,%d1
addl %d0,%d1
movel %d1,%a2@(4)
moveal %fp@(-12),%a2
moveal %fp@(-8),%a3
unlk %fp
rts
linkw %fp,#0
.short 0x48e7
.short 0x0038
moveal %fp@(8),%a2
moveal %fp@(12),%a3
moveal %a2@(4),%a1
.short 0xe9ea
.short 0x0008
.short 0x0003
lea %a1@(-52),%a0
invalid
.short 0x0000
moveb %a4@+,%sp@+
bhis 0x0000391e
moveq #1,%d1
cmpl %d0,%d1
beqs 0x0000392a
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x000039c2
moveal %a2@(24),%a4
invalid
.short 0x0000
moveq #-4,%d6
bnes 0x0000396e
movel %a2@(32),%d1
invalid
.short 0x0000
mvsb %d0,%d6
bnes 0x0000396e
moveb %a2@(43),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x0000396e
invalid
.short 0x0008
.short 0x0008
.short 0x002c
bnes 0x0000396e
movel %a2@(48),%d0
addql #3,%d0
moveq #-4,%d1
andl %d1,%d0
moveal %d0,%a4
lea %a4@(52),%a0
cmpal %a1,%a0
beqs 0x00003978
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x0000399a
movel %a2@(48),%sp@-
pea %a2@(52)
movel %a2@(36),%sp@-
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
cp0ldb %a2@+,%d2,#4,#320
.short 0x0024
clrl %a3@(28)
tstl %a3@(28)
bnes 0x000039c2
invalid
.short 0x0000
mvsb %d4,%d6
.short 0x0020
invalid
.short 0x0000
mvsb %a0,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
invalid
moveb %d0,%d6
.short 0xfff4
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x043c
.short 0x0004
bnes 0x000039f2
moveq #1,%d1
cmpl %d0,%d1
beqs 0x000039fe
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x00003a9c
movel %a2@(24),%d1
invalid
.short 0x0000
mvsb %a4,%d6
bnes 0x00003a48
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003a48
cmpiw #12,%d2
.short 0x0024
bnes 0x00003a48
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003a48
cmpiw #8192,%d2
.short 0x0026
bnes 0x00003a48
movel %a2@(1068),%d1
invalid
.short 0x0000
mvsb %a0@,%d6
bnes 0x00003a48
movel %a2@(1076),%d1
invalid
.short 0x0000
mvsb %a4@,%d6
beqs 0x00003a52
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003a74
movel %a2@(1080),%sp@-
movel %a2@(1072),%sp@-
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
wddataw %a0@(0000000000000000)
.short 0x0024
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00003a9c
invalid
.short 0x0000
mvsb %a0@+,%d6
.short 0x0020
invalid
.short 0x0000
mvsb %a4@+,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a3
moveal %fp@(12),%a2
.short 0xe9eb
.short 0x0008
.short 0x0003
moveq #40,%d1
cmpl %a3@(4),%d1
bnes 0x00003acc
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003ad6
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003b3a
movel %a3@(24),%d1
invalid
.short 0x0000
mvsb %a0@-,%d6
bnes 0x00003aee
movel %a3@(32),%d1
invalid
.short 0x0000
mvsb %a4@-,%d6
beqs 0x00003af8
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003b12
movel %a3@(36),%sp@-
pea %a3@(28)
movel %a3@(12),%sp@-
invalid
breakpoint
.short 0xfb02
movel %d0,%a2@(36)
clrl %a2@(28)
tstl %a2@(28)
bnes 0x00003b3a
invalid
.short 0x0000
mvsb %a0@(32),%d6
invalid
.short 0x0000
mvsb %a4@(40),%d6
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a2@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x0434
.short 0x0004
bnes 0x00003b6c
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003b78
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x00003c06
movel %a2@(24),%d1
invalid
.short 0x0000
mvsb %a0@(0000000000000032,%d6:w:8),%d6
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003bb6
cmpiw #12,%d2
.short 0x0024
bnes 0x00003bb6
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003bb6
cmpiw #8192,%d2
.short 0x0026
bnes 0x00003bb6
movel %a2@(1068),%d1
invalid
.short 0x0000
invalid
beqs 0x00003bc0
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003bde
movel %a2@(1072),%sp@-
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xfa5e
movel %d0,%a3@(36)
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00003c06
invalid
.short 0x0000
mvsb 0x00000020,%d6
invalid
.short 0x0000
mvsb #40,%d6
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x0838
.short 0x0004
bnes 0x00003c38
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003c44
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x00003cec
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %d0,%d6
bnes 0x00003c9c
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003c9c
cmpiw #12,%d2
.short 0x0024
bnes 0x00003c9c
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003c9c
cmpiw #8192,%d2
.short 0x0026
bnes 0x00003c9c
moveb %a2@(1071),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003c9c
cmpiw #12,%d2
.short 0x0430
bnes 0x00003c9c
moveq #1,%d1
cmpl %a2@(1076),%d1
bnes 0x00003c9c
cmpiw #8192,%d2
.short 0x0432
beqs 0x00003ca6
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003cc4
pea %a2@(1080)
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xf9a4
movel %d0,%a3@(36)
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00003cec
invalid
.short 0x0000
mvsw %d4,%d6
.short 0x0020
invalid
.short 0x0000
mvsw %a0,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x042c
.short 0x0004
bnes 0x00003d1e
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003d28
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003da6
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %a4,%d6
bnes 0x00003d5a
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003d5a
cmpiw #12,%d2
.short 0x0024
bnes 0x00003d5a
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003d5a
cmpiw #8192,%d2
.short 0x0026
beqs 0x00003d64
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003d7e
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xf916
movel %d0,%a3@(36)
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00003da6
invalid
.short 0x0000
mvsw %a0@,%d6
.short 0x0020
invalid
.short 0x0000
mvsw %a4@,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x042c
.short 0x0004
bnes 0x00003dd8
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003de2
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003e60
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %a0@+,%d6
bnes 0x00003e14
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003e14
cmpiw #12,%d2
.short 0x0024
bnes 0x00003e14
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003e14
cmpiw #8192,%d2
.short 0x0026
beqs 0x00003e1e
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003e38
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xf884
movel %d0,%a3@(36)
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00003e60
invalid
.short 0x0000
mvsw %a4@+,%d6
.short 0x0020
invalid
.short 0x0000
mvsw %a0@-,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x0434
.short 0x0004
bnes 0x00003e92
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003e9e
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x00003f2c
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %a4@-,%d6
bnes 0x00003edc
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003edc
cmpiw #12,%d2
.short 0x0024
bnes 0x00003edc
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003edc
cmpiw #8192,%d2
.short 0x0026
bnes 0x00003edc
movel %a2@(1068),%d1
invalid
.short 0x0000
mvsw %a0@(26378),%d6
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003f04
movel %a2@(1072),%sp@-
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xf7e0
movel %d0,%a3@(36)
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00003f2c
invalid
.short 0x0000
mvsw %a4@(32),%d6
invalid
.short 0x0000
mvsw %a0@(0000000000000028,%d0:w),%d6
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a3
.short 0xe9ea
.short 0x0008
.short 0x0003
invalid
.short 0x0000
.short 0x043c
.short 0x0004
bnes 0x00003f5e
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00003f6a
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x00004008
movel %a2@(24),%d1
invalid
.short 0x0000
mvsw %a4@(000000000000003e,%d6:w:8),%d6
moveb %a2@(35),%d0
.short 0x0200
.short 0x000c
cmpib #12,%d0
bnes 0x00003fb4
cmpiw #12,%d2
.short 0x0024
bnes 0x00003fb4
moveq #1,%d1
cmpl %a2@(40),%d1
bnes 0x00003fb4
cmpiw #8192,%d2
.short 0x0026
bnes 0x00003fb4
movel %a2@(1068),%d1
invalid
.short 0x0000
mvsw 0x0000660c,%d6
movel %a2@(1076),%d1
invalid
.short 0x0000
mvsw #26378,%d6
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x00003fe0
movel %a2@(1080),%sp@-
movel %a2@(1072),%sp@-
pea %a2@(44)
pea %a2@(28)
movel %a2@(12),%sp@-
invalid
breakpoint
.short 0xf730
movel %d0,%a3@(36)
clrl %a3@(28)
tstl %a3@(28)
bnes 0x00004008
invalid
.short 0x0000
mvzb %d0,%d6
.short 0x0020
invalid
.short 0x0000
mvzb %d4,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a3@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a3,%sp@-
movel %a2,%sp@-
moveal %fp@(8),%a3
moveal %fp@(12),%a2
.short 0xe9eb
.short 0x0008
.short 0x0003
moveq #56,%d1
cmpl %a3@(4),%d1
bnes 0x00004038
moveq #1,%d1
cmpl %d0,%d1
beqs 0x00004044
invalid
breakpoint
.short 0xfed0
.short 0x001c
braw 0x000040c8
movel %a3@(24),%d1
invalid
.short 0x0000
mvzb %a0,%d6
bnes 0x00004074
movel %a3@(32),%d1
invalid
.short 0x0000
mvzb %a4,%d6
bnes 0x00004074
movel %a3@(40),%d1
invalid
.short 0x0000
mvzb %a0@,%d6
bnes 0x00004074
movel %a3@(48),%d1
invalid
.short 0x0000
mvzb %a4@,%d6
beqs 0x0000407e
invalid
breakpoint
.short 0xfed0
.short 0x001c
bras 0x000040a0
movel %a3@(52),%sp@-
movel %a3@(44),%sp@-
movel %a3@(36),%sp@-
pea %a3@(28)
movel %a3@(12),%sp@-
invalid
breakpoint
.short 0xf6a0
movel %d0,%a2@(36)
clrl %a2@(28)
tstl %a2@(28)
bnes 0x000040c8
invalid
.short 0x0000
mvzb %a0@+,%d6
.short 0x0020
invalid
.short 0x0000
mvzb %a4@+,%d6
.short 0x0028
invalid
.short 0x001c
.short 0x002c
invalid
.short 0x0001
.short 0x0003
moveq #48,%d1
movel %d1,%a2@(4)
moveal %fp@(-8),%a2
moveal %fp@(-4),%a3
unlk %fp
rts
linkw %fp,#0
movel %a2,%sp@-
moveal %fp@(8),%a2
moveal %fp@(12),%a1
invalid
.short 0x0001
.short 0x0003
moveq #32,%d1
movel %d1,%a1@(4)
invalid
.short 0x0008
.short 0x0008
clrl %a1@(12)
invalid
.short 0x0010
.short 0x0010
moveq #100,%d1
addl %a2@(20),%d1
movel %d1,%a1@(20)
invalid
.short 0x0000
mvzb %a0@-,%d6
.short 0x0018
invalid
breakpoint
.short 0xfed1
.short 0x001c
movel %a2@(20),%d0
invalid
breakpoint
.short 0xd508
invalid
.short 0x0000
invalid
bhis 0x0000413a
movel %a2@(20),%d0
invalid
breakpoint
addal %d4,%a0
tstl %a0@(0000000000000000,%d0:l:4)
bnes 0x0000413e
clrl %d0
bras 0x00004154
movel %a2@(20),%d0
invalid
breakpoint
addal %d4,%a0
movel %a1,%sp@-
movel %a2,%sp@-
moveal %a0@(0000000000000000,%d0:l:4),%a0
jsr %a0@
moveq #1,%d0
moveal %fp@(-4),%a2
unlk %fp
rts
linkw %fp,#-512
.short 0x48e7
movel 0x0000226e,%d0
.short 0x0008
movel %fp@(12),%d1
moveal %a1,%a3
moveal %d1,%a4
moveq #5,%d2
cmpl %a1@(20),%d2
bcsw 0x00004264
movel %a1@(20),%d0
invalid
.short 0x0000
bgts 0x0000411e
moveal %a0@(0000000000000000,%d0:l:4),%a0
jmp %a0@
.short 0x0000
bgts 0x00004140
.short 0x0000
bles 0x0000419c
.short 0x0000
bgts 0x0000415c
.short 0x0000
bles 0x0000420e
.short 0x0000
bles 0x00004206
.short 0x0000
bles 0x0000412a
invalid
.short 0x0401
.short 0x0014
pea %a3@(32)
invalid
.short 0x04ff
cmpw #24576,%d3
invalid
invalid
.short 0x0401
.short 0x0014
invalid
.short 0x04ff
cmpb %a2@(18553),%d3
.short 0x0401
.short 0x0000
pea 0x000001ff
lea %fp@(-512),%a2
movel %a2,%sp@-
invalid
.short 0x04ff
cmpb %a4@(12042),%d3
invalid
.short 0x04ff
.short 0xc14c
addql #1,%d0
movel %d0,%sp@-
movel %a2,%sp@-
movel %a3@(24),%sp@-
movel %a3@(16),%sp@-
invalid
breakpoint
andl %d7,%fp@(-8452)
.short 0x0024
bras 0x00004244
invalid
.short 0x0401
.short 0x0000
subql #1,%a0@
bmis 0x00004214
invalid
.short 0x0401
.short 0x0004
moveb %a0@,%d0
invalid
.short 0x0401
.short 0x0004
bras 0x00004222
invalid
.short 0x0401
.short 0x0000
invalid
.short 0x04ff
.short 0xb15e
.short 0x584f
moveb %d0,%fp@(-512)
clrb %fp@(-511)
pea 0x00000001
pea %fp@(-512)
movel %a3@(24),%sp@-
movel %a3@(16),%sp@-
invalid
breakpoint
.short 0xcf62
.short 0x504f
.short 0x504f
tstl %d0
beqs 0x00004270
movel %d0,%sp@-
invalid
.short 0x0000
moveq #57,%d5
invalid
.short 0x04ff
.short 0xb962
bras 0x00004270
.short 0x23eb
.short 0x0020
.short 0x0000
orl %d0,%a4@(17024)
bras 0x0000427a
movel %d1,%sp@-
movel %a1,%sp@-
invalid
.short 0x0000
.short 0x0668
bras 0x0000427a
invalid
breakpoint
.short 0xfecf
.short 0x001c
moveq #1,%d0
invalid
moveb %d4,%d6
.short 0xfdf0
unlk %fp
rts
linkw %fp,#-60
movel %d3,%sp@-
movel %d2,%sp@-
pea 0x000001a4
clrl %sp@-
movel %fp@(12),%sp@-
invalid
.short 0x04ff
cmpb %a4@+,%d6
movel %d0,%d3
.short 0x504f
.short 0x584f
moveq #-1,%d1
cmpl %d3,%d1
beqs 0x00004316
pea %fp@(-60)
movel %d3,%sp@-
invalid
.short 0x04ff
eorl %d2,%a2@(9216)
.short 0x504f
moveq #-1,%d1
cmpl %d2,%d1
beqs 0x0000430c
movel %fp@(-44),%sp@-
pea 0x00000001
invalid
.short 0x0000
.short 0x8018
clrl %sp@-
movel %d3,%sp@-
invalid
.short 0x04ff
.short 0xb93c
.short 0xdefc
.short 0x0014
tstl %d0
bnes 0x0000430c
movel %fp@(8),%sp@-
invalid
.short 0x0000
invalid
movel %d0,%d2
movel %fp@(-44),%sp@-
invalid
.short 0x0000
.short 0x8018
invalid
.short 0x0401
invalid
invalid
.short 0x04ff
andl %fp@(12035),%d1
invalid
.short 0x04ff
cmpl %d6,%d1
movel %d2,%d0
bras 0x00004316
movel %d3,%sp@-
invalid
.short 0x04ff
cmpw %pc@(0x0000b413),%d1
movel %fp@(-68),%d2
movel %fp@(-64),%d3
unlk %fp
rts
linkw %fp,#-4
pea %fp@(-4)
movel %fp@(20),%sp@-
movel %fp@(16),%sp@-
movel %fp@(12),%sp@-
invalid
.short 0x04ff
.short 0xb6c0
invalid
.short 0x0000
.short 0x8018
.short 0x504f
.short 0x504f
beqs 0x00004354
movel %fp@(8),%sp@-
invalid
.short 0x0000
.short 0x003e
bras 0x0000435e
moveq #8,%d1
invalid
.short 0x0401
bclr %d2,%a0@(ffffffffffffffff,%d7:w)
unlk %fp
rts
linkw %fp,#0
movel %fp@(12),%d0
invalid
.short 0x0000
.short 0x8018
beqs 0x0000437e
movel %fp@(8),%sp@-
invalid
.short 0x0000
.short 0x0014
bras 0x00004388
moveq #8,%d1
invalid
.short 0x0401
bclr %d2,%a0@(ffffffffffffffff,%d7:w)
unlk %fp
rts
linkw %fp,#-56
movel %a3,%sp@-
movel %a2,%sp@-
clrl %fp@(-16)
moveal %fp@(8),%a0
invalid
.short 0x002c
.short 0xffd4
invalid
.short 0x0000
.short 0x8018
movel %a0,%fp@(-4)
invalid
.short 0xfeed
.short 0xface
bnew 0x00004728
moveal %fp@(-4),%a0
moveq #15,%d1
cmpl %a0@(4),%d1
bnew 0x00004728
moveq #1,%d1
cmpl %a0@(8),%d1
bcsw 0x00004728
moveal %fp@(-4),%a0
invalid
.short 0x0000
.short 0x001b
beqw 0x00004728
moveal %fp@(-4),%a0
moveq #2,%d1
cmpl %a0@(12),%d1
beqs 0x000043f2
moveq #5,%d1
cmpl %a0@(12),%d1
bnew 0x00004728
invalid
.short 0x0000
mvzw %a4,%d2
pea 0x0000000a
invalid
btst %d2,%d0
.short 0x2f7e
jsr %a2@
movel %d0,%fp@(-52)
invalid
.short 0x0000
mvzw %a4,%d2
pea 0x0000000b
jsr %a2@
movel %d0,%fp@(-56)
invalid
.short 0x0000
.short 0x80f0
invalid
.short 0x04ff
eorl %d6,%a4@
.short 0xdefc
.short 0x0014
tstl %d0
beqs 0x00004446
movel %fp@(-52),%sp@-
pea 0x0000000a
jsr %a2@
movel %fp@(-56),%sp@-
pea 0x0000000b
jsr %a2@
moveq #14,%d1
braw 0x0000472a
moveal %fp@(-4),%a0
invalid
.short 0x0010
.short 0xffe0
invalid
.short 0x0000
.short 0x8018
.short 0xffec
moveq #28,%d1
braw 0x00004704
moveal %fp@(-20),%a0
movel %a0,%fp@(-8)
moveq #1,%d1
cmpl %a0@,%d1
beqs 0x0000447e
movel %a0@,%d0
subql #4,%d0
cmpl %d0,%d1
bcsw 0x000046fc
movel %a0,%fp@(-16)
braw 0x000046fc
moveal %fp@(-20),%a0
movel %a0,%fp@(-12)
invalid
.short 0x0000
.short 0x8018
addal %a0@(32),%a3
movel %a3,%fp@(-24)
movel %a0@(24),%d0
invalid
.short 0x0fff
breakpoint
invalid
.short 0xf800
.short 0x0000
addl %fp@(-44),%d0
movel %d0,%fp@(-28)
invalid
.short 0x0000
moveq #73,%d5
movel %fp@(-12),%d1
addql #8,%d1
movel %d1,%sp@-
invalid
.short 0x04ff
cmpb #79,%d7
tstl %d0
bnew 0x00004618
moveal %fp@(-4),%a1
moveq #2,%d1
cmpl %a1@(12),%d1
bnes 0x000044ea
moveal %fp@(-12),%a0
tstl %a0@(32)
bnes 0x000044ea
moveq #28,%d1
addl %a1@(20),%d1
movel %d1,%fp@(-40)
bras 0x000044ee
clrl %fp@(-40)
clrl %fp@(-36)
moveal %fp@(-36),%a3
cmpal %fp@(-40),%a3
bges 0x0000451c
moveal %fp@(-24),%a1
moveal %fp@(-28),%a0
movel %a1@,%a0@
addql #4,%fp@(-28)
addql #4,%fp@(-24)
addql #4,%fp@(-36)
movel %fp@(-36),%d1
cmpl %fp@(-40),%d1
blts 0x000044fc
moveal %fp@(-12),%a0
invalid
.short 0x0000
.short 0x0037
beqs 0x00004598
invalid
.short 0xffd8
.short 0xffdc
bras 0x00004548
movel %fp@(-28),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a3
clrl %a3@
addql #4,%fp@(-28)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %a0@(28),%d0
subl %a0@(36),%d0
cmpl %fp@(-36),%d0
bhis 0x00004530
clrl %fp@(-36)
moveal %fp@(-12),%a0
movel %fp@(-36),%d1
cmpl %a0@(36),%d1
bccw 0x000046fc
movel %fp@(-28),%d0
.short 0x0a40
.short 0x0004
moveal %fp@(-24),%a0
moveal %d0,%a3
movel %a0@,%a3@
addql #4,%fp@(-28)
addql #4,%fp@(-24)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %fp@(-36),%d1
cmpl %a0@(36),%d1
bcss 0x0000456a
braw 0x000046fc
invalid
.short 0xffd8
.short 0xffdc
moveal %fp@(-12),%a0
moveal %fp@(-36),%a3
cmpal %a0@(36),%a3
bccs 0x000045d6
movel %fp@(-28),%d0
.short 0x0a40
.short 0x0004
moveal %fp@(-24),%a0
moveal %d0,%a3
movel %a0@,%a3@
addql #4,%fp@(-28)
addql #4,%fp@(-24)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %fp@(-36),%d1
cmpl %a0@(36),%d1
bcss 0x000045ac
clrl %fp@(-36)
moveal %fp@(-12),%a0
movel %a0@(28),%d0
subl %a0@(36),%d0
cmpl %fp@(-36),%d0
blsw 0x000046fc
movel %fp@(-28),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a3
clrl %a3@
addql #4,%fp@(-28)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %a0@(28),%d0
subl %a0@(36),%d0
cmpl %fp@(-36),%d0
bhis 0x000045ee
braw 0x000046fc
invalid
.short 0x0000
moveq #80,%d5
movel %fp@(-12),%d1
addql #8,%d1
movel %d1,%sp@-
invalid
.short 0x04ff
.short 0xbcd0
.short 0x504f
tstl %d0
beqw 0x000046fc
moveal %fp@(-12),%a0
invalid
.short 0x0000
.short 0x0037
beqs 0x000046a0
clrl %fp@(-36)
bras 0x00004658
moveal %fp@(-28),%a0
clrl %a0@
addql #4,%fp@(-28)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %a0@(28),%d0
subl %a0@(36),%d0
cmpl %fp@(-36),%d0
bhis 0x00004646
clrl %fp@(-36)
moveal %fp@(-12),%a0
moveal %fp@(-36),%a3
cmpal %a0@(36),%a3
bccw 0x000046fc
moveal %fp@(-24),%a0
moveal %fp@(-28),%a1
movel %a0@,%a1@
addql #4,%fp@(-28)
addql #4,%fp@(-24)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %fp@(-36),%d1
cmpl %a0@(36),%d1
bcss 0x0000467a
bras 0x000046fc
clrl %fp@(-36)
moveal %fp@(-12),%a0
moveal %fp@(-36),%a3
cmpal %a0@(36),%a3
bccs 0x000046d6
moveal %fp@(-24),%a0
moveal %fp@(-28),%a1
movel %a0@,%a1@
addql #4,%fp@(-28)
addql #4,%fp@(-24)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %fp@(-36),%d1
cmpl %a0@(36),%d1
bcss 0x000046b2
clrl %fp@(-36)
bras 0x000046ea
moveal %fp@(-28),%a0
clrl %a0@
addql #4,%fp@(-28)
addql #4,%fp@(-36)
moveal %fp@(-12),%a0
movel %a0@(28),%d0
subl %a0@(36),%d0
cmpl %fp@(-36),%d0
bhis 0x000046dc
moveal %fp@(-8),%a0
movel %a0@(4),%d1
addl %d1,%fp@(-20)
subql #1,%fp@(-32)
moveq #-1,%d1
cmpl %fp@(-32),%d1
bnew 0x0000445e
tstl %fp@(-16)
beqs 0x00004728
moveal %fp@(-16),%a0
moveq #4,%d1
cmpl %a0@(8),%d1
beqs 0x00004734
moveq #8,%d1
invalid
.short 0x0401
bclr %d2,%a0@(ffffffffffffffff,%d7:w)
bras 0x00004750
movel %fp@(-52),%sp@-
pea 0x0000000a
invalid
btst %d2,%d0
.short 0x2f7e
jsr %a2@
movel %fp@(-56),%sp@-
pea 0x0000000b
jsr %a2@
clrl %d0
moveal %fp@(-64),%a2
moveal %fp@(-60),%a3
unlk %fp
rts
linkw %fp,#-24
movel %a2,%sp@-
moveal %fp@(8),%a0
invalid
.short 0x002c
.short 0xffe8
invalid
.short 0x07ff
cp1stb %sp,%d0,#8,#488
movel %fp@(12),%d0
invalid
.short 0x0000
btst %d0,%d0
lsrl #2,%d0
movel %d0,%fp@(-8)
subql #3,%fp@(-8)
invalid
.short 0x03ff
breakpoint
.short 0xfff8
movel %fp@(-8),%d0
invalid
bvcw 0x00004798
movel %d0,%fp@(-8)
movel %d0,%fp@(-4)
invalid
.short 0x0000
mvzw %a4,%d2
pea 0x0000000a
invalid
btst %d2,%d0
.short 0x2f7e
jsr %a2@
movel %d0,%fp@(-16)
invalid
.short 0x0000
mvzw %a4,%d2
pea 0x0000000b
jsr %a2@
movel %d0,%fp@(-20)
invalid
.short 0x0000
.short 0x80f0
invalid
.short 0x04ff
cmpal %a4@-,%a4
.short 0xdefc
.short 0x0014
tstl %d0
bnew 0x00004890
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
movel %fp@(-4),%a1@
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
addql #4,%fp@(-24)
movel %fp@(-24),%d0
.short 0x0a40
.short 0x0004
moveal %d0,%a1
invalid
.short 0xa000
.short 0x0000
movel %fp@(-16),%sp@-
pea 0x0000000a
jsr %a2@
movel %fp@(-20),%sp@-
pea 0x0000000b
jsr %a2@
clrl %d0
bras 0x000048b4
movel %fp@(-16),%sp@-
pea 0x0000000a
invalid
btst %d2,%d0
.short 0x2f7e
jsr %a2@
movel %fp@(-20),%sp@-
pea 0x0000000b
jsr %a2@
moveq #14,%d1
invalid
.short 0x0401
bclr %d2,%a0@(ffffffffffffffff,%d7:w)
moveal %fp@(-28),%a2
unlk %fp
rts
linkw %fp,#0
movel %fp@(8),%sp@-
invalid
.short 0x0000
.short 0x80f0
invalid
.short 0x04ff
cmpl %a0,%d1
nop
linkw %fp,#0
moveal %fp@(12),%a0
invalid
breakpoint
.short 0xfecf
.short 0x001c
moveq #1,%d0
unlk %fp
rts
