; Function: func_00003284
; Address: 0x00003284 - 0x000033b3
; Size: 304 bytes
; Frame: 64 bytes
; Purpose: Unknown
; Description: 304 bytes, frame size 64
; Confidence: UNKNOWN
;
0x00003284:  linkw %fp,#-64
0x00003286:  .short 0x48e7
0x00003288:  movew #9774,%d6
0x0000328a:  .short 0x0008
0x0000328c:  movel %fp@(12),%d2
0x0000328e:  moveal %fp@(16),%a5
0x00003290:  invalid
0x00003292:  .short 0x04ff
0x00003294:  cp1bcbusy 0x0000281a
0x00003296:  pea %fp@(-56)
0x00003298:  invalid
0x0000329a:  .short 0x0000
0x0000329c:  mvzw %a3@-,%d3
0x0000329e:  movel %d2,%sp@-
0x000032a0:  movel %d3,%sp@-
0x000032a2:  invalid
0x000032a4:  .short 0x0000
0x000032a6:  moveb %a2@-,%a3@(000000000000004f,%d5:w)
0x000032a8:  .short 0x504f
0x000032aa:  tstl %d0
0x000032ac:  bnew 0x00000126
0x000032ae:  pea %fp@(-60)
0x000032b0:  movel %d2,%sp@-
0x000032b2:  movel %d3,%sp@-
0x000032b4:  invalid
0x000032b6:  .short 0x0000
0x000032b8:  bchg %d2,%a0@+
0x000032ba:  .short 0x504f
0x000032bc:  .short 0x584f
0x000032be:  tstl %d0
0x000032c0:  bnew 0x00000126
0x000032c2:  movel %d2,%d0
0x000032c4:  moveq #28,%d5
0x000032c6:  asll %d5,%d0
0x000032c8:  invalid
0x000032ca:  .short 0x0000
0x000032cc:  .short 0x801c
0x000032ce:  pea %fp@(-32)
0x000032d0:  movel %fp@(-56),%sp@-
0x000032d2:  invalid
0x000032d4:  .short 0x0000
0x000032d6:  .short 0x2afe
0x000032d8:  .short 0x504f
0x000032da:  tstl %d0
0x000032dc:  bnew 0x00000126
0x000032de:  subal %a2,%a2
0x000032e0:  lea %fp@(-32),%a4
0x000032e2:  invalid
0x000032e4:  .short 0x0000
0x000032e6:  .short 0x8024
0x000032e8:  movel %a2,%d1
0x000032ea:  asll #3,%d1
0x000032ec:  tstl %a4@(0000000000000004,%d1:l)
0x000032ee:  beqs 0x000000c4
0x000032f0:  lea %a2@(0000000000000000,%a2:l:2),%a0
0x000032f2:  movel %a0,%d0
0x000032f4:  asll #2,%d0
0x000032f6:  .short 0x27b4
0x000032f8:  moveb %d0,%d4
0x000032fa:  btst #-76,%d4
0x000032fc:  moveb %d4,%d4
0x000032fe:  .short 0x0808
0x00003300:  movel %a3@(0000000000000008,%d0:l),%sp@-
0x00003302:  movel %a3@(0000000000000004,%d0:l),%sp@-
0x00003304:  invalid
0x00003306:  .short 0x0000
0x00003308:  .short 0x8024
0x0000330a:  movel %d0,%sp@-
0x0000330c:  movel %d4,%sp@-
0x0000330e:  movel %fp@(-60),%sp@-
0x00003310:  movel %d3,%sp@-
0x00003312:  invalid
0x00003314:  .short 0x0000
0x00003316:  .short 0x108a
0x00003318:  .short 0xdefc
0x0000331a:  .short 0x0018
0x0000331c:  tstl %d0
0x0000331e:  bnes 0x00000126
0x00003320:  .short 0x524a
0x00003322:  moveq #3,%d5
0x00003324:  cmpl %a2,%d5
0x00003326:  bges 0x00000080
0x00003328:  invalid
0x0000332a:  btst %d2,%d0
0x0000332c:  movel %a0,0x00000000
0x0000332e:  .short 0x8020
0x00003330:  pea %fp@(-64)
0x00003332:  invalid
0x00003334:  .short 0x04ff
0x00003336:  .short 0xfdfe
0x00003338:  movel %d0,%sp@-
0x0000333a:  invalid
0x0000333c:  .short 0x04ff
0x0000333e:  .short 0xf8ec
0x00003340:  .short 0x504f
0x00003342:  tstl %d0
0x00003344:  bnes 0x00000126
0x00003346:  movel %fp@(-64),%sp@-
0x00003348:  movel %fp@(-56),%sp@-
0x0000334a:  invalid
0x0000334c:  .short 0x0000
0x0000334e:  movel %a2@(20559),%d5
0x00003350:  tstl %d0
0x00003352:  bnes 0x00000126
0x00003354:  movel %fp@(-64),%a5@
0x00003356:  invalid
0x00003358:  .short 0x0000
0x0000335a:  moveaw #18552,%a0
0x0000335c:  .short 0x000a
0x0000335e:  invalid
0x00003360:  btst %d2,%d0
0x00003362:  .short 0x2f7e
0x00003364:  jsr %a2@
0x00003366:  invalid
0x00003368:  .short 0x0000
0x0000336a:  moveaw #18552,%a0
0x0000336c:  .short 0x000b
0x0000336e:  jsr %a2@
0x00003370:  clrl %d0
0x00003372:  invalid
0x00003374:  movew #-96,%d6
0x00003376:  unlk %fp
0x00003378:  rts
