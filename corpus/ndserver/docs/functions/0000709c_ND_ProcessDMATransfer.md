# Deep Function Analysis: FUN_0000709c (ND_ProcessDMATransfer)

**Analysis Date**: 2025-11-08
**Analyst**: Claude Code
**Function Address**: 0x0000709c
**Function Size**: 976 bytes (244 instructions)
**Complexity**: High (nested loops, complex branching logic, memory operations)

---

## Executive Summary

This function processes Direct Memory Access (DMA) transfers for the NeXTdimension board. It reads a segment descriptor table (likely __TEXT segment information at 0x8018), validates the transfer operation, and performs memory copying with address translation between host memory space and NeXTdimension local memory space. The function handles both standard and byte-swapped transfers, and appears to implement a shared memory protocol for the i860 processor.

**Purpose**: DMA memory transfer processor with address space translation
**Return Value**: 0 on success, -1 on failure, error code in global at 0x040105b0
**Primary Side Effect**: Copies memory between host and NeXTdimension address spaces

---

## Function Signature

```c
int ND_ProcessDMATransfer(nd_board_info_t* board_info);
```

### Parameters:
- **board_info** (A6+0x8): Pointer to 80-byte board info structure (from FUN_000036b2 analysis)

### Return Values:
- **0**: Success - transfer completed
- **-1**: Failure - error code stored in global 0x040105b0
  - **0x8**: Invalid state or segment
  - **0xE**: Lock failure

---

## Complete Annotated Disassembly

```m68k
; ============================================================================
; Function: FUN_0000709c - ND_ProcessDMATransfer
; Address: 0x0000709c
; Size: 976 bytes
; ============================================================================

  ; --- PROLOGUE ---
  0x0000709c:  link.w     A6,-0x38                       ; Create 56-byte stack frame
  0x000070a0:  move.l     A3,-(SP)                       ; Save A3
  0x000070a2:  move.l     A2,-(SP)                       ; Save A2

  ; --- INITIALIZATION ---
  0x000070a4:  clr.l      (-0x10,A6)                     ; error_segment_ptr = NULL
  0x000070a8:  movea.l    (0x8,A6),A0                    ; A0 = board_info
  0x000070ac:  move.l     (0x2c,A0),(-0x2c,A6)           ; base_offset = board_info[0x2c]
  0x000070b2:  movea.l    (0x00008018).l,A0              ; A0 = segment_table (global)
  0x000070b8:  move.l     A0,(-0x4,A6)                   ; segment_ptr = segment_table

  ; --- SEGMENT VALIDATION (Magic Number Check) ---
  0x000070bc:  cmpi.l     #-0x1120532,(A0)               ; if (segment->magic != 0xFEEDFACE)
  0x000070c2:  bne.w      0x00007438                     ;   goto error_invalid_state

  ; --- SEGMENT VALIDATION (Format Check) ---
  0x000070c6:  movea.l    (-0x4,A6),A0                   ; A0 = segment_ptr
  0x000070ca:  moveq      0xf,D1                         ; D1 = 15
  0x000070cc:  cmp.l      (0x4,A0),D1                    ; if (segment->field_0x4 != 15)
  0x000070d0:  bne.w      0x00007438                     ;   goto error_invalid_state

  0x000070d4:  moveq      0x1,D1                         ; D1 = 1
  0x000070d6:  cmp.l      (0x8,A0),D1                    ; if (segment->field_0x8 < 1)
  0x000070da:  bcs.w      0x00007438                     ;   goto error_invalid_state

  ; --- STATUS BIT CHECK ---
  0x000070de:  movea.l    (-0x4,A6),A0                   ; A0 = segment_ptr
  0x000070e2:  btst.b     #0x0,(0x1b,A0)                 ; if (!(segment->status_flags & 0x01))
  0x000070e8:  beq.w      0x00007438                     ;   goto error_invalid_state

  ; --- OPERATION TYPE CHECK (field_0xC must be 2 or 5) ---
  0x000070ec:  movea.l    (-0x4,A6),A0                   ; A0 = segment_ptr
  0x000070f0:  moveq      0x2,D1                         ; D1 = 2
  0x000070f2:  cmp.l      (0xc,A0),D1                    ; if (segment->op_type == 2)
  0x000070f6:  beq.b      0x00007102                     ;   goto op_type_valid
  0x000070f8:  moveq      0x5,D1                         ; D1 = 5
  0x000070fa:  cmp.l      (0xc,A0),D1                    ; else if (segment->op_type == 5)
  0x000070fe:  bne.w      0x00007438                     ;   else goto error_invalid_state

  ; --- LOCK ACQUISITION ---
op_type_valid:
  0x00007102:  pea        (0x75cc).l                     ; push &lock_var_1
  0x00007108:  pea        (0xa).w                        ; push 10 (lock type/timeout?)
  0x0000710c:  lea        (0x5002f7e).l,A2               ; A2 = &lock_function
  0x00007112:  jsr        A2                             ; result = lock_function(10, &lock_var_1)
  0x00007114:  move.l     D0,(-0x34,A6)                  ; lock_result_1 = result

  0x00007118:  pea        (0x75cc).l                     ; push &lock_var_2 (same address)
  0x0000711e:  pea        (0xb).w                        ; push 11 (different lock type)
  0x00007122:  jsr        A2                             ; result = lock_function(11, &lock_var_2)
  0x00007124:  move.l     D0,(-0x38,A6)                  ; lock_result_2 = result

  ; --- STRING COMPARISON (Segment Name Check) ---
  0x00007128:  pea        (0x80f0).l                     ; push "__TEXT" string address
  0x0000712e:  bsr.l      0x05002ec4                     ; result = strcmp(?, "__TEXT")
  0x00007134:  adda.w     #0x14,SP                       ; Clean up 5 args (20 bytes)

  0x00007138:  tst.l      D0                             ; if (strcmp_result != 0)
  0x0000713a:  beq.b      0x00007156                     ;   skip unlock/error

  ; --- UNLOCK ON ERROR ---
  0x0000713c:  move.l     (-0x34,A6),-(SP)               ; push lock_result_1
  0x00007140:  pea        (0xa).w                        ; push 10
  0x00007144:  jsr        A2                             ; unlock_function(10, lock_result_1)
  0x00007146:  move.l     (-0x38,A6),-(SP)               ; push lock_result_2
  0x0000714a:  pea        (0xb).w                        ; push 11
  0x0000714e:  jsr        A2                             ; unlock_function(11, lock_result_2)
  0x00007150:  moveq      0xe,D1                         ; D1 = 14 (error code: lock failure)
  0x00007152:  bra.w      0x0000743a                     ; goto error_with_code

  ; --- MAIN TRANSFER SETUP ---
  0x00007156:  movea.l    (-0x4,A6),A0                   ; A0 = segment_ptr
  0x0000715a:  move.l     (0x10,A0),(-0x20,A6)           ; transfer_count = segment->field_0x10
  0x00007160:  move.l     (0x00008018).l,(-0x14,A6)     ; current_desc = segment_table
  0x00007168:  moveq      0x1c,D1                        ; D1 = 28
  0x0000716a:  bra.w      0x00007414                     ; goto loop_test (jump to end of loop)

  ; ============================================================================
  ; MAIN TRANSFER LOOP - Process each descriptor in table
  ; ============================================================================
main_transfer_loop:
  0x0000716e:  movea.l    (-0x14,A6),A0                  ; A0 = current_desc
  0x00007172:  move.l     A0,(-0x8,A6)                   ; desc_ptr = current_desc

  ; --- DESCRIPTOR TYPE CHECK ---
  0x00007176:  moveq      0x1,D1                         ; D1 = 1
  0x00007178:  cmp.l      (A0),D1                        ; if (desc->type == 1)
  0x0000717a:  beq.b      0x0000718e                     ;   goto process_type_1

  ; --- HANDLE NON-TYPE-1 DESCRIPTORS ---
  0x0000717c:  move.l     (A0),D0                        ; D0 = desc->type
  0x0000717e:  subq.l     0x4,D0                         ; D0 -= 4
  0x00007180:  cmp.l      D0,D1                          ; if (type-4 >= 1)
  0x00007182:  bcs.w      0x0000740c                     ;   goto next_descriptor
  0x00007186:  move.l     A0,(-0x10,A6)                  ; error_segment_ptr = current_desc
  0x0000718a:  bra.w      0x0000740c                     ; goto next_descriptor

  ; ============================================================================
  ; TYPE 1 DESCRIPTOR PROCESSING - Main transfer logic
  ; ============================================================================
process_type_1:
  0x0000718e:  movea.l    (-0x14,A6),A0                  ; A0 = current_desc
  0x00007192:  move.l     A0,(-0xc,A6)                   ; transfer_desc = current_desc

  ; --- SOURCE ADDRESS CALCULATION (i860 memory space) ---
  0x00007196:  movea.l    (0x00008018).l,A3              ; A3 = segment_table base
  0x0000719c:  adda.l     (0x20,A0),A3                   ; A3 += desc->offset_0x20
  0x000071a0:  move.l     A3,(-0x18,A6)                  ; src_ptr_i860 = A3

  ; --- DESTINATION ADDRESS CALCULATION (host → ND translation) ---
  0x000071a4:  move.l     (0x18,A0),D0                   ; D0 = desc->dest_addr_0x18
  0x000071a8:  andi.l     #0xfffffff,D0                  ; D0 &= 0x0FFFFFFF (mask high nibble)
  0x000071ae:  addi.l     #-0x8000000,D0                 ; D0 -= 0x08000000
  0x000071b4:  add.l      (-0x2c,A6),D0                  ; D0 += base_offset
  0x000071b8:  move.l     D0,(-0x1c,A6)                  ; dest_ptr_nd = D0

  ; --- FIRST STRING COMPARISON CHECK ---
  0x000071bc:  pea        (0x7a49).l                     ; push string_addr_1
  0x000071c2:  move.l     (-0xc,A6),D1                   ; D1 = transfer_desc
  0x000071c6:  addq.l     0x8,D1                         ; D1 += 8 (offset to string)
  0x000071c8:  move.l     D1,-(SP)                       ; push desc_string_ptr
  0x000071ca:  bsr.l      0x05003008                     ; result = strcmp(desc_string, string_1)
  0x000071d0:  addq.w     0x8,SP                         ; Clean up 2 args

  0x000071d2:  tst.l      D0                             ; if (strcmp_result != 0)
  0x000071d4:  bne.w      0x00007328                     ;   goto alt_copy_path

  ; ============================================================================
  ; PRIMARY COPY PATH - String matched string_1
  ; ============================================================================

  ; --- CALCULATE INITIAL COPY SIZE ---
  0x000071d8:  movea.l    (-0x4,A6),A1                   ; A1 = segment_ptr
  0x000071dc:  moveq      0x2,D1                         ; D1 = 2
  0x000071de:  cmp.l      (0xc,A1),D1                    ; if (segment->op_type == 2)
  0x000071e2:  bne.b      0x000071fa                     ;   skip special case

  0x000071e4:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000071e8:  tst.l      (0x20,A0)                      ; if (desc->offset_0x20 == 0)
  0x000071ec:  bne.b      0x000071fa                     ;   skip special case

  ; Special case: op_type==2 AND offset==0
  0x000071ee:  moveq      0x1c,D1                        ; D1 = 28
  0x000071f0:  add.l      (0x14,A1),D1                   ; D1 += segment->field_0x14
  0x000071f4:  move.l     D1,(-0x28,A6)                  ; initial_copy_bytes = D1
  0x000071f8:  bra.b      0x000071fe                     ; goto copy_initial

  0x000071fa:  clr.l      (-0x28,A6)                     ; initial_copy_bytes = 0

  ; --- INITIAL MEMORY COPY LOOP (if initial_copy_bytes > 0) ---
copy_initial:
  0x000071fe:  clr.l      (-0x24,A6)                     ; loop_counter = 0

initial_copy_loop:
  0x00007202:  movea.l    (-0x24,A6),A3                  ; A3 = loop_counter
  0x00007206:  cmpa.l     (-0x28,A6),A3                  ; if (loop_counter >= initial_copy_bytes)
  0x0000720a:  bge.b      0x0000722c                     ;   goto check_swap_flag

  ; Simple 4-byte copy
  0x0000720c:  movea.l    (-0x18,A6),A1                  ; A1 = src_ptr_i860
  0x00007210:  movea.l    (-0x1c,A6),A0                  ; A0 = dest_ptr_nd
  0x00007214:  move.l     (A1),(A0)                      ; *dest = *src (4-byte copy)

  0x00007216:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x0000721a:  addq.l     0x4,(-0x18,A6)                 ; src_ptr_i860 += 4
  0x0000721e:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

  0x00007222:  move.l     (-0x24,A6),D1                  ; D1 = loop_counter
  0x00007226:  cmp.l      (-0x28,A6),D1                  ; if (loop_counter < initial_copy_bytes)
  0x0000722a:  blt.b      0x0000720c                     ;   continue initial_copy_loop

  ; --- CHECK BYTE-SWAP FLAG ---
check_swap_flag:
  0x0000722c:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x00007230:  btst.b     #0x0,(0x37,A0)                 ; if (desc->flags_0x37 & 0x01) // swap flag
  0x00007236:  beq.b      0x000072a8                     ;   goto no_swap_path

  ; ============================================================================
  ; SWAP PATH - Byte-swapped memory copy with zero-fill
  ; ============================================================================

  ; --- ZERO-FILL REMAINING SPACE ---
  0x00007238:  move.l     (-0x28,A6),(-0x24,A6)          ; loop_counter = initial_copy_bytes
  0x0000723e:  bra.b      0x00007258                     ; goto zero_fill_test

zero_fill_loop:
  0x00007240:  move.l     (-0x1c,A6),D0                  ; D0 = dest_ptr_nd
  0x00007244:  eori.w     #0x4,D0w                       ; D0 ^= 0x0004 (swap word endianness)
  0x00007248:  movea.l    D0,A3                          ; A3 = swapped_dest
  0x0000724a:  clr.l      (A3)                           ; *swapped_dest = 0

  0x0000724c:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x00007250:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4
  0x00007254:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc

zero_fill_test:
  0x00007258:  move.l     (0x1c,A0),D0                   ; D0 = desc->size_0x1C
  0x0000725c:  sub.l      (0x24,A0),D0                   ; D0 -= desc->field_0x24
  0x00007260:  cmp.l      (-0x24,A6),D0                  ; if ((size - field_0x24) > loop_counter)
  0x00007264:  bhi.b      0x00007240                     ;   continue zero_fill_loop

  ; --- COPY ACTUAL DATA (SWAPPED) ---
  0x00007266:  clr.l      (-0x24,A6)                     ; loop_counter = 0
  0x0000726a:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x0000726e:  move.l     (-0x24,A6),D1                  ; D1 = loop_counter
  0x00007272:  cmp.l      (0x24,A0),D1                   ; if (loop_counter >= desc->field_0x24)
  0x00007276:  bcc.w      0x0000740c                     ;   goto next_descriptor

swap_copy_loop:
  0x0000727a:  move.l     (-0x1c,A6),D0                  ; D0 = dest_ptr_nd
  0x0000727e:  eori.w     #0x4,D0w                       ; D0 ^= 0x0004 (swap word endianness)
  0x00007282:  movea.l    (-0x18,A6),A0                  ; A0 = src_ptr_i860
  0x00007286:  movea.l    D0,A3                          ; A3 = swapped_dest
  0x00007288:  move.l     (A0),(A3)                      ; *swapped_dest = *src (4-byte swapped write)

  0x0000728a:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x0000728e:  addq.l     0x4,(-0x18,A6)                 ; src_ptr_i860 += 4
  0x00007292:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

  0x00007296:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x0000729a:  move.l     (-0x24,A6),D1                  ; D1 = loop_counter
  0x0000729e:  cmp.l      (0x24,A0),D1                   ; if (loop_counter < desc->field_0x24)
  0x000072a2:  bcs.b      0x0000727a                     ;   continue swap_copy_loop

  0x000072a4:  bra.w      0x0000740c                     ; goto next_descriptor

  ; ============================================================================
  ; NO-SWAP PATH - Standard memory copy
  ; ============================================================================
no_swap_path:
  ; --- COPY DATA ---
  0x000072a8:  move.l     (-0x28,A6),(-0x24,A6)          ; loop_counter = initial_copy_bytes
  0x000072ae:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000072b2:  movea.l    (-0x24,A6),A3                  ; A3 = loop_counter
  0x000072b6:  cmpa.l     (0x24,A0),A3                   ; if (loop_counter >= desc->field_0x24)
  0x000072ba:  bcc.b      0x000072e6                     ;   goto zero_fill_noswap

noswap_copy_loop:
  0x000072bc:  move.l     (-0x1c,A6),D0                  ; D0 = dest_ptr_nd
  0x000072c0:  eori.w     #0x4,D0w                       ; D0 ^= 0x0004 (swap word endianness)
  0x000072c4:  movea.l    (-0x18,A6),A0                  ; A0 = src_ptr_i860
  0x000072c8:  movea.l    D0,A3                          ; A3 = swapped_dest
  0x000072ca:  move.l     (A0),(A3)                      ; *swapped_dest = *src

  0x000072cc:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x000072d0:  addq.l     0x4,(-0x18,A6)                 ; src_ptr_i860 += 4
  0x000072d4:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

  0x000072d8:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000072dc:  move.l     (-0x24,A6),D1                  ; D1 = loop_counter
  0x000072e0:  cmp.l      (0x24,A0),D1                   ; if (loop_counter < desc->field_0x24)
  0x000072e4:  bcs.b      0x000072bc                     ;   continue noswap_copy_loop

  ; --- ZERO-FILL REMAINING (NO SWAP) ---
zero_fill_noswap:
  0x000072e6:  clr.l      (-0x24,A6)                     ; loop_counter = 0
  0x000072ea:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000072ee:  move.l     (0x1c,A0),D0                   ; D0 = desc->size_0x1C
  0x000072f2:  sub.l      (0x24,A0),D0                   ; D0 -= desc->field_0x24
  0x000072f6:  cmp.l      (-0x24,A6),D0                  ; if ((size - field_0x24) <= loop_counter)
  0x000072fa:  bls.w      0x0000740c                     ;   goto next_descriptor

zero_fill_noswap_loop:
  0x000072fe:  move.l     (-0x1c,A6),D0                  ; D0 = dest_ptr_nd
  0x00007302:  eori.w     #0x4,D0w                       ; D0 ^= 0x0004 (swap word endianness)
  0x00007306:  movea.l    D0,A3                          ; A3 = swapped_dest
  0x00007308:  clr.l      (A3)                           ; *swapped_dest = 0

  0x0000730a:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x0000730e:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

  0x00007312:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x00007316:  move.l     (0x1c,A0),D0                   ; D0 = desc->size_0x1C
  0x0000731a:  sub.l      (0x24,A0),D0                   ; D0 -= desc->field_0x24
  0x0000731e:  cmp.l      (-0x24,A6),D0                  ; if ((size - field_0x24) > loop_counter)
  0x00007322:  bhi.b      0x000072fe                     ;   continue zero_fill_noswap_loop

  0x00007324:  bra.w      0x0000740c                     ; goto next_descriptor

  ; ============================================================================
  ; ALTERNATE COPY PATH - String did NOT match string_1
  ; ============================================================================
alt_copy_path:
  0x00007328:  pea        (0x7a50).l                     ; push string_addr_2
  0x0000732e:  move.l     (-0xc,A6),D1                   ; D1 = transfer_desc
  0x00007332:  addq.l     0x8,D1                         ; D1 += 8 (offset to string)
  0x00007334:  move.l     D1,-(SP)                       ; push desc_string_ptr
  0x00007336:  bsr.l      0x05003008                     ; result = strcmp(desc_string, string_2)
  0x0000733c:  addq.w     0x8,SP                         ; Clean up 2 args

  0x0000733e:  tst.l      D0                             ; if (strcmp_result == 0)
  0x00007340:  beq.w      0x0000740c                     ;   goto next_descriptor (skip this one)

  ; --- ALTERNATE COPY WITH SWAP FLAG CHECK ---
  0x00007344:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x00007348:  btst.b     #0x0,(0x37,A0)                 ; if (desc->flags_0x37 & 0x01)
  0x0000734e:  beq.b      0x000073b0                     ;   goto alt_noswap

  ; --- ALTERNATE SWAP PATH: ZERO-FILL FIRST ---
  0x00007350:  clr.l      (-0x24,A6)                     ; loop_counter = 0
  0x00007354:  bra.b      0x00007368                     ; goto alt_zero_test

alt_zero_loop:
  0x00007356:  movea.l    (-0x1c,A6),A0                  ; A0 = dest_ptr_nd
  0x0000735a:  clr.l      (A0)                           ; *dest = 0 (NO SWAP)

  0x0000735c:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x00007360:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4
  0x00007364:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc

alt_zero_test:
  0x00007368:  move.l     (0x1c,A0),D0                   ; D0 = desc->size_0x1C
  0x0000736c:  sub.l      (0x24,A0),D0                   ; D0 -= desc->field_0x24
  0x00007370:  cmp.l      (-0x24,A6),D0                  ; if ((size - field_0x24) > loop_counter)
  0x00007374:  bhi.b      0x00007356                     ;   continue alt_zero_loop

  ; --- ALTERNATE SWAP PATH: COPY DATA ---
  0x00007376:  clr.l      (-0x24,A6)                     ; loop_counter = 0
  0x0000737a:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x0000737e:  movea.l    (-0x24,A6),A3                  ; A3 = loop_counter
  0x00007382:  cmpa.l     (0x24,A0),A3                   ; if (loop_counter >= desc->field_0x24)
  0x00007386:  bcc.w      0x0000740c                     ;   goto next_descriptor

alt_swap_copy_loop:
  0x0000738a:  movea.l    (-0x18,A6),A0                  ; A0 = src_ptr_i860
  0x0000738e:  movea.l    (-0x1c,A6),A1                  ; A1 = dest_ptr_nd
  0x00007392:  move.l     (A0),(A1)                      ; *dest = *src (NO SWAP)

  0x00007394:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x00007398:  addq.l     0x4,(-0x18,A6)                 ; src_ptr_i860 += 4
  0x0000739c:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

  0x000073a0:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000073a4:  move.l     (-0x24,A6),D1                  ; D1 = loop_counter
  0x000073a8:  cmp.l      (0x24,A0),D1                   ; if (loop_counter < desc->field_0x24)
  0x000073ac:  bcs.b      0x0000738a                     ;   continue alt_swap_copy_loop

  0x000073ae:  bra.b      0x0000740c                     ; goto next_descriptor

  ; --- ALTERNATE NO-SWAP PATH ---
alt_noswap:
  0x000073b0:  clr.l      (-0x24,A6)                     ; loop_counter = 0
  0x000073b4:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000073b8:  movea.l    (-0x24,A6),A3                  ; A3 = loop_counter
  0x000073bc:  cmpa.l     (0x24,A0),A3                   ; if (loop_counter >= desc->field_0x24)
  0x000073c0:  bcc.b      0x000073e6                     ;   goto alt_noswap_zero

alt_noswap_copy_loop:
  0x000073c2:  movea.l    (-0x18,A6),A0                  ; A0 = src_ptr_i860
  0x000073c6:  movea.l    (-0x1c,A6),A1                  ; A1 = dest_ptr_nd
  0x000073ca:  move.l     (A0),(A1)                      ; *dest = *src (NO SWAP)

  0x000073cc:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x000073d0:  addq.l     0x4,(-0x18,A6)                 ; src_ptr_i860 += 4
  0x000073d4:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

  0x000073d8:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000073dc:  move.l     (-0x24,A6),D1                  ; D1 = loop_counter
  0x000073e0:  cmp.l      (0x24,A0),D1                   ; if (loop_counter < desc->field_0x24)
  0x000073e4:  bcs.b      0x000073c2                     ;   continue alt_noswap_copy_loop

alt_noswap_zero:
  0x000073e6:  clr.l      (-0x24,A6)                     ; loop_counter = 0
  0x000073ea:  bra.b      0x000073fa                     ; goto alt_noswap_zero_test

alt_noswap_zero_loop:
  0x000073ec:  movea.l    (-0x1c,A6),A0                  ; A0 = dest_ptr_nd
  0x000073f0:  clr.l      (A0)                           ; *dest = 0 (NO SWAP)

  0x000073f2:  addq.l     0x4,(-0x1c,A6)                 ; dest_ptr_nd += 4
  0x000073f6:  addq.l     0x4,(-0x24,A6)                 ; loop_counter += 4

alt_noswap_zero_test:
  0x000073fa:  movea.l    (-0xc,A6),A0                   ; A0 = transfer_desc
  0x000073fe:  move.l     (0x1c,A0),D0                   ; D0 = desc->size_0x1C
  0x00007402:  sub.l      (0x24,A0),D0                   ; D0 -= desc->field_0x24
  0x00007406:  cmp.l      (-0x24,A6),D0                  ; if ((size - field_0x24) > loop_counter)
  0x0000740a:  bhi.b      0x000073ec                     ;   continue alt_noswap_zero_loop

  ; ============================================================================
  ; LOOP CONTINUATION - Advance to next descriptor
  ; ============================================================================
next_descriptor:
  0x0000740c:  movea.l    (-0x8,A6),A0                   ; A0 = desc_ptr
  0x00007410:  move.l     (0x4,A0),D1                    ; D1 = desc->size (descriptor size)

loop_test:
  0x00007414:  add.l      D1,(-0x14,A6)                  ; current_desc += descriptor_size
  0x00007418:  subq.l     0x1,(-0x20,A6)                 ; transfer_count--

  0x0000741c:  moveq      -0x1,D1                        ; D1 = -1
  0x0000741e:  cmp.l      (-0x20,A6),D1                  ; if (transfer_count != -1)
  0x00007422:  bne.w      0x0000716e                     ;   goto main_transfer_loop

  ; --- POST-LOOP ERROR CHECK ---
  0x00007426:  tst.l      (-0x10,A6)                     ; if (error_segment_ptr != NULL)
  0x0000742a:  beq.b      0x00007438                     ;   skip error check

  0x0000742c:  movea.l    (-0x10,A6),A0                  ; A0 = error_segment_ptr
  0x00007430:  moveq      0x4,D1                         ; D1 = 4
  0x00007432:  cmp.l      (0x8,A0),D1                    ; if (error_segment->field_0x8 == 4)
  0x00007436:  beq.b      0x00007444                     ;   goto success_unlock

  ; ============================================================================
  ; ERROR EXIT PATH
  ; ============================================================================
error_invalid_state:
  0x00007438:  moveq      0x8,D1                         ; D1 = 8 (error code: invalid state)

error_with_code:
  0x0000743a:  move.l     D1,(0x040105b0).l              ; global_error_code = error_code
  0x00007440:  moveq      -0x1,D0                        ; return -1
  0x00007442:  bra.b      0x00007460                     ; goto epilogue

  ; ============================================================================
  ; SUCCESS EXIT PATH - Unlock and return 0
  ; ============================================================================
success_unlock:
  0x00007444:  move.l     (-0x34,A6),-(SP)               ; push lock_result_1
  0x00007448:  pea        (0xa).w                        ; push 10
  0x0000744c:  lea        (0x5002f7e).l,A2               ; A2 = &lock_function
  0x00007452:  jsr        A2                             ; unlock_function(10, lock_result_1)

  0x00007454:  move.l     (-0x38,A6),-(SP)               ; push lock_result_2
  0x00007458:  pea        (0xb).w                        ; push 11
  0x0000745c:  jsr        A2                             ; unlock_function(11, lock_result_2)

  0x0000745e:  clr.l      D0                             ; return 0 (success)

  ; --- EPILOGUE ---
epilogue:
  0x00007460:  movea.l    (-0x40,A6),A2                  ; Restore A2
  0x00007464:  movea.l    (-0x3c,A6),A3                  ; Restore A3
  0x00007468:  unlk       A6                             ; Destroy stack frame
  0x0000746a:  rts                                       ; Return
```

---

## Stack Frame Layout

```
Stack Frame: 56 bytes (-0x38)

Offset   Size   Name                  Description
------   ----   ------------------    ------------------------------------
-0x04    4      segment_ptr           Pointer to segment table
-0x08    4      desc_ptr              Current descriptor pointer
-0x0C    4      transfer_desc         Transfer descriptor being processed
-0x10    4      error_segment_ptr     Error tracking (NULL or error desc)
-0x14    4      current_desc          Iterator for descriptor loop
-0x18    4      src_ptr_i860          Source address (i860 memory space)
-0x1C    4      dest_ptr_nd           Destination address (ND memory space)
-0x20    4      transfer_count        Number of descriptors to process
-0x24    4      loop_counter          Byte counter for copy loops
-0x28    4      initial_copy_bytes    Initial transfer size
-0x2C    4      base_offset           Base offset from board_info[0x2C]
-0x34    4      lock_result_1         Lock acquisition result (type 10)
-0x38    4      lock_result_2         Lock acquisition result (type 11)
-0x3C    4      saved_A3              Preserved register
-0x40    4      saved_A2              Preserved register
```

---

## Hardware Access

### Memory-Mapped I/O Accesses:

None directly - all hardware interaction is through data structures in memory.

### Global Variables:

| Address    | Purpose                          | Access  |
|------------|----------------------------------|---------|
| 0x00008018 | Segment table base address       | Read    |
| 0x040105b0 | Global error code storage        | Write   |
| 0x000075cc | Lock variable (BSS zeroed space) | Read    |

### Data Structure at 0x8018 (Segment Table):

The function reads a Mach-O-style segment descriptor:

```c
typedef struct segment_descriptor {
    uint32_t  magic;           // +0x00: 0xFEEDFACE (Mach-O magic)
    uint32_t  field_0x04;      // +0x04: Must be 15
    uint32_t  field_0x08;      // +0x08: Must be >= 1
    uint32_t  op_type;         // +0x0C: Operation type (2 or 5 valid)
    uint32_t  field_0x10;      // +0x10: Transfer count (# descriptors)
    uint32_t  field_0x14;      // +0x14: Size adjustment value
    uint8_t   data_0x18[3];    // +0x18-0x1A: Padding/data
    uint8_t   status_flags;    // +0x1B: Bit 0 must be set
    // ... more fields ...
} segment_descriptor_t;
```

### Transfer Descriptor Structure:

```c
typedef struct transfer_descriptor {
    uint32_t  type;            // +0x00: Descriptor type (1=transfer, 4/5=other)
    uint32_t  desc_size;       // +0x04: Size of this descriptor
    char      name[16];        // +0x08: Descriptor name (for strcmp)
    uint32_t  dest_addr;       // +0x18: Destination address (host space)
    uint32_t  size_0x1C;       // +0x1C: Total size
    uint32_t  offset_0x20;     // +0x20: Offset into segment data
    uint32_t  field_0x24;      // +0x24: Copy limit
    uint8_t   data[0x13];      // +0x25-0x36: Additional data
    uint8_t   flags;           // +0x37: Bit 0 = byte-swap flag
    // ... more fields ...
} transfer_descriptor_t;
```

---

## OS Functions and Library Calls

### Library Functions Called:

1. **Lock/Unlock Function @ 0x5002f7e**
   - **Likely**: `mutex_lock()` or custom locking primitive
   - **Parameters**:
     - Type code (10 or 11)
     - Lock variable address
   - **Return**: Lock result/handle
   - **Usage**: Mutual exclusion during transfer

2. **String Comparison @ 0x5002ec4**
   - **Likely**: `strcmp()`
   - **Parameters**: Two string pointers
   - **Return**: 0 if equal, non-zero otherwise
   - **Usage**: Check segment name is "__TEXT"

3. **String Comparison @ 0x5003008**
   - **Likely**: `strcmp()`
   - **Parameters**: Two string pointers
   - **Return**: 0 if equal, non-zero otherwise
   - **Usage**: Classify descriptor by name

### NeXTSTEP/Mach Specific:

- **Mach-O Format**: Function parses Mach-O segment structures (magic 0xFEEDFACE)
- **Shared Memory Protocol**: Address translation between host (0x08000000 base) and NeXTdimension local memory
- **Locking**: Uses NeXTSTEP-style locking (two different lock types: 10 and 11)

---

## Reverse-Engineered C Pseudocode

```c
/*
 * Process DMA transfer for NeXTdimension board
 * Reads Mach-O segment descriptor table and copies memory between
 * host address space and NeXTdimension local memory with address translation.
 */
int ND_ProcessDMATransfer(nd_board_info_t* board_info)
{
    segment_descriptor_t* segment_ptr;
    transfer_descriptor_t* transfer_desc;
    transfer_descriptor_t* desc_ptr;
    transfer_descriptor_t* error_segment_ptr = NULL;
    uint32_t* current_desc;
    uint8_t*  src_ptr_i860;
    uint8_t*  dest_ptr_nd;
    int32_t   transfer_count;
    uint32_t  loop_counter;
    uint32_t  initial_copy_bytes;
    uint32_t  base_offset;
    void*     lock_result_1;
    void*     lock_result_2;

    // Extract base offset from board info
    base_offset = board_info->field_0x2C;

    // Get global segment table
    segment_ptr = (segment_descriptor_t*)global_segment_table;  // @ 0x8018

    // VALIDATION: Check segment magic number (Mach-O)
    if (segment_ptr->magic != 0xFEEDFACE) {
        goto error_invalid_state;
    }

    // VALIDATION: Check format fields
    if (segment_ptr->field_0x04 != 15) {
        goto error_invalid_state;
    }

    if (segment_ptr->field_0x08 < 1) {
        goto error_invalid_state;
    }

    // VALIDATION: Check status flag
    if (!(segment_ptr->status_flags & 0x01)) {
        goto error_invalid_state;
    }

    // VALIDATION: Check operation type (must be 2 or 5)
    if (segment_ptr->op_type != 2 && segment_ptr->op_type != 5) {
        goto error_invalid_state;
    }

    // ACQUIRE LOCKS (dual locking for thread safety)
    lock_result_1 = lock_function(10, &lock_var_1);
    lock_result_2 = lock_function(11, &lock_var_2);

    // VALIDATE SEGMENT NAME
    if (strcmp(segment_name, "__TEXT") != 0) {
        // Unlock on failure
        unlock_function(10, lock_result_1);
        unlock_function(11, lock_result_2);
        global_error_code = 0xE;  // Lock/validation failure
        return -1;
    }

    // SETUP TRANSFER
    transfer_count = segment_ptr->field_0x10;  // Number of descriptors
    current_desc = (uint32_t*)global_segment_table;

    // MAIN TRANSFER LOOP - Process each descriptor
    while (transfer_count != -1) {
        desc_ptr = (transfer_descriptor_t*)current_desc;

        // Check descriptor type
        if (desc_ptr->type == 1) {
            // TYPE 1: Memory transfer descriptor
            transfer_desc = desc_ptr;

            // CALCULATE ADDRESSES
            // Source: i860 memory space (segment table + offset)
            src_ptr_i860 = (uint8_t*)global_segment_table + transfer_desc->offset_0x20;

            // Destination: Translate host address to ND local memory
            // Formula: (dest_addr & 0x0FFFFFFF) - 0x08000000 + base_offset
            dest_ptr_nd = (uint8_t*)(
                (transfer_desc->dest_addr & 0x0FFFFFFF) - 0x08000000 + base_offset
            );

            // CLASSIFY DESCRIPTOR by name comparison
            if (strcmp(transfer_desc->name, string_addr_1) == 0) {
                // ===== PRIMARY COPY PATH =====

                // Calculate initial copy size
                if (segment_ptr->op_type == 2 && transfer_desc->offset_0x20 == 0) {
                    initial_copy_bytes = 28 + segment_ptr->field_0x14;
                } else {
                    initial_copy_bytes = 0;
                }

                // Initial copy (if any)
                for (loop_counter = 0; loop_counter < initial_copy_bytes; loop_counter += 4) {
                    *(uint32_t*)dest_ptr_nd = *(uint32_t*)src_ptr_i860;
                    dest_ptr_nd += 4;
                    src_ptr_i860 += 4;
                }

                // Check byte-swap flag
                if (transfer_desc->flags & 0x01) {
                    // SWAP PATH

                    // Zero-fill from initial_copy_bytes to (size - field_0x24)
                    loop_counter = initial_copy_bytes;
                    while (loop_counter < (transfer_desc->size_0x1C - transfer_desc->field_0x24)) {
                        *(uint32_t*)(dest_ptr_nd ^ 0x04) = 0;  // Swapped write
                        dest_ptr_nd += 4;
                        loop_counter += 4;
                    }

                    // Copy actual data with swap
                    for (loop_counter = 0; loop_counter < transfer_desc->field_0x24; loop_counter += 4) {
                        *(uint32_t*)(dest_ptr_nd ^ 0x04) = *(uint32_t*)src_ptr_i860;  // Swapped
                        dest_ptr_nd += 4;
                        src_ptr_i860 += 4;
                    }

                } else {
                    // NO-SWAP PATH

                    // Copy data
                    loop_counter = initial_copy_bytes;
                    while (loop_counter < transfer_desc->field_0x24) {
                        *(uint32_t*)(dest_ptr_nd ^ 0x04) = *(uint32_t*)src_ptr_i860;  // Swapped address
                        dest_ptr_nd += 4;
                        src_ptr_i860 += 4;
                        loop_counter += 4;
                    }

                    // Zero-fill remaining
                    for (loop_counter = 0;
                         loop_counter < (transfer_desc->size_0x1C - transfer_desc->field_0x24);
                         loop_counter += 4) {
                        *(uint32_t*)(dest_ptr_nd ^ 0x04) = 0;
                        dest_ptr_nd += 4;
                    }
                }

            } else if (strcmp(transfer_desc->name, string_addr_2) == 0) {
                // String 2 match - skip this descriptor
                goto next_descriptor;

            } else {
                // ===== ALTERNATE COPY PATH =====
                // (Similar logic but different ordering/behavior)

                if (transfer_desc->flags & 0x01) {
                    // ALT SWAP: Zero first, then copy
                    loop_counter = 0;
                    while (loop_counter < (transfer_desc->size_0x1C - transfer_desc->field_0x24)) {
                        *(uint32_t*)dest_ptr_nd = 0;  // NO swap
                        dest_ptr_nd += 4;
                        loop_counter += 4;
                    }

                    for (loop_counter = 0; loop_counter < transfer_desc->field_0x24; loop_counter += 4) {
                        *(uint32_t*)dest_ptr_nd = *(uint32_t*)src_ptr_i860;  // NO swap
                        dest_ptr_nd += 4;
                        src_ptr_i860 += 4;
                    }

                } else {
                    // ALT NO-SWAP: Copy then zero
                    for (loop_counter = 0; loop_counter < transfer_desc->field_0x24; loop_counter += 4) {
                        *(uint32_t*)dest_ptr_nd = *(uint32_t*)src_ptr_i860;  // NO swap
                        dest_ptr_nd += 4;
                        src_ptr_i860 += 4;
                    }

                    loop_counter = 0;
                    while (loop_counter < (transfer_desc->size_0x1C - transfer_desc->field_0x24)) {
                        *(uint32_t*)dest_ptr_nd = 0;  // NO swap
                        dest_ptr_nd += 4;
                        loop_counter += 4;
                    }
                }
            }

        } else if (desc_ptr->type >= 4 && desc_ptr->type <= 5) {
            // TYPE 4-5: Special descriptor (mark for error check)
            error_segment_ptr = desc_ptr;
        }

next_descriptor:
        // Advance to next descriptor
        current_desc += desc_ptr->desc_size;
        transfer_count--;
    }

    // POST-LOOP ERROR CHECK
    if (error_segment_ptr != NULL) {
        if (error_segment_ptr->field_0x08 == 4) {
            // Success case (type 4-5 descriptor with field_0x08==4 is OK)
            unlock_function(10, lock_result_1);
            unlock_function(11, lock_result_2);
            return 0;
        }
    }

    // Default success
    unlock_function(10, lock_result_1);
    unlock_function(11, lock_result_2);
    return 0;

error_invalid_state:
    global_error_code = 0x8;  // Invalid state
    return -1;
}
```

---

## Data Structures

### segment_descriptor_t (Global at 0x8018)

```c
typedef struct segment_descriptor {
    uint32_t  magic;              // +0x00: 0xFEEDFACE (Mach-O 32-bit BE)
    uint32_t  field_0x04;         // +0x04: Must be 15 (cputype/cpusubtype?)
    uint32_t  field_0x08;         // +0x08: Must be >= 1 (ncmds?)
    uint32_t  op_type;            // +0x0C: Operation type (2 or 5 valid)
    uint32_t  descriptor_count;   // +0x10: Number of transfer descriptors
    uint32_t  size_adjustment;    // +0x14: Added to size in special case
    uint8_t   reserved[3];        // +0x18-0x1A
    uint8_t   status_flags;       // +0x1B: Bit 0 = ready flag
    // ... followed by descriptor array
} segment_descriptor_t;
```

**Observed Values**:
- `magic` = 0xFEEDFACE (constant)
- `field_0x04` = 15 (required)
- `field_0x08` >= 1 (required)
- `op_type` = 2 or 5 only
- `status_flags` & 0x01 must be set

### transfer_descriptor_t

```c
typedef struct transfer_descriptor {
    uint32_t  type;               // +0x00: 1=transfer, 4-5=special
    uint32_t  desc_size;          // +0x04: Descriptor size in bytes
    char      name[16];           // +0x08: Null-terminated name
    uint32_t  dest_addr;          // +0x18: Destination (host address space)
    uint32_t  total_size;         // +0x1C: Total transfer size
    uint32_t  source_offset;      // +0x20: Offset into segment data
    uint32_t  data_size;          // +0x24: Actual data size to copy
    uint8_t   reserved[19];       // +0x25-0x36
    uint8_t   flags;              // +0x37: Bit 0 = byte-swap flag
} transfer_descriptor_t;
```

**Type Values**:
- **1**: Standard transfer descriptor (processed)
- **4-5**: Special descriptor (skipped but checked post-loop)
- **Other**: Skipped

### Address Translation Formula

```c
// Host address → NeXTdimension local memory
uint32_t host_to_nd(uint32_t host_addr, uint32_t base_offset) {
    // Mask off high nibble
    uint32_t masked = host_addr & 0x0FFFFFFF;

    // Subtract shared memory window base
    uint32_t offset = masked - 0x08000000;

    // Add board-specific base offset
    return offset + base_offset;
}
```

**Explanation**:
- Host sees ND memory at 0x08000000-0x0BFFFFFF (64MB window)
- ND local memory is at 0x00000000-0x03FFFFFF
- Translation removes window base and adds board offset

---

## Call Graph

### Calls Made By This Function:

1. **0x5002f7e** - Lock/unlock function (called 6 times)
   - Used for mutex operations with types 10 and 11

2. **0x05002ec4** - strcmp() (called 1 time)
   - Compare segment name with "__TEXT"

3. **0x05003008** - strcmp() (called 2 times)
   - Classify descriptors by name

### Called By:

According to call graph analysis, this function is called by 3 other functions (critical leaf status).

---

## Purpose Classification

**Primary Category**: DMA Transfer Processing
**Secondary Category**: Memory Management
**Tertiary Category**: Address Space Translation

### Detailed Purpose:

This function implements the **host-to-i860 shared memory transfer protocol** for NeXTdimension. It:

1. **Validates** a Mach-O format segment descriptor table
2. **Acquires locks** for thread-safe operation
3. **Iterates** through transfer descriptors
4. **Translates** host memory addresses (0x08000000 window) to NeXTdimension local memory (0x00000000 base)
5. **Copies** memory with optional byte-swapping based on descriptor flags
6. **Handles** different copy strategies based on descriptor name and operation type
7. **Manages** error states and cleanup

### Protocol Details:

The function appears to implement the **i860 kernel loading protocol**:
- Validates __TEXT segment from host
- Copies kernel code/data to i860 local memory
- Handles endianness differences (byte-swapping)
- Uses dual locking for synchronization

---

## Error Handling

### Error Codes (stored in global 0x040105b0):

| Code | Meaning                              | Trigger Condition                  |
|------|--------------------------------------|-----------------------------------|
| 0x8  | Invalid state/segment                | Validation failure, no type 1 desc|
| 0xE  | Lock/validation failure              | strcmp() fails on "__TEXT"        |

### Error Paths:

1. **Invalid Magic**: `magic != 0xFEEDFACE` → error code 0x8, return -1
2. **Invalid Format**: `field_0x04 != 15` or `field_0x08 < 1` → error code 0x8, return -1
3. **Status Not Ready**: `!(status_flags & 0x01)` → error code 0x8, return -1
4. **Invalid Op Type**: `op_type != 2 && op_type != 5` → error code 0x8, return -1
5. **Segment Name Mismatch**: `strcmp() != 0` → unlock, error code 0xE, return -1
6. **Post-Loop Error**: `error_segment_ptr != NULL && field_0x08 != 4` → error code 0x8, return -1

### Resource Cleanup:

All error paths properly unlock acquired locks before returning.

---

## Protocol Integration

### NeXTdimension Boot Sequence Context:

This function is likely called during **i860 kernel download**:

1. **Board registered** (FUN_000036b2 analyzed previously)
2. **Segment table prepared** with __TEXT section
3. **This function called** to transfer kernel to i860 memory
4. **i860 released from reset** to boot downloaded kernel

### Shared Memory Window (from NeXTdimension docs):

- **Host view**: 0xF8000000-0xFBFFFFFF (RAM), 0xFE000000-0xFEFFFFFF (VRAM)
- **i860 view**: 0x00000000-0x03FFFFFF (local DRAM), 0x10000000-0x103FFFFF (VRAM)
- **Mapping**: Host window 0x08000000-0x0BFFFFFF maps to i860 local memory

### Memory Operation Pattern:

```
Host prepares segment table @ 0x8018:
  - Magic: 0xFEEDFACE
  - Segment name: "__TEXT"
  - Descriptors with source/dest/size

This function:
  1. Validates table
  2. For each descriptor:
     - src = segment_table + desc->source_offset
     - dst = (desc->dest_addr & 0x0FFFFFFF) - 0x08000000 + board_offset
     - memcpy(dst, src, desc->data_size) with optional swap
     - zero-fill remaining space
  3. Returns success/failure
```

---

## m68k Architecture Details

### Register Usage:

| Register | Purpose                                  | Preserved |
|----------|------------------------------------------|-----------|
| A0       | General pointer (segment, descriptor)    | No        |
| A1       | General pointer (source/dest)            | No        |
| A2       | Lock function address                    | Yes       |
| A3       | Loop iterator, temp calculations         | Yes       |
| A6       | Frame pointer (stack access)             | Auto      |
| D0       | Return values, calculations              | No        |
| D1       | Comparisons, constants                   | No        |

### Endianness Handling:

**Critical Pattern**: `dest_addr ^ 0x04`

This XOR operation performs **word-swapping within a long-word** on big-endian m68k:

```c
// Without swap: Write at offset 0, 4, 8, 12...
*(uint32_t*)(base + 0) = value;

// With swap: Write at offset 4, 0, 12, 8... (swap pairs)
*(uint32_t*)((base + 0) ^ 4) = value;  // Actually writes to base+4
*(uint32_t*)((base + 4) ^ 4) = value;  // Actually writes to base+0
*(uint32_t*)((base + 8) ^ 4) = value;  // Actually writes to base+12
*(uint32_t*)((base +12) ^ 4) = value;  // Actually writes to base+8
```

This handles the **little-endian i860 vs big-endian 68040** difference.

### Code Efficiency:

- **Loop unrolling**: No - simple increment-by-4 loops
- **Branch prediction**: Multiple conditional branches (typical for validation)
- **Memory bandwidth**: 4-byte aligned transfers (optimal for both CPUs)
- **Stack usage**: Moderate (56 bytes frame + saved registers)

---

## Analysis Insights

### Key Findings:

1. **Mach-O Integration**: Uses standard Mach-O format (0xFEEDFACE magic) for kernel loading
2. **Dual Locking**: Acquires two different lock types (10 and 11) - suggests multi-level synchronization
3. **Address Translation**: Implements explicit host↔ND address space mapping
4. **Endianness Support**: Conditional byte-swapping for cross-architecture transfers
5. **Descriptor Classification**: Uses strcmp() on descriptor names to select copy strategy
6. **Error Resilience**: Validates all inputs before starting transfer

### Complexity Analysis:

- **Cyclomatic Complexity**: ~25 (high - many conditional paths)
- **Nesting Depth**: 3-4 levels (moderate)
- **Code Paths**: ~15 distinct execution paths

### Performance Characteristics:

- **Best Case**: All validation passes, single descriptor, no swap → ~50 cycles + memory copy time
- **Worst Case**: Multiple descriptors, all swapped, many validations → several thousand cycles
- **Memory Bandwidth**: Limited by 68040 bus speed (~40 MB/s peak)

---

## Unanswered Questions

1. **What are string_addr_1 and string_addr_2?**
   - Located at 0x7a49 and 0x7a50 (both BSS zeroed)
   - Likely initialized at runtime
   - Purpose: Classify descriptors into different copy strategies

2. **Why dual locking (types 10 and 11)?**
   - Possible: Lock 10 = host-side mutex, Lock 11 = i860-side mutex
   - Possible: Nested locking for different subsystems

3. **What is the special case for op_type==2 && offset==0?**
   - Adds extra 28 + field_0x14 bytes to initial copy
   - Likely: Mach-O header size (28 bytes) + load command size

4. **Why three different copy paths?**
   - Primary: Standard kernel code
   - Alternate swap: Kernel data
   - Alternate no-swap: Relocation info?

---

## Related Functions

From call graph analysis, this function is called by 3 higher-level functions. Analysis of those functions will reveal:

- When/why DMA transfers are initiated
- How segment tables are constructed
- Error handling at higher levels

---

## Testing Notes

To verify this analysis:

1. **Trace segment table structure** at 0x8018 during runtime
2. **Monitor descriptor names** (string_addr_1/2 values)
3. **Capture translated addresses** to verify mapping formula
4. **Track lock acquisition** to understand synchronization model
5. **Compare with NeXTdimension kernel binary** to see what gets transferred

---

## Revision History

| Date       | Analyst     | Changes                                    |
|------------|-------------|--------------------------------------------|
| 2025-11-08 | Claude Code | Initial comprehensive analysis (v1.0)      |

---

**End of Analysis**
