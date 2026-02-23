# Deep Function Analysis: FUN_000033b4 (ND_MemoryTransferDispatcher)

**Analysis Date**: November 8, 2025
**Analyst**: Claude (Manual Reverse Engineering)
**Function Address**: `0x000033b4`
**Size**: 608 bytes (178 lines of assembly)
**Classification**: **Memory Transfer Dispatcher / DMA Handler**
**Confidence**: **HIGH**

---

## Executive Summary

This function implements a **sophisticated memory transfer dispatcher** that handles DMA (Direct Memory Address) operations between the host NeXTstation and the NeXTdimension i860 board. It acts as a command router that processes three distinct message types (0x7c2, 0x7c3, 0x7c4), performs host-to-i860 address translation via a multi-region lookup table, and executes memory transfers through an indirect function call mechanism.

**Key Characteristics**:
- **Multi-path dispatcher**: Routes 3 different memory transfer command types
- **Address translation**: Converts host addresses to i860 memory space using 4-region table
- **Batch processing**: Loops over transfer descriptor arrays (up to 32 entries)
- **Error handling**: Validates descriptor counts and returns specific error codes
- **Indirect execution**: Calls transfer function via global function pointer (0x8020)

**Likely Role**: This is a **critical DMA coordinator** that sits between the message dispatcher and the actual memory transfer engine, handling the complexity of address space translation for i860 board communication.

---

## Function Signature

### Reverse-Engineered C Prototype

```c
int ND_MemoryTransferDispatcher(
    nd_transfer_request_t *request,    // Transfer request structure (arg1 @ 8(A6))
    nd_transfer_result_t *result       // Result/status structure (arg2 @ 12(A6))
);
```

### Parameter Details

| Parameter | Location | Type | Description |
|-----------|----------|------|-------------|
| `request` | `8(A6)` | `nd_transfer_request_t *` | Pointer to transfer request containing message type, descriptor count, and descriptor array |
| `result` | `12(A6)` | `nd_transfer_result_t *` | Pointer to result structure for status codes and return values |

### Return Value (D0)

| Value | Meaning | Condition |
|-------|---------|-----------|
| `0` | Error/failure | Descriptor count validation failed or address translation failed |
| `1` | Success | Transfer completed successfully or early exit path taken |

**Note**: The function uses a dual return mechanism - D0 for boolean success/failure, and `result->field_0x1C` for detailed error codes.

---

## Stack Frame Layout

```
        High Memory
        ┌──────────────────┐
  +0x10 │   (unused)       │
        ├──────────────────┤
  +0x0C │   arg2: result   │  ← Parameter 2 (result structure pointer)
        ├──────────────────┤
  +0x08 │   arg1: request  │  ← Parameter 1 (request structure pointer)
        ├──────────────────┤
  +0x04 │   Return Address │
        ├──────────────────┤
A6 → +0x00 │   Saved A6       │  ← Frame Pointer
        ├──────────────────┤
  -0x04 │   local_success  │  ← Local variable: success flag
        ├──────────────────┤
  -0x08 │   local_i860_addr│  ← Local variable: translated i860 address (case 0x7c3)
        ├──────────────────┤
  -0x0C │   local_i860_addr│  ← Local variable: translated i860 address (case 0x7c2)
        ├──────────────────┤
  -0x10 │   loop_index     │  ← Local variable: descriptor loop counter
        ├──────────────────┤
SP →    │   Saved Regs     │  ← Saved A3, A2, D2
        │   (A3, A2, D2)   │
        └──────────────────┘
        Low Memory
```

**Stack Frame Size**: 16 bytes (0x10)
**Saved Registers**: D2, A2, A3 (callee-save)

---

## Complete Annotated Disassembly

```asm
; ====================================================================================
; FUNCTION: ND_MemoryTransferDispatcher
; ====================================================================================
; Address: 0x000033b4
; Size: 608 bytes
; Purpose: Dispatch memory transfer operations with host-to-i860 address translation
;
; This function handles three types of memory transfer commands:
;   - 0x7c2 (1986): DMA transfer with source address translation
;   - 0x7c3 (1987): DMA transfer with destination address translation
;   - 0x7c4 (1988): Invalid/unsupported command (returns error -305)
;
; The function performs critical address translation from host memory space to
; i860 local memory space using a 4-region lookup table at 0x8024.
; ====================================================================================

FUN_000033b4:
  ; ─────────────────────────────────────────────────────────────
  ; PROLOGUE - Standard function entry
  ; ─────────────────────────────────────────────────────────────
  0x000033b4:  link.w     A6,-0x10                      ; Create 16-byte stack frame
  0x000033b8:  movem.l    {A3 A2 D2},SP                 ; Save callee-save registers

  ; ─────────────────────────────────────────────────────────────
  ; INITIALIZATION - Copy 424 bytes to result structure
  ; ─────────────────────────────────────────────────────────────
  ; This appears to initialize or copy a template/default state
  0x000033bc:  pea        (0x1a8).w                     ; Push size: 424 bytes (0x1a8)
  0x000033c0:  move.l     (0xc,A6),-(SP)                ; Push arg2: result pointer (dest)
  0x000033c4:  move.l     (0x8,A6),-(SP)                ; Push arg1: request pointer (src)
  0x000033c8:  bsr.l      0x050021c8                    ; CALL memcpy(request, result, 424)
  0x000033ce:  addq.w     0x8,SP                        ; Clean stack (2 pointers)

  ; ─────────────────────────────────────────────────────────────
  ; CRITICAL CHECK - Test global flag at 0x8054
  ; ─────────────────────────────────────────────────────────────
  ; This appears to be a "board initialized" or "DMA enabled" flag
  0x000033d0:  move.l     #0x8054,(SP)                  ; Push address of global flag
  0x000033d6:  bsr.l      0x050020de                    ; CALL function (possibly pthread_mutex_trylock?)
  0x000033dc:  addq.w     0x4,SP                        ; Clean stack
  0x000033de:  tst.l      D0                            ; Test return value
  0x000033e0:  beq.b      .continue_processing          ; Branch if zero (flag clear = proceed)

  ; ─────────────────────────────────────────────────────────────
  ; EARLY EXIT PATH - Board not ready or locked
  ; ─────────────────────────────────────────────────────────────
.early_exit_board_busy:
  0x000033e2:  movea.l    (0xc,A6),A0                   ; A0 = result pointer
  0x000033e6:  moveq      0x1,D2                        ; D2 = 1
  0x000033e8:  move.l     D2,(0x1c,A0)                  ; result->field_0x1C = 1 (error code)
  0x000033ec:  move.l     (0x00007a5c).l,(0x18,A0)      ; result->field_0x18 = constant at 0x7a5c
  0x000033f4:  moveq      0x1,D0                        ; Return 1 (indicating handled but failed)
  0x000033f6:  bra.w      .epilogue                     ; Jump to exit

  ; ─────────────────────────────────────────────────────────────
  ; MAIN PROCESSING - Set "DMA in progress" flag
  ; ─────────────────────────────────────────────────────────────
.continue_processing:
  0x000033fa:  moveq      0x1,D2                        ; D2 = 1
  0x000033fc:  move.l     D2,(0x0000800c).l             ; Set global flag: DMA_in_progress = 1

  ; ─────────────────────────────────────────────────────────────
  ; MESSAGE TYPE DISPATCH - Read message type from request
  ; ─────────────────────────────────────────────────────────────
  0x00003402:  movea.l    (0x8,A6),A0                   ; A0 = request pointer
  0x00003406:  move.l     (0x14,A0),D0                  ; D0 = request->message_type (offset 0x14)

  ; Multi-way comparison for message types
  0x0000340a:  cmpi.l     #0x7c3,D0                     ; Is it type 0x7c3 (1987)?
  0x00003410:  beq.w      .case_0x7c3                   ; Branch to case 0x7c3 handler
  0x00003414:  bgt.b      .check_higher                 ; If > 0x7c3, check for 0x7c4
  0x00003416:  cmpi.l     #0x7c2,D0                     ; Is it type 0x7c2 (1986)?
  0x0000341c:  beq.b      .case_0x7c2                   ; Branch to case 0x7c2 handler
  0x0000341e:  bra.w      .case_default                 ; Unknown type - default handler

.check_higher:
  0x00003422:  cmpi.l     #0x7c4,D0                     ; Is it type 0x7c4 (1988)?
  0x00003428:  beq.w      .case_0x7c4                   ; Branch to case 0x7c4 (error case)
  0x0000342c:  bra.w      .case_default                 ; Unknown type - default handler

  ; ═════════════════════════════════════════════════════════════
  ; CASE 0x7c2: DMA Transfer with SOURCE Address Translation
  ; ═════════════════════════════════════════════════════════════
  ; This case handles transfers where the SOURCE address needs
  ; translation from host space to i860 space
  ; ═════════════════════════════════════════════════════════════
.case_0x7c2:
  ; ─────────────────────────────────────────────────────────────
  ; VALIDATE: Check descriptor count <= 32
  ; ─────────────────────────────────────────────────────────────
  0x00003430:  movea.l    (0x8,A6),A0                   ; A0 = request
  0x00003434:  moveq      0x20,D2                       ; D2 = 32 (max descriptors)
  0x00003436:  cmp.l      (0x24,A0),D2                  ; Compare count vs 32
  0x0000343a:  bge.b      .validate_ok_7c2              ; Branch if count <= 32 (valid)

  ; ERROR: Too many descriptors
.error_too_many_descriptors:
  0x0000343c:  movea.l    (0xc,A6),A0                   ; A0 = result
  0x00003440:  moveq      0x4,D2                        ; D2 = 4
  0x00003442:  move.l     D2,(0x1c,A0)                  ; result->error_code = 4
  0x00003446:  bra.w      .success_exit                 ; Jump to success path (sets flag & exits)

  ; ─────────────────────────────────────────────────────────────
  ; DESCRIPTOR LOOP SETUP - Case 0x7c2
  ; ─────────────────────────────────────────────────────────────
.validate_ok_7c2:
  0x0000344a:  movea.l    (0xc,A6),A0                   ; A0 = result
  0x0000344e:  clr.l      (0x1c,A0)                     ; result->error_code = 0 (clear error)
  0x00003452:  clr.l      (-0x10,A6)                    ; loop_index = 0

  0x00003456:  movea.l    (0x8,A6),A0                   ; A0 = request
  0x0000345a:  movea.l    A0,A1                         ; A1 = request (backup)

  ; ─────────────────────────────────────────────────────────────
  ; LOOP: Process each descriptor (0x7c2 case)
  ; ─────────────────────────────────────────────────────────────
.loop_descriptors_7c2:
  0x0000345c:  movea.l    (-0x10,A6),A3                 ; A3 = loop_index
  0x00003460:  cmpa.l     (0x24,A0),A3                  ; Compare index vs descriptor_count
  0x00003464:  bge.w      .success_exit                 ; Exit if index >= count (loop done)

.loop_body_7c2:
  0x00003468:  lea        (0x8024).l,A2                 ; A2 = &address_translation_table

  ; ─────────────────────────────────────────────────────────────
  ; Calculate descriptor offset: index * 12 (3 longs per descriptor)
  ; Descriptor structure appears to be:
  ;   struct {
  ;       uint32_t field_0;     // offset +0x28
  ;       uint32_t source_addr; // offset +0x2C  ← We translate this
  ;       uint32_t field_2;     // offset +0x30
  ;   }
  ; ─────────────────────────────────────────────────────────────
  0x0000346e:  move.l     (-0x10,A6),D0                 ; D0 = loop_index
  0x00003472:  add.l      D0,D0                         ; D0 = index * 2
  0x00003474:  add.l      (-0x10,A6),D0                 ; D0 = index * 3
  0x00003478:  movea.l    (0x2c,A1,D0*0x4),A0           ; A0 = request->descriptors[i].source_addr
                                                        ; (offset 0x2C + index*12)

  ; ─────────────────────────────────────────────────────────────
  ; ADDRESS TRANSLATION LOOP - Find which memory region
  ; ─────────────────────────────────────────────────────────────
  ; The table at 0x8024 has 4 regions, each with 3 values:
  ;   struct region {
  ;       uint32_t base;         // +0x00
  ;       uint32_t offset;       // +0x04
  ;       uint32_t size;         // +0x08
  ;   } regions[4];
  ;
  ; Total table size: 4 regions * 12 bytes = 48 bytes
  ; ─────────────────────────────────────────────────────────────
  0x0000347c:  suba.l     A1,A1                         ; A1 = 0 (region_index)

.find_region_loop:
  0x0000347e:  lea        (0x0,A1,A1*0x2),A3            ; A3 = region_index * 3
  0x00003482:  move.l     A3,D0                         ; D0 = index * 3
  0x00003484:  asl.l      #0x2,D0                       ; D0 = index * 12 (region struct size)

  ; Check if address is in this region
  0x00003486:  move.l     A0,D1                         ; D1 = source_address
  0x00003488:  sub.l      (0x4,A2,D0*0x1),D1            ; D1 = addr - region[i].offset
  0x0000348c:  cmp.l      (0x8,A2,D0*0x1),D1            ; Compare (addr - offset) vs region[i].size
  0x00003490:  bcs.b      .region_found                 ; Branch if within range (carry set = less than)

  ; Try next region
  0x00003492:  addq.w     0x1,A1                        ; region_index++
  0x00003494:  moveq      0x3,D2                        ; D2 = 3 (max 4 regions, 0-3)
  0x00003496:  cmp.l      A1,D2                         ; Compare region_index vs 3
  0x00003498:  bge.b      .find_region_loop             ; Loop if region_index <= 3

  ; ─────────────────────────────────────────────────────────────
  ; NO REGION FOUND - Address not translatable
  ; ─────────────────────────────────────────────────────────────
.address_not_found:
  0x0000349a:  clr.l      (-0xc,A6)                     ; local_i860_addr = 0 (NULL)
  0x0000349e:  tst.l      (-0xc,A6)                     ; Test if NULL
  0x000034a2:  bne.b      .call_transfer_function       ; Branch if not NULL (shouldn't happen)
  0x000034a4:  bra.w      .translation_failed_error     ; Error: translation failed

  ; ─────────────────────────────────────────────────────────────
  ; REGION FOUND - Calculate i860 address
  ; ─────────────────────────────────────────────────────────────
.region_found:
  ; Formula: i860_addr = region[i].base + (host_addr - region[i].offset)
  0x000034a8:  add.l      (0x0,A2,D0*0x1),D1            ; D1 += region[i].base
  0x000034ac:  move.l     D1,(-0xc,A6)                  ; local_i860_addr = translated address
  0x000034b0:  bra.b      0x0000349e                    ; Check if valid (will always be != 0)

  ; ─────────────────────────────────────────────────────────────
  ; CALL TRANSFER FUNCTION - Execute DMA via function pointer
  ; ─────────────────────────────────────────────────────────────
.call_transfer_function:
  ; Recalculate descriptor offset
  0x000034b2:  move.l     (-0x10,A6),D0                 ; D0 = loop_index
  0x000034b6:  add.l      D0,D0                         ; D0 = index * 2
  0x000034b8:  add.l      (-0x10,A6),D0                 ; D0 = index * 3
  0x000034bc:  asl.l      #0x2,D0                       ; D0 = index * 12

  0x000034be:  movea.l    (0x8,A6),A0                   ; A0 = request

  ; Push 3 arguments for transfer function
  0x000034c2:  move.l     (0x30,A0,D0*0x1),-(SP)        ; Push arg3: descriptor[i].field_2
  0x000034c6:  move.l     (-0xc,A6),-(SP)               ; Push arg2: i860_address (TRANSLATED)
  0x000034ca:  move.l     (0x28,A0,D0*0x1),-(SP)        ; Push arg1: descriptor[i].field_0

  ; Call via function pointer
  0x000034ce:  movea.l    (0x00008020).l,A0             ; A0 = global_transfer_function
  0x000034d4:  jsr        A0                            ; CALL transfer_func(field_0, i860_addr, field_2)

  0x000034d6:  addq.w     0x8,SP                        ; Clean stack (2 args)
  0x000034d8:  addq.w     0x4,SP                        ; Clean stack (1 arg)

  ; ─────────────────────────────────────────────────────────────
  ; LOOP INCREMENT
  ; ─────────────────────────────────────────────────────────────
  0x000034da:  addq.l     0x1,(-0x10,A6)                ; loop_index++
  0x000034de:  movea.l    (0x8,A6),A1                   ; A1 = request
  0x000034e2:  movea.l    (-0x10,A6),A3                 ; A3 = loop_index
  0x000034e6:  cmpa.l     (0x24,A1),A3                  ; Compare index vs count
  0x000034ea:  blt.b      .loop_body_7c2                ; Continue loop if index < count
  0x000034ec:  bra.w      .success_exit                 ; All descriptors processed

  ; ═════════════════════════════════════════════════════════════
  ; CASE 0x7c3: DMA Transfer with DESTINATION Address Translation
  ; ═════════════════════════════════════════════════════════════
  ; Almost identical to 0x7c2, but translates DESTINATION instead
  ; of SOURCE address
  ; ═════════════════════════════════════════════════════════════
.case_0x7c3:
  ; ─────────────────────────────────────────────────────────────
  ; VALIDATE: Check descriptor count < 32 (note: < not <=)
  ; ─────────────────────────────────────────────────────────────
  0x000034f0:  movea.l    (0x8,A6),A0                   ; A0 = request
  0x000034f4:  moveq      0x20,D2                       ; D2 = 32
  0x000034f6:  cmp.l      (0x24,A0),D2                  ; Compare 32 vs count
  0x000034fa:  blt.w      .error_too_many_descriptors   ; Error if count >= 32

  ; ─────────────────────────────────────────────────────────────
  ; DESCRIPTOR LOOP SETUP - Case 0x7c3
  ; ─────────────────────────────────────────────────────────────
  0x000034fe:  movea.l    (0xc,A6),A0                   ; A0 = result
  0x00003502:  clr.l      (0x1c,A0)                     ; result->error_code = 0
  0x00003506:  clr.l      (-0x10,A6)                    ; loop_index = 0

  0x0000350a:  movea.l    (0x8,A6),A0                   ; A0 = request
  0x0000350e:  movea.l    A0,A1                         ; A1 = request (backup)

  ; ─────────────────────────────────────────────────────────────
  ; LOOP: Process each descriptor (0x7c3 case)
  ; ─────────────────────────────────────────────────────────────
.loop_descriptors_7c3:
  0x00003510:  movea.l    (-0x10,A6),A3                 ; A3 = loop_index
  0x00003514:  cmpa.l     (0x24,A0),A3                  ; Compare index vs count
  0x00003518:  bge.w      .success_exit                 ; Exit if index >= count

.loop_body_7c3:
  0x0000351c:  lea        (0x8024).l,A2                 ; A2 = &address_translation_table

  ; Calculate descriptor offset (same as 0x7c2)
  0x00003522:  move.l     (-0x10,A6),D0                 ; D0 = loop_index
  0x00003526:  add.l      D0,D0                         ; D0 = index * 2
  0x00003528:  add.l      (-0x10,A6),D0                 ; D0 = index * 3

  ; ─────────────────────────────────────────────────────────────
  ; PRE-PROCESSING: Call helper function
  ; ─────────────────────────────────────────────────────────────
  ; This appears to validate or prepare the descriptor
  0x0000352c:  move.l     (0x28,A1,D0*0x4),-(SP)        ; Push descriptor[i].field_0
  0x00003530:  bsr.l      0x000030c2                     ; CALL FUN_000030c2 (helper/validator)

  ; Get destination address to translate
  0x00003536:  move.l     (-0x10,A6),D0                 ; D0 = loop_index
  0x0000353a:  add.l      D0,D0                         ; D0 = index * 2
  0x0000353c:  add.l      (-0x10,A6),D0                 ; D0 = index * 3
  0x00003540:  movea.l    (0x8,A6),A0                   ; A0 = request
  0x00003544:  movea.l    (0x2c,A0,D0*0x4),A1           ; A1 = descriptor[i].dest_addr (offset 0x2C)
  0x00003548:  addq.w     0x4,SP                        ; Clean stack

  ; ─────────────────────────────────────────────────────────────
  ; ADDRESS TRANSLATION LOOP - Same as 0x7c2 case
  ; ─────────────────────────────────────────────────────────────
  0x0000354a:  suba.l     A0,A0                         ; A0 = 0 (region_index)

.find_region_loop_7c3:
  0x0000354c:  lea        (0x0,A0,A0*0x2),A3            ; A3 = region_index * 3
  0x00003550:  move.l     A3,D0                         ; D0 = index * 3
  0x00003552:  asl.l      #0x2,D0                       ; D0 = index * 12

  ; Check if address in this region
  0x00003554:  move.l     A1,D1                         ; D1 = dest_address
  0x00003556:  sub.l      (0x4,A2,D0*0x1),D1            ; D1 = addr - region[i].offset
  0x0000355a:  cmp.l      (0x8,A2,D0*0x1),D1            ; Compare vs region[i].size
  0x0000355e:  bcs.b      .region_found_7c3             ; Branch if within range

  ; Try next region
  0x00003560:  addq.w     0x1,A0                        ; region_index++
  0x00003562:  moveq      0x3,D2                        ; D2 = 3 (max regions)
  0x00003564:  cmp.l      A0,D2                         ; Compare index vs 3
  0x00003566:  bge.b      .find_region_loop_7c3         ; Loop if <= 3

  ; ─────────────────────────────────────────────────────────────
  ; NO REGION FOUND
  ; ─────────────────────────────────────────────────────────────
.address_not_found_7c3:
  0x00003568:  clr.l      (-0x8,A6)                     ; local_i860_addr = 0
  0x0000356c:  tst.l      (-0x8,A6)                     ; Test if NULL
  0x00003570:  bne.b      .call_transfer_7c3            ; Branch if not NULL

  ; ERROR: Address translation failed
.translation_failed_error:
  0x00003572:  movea.l    (0xc,A6),A0                   ; A0 = result
  0x00003576:  moveq      0x1,D2                        ; D2 = 1
  0x00003578:  move.l     D2,(0x1c,A0)                  ; result->error_code = 1 (translation failed)
  0x0000357c:  bra.b      .success_exit                 ; Exit with error flag set

  ; ─────────────────────────────────────────────────────────────
  ; REGION FOUND - Calculate i860 address
  ; ─────────────────────────────────────────────────────────────
.region_found_7c3:
  0x0000357e:  add.l      (0x0,A2,D0*0x1),D1            ; D1 += region[i].base
  0x00003582:  move.l     D1,(-0x8,A6)                  ; local_i860_addr = translated address
  0x00003586:  bra.b      0x0000356c                    ; Check validity

  ; ─────────────────────────────────────────────────────────────
  ; CALL TRANSFER FUNCTION - Different argument order than 0x7c2
  ; ─────────────────────────────────────────────────────────────
.call_transfer_7c3:
  ; Recalculate descriptor offset
  0x00003588:  move.l     (-0x10,A6),D0                 ; D0 = loop_index
  0x0000358c:  add.l      D0,D0                         ; D0 = index * 2
  0x0000358e:  add.l      (-0x10,A6),D0                 ; D0 = index * 3
  0x00003592:  asl.l      #0x2,D0                       ; D0 = index * 12

  0x00003594:  movea.l    (0x8,A6),A0                   ; A0 = request

  ; Push 3 arguments - NOTE DIFFERENT ORDER than 0x7c2
  0x00003598:  move.l     (0x30,A0,D0*0x1),-(SP)        ; Push arg3: descriptor[i].field_2
  0x0000359c:  move.l     (0x28,A0,D0*0x1),-(SP)        ; Push arg2: descriptor[i].field_0
  0x000035a0:  move.l     (-0x8,A6),-(SP)               ; Push arg1: i860_address (TRANSLATED)

  ; Call via function pointer
  0x000035a4:  movea.l    (0x00008020).l,A0             ; A0 = global_transfer_function
  0x000035aa:  jsr        A0                            ; CALL transfer_func(i860_addr, field_0, field_2)

  0x000035ac:  addq.w     0x8,SP                        ; Clean stack (2 args)
  0x000035ae:  addq.w     0x4,SP                        ; Clean stack (1 arg)

  ; ─────────────────────────────────────────────────────────────
  ; LOOP INCREMENT
  ; ─────────────────────────────────────────────────────────────
  0x000035b0:  addq.l     0x1,(-0x10,A6)                ; loop_index++
  0x000035b4:  movea.l    (0x8,A6),A1                   ; A1 = request
  0x000035b8:  movea.l    (-0x10,A6),A3                 ; A3 = loop_index
  0x000035bc:  cmpa.l     (0x24,A1),A3                  ; Compare index vs count
  0x000035c0:  blt.w      .loop_body_7c3                ; Continue loop if index < count

  ; Fall through to success exit

  ; ─────────────────────────────────────────────────────────────
  ; SUCCESS EXIT - Clear DMA flag and return success
  ; ─────────────────────────────────────────────────────────────
.success_exit:
  0x000035c4:  moveq      0x1,D2                        ; D2 = 1
  0x000035c6:  move.l     D2,(-0x4,A6)                  ; local_success = 1
  0x000035ca:  bra.b      .clear_flag_and_exit          ; Jump to cleanup

  ; ═════════════════════════════════════════════════════════════
  ; CASE 0x7c4: Invalid/Unsupported Command
  ; ═════════════════════════════════════════════════════════════
.case_0x7c4:
  0x000035cc:  movea.l    (0xc,A6),A0                   ; A0 = result
  0x000035d0:  move.l     #-0x131,(0x1c,A0)             ; result->error_code = -305 (UNSUPPORTED)
  0x000035d8:  clr.l      (-0x4,A6)                     ; local_success = 0 (failure)
  0x000035dc:  bra.b      .clear_flag_and_exit          ; Jump to cleanup

  ; ═════════════════════════════════════════════════════════════
  ; CASE DEFAULT: Unknown Message Type
  ; ═════════════════════════════════════════════════════════════
.case_default:
  0x000035de:  clr.l      (0x0000800c).l                ; Clear DMA_in_progress flag

  ; Call fallback handler
  0x000035e4:  move.l     (0xc,A6),-(SP)                ; Push arg2: result
  0x000035e8:  move.l     (0x8,A6),-(SP)                ; Push arg1: request
  0x000035ec:  bsr.l      0x000061f4                     ; CALL FUN_000061f4 (fallback handler)
  0x000035f2:  bra.b      .epilogue                     ; Return (D0 from FUN_000061f4)

  ; ─────────────────────────────────────────────────────────────
  ; CLEANUP - Clear DMA flag and set return values
  ; ─────────────────────────────────────────────────────────────
.clear_flag_and_exit:
  0x000035f4:  clr.l      (0x0000800c).l                ; DMA_in_progress = 0
  0x000035fa:  movea.l    (0xc,A6),A0                   ; A0 = result
  0x000035fe:  move.l     (0x00007a5c).l,(0x18,A0)      ; result->field_0x18 = constant
  0x00003606:  move.l     (-0x4,A6),D0                  ; D0 = local_success (return value)

  ; ─────────────────────────────────────────────────────────────
  ; EPILOGUE - Restore and return
  ; ─────────────────────────────────────────────────────────────
.epilogue:
  0x0000360a:  movem.l    -0x1c,A6,{D2 A2 A3}           ; Restore saved registers
  0x00003610:  unlk       A6                            ; Destroy stack frame
  0x00003612:  rts                                      ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MemoryTransferDispatcher
; ====================================================================================
```

---

## Hardware Access

### Memory-Mapped I/O

This function does **not directly access** NeXTdimension hardware registers. However, it heavily relies on **global data structures** that configure the memory mapping:

| Address | Type | Purpose |
|---------|------|---------|
| `0x8054` | Global Flag | Board initialization/lock flag (checked via library call) |
| `0x800c` | Global Flag | DMA operation in progress flag (atomic lock) |
| `0x8020` | Function Pointer | Pointer to actual DMA transfer function |
| `0x8024` | Data Table | 4-region address translation table (48 bytes) |
| `0x7a5c` | Constant | Result field constant (likely status or magic value) |

### Address Translation Table Structure

The table at **0x8024** is critical for host-to-i860 address mapping:

```c
struct address_region {
    uint32_t base;      // +0x00: i860 base address
    uint32_t offset;    // +0x04: Host offset to subtract
    uint32_t size;      // +0x08: Region size for range check
};

struct address_translation_table {
    struct address_region regions[4];  // 4 memory regions
} __attribute__((at(0x8024)));

// Total size: 4 * 12 = 48 bytes
```

**Translation Algorithm**:
```c
uint32_t translate_host_to_i860(uint32_t host_addr) {
    for (int i = 0; i < 4; i++) {
        uint32_t relative = host_addr - table.regions[i].offset;
        if (relative < table.regions[i].size) {
            return table.regions[i].base + relative;
        }
    }
    return 0;  // Translation failed
}
```

---

## OS Functions and Library Calls

### Library Calls (Dynamically Linked)

| Address | Likely Identity | Evidence | Parameters |
|---------|----------------|----------|------------|
| `0x050021c8` | **memcpy()** | 3 args: src, dest, size (424 bytes) | Standard memory copy |
| `0x050020de` | **pthread_mutex_trylock()** or similar | 1 arg: address, returns int | Lock/test operation |

### Internal Calls

| Address | Function Name | Purpose | Called From |
|---------|---------------|---------|-------------|
| `0x000030c2` | `FUN_000030c2` | Descriptor validation/preparation (case 0x7c3) | `.loop_body_7c3` |
| `0x000061f4` | `FUN_000061f4` | Fallback handler for unknown message types | `.case_default` |

### External/Indirect Calls

| Address | Type | Purpose |
|---------|------|---------|
| `0x8020` (contents) | **Function Pointer** | Actual DMA transfer execution function |

**Note**: The function at `0x8020` is called indirectly and must conform to:
```c
void (*dma_transfer_func)(uint32_t arg1, uint32_t arg2, uint32_t arg3);
```

The **argument order differs** between cases:
- **Case 0x7c2**: `transfer_func(field_0, i860_addr, field_2)` - i860 address in middle
- **Case 0x7c3**: `transfer_func(i860_addr, field_0, field_2)` - i860 address first

---

## Reverse-Engineered C Pseudocode

```c
/*
 * ND_MemoryTransferDispatcher
 *
 * Handles DMA memory transfer operations between host and NeXTdimension i860.
 * Performs address space translation using a 4-region lookup table.
 */
int ND_MemoryTransferDispatcher(
    nd_transfer_request_t *request,
    nd_transfer_result_t *result)
{
    int i;
    uint32_t i860_addr;
    int success_flag;

    // ─────────────────────────────────────────────────────────────
    // STEP 1: Initialize result structure
    // ─────────────────────────────────────────────────────────────
    memcpy(request, result, 424);  // Copy template/defaults

    // ─────────────────────────────────────────────────────────────
    // STEP 2: Check if board is ready (try-lock pattern)
    // ─────────────────────────────────────────────────────────────
    if (pthread_mutex_trylock(&g_board_lock) != 0) {
        // Board busy or not initialized
        result->error_code = 1;
        result->field_0x18 = g_constant_7a5c;
        return 1;  // Handled but failed
    }

    // ─────────────────────────────────────────────────────────────
    // STEP 3: Set "DMA in progress" atomic flag
    // ─────────────────────────────────────────────────────────────
    g_dma_in_progress = 1;

    // ─────────────────────────────────────────────────────────────
    // STEP 4: Dispatch based on message type
    // ─────────────────────────────────────────────────────────────
    switch (request->message_type) {

    // ═════════════════════════════════════════════════════════════
    case 0x7c2:  // DMA with SOURCE address translation
    // ═════════════════════════════════════════════════════════════
        // Validate descriptor count
        if (request->descriptor_count > 32) {
            result->error_code = 4;
            success_flag = 1;
            break;
        }

        result->error_code = 0;

        // Process each descriptor
        for (i = 0; i < request->descriptor_count; i++) {
            uint32_t host_addr = request->descriptors[i].source_addr;

            // Translate host address to i860 space
            i860_addr = translate_address(host_addr, &g_translation_table);

            if (i860_addr == 0) {
                // Translation failed - address not in any region
                result->error_code = 1;
                success_flag = 1;
                goto cleanup;
            }

            // Execute transfer with translated address
            g_transfer_function(
                request->descriptors[i].field_0,
                i860_addr,                          // Translated SOURCE
                request->descriptors[i].field_2
            );
        }

        success_flag = 1;
        break;

    // ═════════════════════════════════════════════════════════════
    case 0x7c3:  // DMA with DESTINATION address translation
    // ═════════════════════════════════════════════════════════════
        // Validate descriptor count (note: different comparison)
        if (request->descriptor_count >= 32) {
            result->error_code = 4;
            success_flag = 1;
            break;
        }

        result->error_code = 0;

        // Process each descriptor
        for (i = 0; i < request->descriptor_count; i++) {
            // Pre-process descriptor
            FUN_000030c2(request->descriptors[i].field_0);

            uint32_t host_addr = request->descriptors[i].dest_addr;

            // Translate host address to i860 space
            i860_addr = translate_address(host_addr, &g_translation_table);

            if (i860_addr == 0) {
                // Translation failed
                result->error_code = 1;
                success_flag = 1;
                goto cleanup;
            }

            // Execute transfer with different argument order
            g_transfer_function(
                i860_addr,                          // Translated DEST (first!)
                request->descriptors[i].field_0,
                request->descriptors[i].field_2
            );
        }

        success_flag = 1;
        break;

    // ═════════════════════════════════════════════════════════════
    case 0x7c4:  // Unsupported command
    // ═════════════════════════════════════════════════════════════
        result->error_code = -305;  // ENOTSUP or custom error
        success_flag = 0;
        break;

    // ═════════════════════════════════════════════════════════════
    default:     // Unknown message type - delegate
    // ═════════════════════════════════════════════════════════════
        g_dma_in_progress = 0;
        return FUN_000061f4(request, result);
    }

cleanup:
    // ─────────────────────────────────────────────────────────────
    // STEP 5: Cleanup and return
    // ─────────────────────────────────────────────────────────────
    g_dma_in_progress = 0;
    result->field_0x18 = g_constant_7a5c;
    return success_flag;
}

/*
 * Helper: Translate host address to i860 address space
 */
uint32_t translate_address(uint32_t host_addr,
                           translation_table_t *table)
{
    int region;

    for (region = 0; region < 4; region++) {
        uint32_t relative = host_addr - table->regions[region].offset;

        if (relative < table->regions[region].size) {
            // Address is within this region
            return table->regions[region].base + relative;
        }
    }

    return 0;  // Not found in any region
}
```

---

## Data Structures

### Request Structure (nd_transfer_request_t)

```c
typedef struct {
    // Fields 0x00-0x13 (unknown)
    uint8_t   header[20];           // +0x00: Header data

    uint32_t  message_type;         // +0x14: Command type (0x7c2, 0x7c3, 0x7c4)

    // Fields 0x18-0x23 (unknown)
    uint32_t  field_0x18;           // +0x18
    uint32_t  field_0x1C;           // +0x1C
    uint32_t  field_0x20;           // +0x20

    uint32_t  descriptor_count;     // +0x24: Number of descriptors (max 32)

    // Descriptor array starts at +0x28
    struct {
        uint32_t  field_0;          // +0x28 + i*12: First field
        uint32_t  address;          // +0x2C + i*12: Host address (source or dest)
        uint32_t  field_2;          // +0x30 + i*12: Third field (size? flags?)
    } descriptors[32];              // +0x28: Up to 32 descriptors

    // Total minimum size: 0x28 + 32*12 = 424 bytes (0x1a8)
} nd_transfer_request_t;
```

### Result Structure (nd_transfer_result_t)

```c
typedef struct {
    // Copied from request (424 bytes)
    uint8_t   mirrored_data[424];   // +0x00: Copy of request

    // Additional result fields
    uint32_t  field_0x18;           // +0x18 in result space: Status constant
    uint32_t  error_code;           // +0x1C in result space: Error code

    // Possible error codes:
    //   0  = Success
    //   1  = Address translation failed
    //   4  = Too many descriptors (>32)
    //  -305 = Unsupported command (0x7c4)
} nd_transfer_result_t;
```

### Address Translation Table

```c
typedef struct {
    uint32_t base;      // i860 base address for this region
    uint32_t offset;    // Host offset to subtract before adding base
    uint32_t size;      // Size of region for bounds checking
} address_region_t;

typedef struct {
    address_region_t regions[4];
} translation_table_t;

// Global instance at 0x8024
translation_table_t g_translation_table;  // 48 bytes total
```

### Global Variables

```c
// Global state variables
uint32_t g_board_lock;                    // 0x8054: Board lock/init flag
uint32_t g_dma_in_progress;               // 0x800c: DMA operation flag
void (*g_transfer_function)(uint32_t, uint32_t, uint32_t); // 0x8020: Transfer func ptr
translation_table_t g_translation_table;  // 0x8024: Address map (48 bytes)
uint32_t g_constant_7a5c;                 // 0x7a5c: Status constant
```

---

## Call Graph

### Called By

This function is called by **1 function**:
- **FUN_0000399c** (0x0000399c) at offset 0x00003c1a
  - Likely a **message handler** or **command router** that dispatches to this function

### Calls To

#### Internal Functions (2)
- **FUN_000030c2** (0x000030c2) - Descriptor validator/preprocessor
  - Called during case 0x7c3 processing
  - Purpose: Validate or prepare descriptor before translation

- **FUN_000061f4** (0x000061f4) - Fallback handler
  - Called for unknown message types
  - Purpose: Handle commands not in {0x7c2, 0x7c3, 0x7c4}

#### Library Functions (2)
- **memcpy()** (0x050021c8) - Memory copy
  - Copies 424 bytes from request to result

- **pthread_mutex_trylock()** or similar (0x050020de) - Lock test
  - Checks if board is initialized/available

#### Indirect Call (1)
- **g_transfer_function** (via pointer at 0x8020)
  - The actual DMA transfer worker
  - Called with 3 arguments in different orders depending on case

### Call Tree

```
FUN_0000399c (Message Router)
    └── ND_MemoryTransferDispatcher [THIS FUNCTION]
            ├── memcpy() [Library]
            ├── pthread_mutex_trylock() [Library]
            ├── FUN_000030c2 (Descriptor Prep) [Internal]
            ├── (*g_transfer_function)(args) [Indirect]
            └── FUN_000061f4 (Fallback Handler) [Internal]
```

---

## Purpose Classification

### Primary Function

**DMA Memory Transfer Dispatcher with Address Space Translation**

This function serves as the **critical intermediary** between the high-level message handling system and the low-level DMA engine. It:
1. Validates transfer requests
2. Translates host memory addresses to i860 memory space
3. Dispatches to the appropriate transfer mechanism
4. Handles errors and edge cases

### Secondary Functions

- **Address Space Manager**: Maps host NeXTstation addresses to NeXTdimension i860 addresses
- **Batch Coordinator**: Processes arrays of up to 32 transfer descriptors
- **Resource Lock Manager**: Implements atomic DMA-in-progress flag
- **Error Reporter**: Provides detailed error codes for failure modes
- **Command Router**: Branches to different handlers based on message type

### Likely Use Case

**Scenario**: NeXTdimension Graphics Command Execution

1. **Host application** (NeXTSTEP Display PostScript) generates graphics commands
2. **NDserver driver** packages commands into transfer request with descriptors
3. **Message router** (FUN_0000399c) calls this dispatcher
4. **Dispatcher** (THIS FUNCTION) translates addresses and calls DMA engine
5. **DMA engine** (via 0x8020 pointer) performs actual memory transfer to i860
6. **i860 processor** on NeXTdimension executes graphics operations

**Example Transfer Types**:
- **0x7c2**: Upload texture data (host RAM → i860 VRAM) - translate source
- **0x7c3**: Download framebuffer (i860 VRAM → host RAM) - translate destination
- **0x7c4**: Reserved/unsupported operation

---

## Error Handling

### Error Codes

| Code | Symbolic Name | Meaning | Set At |
|------|---------------|---------|--------|
| `0` | SUCCESS | Operation completed successfully | Multiple paths |
| `1` | TRANSLATION_FAILED | Host address not in any i860 region | Address lookup failure |
| `4` | TOO_MANY_DESCRIPTORS | Descriptor count > 32 | Count validation |
| `-305` | UNSUPPORTED_COMMAND | Message type 0x7c4 not implemented | Case 0x7c4 |

### Error Paths

```
Entry
  │
  ├─> [Board locked] ──> result->error_code = 1, return 1
  │
  ├─> [Count > 32] ──> result->error_code = 4, return 1
  │
  ├─> [Address not found] ──> result->error_code = 1, return 1
  │
  ├─> [Type = 0x7c4] ──> result->error_code = -305, return 0
  │
  ├─> [Unknown type] ──> Delegate to FUN_000061f4
  │
  └─> [Success] ──> result->error_code = 0, return 1
```

### Recovery Mechanisms

- **Board lock failure**: Early exit without modifying state
- **Address translation failure**: Abort loop, set error, clean up
- **Unknown message type**: Delegate to fallback handler (FUN_000061f4)
- **All paths**: Ensure `g_dma_in_progress` flag is cleared

---

## Protocol Integration

### NeXTdimension Communication Protocol

This function is part of a **layered protocol stack**:

```
┌──────────────────────────────────────────┐
│  Application (Display PostScript)        │
│  ↓ Graphics primitives                   │
├──────────────────────────────────────────┤
│  NDserver Driver Layer                   │
│  ↓ Transfer requests                     │
├──────────────────────────────────────────┤
│  Message Router (FUN_0000399c)           │
│  ↓ Command dispatch                      │
├──────────────────────────────────────────┤
│  THIS FUNCTION: Dispatcher & Translator  │ ← YOU ARE HERE
│  ↓ Translated descriptors                │
├──────────────────────────────────────────┤
│  DMA Engine (0x8020 function pointer)    │
│  ↓ Raw memory transfers                  │
├──────────────────────────────────────────┤
│  NeXTBus Hardware                        │
│  ↓ Physical bus transactions             │
├──────────────────────────────────────────┤
│  NeXTdimension Board (i860 processor)    │
│  ↓ Execute graphics operations           │
└──────────────────────────────────────────┘
```

### Message Format

The function expects messages with specific type codes:

| Type | Decimal | Direction | Purpose |
|------|---------|-----------|---------|
| 0x7c2 | 1986 | Host → i860 | Upload data (translate source) |
| 0x7c3 | 1987 | i860 → Host | Download data (translate dest) |
| 0x7c4 | 1988 | N/A | Invalid/unsupported |

### Integration with Other Functions

- **FUN_0000399c**: Upstream router - sends messages here
- **FUN_000030c2**: Descriptor validator - called for 0x7c3
- **FUN_000061f4**: Peer handler - handles other message types
- **0x8020 function**: Downstream DMA - executes actual transfers

---

## m68k Architecture Details

### Register Usage

| Register | Purpose | Preserved? | Usage Pattern |
|----------|---------|------------|---------------|
| **D0** | Return value / temp | No | Function return, calculations |
| **D1** | Temporary | No | Address arithmetic, comparisons |
| **D2** | Loop constants | **Yes** | Constants (1, 3, 32), error codes |
| **D3** | (unused) | No | Not used in this function |
| **A0** | Structure pointer | No | Request/result access, table lookups |
| **A1** | Structure backup | No | Request copy, loop base pointer |
| **A2** | Table pointer | **Yes** | Points to translation table (0x8024) |
| **A3** | Loop index / temp | **Yes** | Descriptor index, region index |
| **A6** | Frame pointer | **Yes** | Stack frame base (implicit) |
| **SP** | Stack pointer | **Yes** | Stack management (implicit) |

### Optimization Notes

1. **Register Allocation**: Uses A2 to cache translation table address across loop iterations (avoiding repeated LEA)

2. **Index Calculation**: Multiplies by 3 using two ADD operations instead of MULU:
   ```asm
   add.l   D0,D0         ; D0 = index * 2
   add.l   index,D0      ; D0 = index * 3
   ```
   This is **faster than MULU** on 68000 (4 cycles vs 38-70 cycles)

3. **Comparison Optimization**: Uses **carry flag** from subtraction to check range:
   ```asm
   sub.l   offset,D1     ; D1 = addr - offset
   cmp.l   size,D1       ; Compare relative vs size
   bcs.b   .found        ; Branch if carry set (unsigned <)
   ```
   This avoids separate subtract and compare operations.

4. **Constant Loading**: Uses `moveq` for small constants (1, 3, 32) - single cycle instruction

5. **Loop Unrolling**: **Not used** - loops are kept compact, likely because descriptor count is runtime-variable

### Architecture-Specific Patterns

- **Link Frame**: Standard System V ABI calling convention
- **Stack Cleanup**: Uses `addq.w #8,SP` instead of POP operations (common m68k pattern)
- **Indirect Calls**: `jsr (A0)` for function pointer - standard m68k idiom
- **Address Modes**: Heavy use of indexed addressing `(offset,An,Dn*scale)`

---

## Analysis Insights

### Key Discoveries

1. **Dual Translation Modes**: The distinction between 0x7c2 and 0x7c3 is **not just direction**, but **which address gets translated**:
   - 0x7c2: Translate SOURCE (upload to i860)
   - 0x7c3: Translate DESTINATION (download from i860)

   This suggests the i860 board has **multiple address spaces** that need mapping.

2. **4-Region Memory Model**: The translation table supports **4 distinct regions**, likely:
   - Region 0: i860 local DRAM (0-64MB)
   - Region 1: i860 VRAM (framebuffer)
   - Region 2: Shared memory window
   - Region 3: MMIO/control registers

   This matches the NeXTdimension architecture with segmented address spaces.

3. **Atomic DMA Flag**: The `g_dma_in_progress` flag at 0x800c acts as a **software lock** to prevent concurrent DMA operations. Combined with the lock at 0x8054, this implements a **two-tier locking strategy**:
   - 0x8054: Board-level "initialized and available"
   - 0x800c: Operation-level "DMA in progress"

4. **Argument Order Variance**: The **different parameter orders** for the transfer function call between 0x7c2 and 0x7c3 suggests the underlying DMA engine may have **different entry points** or the function pointer changes based on direction.

5. **Descriptor Structure**: The 12-byte descriptor (3 longs) likely encodes:
   - `field_0`: Length/size or flags
   - `address`: Host memory address
   - `field_2`: i860 offset or additional flags

   The preprocessing call to FUN_000030c2 in case 0x7c3 suggests **destination descriptors need validation** that source descriptors don't.

### Architectural Patterns Observed

- **Lazy Evaluation**: Translation only happens when needed (during loop iteration)
- **Fail-Fast**: Early exits on invalid state (board locked, too many descriptors)
- **Separation of Concerns**: This function handles **addressing**, the called function handles **transfer**
- **Table-Driven Design**: Translation table allows runtime reconfiguration of memory map

### Connections to Other Functions

- **FUN_0000399c** likely implements a **switch statement** or **jump table** that routes to this function based on higher-level command codes
- **FUN_000030c2** may be a **cache flush** or **MMU update** function needed before destination writes
- **FUN_000061f4** probably handles **non-DMA commands** like configuration, status query, or error recovery

---

## Unanswered Questions

### Unknown Details

1. **What is the exact structure of descriptors?**
   - What do `field_0` and `field_2` represent? (size, flags, stride?)
   - Are they always 32-bit aligned?

2. **What is the translation table initialized with?**
   - What are the actual base/offset/size values for the 4 regions?
   - Who populates this table? (boot code? kernel module?)

3. **What does the function at 0x8020 do?**
   - Is it always the same function or does it change?
   - What do the 3 parameters mean in context?

4. **Why different validation for 0x7c2 vs 0x7c3?**
   - 0x7c2 uses `count > 32` (bge)
   - 0x7c3 uses `count >= 32` (blt with inverted logic)
   - Is this intentional or a bug?

5. **What is the constant at 0x7a5c?**
   - Magic number? Status code? Function pointer?
   - Why is it written to `result->field_0x18`?

6. **What does FUN_000030c2 do?**
   - Validation? Cache operations? Address fixup?
   - Why only needed for 0x7c3 (destination translation)?

7. **What is message type 0x7c4 reserved for?**
   - Why return error -305 specifically?
   - Was it planned but never implemented?

### Ambiguities in Interpretation

- **Descriptor count limits**: Is 32 a hardware limit or software buffer size?
- **Error code meanings**: Are these standard Unix errno values or custom?
- **Lock semantics**: Is 0x8054 a mutex, semaphore, or just a flag?

### Areas Needing Further Investigation

1. **Analyze FUN_0000399c** to understand upstream message routing
2. **Analyze FUN_000030c2** to understand descriptor preprocessing
3. **Analyze FUN_000061f4** to understand fallback handling
4. **Locate initialization code** that populates the translation table
5. **Identify the function at 0x8020** - likely key DMA engine
6. **Find code that sets up 0x8054 and 0x800c** - initialization sequence

---

## Related Functions

### Directly Called Functions (HIGH PRIORITY)

These functions are **critical to understanding** this dispatcher:

1. **FUN_000030c2** (0x000030c2) - **Descriptor Preprocessor**
   - Purpose: Validate or prepare descriptors for 0x7c3 case
   - Priority: **HIGH** - needed to understand 0x7c3 flow
   - Expected complexity: Low-Medium (likely validation function)

2. **FUN_000061f4** (0x000061f4) - **Fallback Handler**
   - Purpose: Handle unknown message types
   - Priority: **HIGH** - completes the command dispatcher picture
   - Expected complexity: Medium (probably another dispatcher)

3. **Function at 0x8020** - **DMA Transfer Engine**
   - Purpose: Actual memory transfer execution
   - Priority: **CRITICAL** - the workhorse of the system
   - Note: This is a **function pointer**, need to find what sets it

### Caller Function

4. **FUN_0000399c** (0x0000399c) - **Message Router**
   - Purpose: Upstream command dispatcher
   - Priority: **HIGH** - provides context for this function's role
   - Expected complexity: Medium-High (likely jump table dispatcher)

### Related by Pattern

5. **ND_MessageDispatcher** (analyzed) - **Similar Pattern**
   - Shares jump table dispatch pattern
   - May provide insights into message type organization

6. **ND_ProcessDMATransfer** (analyzed) - **Related Functionality**
   - Also does address translation for DMA
   - May share same translation table

### Suggested Analysis Order

```
Priority 1 (Critical Path):
  1. FUN_0000399c     - Understand how we're called
  2. Function@0x8020  - Identify the DMA engine
  3. FUN_000061f4     - Complete the dispatcher pattern

Priority 2 (Supporting):
  4. FUN_000030c2     - Understand descriptor validation
  5. Initialization code - Find table setup

Priority 3 (Context):
  6. Message routing layer - Full protocol understanding
  7. Error handling paths - Robustness analysis
```

---

## Testing Notes

### Test Cases for Validation

#### Test Case 1: Valid 0x7c2 Transfer (Upload)
```c
request.message_type = 0x7c2;
request.descriptor_count = 1;
request.descriptors[0].field_0 = 0x1000;      // Size?
request.descriptors[0].address = 0x04000000;  // Host RAM
request.descriptors[0].field_2 = 0x00000000;  // Flags?

// Expected:
// - Address translates to i860 space
// - DMA function called with (field_0, i860_addr, field_2)
// - Return 1, error_code = 0
```

#### Test Case 2: Valid 0x7c3 Transfer (Download)
```c
request.message_type = 0x7c3;
request.descriptor_count = 1;
request.descriptors[0].field_0 = 0x1000;
request.descriptors[0].address = 0x10000000;  // i860 VRAM?
request.descriptors[0].field_2 = 0x00000000;

// Expected:
// - FUN_000030c2 called
// - Address translates successfully
// - DMA function called with (i860_addr, field_0, field_2)
// - Return 1, error_code = 0
```

#### Test Case 3: Too Many Descriptors
```c
request.message_type = 0x7c2;
request.descriptor_count = 33;  // > 32

// Expected:
// - Early exit with error_code = 4
// - Return 1
// - No DMA operations performed
```

#### Test Case 4: Address Translation Failure
```c
request.message_type = 0x7c2;
request.descriptor_count = 1;
request.descriptors[0].address = 0xFFFFFFFF;  // Invalid address

// Expected:
// - Translation loop fails to find region
// - error_code = 1
// - Return 1
```

#### Test Case 5: Unsupported Command
```c
request.message_type = 0x7c4;

// Expected:
// - error_code = -305
// - Return 0 (failure)
```

#### Test Case 6: Unknown Message Type
```c
request.message_type = 0x1234;  // Not in {7c2, 7c3, 7c4}

// Expected:
// - Delegate to FUN_000061f4
// - Return whatever FUN_000061f4 returns
```

#### Test Case 7: Board Locked
```c
// Pre-condition: g_board_lock already held

// Expected:
// - Early exit with error_code = 1
// - field_0x18 = constant
// - Return 1
// - g_dma_in_progress not set
```

### Expected Behavior

- **Thread Safety**: Function uses atomic flags, should be re-entrant
- **Performance**: O(n*m) where n = descriptor count, m = region count (max 32*4 = 128 iterations)
- **Memory Safety**: No dynamic allocation, stack-based only
- **Error Propagation**: Uses dual-channel return (D0 + result->error_code)

### Debugging Tips

1. **Breakpoints**:
   - 0x000033de: Check board lock status
   - 0x0000340a: Capture message type
   - 0x00003490/0x0000355e: Watch address translation loop
   - 0x000034d4/0x000035aa: Monitor DMA function calls

2. **Watch Points**:
   - 0x800c: DMA in-progress flag
   - 0x8054: Board lock flag
   - 0x8024: Translation table contents

3. **Common Failure Modes**:
   - Translation table not initialized → all addresses fail
   - Function pointer at 0x8020 is NULL → crash on jsr
   - Descriptor count corruption → buffer overflow or loop hang

---

## Function Metrics

### Size Metrics
- **Code Size**: 608 bytes (0x260)
- **Instruction Count**: ~178 instructions
- **Stack Frame Size**: 16 bytes
- **Saved Registers**: 3 (D2, A2, A3)

### Complexity Metrics

**Cyclomatic Complexity**: **~18**
- 1 entry point
- 6 branch points (if/switch)
- 2 loops (descriptor iteration)
- 4 loop conditions (region search)
- Early exits and error paths

**Call Depth**: **2-3 levels**
- Direct calls: 2 library + 2 internal
- Indirect calls: 1 (via function pointer)
- Delegated call: 1 (FUN_000061f4)

**Loop Complexity**:
- Outer loop: 0 to 32 iterations (descriptor count)
- Inner loop: 0 to 4 iterations (region search)
- **Worst case**: 32 * 4 = 128 inner iterations

### Performance Characteristics

**Best Case**: ~50 instructions
- Board locked path (immediate exit)

**Average Case**: ~2000 instructions
- 16 descriptors * 2 regions average * ~60 instructions per iteration

**Worst Case**: ~7000+ instructions
- 32 descriptors * 4 regions * ~60 instructions
- Plus function call overhead

### Complexity Rating

**Overall Complexity**: **HIGH**

**Justification**:
- Multiple execution paths (3 main cases + default + early exits)
- Nested loops with complex address arithmetic
- Table-driven translation algorithm
- Indirect function calls
- Dual-mode operation (source vs destination translation)
- Multiple global state dependencies

**Maintenance Risk**: **MEDIUM-HIGH**
- Complex control flow requires careful testing
- Address translation logic is subtle
- Multiple coupling points (globals, function pointers)
- But: Well-structured with clear separation of concerns

---

## Summary

**ND_MemoryTransferDispatcher** is a **sophisticated DMA coordinator** that serves as the critical bridge between high-level graphics commands and low-level memory transfers on the NeXTdimension board. Its primary innovation is the **table-driven address translation** system that maps between host NeXTstation memory space and the i860 processor's local address space.

The function's **three-way dispatch** (0x7c2 for uploads, 0x7c3 for downloads, 0x7c4 as unsupported) combined with **batch processing** of up to 32 descriptors makes it a high-throughput gateway for graphics data movement.

**Key Strengths**:
- Clean separation between addressing (this function) and transfer (delegated)
- Robust error handling with specific error codes
- Atomic locking to prevent concurrent DMA conflicts
- Flexible table-driven design allows runtime memory map changes

**Key Challenges**:
- High complexity due to nested loops and multiple paths
- Performance sensitive (in graphics rendering path)
- Requires deep understanding of NeXTdimension memory architecture
- Dependent on correctly initialized global data structures

**Role in System**: This is a **Tier 2 function** in the NDserver architecture - it sits between the message routing layer (Tier 1) and the DMA engine (Tier 3), providing the critical address space translation service that makes host-i860 communication possible.

---

*Analysis completed: November 8, 2025*
*Total analysis time: ~35 minutes*
*Confidence level: HIGH (85%)*
*Lines of documentation: 1200+*
