# Deep Function Analysis: FUN_0000746c (ND_WriteBranchInstruction)

**Analysis Date**: 2025-11-08
**Analyst**: Claude Code
**Function Address**: 0x0000746c
**Function Size**: 352 bytes (88 instructions)
**Complexity**: Low-Medium (simple control flow, repetitive writes)

---

## Executive Summary

This function writes an **i860 branch instruction sequence** to NeXTdimension local memory. It acquires dual locks (same as ND_ProcessDMATransfer), validates the __TEXT segment, then writes 8 long-words to a computed address near the end of i860 memory space. The pattern consists of 7 NOPs (0xA0000000) and 1 branch instruction at the center, suggesting this creates a **jump vector or entry point** for the i860 processor.

**Purpose**: Write i860 startup/entry point code to high memory
**Return Value**: 0 on success, -1 on failure with error code 0xE
**Primary Side Effect**: Modifies i860 memory at offset `(size+0x100)/4 - 3 + 0x68000000`

---

## Function Signature

```c
int ND_WriteBranchInstruction(nd_board_info_t* board_info, uint32_t size);
```

### Parameters:
- **board_info** (A6+0x8): Pointer to 80-byte board info structure
- **size** (A6+0xC): Size parameter (likely kernel size in bytes)

### Return Values:
- **0**: Success - branch instruction written
- **-1**: Failure - segment validation failed
  - Global 0x040105b0 = 0xE (lock/validation failure)

---

## Complete Annotated Disassembly

```m68k
; ============================================================================
; Function: FUN_0000746c - ND_WriteBranchInstruction
; Address: 0x0000746c
; Size: 352 bytes
; ============================================================================

  ; --- PROLOGUE ---
  0x0000746c:  link.w     A6,-0x18                       ; Create 24-byte stack frame
  0x00007470:  move.l     A2,-(SP)                       ; Save A2

  ; --- ADDRESS CALCULATION ---
  0x00007472:  movea.l    (0x8,A6),A0                    ; A0 = board_info
  0x00007476:  move.l     (0x2c,A0),(-0x18,A6)           ; dest_base = board_info->field_0x2C
  0x0000747c:  addi.l     #0x7ffff00,(-0x18,A6)          ; dest_base += 0x07FFFF00
                                                           ; (high memory offset)

  ; --- INSTRUCTION WORD CALCULATION ---
  ; Formula: (size + 0x100) / 4 - 3
  0x00007484:  move.l     (0xc,A6),D0                    ; D0 = size
  0x00007488:  addi.l     #0x100,D0                      ; D0 += 0x100 (256 bytes)
  0x0000748e:  lsr.l      #0x2,D0                        ; D0 /= 4 (convert bytes to words)
  0x00007490:  move.l     D0,(-0x8,A6)                   ; instruction_word = D0
  0x00007494:  subq.l     0x3,(-0x8,A6)                  ; instruction_word -= 3

  ; --- CREATE i860 BRANCH INSTRUCTION ---
  ; i860 Branch instruction format: 0x68000000 | (offset & 0x03FFFFFF)
  0x00007498:  andi.l     #0x3ffffff,(-0x8,A6)           ; instruction_word &= 0x03FFFFFF (26-bit offset)
  0x000074a0:  move.l     (-0x8,A6),D0                   ; D0 = instruction_word
  0x000074a4:  ori.l      #0x68000000,D0                 ; D0 |= 0x68000000 (i860 BR opcode)
  0x000074aa:  move.l     D0,(-0x8,A6)                   ; instruction_word = complete instruction
  0x000074ae:  move.l     D0,(-0x4,A6)                   ; branch_instr = instruction_word (backup)

  ; --- LOCK ACQUISITION (identical to ND_ProcessDMATransfer) ---
  0x000074b2:  pea        (0x75cc).l                     ; push &lock_var_1
  0x000074b8:  pea        (0xa).w                        ; push 10
  0x000074bc:  lea        (0x5002f7e).l,A2               ; A2 = &lock_function
  0x000074c2:  jsr        A2                             ; result = lock_function(10, &lock_var_1)
  0x000074c4:  move.l     D0,(-0x10,A6)                  ; lock_result_1 = result

  0x000074c8:  pea        (0x75cc).l                     ; push &lock_var_2
  0x000074ce:  pea        (0xb).w                        ; push 11
  0x000074d2:  jsr        A2                             ; result = lock_function(11, &lock_var_2)
  0x000074d4:  move.l     D0,(-0x14,A6)                  ; lock_result_2 = result

  ; --- SEGMENT NAME VALIDATION ---
  0x000074d8:  pea        (0x80f0).l                     ; push "__TEXT" string address
  0x000074de:  bsr.l      0x05002ec4                     ; result = strcmp(segment_name, "__TEXT")
  0x000074e4:  adda.w     #0x14,SP                       ; Clean up 5 args (20 bytes)

  0x000074e8:  tst.l      D0                             ; if (strcmp_result != 0)
  0x000074ea:  bne.w      0x000075a0                     ;   goto error_unlock

  ; ============================================================================
  ; WRITE i860 INSTRUCTION SEQUENCE (8 long-words)
  ; Pattern: NOP, NOP, NOP, BRANCH, NOP, NOP, NOP, NOP
  ; ============================================================================

  ; --- WRITE 1: NOP (0xA0000000) ---
  0x000074ee:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x000074f2:  eori.w     #0x4,D0w                       ; D0 ^= 0x04 (endian swap)
  0x000074f6:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x000074f8:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)
  0x000074fe:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 2: NOP (0xA0000000) ---
  0x00007502:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x00007506:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x0000750a:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x0000750c:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)
  0x00007512:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 3: NOP (0xA0000000) ---
  0x00007516:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x0000751a:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x0000751e:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x00007520:  move.l     (-0x4,A6),(A1)                 ; *A1 = branch_instr (BRANCH INSTRUCTION)
  0x00007524:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 4: NOP (0xA0000000) ---
  0x00007528:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x0000752c:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x00007530:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x00007532:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)
  0x00007538:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 5: NOP (0xA0000000) ---
  0x0000753c:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x00007540:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x00007544:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x00007546:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)
  0x0000754c:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 6: NOP (0xA0000000) ---
  0x00007550:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x00007554:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x00007558:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x0000755a:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)
  0x00007560:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 7: NOP (0xA0000000) ---
  0x00007564:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x00007568:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x0000756c:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x0000756e:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)
  0x00007574:  addq.l     0x4,(-0x18,A6)                 ; dest_base += 4

  ; --- WRITE 8: NOP (0xA0000000) ---
  0x00007578:  move.l     (-0x18,A6),D0                  ; D0 = dest_base
  0x0000757c:  eori.w     #0x4,D0w                       ; D0 ^= 0x04
  0x00007580:  movea.l    D0,A1                          ; A1 = swapped_dest
  0x00007582:  move.l     #-0x60000000,(A1)              ; *A1 = 0xA0000000 (i860 NOP)

  ; --- UNLOCK AND SUCCESS RETURN ---
  0x00007588:  move.l     (-0x10,A6),-(SP)               ; push lock_result_1
  0x0000758c:  pea        (0xa).w                        ; push 10
  0x00007590:  jsr        A2                             ; unlock_function(10, lock_result_1)
  0x00007592:  move.l     (-0x14,A6),-(SP)               ; push lock_result_2
  0x00007596:  pea        (0xb).w                        ; push 11
  0x0000759a:  jsr        A2                             ; unlock_function(11, lock_result_2)
  0x0000759c:  clr.l      D0                             ; return 0 (SUCCESS)
  0x0000759e:  bra.b      0x000075c4                     ; goto epilogue

  ; ============================================================================
  ; ERROR EXIT PATH
  ; ============================================================================
error_unlock:
  0x000075a0:  move.l     (-0x10,A6),-(SP)               ; push lock_result_1
  0x000075a4:  pea        (0xa).w                        ; push 10
  0x000075a8:  lea        (0x5002f7e).l,A2               ; A2 = &lock_function
  0x000075ae:  jsr        A2                             ; unlock_function(10, lock_result_1)
  0x000075b0:  move.l     (-0x14,A6),-(SP)               ; push lock_result_2
  0x000075b4:  pea        (0xb).w                        ; push 11
  0x000075b8:  jsr        A2                             ; unlock_function(11, lock_result_2)
  0x000075ba:  moveq      0xe,D1                         ; D1 = 14 (error code)
  0x000075bc:  move.l     D1,(0x040105b0).l              ; global_error_code = 0xE
  0x000075c2:  moveq      -0x1,D0                        ; return -1 (FAILURE)

  ; --- EPILOGUE ---
  0x000075c4:  movea.l    (-0x1c,A6),A2                  ; Restore A2
  0x000075c8:  unlk       A6                             ; Destroy stack frame
  0x000075ca:  rts                                       ; Return
```

---

## Stack Frame Layout

```
Stack Frame: 24 bytes (-0x18)

Offset   Size   Name                Description
------   ----   -----------------   ------------------------------------
-0x04    4      branch_instr        Computed i860 branch instruction
-0x08    4      instruction_word    26-bit offset for branch
-0x10    4      lock_result_1       Lock acquisition result (type 10)
-0x14    4      lock_result_2       Lock acquisition result (type 11)
-0x18    4      dest_base           Destination address (evolving)
-0x1C    4      saved_A2            Preserved register
```

---

## Hardware Access

### Memory-Mapped I/O Writes:

| Address         | Value        | Purpose                              |
|-----------------|--------------|--------------------------------------|
| dest_base+0x00  | 0xA0000000   | i860 NOP instruction                 |
| dest_base+0x04  | 0xA0000000   | i860 NOP instruction                 |
| dest_base+0x08  | 0x68xxxxxx   | i860 BRANCH instruction (computed)   |
| dest_base+0x0C  | 0xA0000000   | i860 NOP instruction                 |
| dest_base+0x10  | 0xA0000000   | i860 NOP instruction                 |
| dest_base+0x14  | 0xA0000000   | i860 NOP instruction                 |
| dest_base+0x18  | 0xA0000000   | i860 NOP instruction                 |
| dest_base+0x1C  | 0xA0000000   | i860 NOP instruction                 |

**Destination Address Calculation**:
```c
dest_base = board_info->field_0x2C + 0x07FFFF00;
```

This places the writes at **high memory** in the NeXTdimension address space (near the top of i860 local DRAM or ROM region).

### Global Variables:

| Address    | Purpose                    | Access  |
|------------|----------------------------|---------|
| 0x040105b0 | Global error code storage  | Write   |
| 0x000075cc | Lock variable (BSS)        | Read    |
| 0x000080f0 | "__TEXT" string            | Read    |

---

## OS Functions and Library Calls

### Library Functions Called:

1. **Lock/Unlock Function @ 0x5002f7e**
   - **Likely**: `mutex_lock()` / `mutex_unlock()`
   - **Parameters**: Type code (10 or 11), lock variable address
   - **Return**: Lock handle/result
   - **Usage**: Dual locking (same as ND_ProcessDMATransfer)

2. **String Comparison @ 0x5002ec4**
   - **Likely**: `strcmp()`
   - **Parameters**: Two string pointers
   - **Return**: 0 if equal
   - **Usage**: Validate segment name is "__TEXT"

### NeXTSTEP/Mach Specific:

- **Dual Locking**: Same pattern as ND_ProcessDMATransfer (types 10 and 11)
- **Segment Validation**: Checks __TEXT segment before proceeding
- **Memory Barriers**: XOR with 0x04 handles endianness

---

## Reverse-Engineered C Pseudocode

```c
/*
 * Write i860 branch instruction sequence to high memory
 *
 * Creates an 8-instruction block with a branch instruction surrounded by NOPs.
 * Used to set up entry point or jump vector for i860 processor startup.
 */
int ND_WriteBranchInstruction(nd_board_info_t* board_info, uint32_t size)
{
    uint32_t  dest_base;
    uint32_t  instruction_word;
    uint32_t  branch_instr;
    void*     lock_result_1;
    void*     lock_result_2;

    // CALCULATE DESTINATION ADDRESS
    // Place code at high memory (near top of i860 DRAM)
    dest_base = board_info->field_0x2C + 0x07FFFF00;

    // CALCULATE BRANCH OFFSET
    // Formula: (size + 256) / 4 - 3
    // This likely points back to the start of the loaded kernel
    instruction_word = ((size + 0x100) / 4) - 3;

    // CREATE i860 BRANCH INSTRUCTION
    // i860 BR instruction: opcode 0x68 with 26-bit signed offset
    instruction_word &= 0x03FFFFFF;  // Mask to 26 bits
    branch_instr = 0x68000000 | instruction_word;

    // ACQUIRE LOCKS
    lock_result_1 = lock_function(10, &lock_var_1);
    lock_result_2 = lock_function(11, &lock_var_2);

    // VALIDATE SEGMENT NAME
    if (strcmp(segment_name, "__TEXT") != 0) {
        // Unlock and fail
        unlock_function(10, lock_result_1);
        unlock_function(11, lock_result_2);
        global_error_code = 0xE;
        return -1;
    }

    // WRITE i860 INSTRUCTION SEQUENCE (8 long-words)
    // Pattern: NOP, NOP, BRANCH, NOP, NOP, NOP, NOP, NOP

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = branch_instr;  // BRANCH
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP
    dest_base += 4;

    *(uint32_t*)(dest_base ^ 0x04) = 0xA0000000;  // NOP

    // UNLOCK AND RETURN SUCCESS
    unlock_function(10, lock_result_1);
    unlock_function(11, lock_result_2);
    return 0;
}
```

---

## Data Structures

### i860 Instruction Encoding

**i860 Branch Instruction (BR)**:
```
Bits 31-26: 011010 (0x1A, opcode for BR)
Bits 25-0:  26-bit signed offset (word offset, not byte)

Complete instruction: 0x68000000 | (offset & 0x03FFFFFF)
```

**i860 NOP Instruction**:
```
0xA0000000 - Standard NOP (likely fnop or integer nop)
```

### Memory Layout Created by This Function

```
Address                 Value         Instruction
----------------------  ------------  ---------------
dest_base + 0x00        0xA0000000    NOP
dest_base + 0x04        0xA0000000    NOP
dest_base + 0x08        0x68xxxxxx    BR <offset>     ← BRANCH TO KERNEL
dest_base + 0x0C        0xA0000000    NOP
dest_base + 0x10        0xA0000000    NOP
dest_base + 0x14        0xA0000000    NOP
dest_base + 0x18        0xA0000000    NOP
dest_base + 0x1C        0xA0000000    NOP
```

**Purpose**: This creates a **jump vector** or **reset handler** that branches to the loaded kernel.

### Address Space Calculation

```c
// Example with 64KB kernel:
size = 65536 (0x10000)
offset = ((65536 + 256) / 4) - 3
       = (65792 / 4) - 3
       = 16448 - 3
       = 16445 (0x403D) word offset

branch_instr = 0x68000000 | 0x0000403D = 0x6800403D

// This branches forward 16445 words = 65780 bytes from the branch instruction
// Which would be near the end of the loaded kernel
```

**Interpretation**: The branch likely points to a **kernel entry point** or **initialization routine** at the end of the loaded code.

---

## Call Graph

### Calls Made By This Function:

1. **0x5002f7e** - Lock/unlock function (called 4 times)
   - Dual locking with types 10 and 11

2. **0x05002ec4** - strcmp()
   - Validate __TEXT segment name

### Called By:

According to call graph analysis, this is a **leaf function** (depth 0, called by 0 functions in the analyzed subset).

**Likely caller**: High-level initialization function after kernel has been loaded by ND_ProcessDMATransfer.

---

## Purpose Classification

**Primary Category**: i860 Processor Initialization
**Secondary Category**: Memory Management / Code Patching
**Tertiary Category**: Boot Sequence

### Detailed Purpose:

This function implements the **final step of i860 kernel loading**:

1. **Kernel Loading Sequence**:
   - ND_ProcessDMATransfer copies kernel to i860 local memory (0x00000000+)
   - ND_WriteBranchInstruction writes entry point vector at high memory
   - i860 processor released from reset
   - i860 executes from high memory vector
   - Vector branches to kernel entry point

2. **Why High Memory?**:
   - i860 reset vector or exception handler may be at high address
   - Avoids conflict with loaded kernel at low addresses
   - Matches typical embedded processor boot patterns

3. **Why NOP Padding?**:
   - i860 has **pipeline hazards** requiring NOPs after branches
   - Provides alignment for instruction fetch
   - Standard practice for i860 assembly programming

### Protocol Integration:

```
Boot Sequence:
1. Host: ND_RegisterBoardSlot (allocate board structure)
2. Host: ND_ProcessDMATransfer (copy kernel to i860 memory @ 0x00000000)
3. Host: ND_WriteBranchInstruction (write entry vector @ high memory)
4. Host: Release i860 from reset
5. i860: Execute from reset vector (high memory)
6. i860: Branch to kernel entry point
7. i860: Kernel initialization begins
```

---

## Error Handling

### Error Codes (stored in global 0x040105b0):

| Code | Meaning                    | Trigger Condition             |
|------|----------------------------|-------------------------------|
| 0xE  | Validation failure         | strcmp() fails on "__TEXT"    |

### Error Paths:

1. **Segment Name Mismatch**: `strcmp() != 0` → unlock both locks, error code 0xE, return -1

### Resource Cleanup:

All error paths properly unlock both acquired locks before returning.

---

## Protocol Integration

### i860 Boot Process Context:

**Before this function**:
- Kernel binary has been copied to i860 local DRAM (0x00000000+)
- Kernel size is known

**This function**:
- Calculates entry point offset based on kernel size
- Writes branch vector at high memory
- Vector points back into loaded kernel

**After this function**:
- i860 released from reset (probably by another function)
- i860 PC starts at reset vector (high memory)
- Executes branch instruction
- Jumps to kernel entry point
- Kernel takes over

### Relationship to ND_ProcessDMATransfer:

| Function                   | Role                           | Memory Region     |
|----------------------------|--------------------------------|-------------------|
| ND_ProcessDMATransfer      | Copy kernel code/data          | 0x00000000+       |
| ND_WriteBranchInstruction  | Write entry point vector       | High memory       |

Both use identical **dual locking** and **__TEXT validation** patterns, confirming they're part of the same initialization sequence.

---

## i860 Architecture Details

### i860 Branch Instruction

**Opcode**: 0x68 (BR - Branch Relative)
**Format**: `BR offset26`
**Encoding**:
- Bits 31-26: 011010 (0x1A → shifted to 0x68 in top byte)
- Bits 25-0: Signed 26-bit word offset

**Behavior**:
- PC-relative branch
- Offset is in **32-bit words**, not bytes
- Effective address: `PC + (offset * 4)`
- Range: ±64MB from current instruction

### i860 Pipeline Considerations

**Why 7-8 NOPs?**:
- i860 has deep pipeline (4-5 stages)
- Branch delay slots require NOPs
- Conservative padding ensures correct execution
- Prevents instruction fetch hazards

**Standard Pattern**:
```asm
    ; Entry point at high memory (e.g., 0x07FFFF00)
    nop                ; Pipeline fill
    nop                ; Pipeline fill
    br  kernel_entry   ; Branch to loaded kernel
    nop                ; Delay slot
    nop                ; Delay slot
    nop                ; Safety padding
    nop                ; Safety padding
    nop                ; Safety padding
```

---

## m68k Architecture Details

### Register Usage:

| Register | Purpose                         | Preserved |
|----------|---------------------------------|-----------|
| A0       | board_info pointer, temp        | No        |
| A1       | Destination pointer (swapped)   | No        |
| A2       | Lock function address           | Yes       |
| A6       | Frame pointer                   | Auto      |
| D0       | Calculations, return value      | No        |
| D1       | Constants                       | No        |

### Endianness Handling:

**XOR with 0x04** pattern (same as ND_ProcessDMATransfer):
- Swaps word positions within long-words
- Handles big-endian 68040 ↔ little-endian i860

**Write pattern**:
```c
// Write to address with XOR swap
*(uint32_t*)(addr ^ 0x04) = value;

// Without swap: Writes to addr
// With swap:    Writes with byte order adjusted for i860
```

### Code Efficiency:

- **Unrolled loop**: 8 identical write blocks (no loop overhead)
- **Instruction size**: Compact (88 instructions in 352 bytes = 4 bytes/instruction average)
- **Branches**: Minimal (1 conditional, 1 unconditional)
- **Stack usage**: Minimal (24 bytes)

---

## Analysis Insights

### Key Findings:

1. **Boot Vector Creation**: Writes i860 startup code to high memory
2. **Kernel Entry Point**: Branch offset calculated from kernel size
3. **Identical Pattern to DMA**: Same locking and validation as ND_ProcessDMATransfer
4. **Pipeline Safety**: 7 NOPs ensure correct i860 pipeline behavior
5. **High Memory Target**: `board_info[0x2C] + 0x07FFFF00` likely near reset vector

### Complexity Analysis:

- **Cyclomatic Complexity**: 3 (low - single if/else)
- **Instruction Repetition**: High (8 nearly identical write blocks)
- **Code Patterns**: Defensive (extra NOPs for safety)

### Performance Characteristics:

- **Execution Time**: ~100-200 cycles (mostly lock overhead)
- **Memory Writes**: 8 long-words (32 bytes)
- **Critical Path**: Lock acquisition dominates

---

## Unanswered Questions

1. **What is the exact i860 reset vector address?**
   - Calculation uses 0x07FFFF00 offset - is this the i860 reset PC?
   - Need i860 hardware reference to confirm

2. **Why write at position 3 (not 0 or 7)?**
   - Branch is at offset +0x08 (3rd long-word)
   - May be required by i860 reset behavior
   - Could be alignment requirement

3. **What if size is very large?**
   - 26-bit offset limits range to ±64MB
   - With formula `(size+256)/4 - 3`, max size ~256MB
   - Likely sufficient for all kernels

4. **Is this called before or after ND_ProcessDMATransfer?**
   - Logic suggests: AFTER (needs kernel size)
   - But both use same validation - redundant?
   - May be defensive programming

---

## Related Functions

### Likely Call Sequence:

```
ND_RegisterBoardSlot       (allocate board_info)
    ↓
ND_ProcessDMATransfer      (load kernel to i860 memory)
    ↓
ND_WriteBranchInstruction  (write entry vector)  ← THIS FUNCTION
    ↓
ND_ReleaseReset (?)        (start i860 execution)
```

---

## Testing Notes

To verify this analysis:

1. **Capture dest_base address** during execution
2. **Dump 32 bytes** starting at dest_base to see instruction pattern
3. **Calculate expected offset** from known kernel size
4. **Compare with i860 kernel binary** to find entry point
5. **Trace i860 execution** starting from reset to verify branch target

**Expected Pattern in Memory**:
```
[dest_base+0x00]: A0 00 00 00  (NOP)
[dest_base+0x04]: A0 00 00 00  (NOP)
[dest_base+0x08]: 68 xx xx xx  (BR <offset>)
[dest_base+0x0C]: A0 00 00 00  (NOP)
[dest_base+0x10]: A0 00 00 00  (NOP)
[dest_base+0x14]: A0 00 00 00  (NOP)
[dest_base+0x18]: A0 00 00 00  (NOP)
[dest_base+0x1C]: A0 00 00 00  (NOP)
```

---

## Revision History

| Date       | Analyst     | Changes                                    |
|------------|-------------|--------------------------------------------|
| 2025-11-08 | Claude Code | Initial comprehensive analysis (v1.0)      |

---

**End of Analysis**
