; ============================================================================
; Function: FUN_000063c0 (Hardware Access Callback Wrapper)
; Address: 0x000063c0 - 0x000063e7
; Size: 40 bytes (10 instructions)
; Category: Hardware Access Wrapper / Error Handler
; Confidence: HIGH (mechanics), MEDIUM (purpose)
; ============================================================================
;
; SUMMARY:
; Small wrapper function that:
;   1. Calls external hardware function at 0x05002228 with param1
;   2. Checks if result = -1 (error condition)
;   3. If error: stores global data at param2
;   4. Returns hardware function result unchanged
;
; CALLING CONVENTION: Motorola 68040 standard (A6 frame pointer)
; REGISTERS AFFECTED: A2, D0, D1 (D0 returned)
; STACK FRAME: 0 bytes
;
; ============================================================================

0x000063c0:  linkw      %fp,#0
;            │
;            └─ Establish stack frame
;               FP = SP (offset 0 = no local variables)
;               Previous A6 saved at SP
;               Next instruction at 0x000063c4
;
;            STACK STATE:
;            ┌──────────────────┐
;            │ Return address   │  SP+0
;            ├──────────────────┤
;            │ Previous A6      │  SP+4  (saved by LINKW)
;            ├──────────────────┤
;            │ param2 @ A6+12   │  SP+8
;            ├──────────────────┤
;            │ param1 @ A6+16   │  SP+12
;            └──────────────────┘
;
;            EFFECT: A6 now points to caller's A6, A7 decremented by 4
;            SIZE: 4 bytes
;            EXECUTION: ~4 cycles (best case)

0x000063c4:  movel      %a2,%sp@-
;            │
;            └─ Save A2 register to stack (callee-save preservation)
;               A2 is used later (0x63c6) to hold param2 address
;               Must be restored before function return
;               Destination: SP (pre-decrement), so SP -= 4 first
;
;            OPERATION SEMANTICS:
;            1. SP = SP - 4
;            2. Memory[SP] = A2
;            3. No register modification
;
;            STACK STATE AFTER:
;            ┌──────────────────┐
;            │ Return address   │  SP+0
;            ├──────────────────┤
;            │ Previous A6      │  SP+4
;            ├──────────────────┤
;            │ Saved A2         │  SP+8  ← SP now points here
;            ├──────────────────┤
;            │ param2           │  SP+12
;            ├──────────────────┤
;            │ param1           │  SP+16
;            └──────────────────┘
;
;            SIZE: 4 bytes
;            EXECUTION: ~4 cycles

0x000063c6:  moveal     %fp@(12),%a2
;            │
;            └─ Load param2 (second parameter) into A2
;               param2 is at offset +12 from A6 (caller's frame)
;               This address is destination for conditional error write
;
;            OPERATION SEMANTICS:
;            A2 = Memory[A6 + 12]
;            (32-bit address load)
;
;            ADDRESSING MODE:
;            - Indirect with displacement (A6@(12))
;            - MOVEAL (address register target, sign-extension)
;
;            REGISTER STATE:
;            Before: A2 = undefined
;            After:  A2 = param2 (address)
;
;            PURPOSE:
;            param2 is a pointer to error buffer
;            A2 holds this address for use in conditional write at 0x63da
;
;            SIZE: 4 bytes
;            EXECUTION: ~6 cycles

0x000063ca:  movel      %fp@(16),%sp@-
;            │
;            └─ Load param1 (first parameter) and push to stack
;               param1 is at offset +16 from A6
;               Pushed so it becomes arg0 for next function call
;               Destination: SP (pre-decrement), so SP -= 4 first
;
;            OPERATION SEMANTICS:
;            1. SP = SP - 4
;            2. Memory[SP] = param1
;            3. No register modification
;            4. param1 remains at A6+16
;
;            PURPOSE:
;            param1 is passed to hardware function at 0x05002228
;            68040 calling convention: arguments on stack (right-to-left)
;            By pushing here, it becomes stack argument 0
;
;            STACK STATE AFTER:
;            ┌──────────────────┐
;            │ Return address   │  SP+0
;            ├──────────────────┤
;            │ Previous A6      │  SP+4
;            ├──────────────────┤
;            │ Saved A2         │  SP+8
;            ├──────────────────┤
;            │ param1 (copy)    │  SP+12  ← SP now points here
;            ├──────────────────┤
;            │ (original param2)│  SP+16
;            ├──────────────────┤
;            │ (original param1)│  SP+20
;            └──────────────────┘
;
;            SIZE: 4 bytes
;            EXECUTION: ~6 cycles

0x000063ce:  bsr.l      0x05002228
;            │
;            └─ Branch to subroutine at 0x05002228 (external hardware function)
;               This is a LONG branch (32-bit displacement)
;               Return address (0x000063d4) is pushed to stack by BSR.L
;               Return value will be in D0
;
;            OPERATION SEMANTICS:
;            1. SP = SP - 4
;            2. Memory[SP] = PC + 6  (return address: 0x000063d4)
;            3. PC = 0x05002228 (call target)
;            4. Continue execution at 0x05002228
;
;            HARDWARE CALL SEMANTICS:
;            - Function: Unknown (external ROM at 0x05002228)
;            - Parameter: param1 on stack
;            - Return: Result in D0 (32-bit signed integer)
;            - Effect: Unknown (likely I/O register access)
;
;            CRITICAL: Return value in D0 is:
;              -1  = Error condition (triggers line 0x63da)
;              0+  = Success (passes through to return)
;
;            STACK STATE DURING CALL:
;            ┌──────────────────┐
;            │ Return address   │  SP+0  (pushed by BSR.L)
;            ├──────────────────┤
;            │ Saved A2 (x2)    │  SP+4
;            ├──────────────────┤
;            │ param1 (arg)     │  SP+8
;            ├──────────────────┤
;            │ Orig saved A2    │  SP+12
;            ├──────────────────┤
;            │ ...original...   │  SP+16+
;            └──────────────────┘
;
;            NOTE: External function may modify registers/stack
;            Unknown return values for registers other than D0
;
;            SIZE: 6 bytes (long branch displacement)
;            EXECUTION: Unknown (external function cost)

0x000063d4:  moveq      #-1,%d1
;            │
;            └─ Load constant -1 (0xFFFFFFFF) into D1
;               This is the error sentinel value
;               Used to compare against hardware return value (D0)
;               MOVEQ is "quick" move (immediate fits in 8 bits)
;
;            OPERATION SEMANTICS:
;            D1 = sign_extend_8_to_32(-1)
;            D1 = 0xFFFFFFFF
;
;            FLAG STATE AFTER:
;            Z = 0  (D1 != 0)
;            N = 1  (D1 < 0, sign bit set)
;            V = 0  (no overflow)
;            C = 0  (no carry)
;
;            PURPOSE:
;            Prepare comparison value for next instruction (CMPL)
;            -1 is the "error" return value from hardware function
;
;            EFFICIENCY NOTE:
;            MOVEQ is fastest way to load into D register
;            2 bytes instruction (opcode + data)
;
;            SIZE: 2 bytes
;            EXECUTION: ~2 cycles

0x000063d6:  cmpl       %d0,%d1
;            │
;            └─ Compare D1 (-1) against D0 (hardware result)
;               This computes D0 - D1 and sets flags, without changing D0/D1
;               Next instruction (BNE) will branch based on flags
;
;            OPERATION SEMANTICS:
;            Flags = D0 - D1  (discard result, keep flags)
;
;            FLAG RESULTS:
;            If (D0 == D1):   Z = 1  (Branch Not Taken, fall through)
;            If (D0 != D1):   Z = 0  (Branch Taken, jump to 0x63e0)
;
;            REGISTER STATE:
;            D0 = unchanged (return value preserved)
;            D1 = unchanged (-1 preserved)
;
;            DATA FLOW:
;            ┌─────────────────┐
;            │  Hardware call  │
;            │   returns D0    │
;            └────────┬────────┘
;                     │
;            ┌────────v─────────┐
;            │ CMPL checks if   │
;            │ D0 == -1?        │
;            └────────┬─────────┘
;                     │
;                 ┌───┴───┐
;                 │       │
;         D0=-1   │       │  D0!=-1
;         (error) │       │  (success)
;                 │       │
;
;            SIZE: 6 bytes
;            EXECUTION: ~6 cycles

0x000063d8:  bne.b      0x000063e0
;            │
;            └─ Branch if Not Equal (Z flag = 0)
;               Conditional branch to 0x000063e0
;               If Z = 0 (D0 != -1): Jump to 0x63e0 (skip error handler)
;               If Z = 1 (D0 = -1):  Fall through to 0x63da (execute error handler)
;
;            OPERATION SEMANTICS:
;            If Z == 0:
;                PC = PC + displacement (0x000063e0)
;            Else:
;                PC = PC + 2 (next instruction at 0x000063da)
;
;            CONTROL FLOW AFTER:
;            ┌────────────────────────┐
;            │ Compare result: D0-(-1) │
;            └────────┬───────────────┘
;                     │
;                 ┌───┴───────────┐
;                 │               │
;          Z=1 (D0=-1)        Z=0 (D0!=-1)
;          Fall through     Branch taken
;               │               │
;               ├───────────────┤
;               │               │
;        0x63da: Store    0x63e0: Skip
;        global at        error
;        param2           handler
;
;            BRANCH TARGET: 0x000063e0 (within function)
;            - 8 bytes forward
;            - Destination: MOVEAL restore instruction
;
;            SIZE: 2 bytes (byte offset)
;            EXECUTION: ~4 cycles (taken), ~2 cycles (not taken)

0x000063da:  movel      (0x040105b0).l,(%a2)
;            │
;            └─ Store error state (EXECUTED ONLY IF D0 = -1)
;               This instruction is skipped if D0 != -1 (branch taken)
;
;            OPERATION SEMANTICS:
;            temp = Memory[0x040105b0]     ; Load global error data
;            Memory[A2] = temp             ; Store to error buffer
;
;            ADDRESSING MODES:
;            Source: Absolute long (0x040105b0)
;            Dest:   Indirect (A2) - A2 holds param2 pointer
;
;            DATA FLOW:
;            0x040105b0 (global) ──┐
;                                  ├──> Memory[A2] (caller's buffer)
;                                  │
;            A2 (from param2) ────┘
;
;            PURPOSE:
;            When hardware returns -1 (error), capture error state
;            Store global error data to caller-provided buffer
;            Caller can then inspect buffer for error details
;
;            REGISTER STATE:
;            A2 = unchanged (still points to error buffer)
;            D0 = unchanged (still contains -1)
;            D1 = unchanged (still contains -1)
;
;            MEMORY EFFECT:
;            Before: (A2) = caller's buffer (undefined content)
;            After:  (A2) = copy of (0x040105b0)
;
;            NOTE: This line executes conditionally
;            Only when previous compare determined D0 = -1
;            The BNE.B at 0x63d8 is the gate
;
;            SIZE: 12 bytes (long absolute addressing requires extended instruction)
;            EXECUTION: ~12 cycles (memory read + write)

0x000063e0:  moveal     (-0x4,%a6),%a2
;            │
;            └─ Restore A2 register from stack before return
;               This is the merge point from both paths (error and success)
;               A2 was saved at 0x63c4, now being restored
;
;            OPERATION SEMANTICS:
;            A2 = Memory[A6 - 4]
;
;            ADDRESSING MODE:
;            Indirect with displacement: A6 - 4
;            Points to location where A2 was saved by MOVEL at 0x63c4
;
;            REGISTER STATE:
;            Before: A2 = either param2 (if came from 0x63da) or modified
;            After:  A2 = restored to caller's original value
;
;            STACK FRAME:
;            A6 - 4 = location of saved A2
;            A6 - 0 = where frame pointer A6 was saved by LINKW
;            A6 + 4 = return address to caller
;            A6 + 8 = param1 (caller's stack)
;            A6 + 12= param2 (caller's stack)
;
;            PURPOSE:
;            Restore A2 to caller's value (callee-save register)
;            This must be done before UNLK to prepare for cleanup
;
;            SIZE: 4 bytes
;            EXECUTION: ~6 cycles

0x000063e4:  unlk       %a6
;            │
;            └─ Unwind stack frame and restore caller's A6
;               Reverse operation of LINKW at 0x63c0
;
;            OPERATION SEMANTICS:
;            A7 = A6
;            A6 = Memory[A6]
;            (Restore caller's A6 and SP in one operation)
;
;            STACK STATE AFTER:
;            SP now points to return address (ready for RTS)
;            A6 restored to caller's value
;            Local storage area reclaimed
;
;            EFFECT:
;            Before UNLK:
;            ┌──────────────────┐
;            │ Return address   │  SP
;            ├──────────────────┤
;            │ Saved A2 (now OK)│  SP+4
;            ├──────────────────┤
;            │ (recovered)      │  SP+8
;            └──────────────────┘
;
;            After UNLK:
;            ┌──────────────────┐
;            │ Return address   │  SP (A7)
;            ├──────────────────┤
;            │ (caller's area)  │  SP+4
;            └──────────────────┘
;
;            SIZE: 4 bytes
;            EXECUTION: ~4 cycles

0x000063e6:  rts
;            │
;            └─ Return from subroutine to caller
;               Pop return address from stack and jump to it
;
;            OPERATION SEMANTICS:
;            PC = Memory[SP]
;            SP = SP + 4
;            Resume execution at return address
;
;            RETURN VALUE:
;            D0 = Hardware function result
;            (Unchanged from 0x63ce return)
;
;            REGISTER STATE AT RETURN:
;            D0 = Result from hardware call (status code)
;            A0-A1, A3-A7 = Caller's state (preserved or modified by caller)
;            A2 = Restored to caller's value
;            D1-D7 = Caller's state (preserved or modified by caller)
;
;            CALLER EXPECTATIONS:
;            After RTS:
;            - Function result in D0
;            - Stack pointer restored (SP now past return address)
;            - All registers restored or caller-save (D0 exception)
;
;            SIZE: 2 bytes
;            EXECUTION: ~4 cycles

; ============================================================================
; EXECUTION PATH SUMMARY
; ============================================================================
;
; SUCCESS PATH (D0 != -1):
; ┌─────────────────────┐
; │ LINKW (frame setup) │  0x63c0 (4 bytes)
; ├─────────────────────┤
; │ MOVEL save A2       │  0x63c4 (4 bytes)
; ├─────────────────────┤
; │ MOVEAL load param2  │  0x63c6 (4 bytes)
; ├─────────────────────┤
; │ MOVEL push param1   │  0x63ca (4 bytes)
; ├─────────────────────┤
; │ BSR.L hardware call │  0x63ce (6 bytes) → returns with D0=result
; ├─────────────────────┤
; │ MOVEQ -1 to D1      │  0x63d4 (2 bytes)
; ├─────────────────────┤
; │ CMPL check D0=-1?   │  0x63d6 (6 bytes) → sets Z=0 if D0!=-1
; ├─────────────────────┤
; │ BNE skip error      │  0x63d8 (2 bytes) → BRANCHES to 0x63e0 (TAKEN)
; ├─────────────────────┤
; │ [MOVEL error store] │  0x63da (12 bytes) ← SKIPPED (branch taken)
; ├─────────────────────┤
; │ MOVEAL restore A2   │  0x63e0 (4 bytes)
; ├─────────────────────┤
; │ UNLK unwind frame   │  0x63e4 (4 bytes)
; ├─────────────────────┤
; │ RTS return          │  0x63e6 (2 bytes) → returns to caller
; └─────────────────────┘
; Total: 54 bytes of execution (12 bytes skipped), ~46 cycles
;
; ERROR PATH (D0 = -1):
; ┌─────────────────────┐
; │ LINKW (frame setup) │  0x63c0 (4 bytes)
; ├─────────────────────┤
; │ MOVEL save A2       │  0x63c4 (4 bytes)
; ├─────────────────────┤
; │ MOVEAL load param2  │  0x63c6 (4 bytes)
; ├─────────────────────┤
; │ MOVEL push param1   │  0x63ca (4 bytes)
; ├─────────────────────┤
; │ BSR.L hardware call │  0x63ce (6 bytes) → returns with D0=-1
; ├─────────────────────┤
; │ MOVEQ -1 to D1      │  0x63d4 (2 bytes)
; ├─────────────────────┤
; │ CMPL check D0=-1?   │  0x63d6 (6 bytes) → sets Z=1 if D0=-1
; ├─────────────────────┤
; │ BNE skip error      │  0x63d8 (2 bytes) → FALLS THROUGH (NOT TAKEN)
; ├─────────────────────┤
; │ MOVEL error store   │  0x63da (12 bytes) ← EXECUTED (fall through)
; ├─────────────────────┤
; │ MOVEAL restore A2   │  0x63e0 (4 bytes)
; ├─────────────────────┤
; │ UNLK unwind frame   │  0x63e4 (4 bytes)
; ├─────────────────────┤
; │ RTS return          │  0x63e6 (2 bytes) → returns to caller
; └─────────────────────┘
; Total: 66 bytes of execution, ~58 cycles
;
; ============================================================================
; REGISTER TRACKING
; ============================================================================
;
; D0 (Return Value Register):
;   Entry:     Undefined
;   0x63ce:    Loaded by BSR.L (hardware result)
;   0x63d6:    Used in CMPL (comparison operand)
;   Exit:      Contains hardware function result (pass-through)
;
; D1 (Temporary Comparison):
;   Entry:     Undefined
;   0x63d4:    Loaded with -1 (0xFFFFFFFF)
;   0x63d6:    Used in CMPL (comparison operand)
;   Exit:      May contain -1 (caller mustn't depend on this)
;
; A2 (Destination Pointer):
;   Entry:     Undefined (callee-save)
;   0x63c4:    Saved to stack [A6-4]
;   0x63c6:    Loaded with param2 address
;   0x63da:    Used as write destination (if error)
;   0x63e0:    Restored from stack
;   Exit:      Restored to caller's original value (preserved)
;
; A6 (Frame Pointer):
;   Entry:     Caller's frame pointer
;   0x63c0:    Modified by LINKW (set to SP)
;   Throughout: Provides offset base for parameter access
;   0x63e4:    Modified by UNLK (restored from [A6])
;   Exit:      Restored to caller's value
;
; A7/SP (Stack Pointer):
;   Entry:     Points to return address
;   0x63c0:    Decremented by 4 (LINKW)
;   0x63c4:    Decremented by 4 (MOVEL save)
;   0x63ca:    Decremented by 4 (MOVEL push)
;   0x63ce:    Decremented by 4 (BSR.L call)
;   0x63e4:    Restored by UNLK
;   0x63e6:    Incremented by 4 (RTS)
;   Exit:      Restored to caller's value
;
; ============================================================================
; MEMORY ACCESS PATTERNS
; ============================================================================
;
; STACK READS (Parameter Access):
;   A6@(12) → param2 (read at 0x63c6)
;   A6@(16) → param1 (read at 0x63ca)
;
; STACK WRITES (Register Preservation):
;   SP@- → Save A2 (write at 0x63c4)
;   SP@- → Push param1 (write at 0x63ca)
;   SP@- → Return address (write at 0x63ce via BSR.L)
;
; GLOBAL READS (Conditional Error Data):
;   0x040105b0 → error state (read at 0x63da if D0=-1)
;
; INDIRECT WRITES (Conditional Error Store):
;   (A2) → error buffer (write at 0x63da if D0=-1)
;
; ============================================================================
; CALLING CONVENTION ANALYSIS
; ============================================================================
;
; MOTOROLA 68040 CALLING CONVENTION:
;
; Argument Passing:
;   - Arguments passed on stack (right-to-left order)
;   - No registers used for small integer arguments
;   - Caller responsibility: push arguments in reverse order
;
; Return Values:
;   - 32-bit integer: D0 (long/pointer)
;   - 64-bit integer: D0:D1
;
; Register Preservation:
;   - Callee-save: A2-A7, D2-D7
;   - Caller-save: A0-A1, D0-D1
;   - This function preserves A2 (callee-save)
;
; Stack Frame:
;   - Optional (this function uses 0-byte frame)
;   - LINKW creates frame if needed
;   - UNLK restores frame
;
; ============================================================================
; CALLING CONTEXT (0x00006ac2)
; ============================================================================
;
; Call Site: 0x00006b3a
;   pea        (0x2c,A2)     ; Push &struct[0x2c] → param2 dest
;   pea        (0x1c,A2)     ; Push &struct[0x1c] → param2
;   movel      (0xc,A2),-(SP); Push struct[0xc] → param1 value
;   bsr.l      0x000063c0    ; Call FUN_000063c0
;   movel      D0,(0x24,A3)  ; Store result in A3[0x24]
;
; Arguments Reconstructed:
;   param1 = struct[0xc]        (hardware value)
;   param2 = &struct[0x1c]      (error buffer address)
;
; Return Value Usage:
;   D0 stored in A3[0x24]       (result saved to caller's state)
;
; Caller Function: FUN_00006ac2 (178 bytes)
;   Purpose: Complex hardware transaction handler
;   Registers: A2=source struct, A3=dest struct
;
; ============================================================================
; FILE METADATA
; ============================================================================
;
; Source: Ghidra export (disassembly_full.asm)
; Disassembler: MAME/Ghidra i860/68k backend
; Analysis Date: November 9, 2025
; Confidence: HIGH (instruction-level), MEDIUM (semantic)
;
; Instruction Count: 10
; Branch Count: 1 (conditional)
; External Calls: 1 (0x05002228)
; Global Data Access: 1 conditional (0x040105b0)
;
; === END OF FILE ===
