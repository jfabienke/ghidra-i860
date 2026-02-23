; ============================================================================
; DISASSEMBLY: FUN_00003eae (ND_InitializeBufferWithSize)
; ============================================================================
; Address: 0x00003eae
; Size: 140 bytes (0x8C)
; Instructions: 35
; Stack Frame: 548 bytes (0x224)
;
; Purpose: Initialize and validate buffer with size constraints
;
; Function Signature:
;   long ND_InitializeBufferWithSize(
;       long *base_ptr,           // A6@0x08
;       long file_size,           // A6@0x0c
;       long max_buffer_size,     // A6@0x10
;       long config_flags         // A6@0x14
;   );
;
; Return Value:
;   D0 = 0x00000000 (success) or -0x133 (-307 error)
;
; Registers Preserved: A2, D2, D3
; ============================================================================

00003eae                                  linkw      A6,-0x224
; │ Setup stack frame
; │ Allocate 548 bytes (0x224) of local variables
; │
; │ Stack structure after LINKW:
; │   [SP]     = saved A6
; │   [SP-4]   = return address
; │   [SP-548] = local buffer area start
; └─

00003eb2                                  movem.l    {A2 D3 D2},-(SP)
; │ Save working registers on stack
; │ Push order (right-to-left): D2, D3, A2
; │ These will be popped in reverse: A2, D3, D2
; └─

00003eb6                                  move.l     (0x14,A6),D2
; │ Load parameter from stack
; │ D2 = arg4 (config_flags / size parameter)
; │ A6@0x14 = [return_addr + 0x14]
; └─

00003eba                                  lea        (-0x224,A6),A2
; │ Calculate address of local buffer area
; │ A2 = A6 - 0x224 (points to local buffer start)
; │ This is 548 bytes of allocated local stack space
; └─

00003ebe                                  moveq      0x24,D3
; │ Load constant size value
; │ D3 = 0x24 (36 decimal)
; │ Used for header offset calculation later
; └─

00003ec0                                  move.l     (0x00007a80).l,(-0x20c,A6)
; │ Copy global variable to local frame
; │ global[0x7a80] → local_frame[-0x20c]
; │ This is 0xC bytes below D2 saved location in frame
; │ Purpose: Save system state or reference data
; └─

00003ec8                                  move.l     (0xc,A6),(-0x208,A6)
; │ Copy parameter to local frame
; │ arg2 (file_size) → local_frame[-0x208]
; │ A6@0x0c = [return_addr + 0x0c]
; └─

00003ece                                  move.l     (0x00007a84).l,(-0x204,A6)
; │ Copy another global to local frame
; │ global[0x7a84] → local_frame[-0x204]
; │ Related to global[0x7a80], part of system state
; └─

00003ed6                                  cmpi.l     #0x200,D2
; │ Validate parameter size
; │ Compare D2 (arg4) with 0x200 (512 decimal)
; │ Sets condition codes based on difference
; │ Purpose: Check if size exceeds maximum allowed
; └─

00003edc                                  bhi.b      0x00003f2a
; │ Branch if Higher (unsigned comparison)
; │ If D2 > 0x200:
; │   Jump to 0x00003f2a (error handler)
; │ Else:
; │   Continue to next instruction (validation passed)
; │
; │ This enforces: arg4 must be ≤ 512 bytes
; └─

; ============================================================================
; NORMAL PATH: arg4 ≤ 512 bytes (size validation passed)
; ============================================================================

00003ede                                  move.l     D2,-(SP)
; │ Push parameter for external function call
; │ Stack[top] = D2 (arg4 / size / count)
; │ This is argument #3 (right-most in C calling convention)
; └─

00003ee0                                  move.l     (0x10,A6),-(SP)
; │ Push another parameter
; │ Stack[top] = arg3 (max_buffer_size)
; │ A6@0x10 = [return_addr + 0x10]
; │ This is argument #2
; └─

00003ee4                                  pea        (0x24,A2)
; │ Push address for external function
; │ Stack[top] = A2 + 0x24 (buffer[0x24])
; │ Points to data area within local buffer
; │ This is argument #1
; │
; │ Three parameters are now on stack:
; │   [SP+0]  = address (A2+0x24)
; │   [SP+4]  = arg3
; │   [SP+8]  = D2 (arg4)
; └─

00003ee8                                  bsr.l      0x0500294e
; │ Branch to subroutine (external function call)
; │ Address: 0x0500294e
; │
; │ Function call: process_data(buffer[0x24], arg3, arg4)
; │ Purpose: Data validation, extraction, or transformation
; │
; │ Return value in D0 (used in next instruction)
; │ Side effects: May modify memory, set condition codes
; └─

00003eee                                  bfins      D2,(-0x202,A6),0x0,0xc
; │ Bit Field Insert operation
; │ Source: D2 (lower 12 bits)
; │ Destination: frame[-0x202] (12 bytes into frame area)
; │ Offset: 0 (start at bit position 0)
; │ Width: 0xc (12 bits)
; │
; │ Operation: Insert bits 0:12 of D2 into frame[-0x202]
; │ This stores the configuration flags (0-4095 range)
; │ Preserves upper bits of destination
; └─

00003ef4                                  move.l     D2,D0
; │ Copy D2 to D0 for calculation
; │ D0 = D2 (arg4 value)
; │ Prepare for size alignment calculation
; └─

00003ef6                                  addq.l     0x3,D0
; │ Add 3 to D0 for alignment rounding
; │ D0 = D0 + 3
; │
; │ This rounds up to next 4-byte boundary:
; │ If D0 = 0x01: D0 becomes 0x04
; │ If D0 = 0x04: D0 becomes 0x07
; │ etc.
; └─

00003ef8                                  moveq      -0x4,D1
; │ Load alignment mask (all bits set except last 2)
; │ D1 = 0xFFFFFFFC
; │ Binary: ...11111100
; │ Masks out lower 2 bits
; └─

00003efa                                  and.l      D1,D0
; │ Apply alignment mask
; │ D0 = D0 & 0xFFFFFFFC
; │ Clears lower 2 bits (aligns down to 4-byte boundary)
; │
; │ Combined with previous ADDQ:
; │ Result: align_up_to_4byte(D2 + 3) → D0
; │
; │ Examples:
; │   Input D2=0x01 → D0=(0x01+3)&~3 = 0x04
; │   Input D2=0x04 → D0=(0x04+3)&~3 = 0x04
; │   Input D2=0x05 → D0=(0x05+3)&~3 = 0x08
; │   Input D2=0xFF → D0=(0xFF+3)&~3 = 0x100
; └─

00003efc                                  move.b     #0x1,(-0x221,A6)
; │ Set flag byte in frame structure
; │ frame[-0x221] = 0x01
; │
; │ This indicates:
; │   Enabled/active flag
; │   Or: buffer is initialized and ready
; └─

00003f02                                  add.l      D3,D0
; │ Add header offset to aligned size
; │ D0 = D0 + D3
; │ D0 = D0 + 0x24 (add 36 bytes for header)
; │
; │ Final buffer size:
; │ D0 = align_up_to_4byte(arg4 + 3) + 0x24
; │
; │ Examples:
; │   arg4=0x10 → D0=0x10+3=0x13, align→0x10, +0x24→0x34
; │   arg4=0x100 → D0=0x100+3=0x103, align→0x100, +0x24→0x124
; │   arg4=0x200 → D0=0x200+3=0x203, align→0x200, +0x24→0x224
; └─

00003f04                                  move.l     D0,(-0x220,A6)
; │ Store calculated size in frame structure
; │ frame[-0x220] = D0 (total buffer size)
; │
; │ This is the control structure entry for size tracking
; └─

00003f08                                  clr.l      (-0x21c,A6)
; │ Clear frame field
; │ frame[-0x21c] = 0
; │ Initialize field #1 to zero
; └─

00003f0c                                  move.l     (0x8,A6),(-0x214,A6)
; │ Copy parameter to frame structure
; │ arg1 (base_ptr) → frame[-0x214]
; │ A6@0x08 = [return_addr + 0x08]
; │
; │ Store the base address pointer for reference
; └─

00003f12                                  clr.l      (-0x218,A6)
; │ Clear another frame field
; │ frame[-0x218] = 0
; │ Initialize field #2 to zero
; └─

00003f16                                  moveq      0x66,D1
; │ Load magic/control number
; │ D1 = 0x66 (102 decimal)
; │
; │ This appears to be:
; │   Control value identifier
; │   Command type or handler ID
; │   Status/state indicator
; └─

00003f18                                  move.l     D1,(-0x210,A6)
; │ Store control value in frame structure
; │ frame[-0x210] = 0x66
; │
; │ This is part of the control/metadata structure
; │ Used by callback to identify message type or handler
; └─

00003f1c                                  clr.l      -(SP)
; │ Push NULL pointer on stack
; │ Stack[top] = 0x00000000
; │ This is argument #2 for next function call
; └─

00003f1e                                  clr.l      -(SP)
; │ Push another NULL pointer on stack
; │ Stack[top] = 0x00000000
; │ This is argument #3 for next function call
; └─

00003f20                                  move.l     A2,-(SP)
; │ Push buffer address on stack
; │ Stack[top] = A2 (address of local buffer)
; │ This is argument #1 for next function call
; │
; │ Three arguments now stacked:
; │   [SP+0]  = A2 (buffer address)
; │   [SP+4]  = 0 (NULL)
; │   [SP+8]  = 0 (NULL)
; └─

00003f22                                  bsr.l      0x050029d2
; │ Branch to subroutine (callback function)
; │ Address: 0x050029d2
; │
; │ Function call: callback(buffer_ptr, NULL, NULL)
; │ Purpose: Signal completion or process initialized buffer
; │
; │ This is the completion/notification function
; │ The buffer is now fully initialized and ready
; └─

00003f28                                  bra.b      0x00003f30
; │ Branch unconditionally to cleanup
; │ Jump directly to register restoration
; │ Skip the error handling section
; │
; │ This branch ensures:
; │   Success path exits cleanly
; │   Error path is separate (below)
; └─

; ============================================================================
; ERROR PATH: arg4 > 512 bytes (size validation failed)
; ============================================================================

00003f2a                                  move.l     #-0x133,D0
; │ Set error return code
; │ D0 = -0x133 (decimal: -307)
; │
; │ Error meaning:
; │   Invalid size parameter
; │   Buffer exceeds maximum allocation limit
; │
; │ Falls through to cleanup (no branch)
; └─

; ============================================================================
; CLEANUP & RETURN
; ============================================================================

00003f30                                  movem.l    -0x230,A6,{D2 D3 A2}
; │ Restore registers from stack frame
; │ Restore in reverse order of preservation:
; │   A2 ← frame[-0x00c] (was saved first, pop last)
; │   D3 ← frame[-0x008]
; │   D2 ← frame[-0x004]
; │
; │ Note: -0x230 offset from A6 means:
; │   A6 - 0x230 = position of saved registers
; │   This is 4 bytes above frame[-0x224]
; └─

00003f36                                  unlk       A6
; │ Unwind stack frame
; │ Restore original A6 (frame pointer)
; │ Deallocate 548 bytes of local variables
; │
; │ After this instruction:
; │   SP points to return address
; │   A6 restored to caller's frame pointer
; └─

00003f38                                  rts
; │ Return to subroutine
; │ Pop return address from stack and jump
; │
; │ Control returns to caller
; │ Return value in D0:
; │   0x00000000 = success
; │   -0x133 = error (size > 512)
; └─

; ============================================================================
; END OF FUNCTION
; ============================================================================

; Offset Summary:
; 00003eae: linkw      (2 bytes, setup frame)
; 00003eb2: movem.l    (4 bytes, save registers)
; 00003eb6: move.l     (4 bytes, load parameter)
; 00003eba: lea        (4 bytes, get buffer address)
; 00003ebe: moveq      (2 bytes, load constant)
; 00003ec0: move.l     (8 bytes, copy global)
; 00003ec8: move.l     (6 bytes, copy parameter)
; 00003ece: move.l     (8 bytes, copy global)
; 00003ed6: cmpi.l     (6 bytes, compare)
; 00003edc: bhi.b      (2 bytes, branch if error)
; 00003ede: move.l     (4 bytes, push parameter)
; 00003ee0: move.l     (6 bytes, push parameter)
; 00003ee4: pea        (6 bytes, push address)
; 00003ee8: bsr.l      (6 bytes, call external)
; 00003eee: bfins      (6 bytes, bit field insert)
; 00003ef4: move.l     (2 bytes, copy register)
; 00003ef6: addq.l     (2 bytes, add 3)
; 00003ef8: moveq      (2 bytes, load mask)
; 00003efa: and.l      (2 bytes, apply mask)
; 00003efc: move.b     (6 bytes, set flag)
; 00003f02: add.l      (2 bytes, add offset)
; 00003f04: move.l     (6 bytes, store size)
; 00003f08: clr.l      (6 bytes, clear field)
; 00003f0c: move.l     (6 bytes, copy base)
; 00003f12: clr.l      (6 bytes, clear field)
; 00003f16: moveq      (2 bytes, load magic)
; 00003f18: move.l     (6 bytes, store magic)
; 00003f1c: clr.l      (4 bytes, push NULL)
; 00003f1e: clr.l      (4 bytes, push NULL)
; 00003f20: move.l     (4 bytes, push buffer)
; 00003f22: bsr.l      (6 bytes, call callback)
; 00003f28: bra.b      (2 bytes, jump cleanup)
; 00003f2a: move.l     (6 bytes, error code)
; 00003f30: movem.l    (6 bytes, restore registers)
; 00003f36: unlk       (2 bytes, unwind frame)
; 00003f38: rts        (2 bytes, return)
;
; Total: 140 bytes (0x8C)

; ============================================================================
; FRAME LAYOUT at [A6-0x224 to A6+0x14]
; ============================================================================
;
; A6+0x14:  [arg4: config_flags] ← STACK PARAMETER #4
; A6+0x10:  [arg3: max_buffer_size] ← STACK PARAMETER #3
; A6+0x0c:  [arg2: file_size] ← STACK PARAMETER #2
; A6+0x08:  [arg1: base_ptr] ← STACK PARAMETER #1
; A6+0x04:  [return address] ← CALLER RETURN ADDR
; A6+0x00:  [saved A6] ← FRAME POINTER SAVE
; A6-0x04:  [saved D2]
; A6-0x08:  [saved D3]
; A6-0x0c:  [saved A2]
; A6-0x10 to A6-0x224: [LOCAL BUFFER AREA] (548 bytes)
;
; Local variable offsets (from A6):
; A6-0x200: [buffer data area start, offset 0x00]
; A6-0x224: [buffer data area end]
; A6-0x202: [config bits (12-bit field from arg4)]
; A6-0x204: [global[0x7a84]]
; A6-0x208: [arg2 copy (file_size)]
; A6-0x20c: [global[0x7a80]]
; A6-0x210: [magic number = 0x66]
; A6-0x214: [base pointer (arg1)]
; A6-0x218: [reserved/zero]
; A6-0x21c: [reserved/zero]
; A6-0x220: [calculated total size]
; A6-0x221: [flag byte = 0x01]

; ============================================================================
; CONTROL STRUCTURE TEMPLATE (548 bytes on stack)
; ============================================================================
;
; Offset  Size  Field Name              Purpose
; ------  ----  ---------------------  ---------------------------------
;  0x00   36b   Header / Metadata       (offset 0x00-0x23)
;  0x24  476b   Data Payload            (offset 0x24-0x1FF)
;  0x200   2b   (in parent frame)       Configuration/size tracking
;  0x202   4b   Config Bits             12 bits from arg4 (BFINS location)
;  0x204   4b   Global State            From global[0x7a84]
;  0x208   4b   File Size               Copy of arg2
;  0x20c   4b   Global State            From global[0x7a80]
;  0x210   4b   Control Value           Magic = 0x66 (102)
;  0x214   4b   Base Pointer            From arg1
;  0x218   4b   Reserved                Zero-filled
;  0x21c   4b   Reserved                Zero-filled
;  0x220   4b   Total Size              Aligned size of arg4 + 0x24
;  0x221   1b   Status Flag             0x01 = enabled/active
;
; Total Frame: 548 bytes (0x224)

; ============================================================================
; EXTERNAL FUNCTION DETAILS
; ============================================================================
;
; Function 1: 0x0500294e (Data processor)
; Called: 0x00003ee8
; Parameters:
;   SP[0] = address (A2 + 0x24, buffer data pointer)
;   SP[4] = arg3 (max_buffer_size)
;   SP[8] = arg4 (size/count parameter)
; Return: D0 (used implicitly in BFINS)
; Purpose: Data validation, extraction, or processing
;
; Function 2: 0x050029d2 (Completion callback)
; Called: 0x00003f22
; Parameters:
;   SP[0] = A2 (initialized buffer address)
;   SP[4] = 0 (NULL)
;   SP[8] = 0 (NULL)
; Return: (not checked)
; Purpose: Signal completion or queue message for processing

; ============================================================================
; ERROR CODES
; ============================================================================
;
; Return Code   Decimal   Hex      Meaning
; -----------   -------   -------  ----------------------------------
; 0x00000000    0         0x000    SUCCESS - buffer initialized
; -0x133        -307      0xFFFFFFED  ERROR - size > 512 bytes
;
; The -0x133 error indicates that arg4 (config_flags) exceeds 512 bytes,
; which is the maximum allowed buffer size for this function.

; ============================================================================
; RELATED FUNCTIONS
; ============================================================================
;
; FUN_00003f3a (0x00003f3a):
;   Similar function, uses magic = 0x67 instead of 0x66
;   Size constant = 0x20 instead of 0x24
;   Same validation pattern (max 512 bytes)
;   Calls similar external functions
;
; FUN_00004024 (0x00004024):
;   Another variant, uses magic = 0x68
;   Size constant = 0x28
;   Follows same initialization pattern
;
; Pattern: These three functions are likely variants of a single
;          initialization template with parameter variation.
;          Possible tool-generated code or copy-paste pattern.

; ============================================================================
; CALLING CONTEXT
; ============================================================================
;
; Caller: FUN_00006e6c (at 0x00006e6c)
; Call 1: 0x00006efe
;   Parameters on stack (in call order):
;     0x00006efa: move.l (0x10,A3),-(SP)   → arg1 (first pushed)
;     0x00006f00: move.l (0x18,A3),-(SP)   → arg2
;     0x00006f02: pea (0x20,A3)            → arg3
;     0x00006efc: pea (0x1ff).w            → arg4 (last pushed)
;     0x00006efe: bsr.l 0x00003eae        → CALL
;
; Call 2: 0x00006f4a (in same function)
;   Similar pattern, different specific values
;
; Usage: FUN_00003eae is called twice within FUN_00006e6c
;        Possibly for different buffer types or phases

; ============================================================================
