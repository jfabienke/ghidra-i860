# NeXTdimension Kernel Reverse Engineering Playbook
## Systematic Mapping of the 720 KB __TEXT Segment

**Document Date**: November 5, 2025
**Target**: ND_MachDriver_reloc (stripped i860 kernel binary)
**Challenge**: 730,440 bytes of executable code with ZERO symbols
**Strategy**: "Landmark and Explore" methodology
**Goal**: Complete functional map of all kernel code

---

## Executive Summary

**The Challenge**:
```
File: ND_MachDriver_reloc
Size: 720 KB of executable code
Symbols: 0 (completely stripped)
Functions: ~500-1000 estimated
Documentation: None
Source code: Lost (NeXT closed in 1997)

Status: Unknown territory
```

**The Strategy**:
```
1. Find Landmarks → Entry points, exception vectors, hardware registers
2. Trace Pathways → Follow code execution from landmarks
3. Identify Structures → Recognize patterns (loops, memcpy, etc.)
4. Deduce Purpose → Infer function purpose from behavior
5. Document Everything → Label, comment, repeat
```

**Expected Timeline**:
- Phase 1 (Tooling): 1-2 days
- Phase 2 (Landmarks): 3-5 days
- Phase 3 (Core Tracing): 2-4 weeks
- Phase 4 (Pattern Recognition): 2-3 weeks
- Phase 5 (Complete Mapping): 6-12 weeks total

**This is archaeological work** - we're mapping an ancient city with no street signs.

---

## Part 1: Strategy Overview - "Landmark and Explore"

### The Archaeologist's Approach

Imagine you're exploring Pompeii with no map. How do you proceed?

```
Step 1: Find obvious landmarks
  → Forum (city center)
  → Amphitheater (entertainment)
  → Aqueduct (infrastructure)

Step 2: Trace roads between landmarks
  → This road connects forum to amphitheater
  → This one goes to residential area

Step 3: Identify building types by structure
  → This has an oven → bakery
  → This has mosaic floors → wealthy villa
  → This has counters → shop

Step 4: Deduce purpose from artifacts
  → Amphora of wine → wine shop
  → Medical tools → doctor's office
  → Graffiti about gladiators → near arena

Step 5: Create a map
  → Document everything you've learned
  → Share knowledge with other archaeologists
```

**Same approach for reverse engineering**:

```
Step 1: Find obvious landmarks (hardware interactions, vectors)
Step 2: Trace execution paths (calls, branches)
Step 3: Identify function types (loops, dispatchers, handlers)
Step 4: Deduce purpose (what registers touched, what called)
Step 5: Create a map (label functions, document findings)
```

---

## Part 2: Tooling and Environment Setup

### Phase 1: Choose Your Weapon

**Option A: Ghidra (Recommended for GaCKliNG)**

**Advantages**:
- ✅ Free and open source
- ✅ Excellent decompiler (assembly → C pseudocode)
- ✅ Scriptable (Python/Java)
- ✅ Active community
- ✅ Can define custom instruction sets

**Disadvantages**:
- ⚠️ i860 support may need custom processor module
- ⚠️ Steeper learning curve than IDA

**Download**: https://ghidra-sre.org/

---

**Option B: IDA Pro**

**Advantages**:
- ✅ Industry standard
- ✅ Powerful scripting (Python/IDC)
- ✅ Best-in-class cross-referencing
- ✅ Mature ecosystem

**Disadvantages**:
- ❌ Expensive ($600-$3,500)
- ⚠️ i860 support may need plugin

**Website**: https://hex-rays.com/ida-pro/

---

**Option C: Binary Ninja**

**Advantages**:
- ✅ Modern UI
- ✅ Excellent API for automation
- ✅ Good decompiler

**Disadvantages**:
- ⚠️ i860 support uncertain
- ❌ Costs money ($300+)

**Website**: https://binary.ninja/

---

**Recommendation for GaCKliNG**: **Ghidra**
- Aligns with open source philosophy
- Free for entire team
- Decompiler is critical for understanding complex functions
- Can share analysis database with community

---

### Phase 2: Project Setup in Ghidra

**Step 1: Create Project**
```
1. Launch Ghidra
2. File → New Project → Non-Shared Project
3. Name: "NeXTdimension_Kernel_RE"
4. Location: ~/Development/previous/ghidra/
```

**Step 2: Import Binary**
```
1. File → Import File
2. Select: ND_MachDriver_reloc
3. Format: Mach-O
4. Language: i860:BE:32:default
   (If not available, you'll need to install i860 processor module)
```

**Step 3: Set Base Address** ⚠️ **CRITICAL**
```
Window → Memory Map
Right-click __TEXT segment → Set Image Base
New Base: 0xF8000000

This ensures all addresses match the virtual memory layout!
```

**Step 4: Define Segments**
```
Window → Memory Map

Segment          Start         End           Length      Permissions
══════════════════════════════════════════════════════════════════════
__TEXT           0xF8000000    0xF80B3FFF    737,280     r-x
__DATA           0xF80B4000    0xF80C5FFF     73,728     rw-
VRAM             0x10000000    0x103FFFFF  4,194,304     rw-
MMIO_Mailbox     0x02000000    0x02000FFF      4,096     rw-
MMIO_Graphics    0xFF800000    0xFF8FFFFF  1,048,576     rw-
ROM              0xFFF00000    0xFFFFFFFF     65,536     r-x
```

---

### Phase 3: Define Hardware Memory Map

**Critical step**: Label all MMIO registers so disassembly is readable.

**Create labels** (Window → Symbol Table → Add):

```
Address          Label                    Type
═══════════════════════════════════════════════════════════
; Mailbox Registers
0x02000000       MAILBOX_STATUS           DWord
0x02000004       MAILBOX_COMMAND          DWord
0x02000008       MAILBOX_ARG1             DWord
0x0200000C       MAILBOX_ARG2             DWord
0x02000010       MAILBOX_ARG3             DWord
0x02000014       MAILBOX_ARG4             DWord
0x02000018       MAILBOX_RESULT           DWord

; DMA Registers
0x02000040       DMA_SRC_ADDR             DWord
0x02000044       DMA_DST_ADDR             DWord
0x02000048       DMA_LENGTH               DWord
0x0200004C       DMA_CONTROL              DWord

; Interrupt Registers
0x020000C0       INT_STATUS               DWord
0x020000C4       INT_MASK                 DWord

; Video Timing Registers
0x02000100       VRAM_TIMING              DWord
0x02000104       VRAM_WIDTH               DWord
0x02000108       VRAM_HEIGHT              DWord

; VRAM Base
0x10000000       VRAM_BASE                Array[4MB]

; Bt463 RAMDAC
0xFF800000       BT463_ADDR_LO            Byte
0xFF800004       BT463_ADDR_HI            Byte
0xFF800008       BT463_CMD_REG0           Byte
0xFF80000C       BT463_CMD_REG1           Byte
0xFF800010       BT463_CMD_REG2           Byte
0xFF800014       BT463_PIXEL_MASK         Byte
0xFF800018       BT463_PALETTE_DATA       Byte
```

**Now when you disassemble**, code like:
```assembly
ld.l 0x02000004(%r0), %r16
```

Will automatically display as:
```assembly
ld.l MAILBOX_COMMAND(%r0), %r16    ; Read command from host
```

**Much more readable!**

---

### Phase 4: Enable Auto-Analysis

```
Analysis → Auto Analyze 'ND_MachDriver_reloc'

Enable:
☑ Decompiler Parameter ID
☑ Function Start Search
☑ Non-Returning Functions - Discovered
☑ Reference
☑ Stack
☑ Subroutine References
☑ Data Reference
☑ ASCII Strings
☑ Create Address Tables

Click "Analyze"

Wait 5-10 minutes for initial analysis to complete.
```

---

## Part 3: Finding the Landmarks

### Landmark 1: The Main Entry Point

**What we know**:
- Mach-O `LC_UNIXTHREAD` command specifies entry point
- Entry point = start of __TEXT segment = `0xF8000000`

**Action**:
```
1. Go to address 0xF8000000
   (Press 'G', enter address)

2. Right-click → Create Function
   (If Ghidra didn't auto-detect it)

3. Rename function: Right-click → Edit Function → Name: "_start"

4. Analyze the code:
```

**Expected code pattern** (kernel entry):
```assembly
; 0xF8000000: _start
_start:
    ; 1. Set up stack pointer
    orh  0x0040, %r0, %r2      ; r2 (SP) = 0x00400000 (top of DRAM)
    or   0x0000, %r2, %r2

    ; 2. Clear BSS section
    orh  0xF80C, %r0, %r16     ; r16 = 0xF80C1D00 (start of BSS)
    or   0x1D00, %r16, %r16
    or   %r0, %r0, %r17        ; r17 = 0 (value to fill)
    orh  0x0000, %r0, %r18
    or   0x0AC0, %r18, %r18    ; r18 = 2752 (BSS size)

clear_bss_loop:
    st.l %r17, 0(%r16)         ; *r16 = 0
    adds 4, %r16, %r16         ; r16 += 4
    subs 1, %r18, %r18         ; r18--
    bnz  clear_bss_loop        ; Loop if not zero
    nop

    ; 3. Call main kernel init
    call kernel_init           ; ← FOLLOW THIS!
    nop

    ; 4. Should never return, but just in case:
infinite_loop:
    br   infinite_loop
    nop
```

**What you've learned**:
- ✅ Confirmed stack at `0x00400000`
- ✅ Confirmed BSS clearing
- ✅ **Found `kernel_init` function** ← Your first major discovery!

**Action**: Go to `kernel_init`, rename it, continue analysis.

---

### Landmark 2: Exception Vector Table

**What we know** (from i860 architecture):
```
Address      Exception Type           Handler Offset
════════════════════════════════════════════════════════
0xF8000000   (Entry point, not vector)
0xF8000008   Data Access Fault        +8
0xF8000018   Instruction Fault        +24
0xF8000028   System Call (Trap)       +40
0xF8000030   External Interrupt       +48
```

**Action**: Check each vector address:

**Vector 1: Data Fault (0xF8000008)**
```assembly
; Expected: br data_fault_handler
0xF8000008:  br   0xF8012340    ; ← Target address
0xF800000C:  nop
```

**Action**:
1. Go to target (`0xF8012340`)
2. Rename function: `data_fault_handler`
3. Add comment: "Handles data access faults (page faults, alignment errors)"

**Vector 2: Trap (0xF8000028)**
```assembly
; Expected: br trap_handler
0xF8000028:  br   0xF8014580    ; ← System call entry point
0xF800002C:  nop
```

**This is HUGE**: `trap_handler` is the gateway to all system calls!

**Action**:
1. Go to `0xF8014580`
2. Rename: `trap_handler`
3. Add comment: "System call entry point - handles all trap instructions"

**Vector 3: External Interrupt (0xF8000030)**
```assembly
; Expected: br interrupt_handler
0xF8000030:  br   0xF8016000    ; ← ISR entry!
0xF8000034:  nop
```

**This is CRITICAL**: All hardware interrupts go here (mailbox, VBLANK, DMA).

**Action**:
1. Go to `0xF8016000`
2. Rename: `external_interrupt_handler`
3. Add comment: "Main ISR - dispatches mailbox, VBLANK, DMA interrupts"

**What you've learned**:
- ✅ Found all exception handlers
- ✅ Identified system call entry point
- ✅ **Found main interrupt dispatcher** ← VERY IMPORTANT

---

### Landmark 3: Interrupt Dispatcher Analysis

**Go to**: `external_interrupt_handler` (0xF8016000)

**Expected pattern**:
```assembly
external_interrupt_handler:
    ; 1. Save registers
    st.l %r1, -4(%r2)
    st.l %r16, -8(%r2)
    st.l %r17, -12(%r2)
    adds -16, %r2, %r2         ; Adjust stack

    ; 2. Read interrupt status
    ld.l INT_STATUS(%r0), %r16  ; r16 = 0x020000C0

    ; 3. Check bit 0: Mailbox interrupt
    and  0x01, %r16, %r17
    bnz  handle_mailbox_interrupt
    nop

    ; 4. Check bit 3: VBLANK interrupt
    and  0x08, %r16, %r17       ; Test bit 3
    bnz  handle_vblank_interrupt
    nop

    ; 5. Check bit 5: DMA complete
    and  0x20, %r16, %r17       ; Test bit 5
    bnz  handle_dma_interrupt
    nop

    ; 6. Unknown interrupt - ignore
    br   isr_exit
    nop

handle_mailbox_interrupt:
    call mailbox_isr           ; ← FOUND MAILBOX HANDLER!
    nop
    br   isr_exit
    nop

handle_vblank_interrupt:
    call vblank_isr            ; ← FOUND VBLANK HANDLER!
    nop
    br   isr_exit
    nop

handle_dma_interrupt:
    call dma_isr               ; ← FOUND DMA HANDLER!
    nop

isr_exit:
    ; Restore registers
    adds 16, %r2, %r2
    ld.l -4(%r2), %r1
    ld.l -8(%r2), %r16
    ld.l -12(%r2), %r17
    bri  %r1                   ; Return from interrupt
    nop
```

**Action**: Follow each handler!

**Discoveries**:
1. `mailbox_isr` - Handles host commands
2. `vblank_isr` - Handles frame timing
3. `dma_isr` - Handles DMA completion

**Rename all three, add comments, continue.**

---

### Landmark 4: Mailbox Command Dispatcher

**Go to**: `mailbox_isr` (address from previous step)

**Expected pattern** (this is the MOST IMPORTANT function):
```assembly
mailbox_isr:
    ; 1. Read command from mailbox
    ld.l MAILBOX_COMMAND(%r0), %r16   ; r16 = command code

    ; 2. Dispatch based on command
    ; (This will be a large switch statement)

    ; Check for CMD_NOP (0x00)
    bte  %r16, %r0, cmd_nop
    nop

    ; Check for CMD_INIT_VIDEO (0x01)
    or   1, %r0, %r17
    bte  %r16, %r17, cmd_init_video
    nop

    ; Check for CMD_SET_MODE (0x02)
    or   2, %r0, %r17
    bte  %r16, %r17, cmd_set_mode
    nop

    ; Check for CMD_FILL_RECT (0x03)
    or   3, %r0, %r17
    bte  %r16, %r17, cmd_fill_rect
    nop

    ; Check for CMD_BLIT (0x04)
    or   4, %r0, %r17
    bte  %r16, %r17, cmd_blit
    nop

    ; ... (more commands)

    ; Unknown command
    br   mailbox_exit
    nop

cmd_nop:
    br   mailbox_exit
    nop

cmd_init_video:
    call handle_init_video     ; ← FOUND VIDEO INIT!
    nop
    br   mailbox_exit
    nop

cmd_fill_rect:
    call handle_fill_rect      ; ← FOUND FILL HANDLER!
    nop
    br   mailbox_exit
    nop

cmd_blit:
    call handle_blit           ; ← FOUND BLIT HANDLER!
    nop
    br   mailbox_exit
    nop

mailbox_exit:
    ; Clear interrupt
    st.l %r0, MAILBOX_STATUS(%r0)
    bri  %r1
    nop
```

**Massive discovery**: You've now found the entry point for **every single graphics primitive**!

**Action**:
1. Create a table:
   ```
   Command Code  Handler Address    Function Name
   ════════════════════════════════════════════════
   0x00          (none)             CMD_NOP
   0x01          0xF8020000         handle_init_video
   0x02          0xF8021000         handle_set_mode
   0x03          0xF8022340         handle_fill_rect
   0x04          0xF8024100         handle_blit
   0x05          0xF8026000         handle_text
   ... etc.
   ```

2. Rename every function
3. Add detailed comments

**You've just mapped the entire command interface!**

---

### Landmark 5: System Call Table

**Go to**: `trap_handler` (from exception vector)

**Expected pattern**:
```assembly
trap_handler:
    ; 1. System call number is in %r16 (by convention)
    ; 2. Arguments are in %r17, %r18, %r19, etc.

    ; Bounds check
    orh  0x0000, %r0, %r24
    or   100, %r24, %r24        ; Max syscall number = 100
    bc   %r16, %r24, invalid_syscall
    nop

    ; Load syscall table base
    orh  0xF80B, %r0, %r24
    or   0x5000, %r24, %r24     ; r24 = 0xF80B5000 (syscall table)

    ; Calculate offset: table[syscall_num]
    shl  2, %r16, %r16          ; syscall_num *= 4 (word size)
    addu %r16, %r24, %r24       ; r24 = &syscall_table[num]

    ; Load function pointer
    ld.l 0(%r24), %r24          ; r24 = syscall_table[num]

    ; Call it
    bri  %r24
    nop

invalid_syscall:
    ; Return error
    or   -1, %r0, %r16
    bri  %r1
    nop
```

**Action**: Find the syscall table!

**Go to**: `0xF80B5000` (syscall table address from code above)

**You'll see**:
```
0xF80B5000:  00 00 00 00    ; syscall 0: null
0xF80B5004:  F8 03 12 00    ; syscall 1: 0xF8031200 → sys_mach_msg_send
0xF80B5008:  F8 03 24 00    ; syscall 2: 0xF8032400 → sys_mach_msg_receive
0xF80B500C:  F8 03 56 00    ; syscall 3: 0xF8035600 → sys_vm_allocate
0xF80B5010:  F8 03 78 00    ; syscall 4: 0xF8037800 → sys_vm_deallocate
... (100+ entries)
```

**Massive discovery**: You've found the entire system call API!

**Action**:
1. Create table of all syscall addresses
2. Rename each function based on likely purpose (compare to Mach documentation)
3. Prioritize analyzing the most common ones

---

## Part 4: Tracing Execution Paths

### Technique 1: Cross-Referencing

**Goal**: Find all places that call a specific function or access a specific address.

**Example**: Find all code that writes to VRAM.

**Action in Ghidra**:
```
1. Go to VRAM_BASE (0x10000000)
2. Right-click → References → Find references to VRAM_BASE
3. Ghidra shows all instructions that reference this address
```

**Result**:
```
Address       Instruction                      Function
════════════════════════════════════════════════════════════════
0xF8022340    st.l %r16, 0(%r17)              handle_fill_rect
0xF8024100    st.q %f8, 0(%r16)               handle_blit
0xF8026000    st.l %r20, 0(%r19)              handle_text
0xF8030000    fst.d %f0, 0(%r16)              fast_memset_64
...
```

**You've found all rendering functions instantly!**

---

### Technique 2: Call Graph Analysis

**Goal**: Understand the calling hierarchy.

**Action in Ghidra**:
```
1. Window → Function Call Graph
2. Select root function: _start
3. View → Expand All
```

**You'll see**:
```
_start
├── kernel_init
│   ├── init_memory_manager
│   ├── init_interrupt_controller
│   ├── init_video_hardware
│   │   ├── program_bt463_ramdac
│   │   ├── set_pixel_clock
│   │   └── clear_framebuffer
│   └── start_mailbox_service
│       └── (enters main loop)
└── infinite_loop (fallback)
```

**Insight**: Now you understand the boot sequence!

---

### Technique 3: Data Flow Analysis

**Goal**: Understand how data flows through the system.

**Example**: Trace how a `CMD_FILL_RECT` command is processed.

**Step-by-step**:
```
1. Host writes to MAILBOX_COMMAND
2. Interrupt fires
3. external_interrupt_handler reads INT_STATUS
4. Dispatches to mailbox_isr
5. mailbox_isr reads MAILBOX_COMMAND
6. Dispatches to handle_fill_rect
7. handle_fill_rect reads MAILBOX_ARG1-4
8. Calls fast_memset_64
9. fast_memset_64 writes to VRAM
10. Returns to mailbox_isr
11. mailbox_isr writes 0 to MAILBOX_STATUS (completion signal)
```

**Action**: Document this flow in a diagram.

---

## Part 5: Pattern Recognition

### Pattern 1: Optimized memcpy (64-bit)

**Signature**:
```assembly
; Fast memory copy using FPU quad-word loads/stores
fast_memcpy_64:
    ; r16 = dest, r17 = src, r18 = count (in 8-byte chunks)

loop:
    fld.d 0(%r17), %f0         ; Load 8 bytes
    fst.d %f0, 0(%r16)         ; Store 8 bytes
    adds  8, %r17, %r17        ; src += 8
    adds  8, %r16, %r16        ; dest += 8
    subs  1, %r18, %r18        ; count--
    bnz   loop
    nop

    bri %r1
    nop
```

**How to find**:
- Search for pattern: `fld.d` followed by `fst.d` in a loop
- Used heavily in `handle_blit`

---

### Pattern 2: Optimized memset (64-bit)

**Signature**:
```assembly
; Fast memory fill using FPU quad-word stores
fast_memset_64:
    ; r16 = dest, r17 = value (32-bit), r18 = count (in 8-byte chunks)

    ; Broadcast value to both halves of f0
    ixfr %r17, %f0             ; Move r17 → f0 (low 32 bits)
    ixfr %r17, %f1             ; Move r17 → f1 (high 32 bits)

loop:
    fst.d %f0, 0(%r16)         ; Store 8 bytes
    adds  8, %r16, %r16        ; dest += 8
    subs  1, %r18, %r18        ; count--
    bnz   loop
    nop

    bri %r1
    nop
```

**How to find**:
- Search for `ixfr` followed by `fst.d` loop
- Used in `handle_fill_rect`

---

### Pattern 3: Switch Statement Dispatcher

**Signature**:
```assembly
; Dispatch based on r16 (command/case value)
dispatcher:
    ; Range check
    orh  MAX_CASES, %r0, %r24
    bc   %r16, %r24, default_case
    nop

    ; Load jump table base
    orh  0xF80B, %r0, %r24
    or   0x6000, %r24, %r24    ; r24 = jump_table

    ; Calculate offset
    shl  2, %r16, %r16         ; case *= 4
    addu %r16, %r24, %r24      ; r24 = &jump_table[case]

    ; Load target
    ld.l 0(%r24), %r24

    ; Jump
    bri  %r24
    nop
```

**How to find**:
- Look for `shl 2` followed by `ld.l` and `bri`
- Found in: command dispatcher, syscall dispatcher

---

### Pattern 4: FPU Math Routine

**Signature** (matrix multiply):
```assembly
; 4x4 matrix multiply: C = A * B
matrix_multiply_4x4:
    ; Load matrix A into f0-f15
    fld.q  0(%r16), %f0
    fld.q 16(%r16), %f4
    fld.q 32(%r16), %f8
    fld.q 48(%r16), %f12

    ; Load matrix B into f16-f31
    fld.q  0(%r17), %f16
    fld.q 16(%r17), %f20
    fld.q 32(%r17), %f24
    fld.q 48(%r17), %f28

    ; Multiply (simplified - actual code is 64+ instructions)
    fmul.ss %f0, %f16, %f32    ; C[0][0] = A[0][0] * B[0][0]
    fmul.ss %f1, %f20, %f33    ; C[0][1] = A[0][1] * B[1][0]
    fadd.ss %f32, %f33, %f32   ; C[0][0] += ...
    ; ... (60+ more multiply-adds)

    ; Store result
    fst.q %f32, 0(%r18)
    fst.q %f36, 16(%r18)
    fst.q %f40, 32(%r18)
    fst.q %f44, 48(%r18)

    bri %r1
    nop
```

**How to find**:
- Search for sequences of `fld.q`, `fmul.ss`, `fadd.ss`
- Complex FPU code = graphics transformations

---

## Part 6: The Iterative Workflow

### Daily Reverse Engineering Cycle

```
┌─────────────────────────────────────────────────────────┐
│ Morning Session (2-3 hours)                             │
├─────────────────────────────────────────────────────────┤
│ 1. Pick a Target Function                               │
│    - Choose from "Unknown Functions" list               │
│    - Prioritize based on:                               │
│      • Frequency of calls (hot path = important)        │
│      • Size (small = easier to understand)              │
│      • Reachability (called from known function)        │
│                                                         │
│ 2. Analyze the Function                                 │
│    - Read disassembly carefully                         │
│    - Note all hardware register accesses                │
│    - Note all function calls                            │
│    - Look for patterns (loops, conditionals)            │
│                                                         │
│ 3. Deduce Purpose                                       │
│    - What hardware does it touch?                       │
│      → VRAM = rendering function                        │
│      → MAILBOX = command handler                        │
│      → DMA = memory transfer                            │
│    - What does it calculate?                            │
│      → Multiplies dimensions = area calculation         │
│      → Increments pointer = loop iteration              │
│    - What calls it?                                     │
│      → Called by fill_rect = likely memset              │
│                                                         │
│ 4. Label and Document                                   │
│    - Rename function (sub_F8045C00 → fast_memset_64)    │
│    - Rename parameters (%r16 → dest, %r17 → value)      │
│    - Add function comment with purpose                  │
│    - Add inline comments for tricky code                │
│                                                         │
│ 5. Update Master Documentation                          │
│    - Add entry to KERNEL_FUNCTION_MAP.md                │
│    - Update call graph diagram                          │
│    - Note any discoveries in research log               │
└─────────────────────────────────────────────────────────┘

Break (30 min)

┌─────────────────────────────────────────────────────────┐
│ Afternoon Session (2-3 hours)                           │
├─────────────────────────────────────────────────────────┤
│ 6. Cross-Reference Analysis                             │
│    - Find all callers of newly-labeled function         │
│    - This reveals what THEY do (propagate knowledge)    │
│                                                         │
│ 7. Pattern Search                                       │
│    - If you identified a new pattern, search for it     │
│    - Example: Found memset → search for similar loops   │
│                                                         │
│ 8. Test Hypotheses in Emulator                          │
│    - If uncertain about function purpose, test it!      │
│    - Set breakpoint in Previous emulator                │
│    - Observe register values, behavior                  │
│                                                         │
│ 9. Document Unknowns                                    │
│    - If stuck, document what you DON'T know             │
│    - Create "TODO" list of mysteries                    │
│    - Move on to next function                           │
└─────────────────────────────────────────────────────────┘

Evening Review (30 min)

┌─────────────────────────────────────────────────────────┐
│ 10. Progress Tracking                                   │
├─────────────────────────────────────────────────────────┤
│ - Update statistics:                                    │
│   • Functions analyzed today: 8                         │
│   • Total functions labeled: 156 / ~800                 │
│   • Percentage complete: 19.5%                          │
│                                                         │
│ - Prioritize tomorrow's targets                         │
│ - Commit Ghidra database to git                         │
│ - Back up analysis notes                                │
└─────────────────────────────────────────────────────────┘
```

---

## Part 7: Practical Example Walkthrough

### Example: Reverse Engineering `handle_fill_rect`

**Starting Point**: We know from mailbox dispatcher that `CMD_FILL_RECT (0x03)` calls a function at `0xF8022340`.

**Step 1: Go to Address**
```
Ghidra: Press 'G', enter 0xF8022340
```

**Step 2: Create Function (if needed)**
```
Right-click → Create Function
```

**Step 3: Initial Disassembly**
```assembly
; 0xF8022340
FUN_f8022340:
    ; Prologue: Save registers
    st.l %r1, -4(%r2)          ; Save return address
    st.l %r16, -8(%r2)         ; Save r16
    st.l %r17, -12(%r2)        ; Save r17
    st.l %r18, -16(%r2)        ; Save r18
    st.l %r19, -20(%r2)        ; Save r19
    adds -24, %r2, %r2         ; Adjust stack pointer

    ; Read arguments from mailbox
    ld.l MAILBOX_ARG1(%r0), %r16   ; r16 = arg1
    ld.l MAILBOX_ARG2(%r0), %r17   ; r17 = arg2
    ld.l MAILBOX_ARG3(%r0), %r18   ; r18 = arg3
    ld.l MAILBOX_ARG4(%r0), %r19   ; r19 = arg4

    ; Calculate VRAM address
    orh  0x1000, %r0, %r20     ; r20 = 0x10000000 (VRAM base)
    or   0x0000, %r20, %r20

    ; Calculate offset: (y * width + x) * 4
    ld.l VRAM_WIDTH(%r0), %r21 ; r21 = screen width (1120)
    mulu %r17, %r21, %r21      ; r21 = y * width
    addu %r16, %r21, %r21      ; r21 = y * width + x
    shl  2, %r21, %r21         ; r21 *= 4 (bytes per pixel)
    addu %r21, %r20, %r20      ; r20 = VRAM base + offset

    ; r20 now points to start of rectangle in VRAM

    ; Calculate total pixels
    mulu %r18, %r19, %r21      ; r21 = width * height

    ; Load fill color
    ld.l MAILBOX_ARG5(%r0), %r22   ; r22 = color (RGBA)

    ; Call fast fill routine
    or   %r20, %r0, %r16       ; r16 = dest
    or   %r22, %r0, %r17       ; r17 = color
    or   %r21, %r0, %r18       ; r18 = count
    call FUN_f8030000          ; ← Unknown function!
    nop

    ; Epilogue: Restore registers
    adds 24, %r2, %r2
    ld.l -4(%r2), %r1
    ld.l -8(%r2), %r16
    ld.l -12(%r2), %r17
    ld.l -16(%r2), %r18
    ld.l -20(%r2), %r19

    bri %r1                    ; Return
    nop
```

**Step 4: Analyze**

**Observations**:
1. Reads 5 arguments from mailbox (x, y, w, h, color)
2. Calculates VRAM address: `VRAM_BASE + (y * width + x) * 4`
3. Calculates pixel count: `width * height`
4. Calls unknown function at `0xF8030000` with (dest, color, count)

**Deduction**:
- This is definitely `handle_fill_rect`
- The unknown function is likely `fast_memset` (fills memory with color)

**Step 5: Rename and Comment**
```
Function name: handle_fill_rect

Parameters:
  (none - reads from mailbox)

Comments:
// CMD_FILL_RECT handler
// Reads: x, y, width, height, color from mailbox
// Fills rectangle at (x,y) with dimensions (width, height)
// Uses fast_memset_32 for actual filling
```

**Step 6: Follow the Trail**

Go to `0xF8030000` (the called function):

```assembly
; 0xF8030000
FUN_f8030000:
    ; r16 = dest, r17 = value, r18 = count

    ; Broadcast value to FPU register
    ixfr %r17, %f0
    ixfr %r17, %f1

fill_loop:
    fst.d %f0, 0(%r16)         ; Store 8 bytes
    adds  8, %r16, %r16        ; dest += 8
    subs  1, %r18, %r18        ; count--
    bnz   fill_loop
    nop

    bri %r1
    nop
```

**Deduction**: This is `fast_memset_64` (uses FPU for fast 64-bit stores)!

**Step 7: Document Both Functions**

```
handle_fill_rect (0xF8022340):
  - Purpose: Draw filled rectangle on screen
  - Caller: mailbox_isr (CMD_FILL_RECT)
  - Calls: fast_memset_64

fast_memset_64 (0xF8030000):
  - Purpose: Fast memory fill using FPU
  - Params: r16=dest, r17=value, r18=count (8-byte chunks)
  - Used by: handle_fill_rect, clear_framebuffer, etc.
```

**Step 8: Update Call Graph**

```
mailbox_isr
  └── handle_fill_rect
        └── fast_memset_64
```

**Progress**: Analyzed 2 functions, labeled both, understood data flow!

---

## Part 8: Documentation Strategy

### Master Document: KERNEL_FUNCTION_MAP.md

Create a living document that tracks all discoveries:

```markdown
# NeXTdimension Kernel Function Map

## Statistics

- Total functions: ~800 (estimated)
- Analyzed: 156
- Progress: 19.5%
- Last updated: 2025-11-05

## Entry Points

### Boot Sequence
- 0xF8000000: `_start` - Kernel entry point
- 0xF8001200: `kernel_init` - Main initialization
- 0xF8002000: `init_video_hardware` - Video setup
- 0xF8003000: `start_mailbox_service` - Begin command processing

### Exception Handlers
- 0xF8000008: `data_fault_handler` - Data access exceptions
- 0xF8000028: `trap_handler` - System call entry
- 0xF8000030: `external_interrupt_handler` - Hardware interrupts

### Interrupt Service Routines
- 0xF8016000: `external_interrupt_handler` - Main ISR dispatcher
- 0xF8016100: `mailbox_isr` - Mailbox interrupt handler
- 0xF8016200: `vblank_isr` - Vertical blank handler
- 0xF8016300: `dma_isr` - DMA completion handler

## Command Handlers

### Graphics Commands
- 0xF8022340: `handle_fill_rect` (CMD_FILL_RECT, 0x03)
  - Purpose: Fill rectangular region with solid color
  - Args: x, y, width, height, color
  - Calls: fast_memset_64
  - Status: ✅ Fully analyzed

- 0xF8024100: `handle_blit` (CMD_BLIT, 0x04)
  - Purpose: Copy rectangular region (with optional alpha)
  - Args: src_x, src_y, dst_x, dst_y, width, height, mode
  - Calls: fast_memcpy_64, alpha_blend_line
  - Status: ⚠️ Partially analyzed (alpha blend unclear)

- 0xF8026000: `handle_text` (CMD_TEXT, 0x05)
  - Purpose: Render text string
  - Args: x, y, font_id, string_ptr, fg_color, bg_color
  - Calls: rasterize_glyph, render_glyph_to_vram
  - Status: ⏳ Not yet analyzed

## Utility Functions

### Memory Operations
- 0xF8030000: `fast_memset_64` - FPU-accelerated memset
  - Status: ✅ Fully analyzed
- 0xF8030100: `fast_memcpy_64` - FPU-accelerated memcpy
  - Status: ✅ Fully analyzed
- 0xF8030200: `memcmp` - Memory comparison
  - Status: ❌ Not analyzed

### Math Functions
- 0xF8035000: `matrix_multiply_4x4` - 4×4 matrix multiplication
  - Status: ⏳ Partially analyzed
- 0xF8035200: `vector_transform` - Apply matrix to vector
  - Status: ❌ Not analyzed

## Unknown Functions

### High Priority (Called Frequently)
- 0xF8040000: Called by handle_text, mailbox_isr
  - Hypothesis: String processing?
- 0xF8042000: Called by handle_blit, handle_fill_rect
  - Hypothesis: Clipping or bounds checking?

### Medium Priority
- 0xF8050000: Called during boot
  - Hypothesis: Hardware detection?

### Low Priority (Rarely Called)
- 0xF8070000: Called once during init
  - Hypothesis: Debug/diagnostic code?

## Mysteries

1. **Function at 0xF8044000**: Complex FPU code, no clear purpose
   - Uses all 32 FPU registers
   - Performs many multiply-adds
   - Possibly: Bezier curve evaluation? Transform pipeline?

2. **Data table at 0xF80B6000**: 4 KB of structured data
   - Pattern: 64-byte records, 64 entries
   - Possibly: Command metadata? Font cache?

## Next Steps

1. Analyze handle_text (high value for GaCKliNG)
2. Identify all bounds checking functions
3. Map complete syscall table
4. Reverse engineer DPS command handler (if it exists)
```

---

## Part 9: Advanced Techniques

### Technique 1: Binary Diff Analysis

**Use case**: NeXT released multiple firmware versions. Compare them!

**Tool**: `radiff2` (part of radare2)

```bash
radiff2 ND_MachDriver_v1.0.bin ND_MachDriver_v1.1.bin

# Shows:
# - Which functions changed (bug fixes!)
# - Which functions were added (new features!)
# - Which data changed (configuration tweaks!)
```

**Insight**: Unchanged code = stable/correct. Changed code = where bugs were.

---

### Technique 2: Emulator-Assisted Analysis

**Use case**: Uncertain about function behavior? Test it!

**Setup**: Previous emulator with GDB stub

```bash
# 1. Launch Previous with debug mode
previous --debug --gdb-port 1234

# 2. Connect GDB
i860-elf-gdb ND_MachDriver_reloc

(gdb) target remote localhost:1234
(gdb) break *0xF8022340           # Break at handle_fill_rect
(gdb) continue

# 3. Trigger command from host (in Previous UI)
# Send CMD_FILL_RECT(100, 100, 200, 50, 0xFF0000)

# 4. When breakpoint hits:
(gdb) info registers              # See all register values
(gdb) x/8x $r16                   # Examine memory at r16
(gdb) step                        # Single-step through code

# 5. Observe behavior, validate hypothesis
```

**Result**: Empirical confirmation of function purpose!

---

### Technique 3: Statistical Analysis

**Use case**: Identify hot paths (most-executed code)

**Tool**: Ghidra's code coverage plugin + emulator trace

```bash
# 1. Run full NeXTSTEP boot in emulator with tracing
previous --trace-exec trace.log

# 2. Import trace into Ghidra
# (Shows heatmap of which functions executed most)

# Result:
# - Bright red = executed 1000+ times (optimize these!)
# - Yellow = executed 10-100 times (important)
# - Blue = executed once (init code)
# - Black = never executed (dead code or easter eggs?)
```

**Insight**: Focus on red/yellow functions first!

---

## Part 10: Pitfalls and How to Avoid Them

### Pitfall 1: Misidentifying Data as Code

**Problem**: Disassembler treats data tables as instructions.

**Example**:
```assembly
; This looks like code...
0xF80B6000:  48 00 12 34    ; br 0x1234?
0xF80B6004:  00 00 00 01    ; or %r0, %r0, %r1?

; But it's actually a data table!
0xF80B6000:  0x48001234     ; Jump table entry
0xF80B6004:  0x00000001     ; Flags field
```

**Solution**:
- Check context: Is this address referenced by `ld.l`, or only by `call`/`br`?
- If only loads → probably data
- In Ghidra: Right-click → Clear Code Bytes → Define as Data

---

### Pitfall 2: Assuming Standard Calling Convention

**Problem**: Assuming all functions use %r1 for return address.

**Reality**: Some functions are special (inline, tail-call optimized).

**Example**:
```assembly
; Normal function:
foo:
    call bar
    nop
    bri %r1        ; Return via %r1

; Tail-call optimized:
foo2:
    call bar
    nop
    ; Fall through to bar's return - no bri!
```

**Solution**: Always check epilogue carefully.

---

### Pitfall 3: Ignoring Delay Slots

**Problem**: Forgetting that instruction after branch *always executes*.

**Example**:
```assembly
bnz  loop
st.l %r16, 0(%r17)    ; ← This ALWAYS runs, even if branch taken!
```

**Solution**: Always read 2 instructions after branch.

---

## Part 11: Success Metrics

### Phase 1: Core Infrastructure Mapped (Week 1-2)

✅ **Completed when**:
- [ ] All exception handlers identified
- [ ] Main mailbox dispatcher mapped
- [ ] All command handlers labeled (even if not analyzed)
- [ ] Interrupt dispatcher understood

**Value**: Can now trace any host command from start to finish.

---

### Phase 2: Graphics Primitives Analyzed (Week 3-6)

✅ **Completed when**:
- [ ] handle_fill_rect fully analyzed
- [ ] handle_blit fully analyzed
- [ ] handle_text fully analyzed
- [ ] All utility functions they call labeled
- [ ] Documented: Arguments, return values, side effects

**Value**: Can now implement GaCKliNG graphics layer.

---

### Phase 3: Complete Functional Map (Week 7-12)

✅ **Completed when**:
- [ ] 90%+ of functions labeled
- [ ] All hardware interactions documented
- [ ] All data structures identified
- [ ] Call graph complete
- [ ] KERNEL_FUNCTION_MAP.md comprehensive

**Value**: Deep understanding enables innovation beyond original.

---

## Conclusion

**You are now equipped to map the NeXTdimension kernel.**

**Remember**:
1. **Start with landmarks** (exception vectors, hardware registers)
2. **Trace systematically** (follow calls, cross-reference)
3. **Recognize patterns** (memcpy, memset, dispatchers)
4. **Document everything** (future you will thank you)
5. **Be patient** (this is weeks/months of work, not days)

**Tools you need**:
- ✅ Ghidra (with i860 support)
- ✅ Previous emulator (for testing)
- ✅ i860 datasheet (for instruction reference)
- ✅ This playbook (for methodology)

**Your advantage**:
- You already have extensive hardware documentation
- You've analyzed the ROM bootstrap
- You understand the mailbox protocol
- You have a clear goal (GaCKliNG implementation)

**This is not just reverse engineering.**
**This is digital archaeology, computer science research, and historical preservation.**

**Go forth and map the unknown.** 🗺️

---

**Document Created**: November 5, 2025
**Target**: ND_MachDriver_reloc __TEXT segment (720 KB)
**Status**: Ready to begin systematic analysis
**Expected Completion**: 6-12 weeks of focused work

---

## References

**Tools**:
- Ghidra: https://ghidra-sre.org/
- IDA Pro: https://hex-rays.com/
- radare2: https://rada.re/

**Documentation**:
- Intel i860 XR Programmer's Reference Manual
- NeXTdimension Hardware Specification
- NEXTDIMENSION_MEMORY_MAP_COMPLETE.md
- KERNEL_ARCHITECTURE_COMPLETE.md

**Community**:
- Previous Emulator Discord: https://discord.gg/next
- NeXT Archive: https://www.nextcomputers.org/

---

*"In the absence of symbols, we create them."*
*- Reverse Engineering Proverb*

*"Every binary tells a story. You just have to learn its language."*
*- The GaCKliNG Philosophy*
