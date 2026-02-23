# Firmware Patching Alternative: Extending NeXT's Kernel vs Building GaCKliNG
## A Technical Analysis of Binary Modification vs Clean Reimplementation

**Document Date**: November 5, 2025
**Status**: Alternative Approach Analysis
**Decision**: Clean reimplementation chosen (GaCKliNG), but patching approach documented for completeness

---

## Executive Summary

**The Opportunity**: NeXT's ND_MachDriver_reloc contains 30 KB of dead space (Emacs changelog) in executable memory that could theoretically be replaced with functional code.

**Two Approaches**:

| Approach | Effort | Risk | Flexibility | Outcome |
|----------|--------|------|-------------|---------|
| **Binary Patching** | Medium | Very High | Limited | Extend original firmware with hooks |
| **Clean Reimplementation (GaCKliNG)** | High | Low | Unlimited | New GPL'd firmware from scratch |

**Decision**: GaCKliNG takes the **clean reimplementation** path because:
- ✅ Lower long-term risk (no dependency on proprietary binary)
- ✅ Full understanding of all code
- ✅ Unlimited feature additions
- ✅ Clean GPL licensing
- ✅ Community can contribute

**But**: The patching approach is fascinating and **theoretically viable**. This document explores it fully.

---

## Part 1: The 30 KB Opportunity

### The Discovery

**File**: `ND_MachDriver_reloc` (795,464 bytes)
**Location**: Offset 765,117 to 795,463
**Size**: 30,347 bytes (29.6 KB)
**Current Content**: GNU Emacs 18.36 ChangeLog (build artifact)
**Virtual Address**: 0xF80BAD5D to 0xF80C25FF (in __TEXT segment)
**Memory Protection**: r-x (read + execute)
**Current Usage**: None (never referenced, never executed)

### What Makes This Space Special?

```
Memory Layout:
┌─────────────────────────────────────────────────────────────┐
│ 0xF8000000: Kernel Entry Point (executed)                   │
│ 0xF8000004: Boot sequence code (executed)                   │
│ ...                                                         │
│ 0xF80BAD5C: Last executable instruction (executed)          │
├─────────────────────────────────────────────────────────────┤
│ 0xF80BAD5D: *** START OF DEAD SPACE ***                     │
│                                                             │
│   "* Version 18.36 released.\n"                             │
│   "Wed Jan 21 02:13:17 1987  Richard M. Stallman..."        │
│   ... (30 KB of pure ASCII text) ...                        │
│                                                             │
│ 0xF80C25FF: *** END OF DEAD SPACE ***                       │
├─────────────────────────────────────────────────────────────┤
│ 0xF80C2600: Padding (segment alignment)                     │
└─────────────────────────────────────────────────────────────┘
```

**Key Properties**:
1. ✅ **Already in executable memory** - no need to remap permissions
2. ✅ **Never accessed** - replacing it won't break existing functionality
3. ✅ **Large enough** - 30 KB can hold ~7,500 i860 instructions
4. ✅ **Predictable location** - always at same offset in binary
5. ❌ **Fixed address** - code must be position-independent or hardcoded to 0xF80BAD5D

---

## Part 2: Binary Patching Approach

### Concept: Replace Dead Space with Functional Code

**Goal**: Turn the inert changelog into executable code that extends the kernel's capabilities.

### Step 1: Write Your Payload

**Option A: Assembly (Maximum Control)**
```assembly
; payload.asm - New feature to draw splash screen
; Target address: 0xF80BAD5D (where Emacs changelog was)

.org 0xF80BAD5D

gackling_splash_entry:
    ; Save all registers we'll use
    st.l %r1,-4(%r2)         ; Save r1 to stack
    st.l %r16,-8(%r2)        ; Save r16
    st.l %r17,-12(%r2)       ; Save r17
    adds -16,%r2,%r2         ; Adjust stack pointer

    ; Draw GaCKliNG logo at (100, 100)
    call draw_logo_internal
    nop

    ; Restore registers
    adds 16,%r2,%r2
    ld.l -4(%r2),%r1
    ld.l -8(%r2),%r16
    ld.l -12(%r2),%r17

    ; Return to caller
    bri %r1
    nop

draw_logo_internal:
    ; Implementation here...
    ; (Must be position-independent!)
    bri %r1
    nop

; Embedded logo data
logo_data:
    .long 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, ...
    ; (32x32 pixels = 4 KB)
```

**Option B: C with Position-Independent Code**
```c
/* payload.c */
__attribute__((section(".payload")))
__attribute__((noinline))
void gackling_splash(void) {
    // Must not reference global variables!
    // Must not call external functions!
    // Must be fully self-contained.

    volatile uint32_t *fb = (uint32_t*)0x10000000; // VRAM base

    // Draw 32x32 logo at (100, 100)
    const uint32_t logo[] = {
        0xFFFFFFFF, 0x00000000, /* ... */
    };

    for (int y = 0; y < 32; y++) {
        for (int x = 0; x < 32; x++) {
            fb[(100 + y) * 1120 + (100 + x)] = logo[y * 32 + x];
        }
    }
}
```

**Compile to raw binary**:
```bash
# Compile with i860 cross-compiler
i860-elf-gcc -c -O2 -fPIC payload.c -o payload.o

# Extract just the code section as raw binary
i860-elf-objcopy -O binary -j .payload payload.o payload.bin

# Verify size
ls -l payload.bin
# Must be ≤ 30,347 bytes!
```

---

### Step 2: Find Injection Point (The Hard Part)

You need to find a place in the original kernel to insert a `call` instruction that jumps to your payload.

**Requirements for a good injection point**:
1. ✅ **Non-critical code** - not in the middle of a critical loop
2. ✅ **Predictable state** - registers and stack in known configuration
3. ✅ **Frequent execution** - actually gets called (not dead code)
4. ✅ **Safe to patch** - overwriting 8 bytes (2 instructions) won't break logic

**Example: Patching the main dispatch loop**

**Original code** (found via disassembly at 0xF8001234):
```assembly
; Main command dispatcher loop
0xF8001234:  ld.l  0x02000100(%r0),%r16   ; Read mailbox command
0xF8001238:  btne  %r16,%r0,process_cmd   ; If command != 0, process it
0xF800123C:  nop
0xF8001240:  br    0xF8001234             ; Loop back (poll again)
0xF8001244:  nop
```

**Patched code**:
```assembly
; Main command dispatcher loop (PATCHED)
0xF8001234:  ld.l  0x02000100(%r0),%r16   ; Read mailbox command
0xF8001238:  call  0xF80BAD5D             ; *** PATCHED: Call our splash code ***
0xF800123C:  nop                          ; *** PATCHED: (delay slot) ***
0xF8001240:  btne  %r16,%r0,process_cmd   ; If command != 0, process it
0xF8001244:  nop
```

**Result**: Every time the kernel polls the mailbox, it calls your splash screen code first.

**Danger**: If your splash code is buggy, **the kernel will crash immediately**.

---

### Step 3: Binary Patching with `dd`

```bash
# 1. Backup original firmware
cp ND_MachDriver_reloc ND_MachDriver_reloc.backup

# 2. Replace Emacs changelog with payload
dd if=payload.bin of=ND_MachDriver_reloc bs=1 seek=765117 conv=notrunc

# 3. Patch the injection point
# Convert "call 0xF80BAD5D" to machine code: 68 00 2E B1 (example encoding)
echo -ne '\x68\x00\x2E\xB1' | dd of=ND_MachDriver_reloc bs=1 seek=4152 conv=notrunc
#                                                                     ↑
#                                          File offset of 0xF8001238 = 840 + 0x1238 - 0xF8000000
#                                                                   = 840 + 4664 = 5504...
# (Actual calculation is complex due to virtual-to-file offset mapping)

# 4. Verify with disassembler
./i860disasm ND_MachDriver_reloc 5504 8

# 5. Test in emulator
previous --firmware ND_MachDriver_reloc
```

**If successful**: Your splash screen appears!
**If failed**: Kernel crashes, screen shows garbage, or system hangs.

---

## Part 3: The Challenge - Making It Extensible

Simply adding a hardcoded splash screen is trivial. The **real challenge** is making the firmware **dynamically extensible** at runtime.

### Challenge 1: Finding Safe Injection Points

**Problem**: Where do you patch the kernel to call your code?

**Analysis Required**:
```bash
# 1. Disassemble entire kernel
./i860disasm ND_MachDriver_reloc 840 730440 > kernel_full.asm

# 2. Identify candidate locations
grep -n "call.*mailbox" kernel_full.asm
grep -n "br.*main_loop" kernel_full.asm

# 3. Manually analyze each candidate
# - Is it called frequently?
# - What's the register state?
# - Can we safely add 2 instructions here?

# 4. Test each candidate in emulator
# (This is trial-and-error debugging)
```

**Example candidates**:

| Location | Frequency | Safety | Use Case |
|----------|-----------|--------|----------|
| **Main dispatch loop** | Every mailbox poll (~1000 Hz) | Medium | Hook all commands |
| **VBLANK interrupt** | 60 Hz | High | Per-frame rendering |
| **CMD_FILL handler entry** | Per fill command | High | Graphics command hooks |
| **Kernel init (boot)** | Once | Very High | Boot-time splash |

**Recommended**: Start with **kernel init** (safest, happens once).

---

### Challenge 2: The ABI and Calling Convention

**Problem**: When your code is called, what's the CPU state?

**You need to know**:
1. Which registers contain important data? (don't clobber them!)
2. Where is the stack pointer? (can you use the stack?)
3. Which registers are "caller-saved" vs "callee-saved"?
4. Is there a frame pointer?

**The solution**: Reverse engineering via disassembly.

**Example analysis** (main dispatch loop entry):
```assembly
; At 0xF8001234 (main loop), what's the state?

; Register usage (observed):
; %r0  = Always zero (i860 convention)
; %r1  = Return address (set by 'call' instruction)
; %r2  = Stack pointer (kernel stack)
; %r16 = Mailbox command value (just loaded)
; %r17 = Command parameter pointer
; %r18 = Kernel state flags
; %r19-r31 = Scratch (safe to use)

; Stack layout:
; %r2+0   = Top of stack
; %r2-64  = 64 bytes available
```

**Your payload must**:
```assembly
gackling_hook:
    ; 1. Save registers you'll use
    st.l %r16,-4(%r2)
    st.l %r17,-8(%r2)
    st.l %r18,-12(%r2)
    adds -16,%r2,%r2        ; Adjust stack

    ; 2. Do your work
    ; ... your code here ...

    ; 3. Restore registers EXACTLY
    adds 16,%r2,%r2
    ld.l -4(%r2),%r16
    ld.l -8(%r2),%r17
    ld.l -12(%r2),%r18

    ; 4. Return
    bri %r1
    nop
```

**If you get this wrong**: Kernel will crash within milliseconds.

---

### Challenge 3: Calling Kernel Functions (Symbol Resolution)

**Problem**: The kernel is **stripped** - no function names, no symbol table.

**Example**: You want to call the kernel's `fill_rect` function to draw your splash screen.

**Without symbols**:
```c
// This won't work - fill_rect is not a known symbol!
void my_splash(void) {
    fill_rect(0, 0, 1120, 832, 0x000000);  // ❌ LINK ERROR
}
```

**Solution 1: Manual Address Discovery**
```bash
# 1. Search for fill_rect code pattern via disassembly
./i860disasm ND_MachDriver_reloc 840 730440 > kernel.asm

# 2. Look for patterns matching "fill" operation
grep -A 20 "orh.*0x0010" kernel.asm | grep "st.l.*0("
# (Looking for "load VRAM base, then store in loop")

# 3. Found candidate at virtual address 0xF8045C00

# 4. Verify by testing in emulator
```

**Solution 2: Hardcode the Address**
```assembly
; payload.asm
gackling_splash:
    ; Manually found fill_rect at 0xF8045C00
    or   %r0, %r0, %r16        ; x = 0
    or   %r0, %r0, %r17        ; y = 0
    orh  0x0004, %r0, %r18
    or   0x0460, %r18, %r18    ; w = 1120
    orh  0x0003, %r0, %r19
    or   0x0040, %r19, %r19    ; h = 832
    or   %r0, %r0, %r20        ; color = black

    call 0xF8045C00            ; *** HARDCODED ADDRESS ***
    nop

    bri %r1
    nop
```

**The problem**: This is **extremely brittle**:
- ✅ Works with this specific firmware version
- ❌ Breaks if NeXT releases a patch (addresses shift)
- ❌ Breaks if you patch other parts of kernel (code moves)

---

### Challenge 4: Accessing Global Variables

**Problem**: Same as functions - you don't know where global variables are stored.

**Example**: You want to read the current screen width.

**Without symbols**:
```c
extern int g_screen_width;  // ❌ Unknown address!
int w = g_screen_width;
```

**Solution: Reverse engineer variable locations**
```bash
# 1. Find code that uses screen width
grep "ld.l.*%r16" kernel.asm | grep "0xF80B"  # Looking in __DATA segment

# 2. Example: Found this instruction:
#    ld.l 0xF80B4120(%r0), %r16   ; Load screen width
#
# So g_screen_width is at address 0xF80B4120

# 3. Hardcode in your payload:
```

```assembly
; Read screen width
ld.l 0xF80B4120(%r0), %r16   ; *** HARDCODED ADDRESS ***
```

**Again, extremely brittle.**

---

## Part 4: The Hook Table Architecture

### A Better Approach: Dynamic Extensibility

Instead of hardcoding features, create an **infrastructure** for dynamic code loading.

### The Concept

```
┌─────────────────────────────────────────────────────────────┐
│  Original Kernel Code                                       │
│  ═════════════════════════════════════════════════════════  │
│                                                             │
│  on_vblank:                                                 │
│      ld.l hook_table+0, %r24    ; ← PATCHED: Check hook     │
│      btne %r24, %r0, call_hook  ; ← PATCHED: If set, call   │
│      nop                                                    │
│      ... original vblank code ...                           │
│                                                             │
│  on_fill_rect:                                              │
│      ld.l hook_table+4, %r24    ; ← PATCHED: Check hook     │
│      btne %r24, %r0, call_hook  ; ← PATCHED: If set, call   │
│      nop                                                    │
│      ... original fill code ...                             │
│                                                             │
│  call_hook:                                                 │
│      bri %r24                   ; ← Jump to hook function   │
│      nop                                                    │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼ (loads address from)
┌─────────────────────────────────────────────────────────────┐
│  Hook Table (in freed Emacs changelog space)                │
│  @ 0xF80BAD5D (30 KB available)                             │
│  ═════════════════════════════════════════════════════════  │
│                                                             │
│  hook_table:                                                │
│      .long 0x00000000       ; on_vblank_hook (NULL)         │
│      .long 0x00000000       ; on_fill_rect_hook (NULL)      │
│      .long 0x00000000       ; on_blit_hook (NULL)           │
│      .long 0x00000000       ; on_text_hook (NULL)           │
│      .long 0x00400000       ; on_boot_hook (set!)           │
│      ... (64 hook slots = 256 bytes)                        │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Hook Manager Code (~2 KB)                             │  │
│  │                                                       │  │
│  │ register_hook(slot, address):                         │  │
│  │     hook_table[slot] = address                        │  │
│  │                                                       │  │
│  │ unregister_hook(slot):                                │  │
│  │     hook_table[slot] = 0                              │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ User Code Area (~27 KB)                               │  │
│  │                                                       │  │
│  │ [Space for host to upload custom i860 code]           │  │
│  │                                                       │  │
│  │ Example: Custom splash screen function                │  │
│  │ @ 0x00400000 (in DRAM, uploaded by host)              │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### How It Works

**1. At boot** (patched kernel initialization):
```assembly
; Kernel init (PATCHED)
kernel_init:
    call init_hook_system   ; ← PATCHED: Initialize hooks
    nop
    ... continue normal boot ...

init_hook_system:
    ; Zero out hook table
    orh  0xF80B, %r0, %r16
    or   0xAD5D, %r16, %r16   ; r16 = 0xF80BAD5D (hook table base)
    or   %r0, %r0, %r17       ; r17 = 0 (NULL)
    or   64, %r0, %r18        ; r18 = 64 (loop counter)

clear_loop:
    st.l %r17, 0(%r16)        ; hook_table[i] = NULL
    adds 4, %r16, %r16        ; i++
    subs 1, %r18, %r18
    bnz  clear_loop
    nop

    bri %r1                   ; Return
    nop
```

**2. At runtime** (host uploads code):
```c
/* Host-side (NDserver-NG) */

// 1. Compile custom splash function to i860 machine code
uint8_t splash_code[] = { /* raw i860 opcodes */ };

// 2. Upload to i860 DRAM via DMA
nd_write_memory(0x00400000, splash_code, sizeof(splash_code));

// 3. Register hook via new mailbox command
nd_mailbox_send(CMD_REGISTER_HOOK, 4, 0x00400000);
//                                  ↑  ↑
//                               slot  address
```

**3. New mailbox command handler** (patched into kernel):
```assembly
; CMD_REGISTER_HOOK (command code = 0x80)
; Args: r16 = slot number, r17 = function address

cmd_register_hook:
    ; Validate slot number (must be 0-63)
    orh  64, %r0, %r18
    bc   %r16, %r18, error_invalid_slot
    nop

    ; Calculate hook_table[slot] address
    orh  0xF80B, %r0, %r18
    or   0xAD5D, %r18, %r18   ; r18 = hook_table base
    shl  2, %r16, %r16        ; slot *= 4 (word size)
    addu %r16, %r18, %r18     ; r18 = &hook_table[slot]

    ; Store function address
    st.l %r17, 0(%r18)        ; hook_table[slot] = address

    ; Return success
    or   1, %r0, %r16         ; return 1
    bri  %r1
    nop

error_invalid_slot:
    or   %r0, %r0, %r16       ; return 0
    bri  %r1
    nop
```

**4. When hook is triggered** (e.g., on VBLANK):
```assembly
; Original VBLANK handler (PATCHED)
vblank_handler:
    ; Check if hook is registered
    ld.l hook_table+0, %r24   ; Load on_vblank_hook
    btne %r24, %r0, call_hook ; If not NULL, call it
    nop

    ; Original VBLANK code
    ... (increment frame counter, etc.) ...

    bri %r1
    nop

call_hook:
    ; Save return address (we need to come back here)
    st.l %r1, -4(%r2)
    adds -8, %r2, %r2

    ; Call the hook
    bri %r24                  ; Jump to user's hook function
    nop

    ; When hook returns, continue with original code
    adds 8, %r2, %r2
    ld.l -4(%r2), %r1
    br   vblank_handler+12    ; Skip the hook check, continue
    nop
```

---

### The Protocol: CMD_REGISTER_HOOK

**Mailbox command structure**:
```c
struct cmd_register_hook {
    uint32_t command;    // 0x80 (CMD_REGISTER_HOOK)
    uint32_t slot;       // 0-63 (which hook)
    uint32_t address;    // 0x00000000 = unregister, else = function pointer
};
```

**Hook slots** (proposed):
```c
#define HOOK_ON_VBLANK          0   // Called every frame (60 Hz)
#define HOOK_ON_BOOT            1   // Called once at kernel startup
#define HOOK_ON_CMD_RECEIVED    2   // Called for every mailbox command
#define HOOK_ON_FILL_RECT       3   // Called before CMD_FILL executes
#define HOOK_ON_BLIT            4   // Called before CMD_BLIT executes
#define HOOK_ON_TEXT            5   // Called before CMD_TEXT executes
#define HOOK_PRE_RENDER         6   // Called before framebuffer update
#define HOOK_POST_RENDER        7   // Called after framebuffer update
// ... etc., up to 64 slots
```

**Example: Install splash screen on boot**:
```c
/* Host code */

// 1. Compile splash function
const uint8_t splash[] = {
    0x68, 0x00, 0x45, 0xC0,  // call fill_rect (hardcoded addr)
    0x44, 0x00, 0x00, 0x01,  // nop (delay slot)
    0x68, 0x00, 0x00, 0x01,  // bri %r1 (return)
    0x44, 0x00, 0x00, 0x01,  // nop (delay slot)
};

// 2. Upload to DRAM
nd_write_memory(0x00400000, splash, sizeof(splash));

// 3. Register on HOOK_ON_BOOT
nd_send_command(CMD_REGISTER_HOOK, HOOK_ON_BOOT, 0x00400000);

// 4. Reboot i860
nd_reset();

// Result: Splash screen appears at boot!
```

---

## Part 5: The "GaCKliNG v0.5 Kernel Patcher"

### A Tool to Automate This

**Concept**: Build a patcher that takes the original NeXT firmware and injects the hook infrastructure.

**Input**: `ND_MachDriver_reloc` (original, 795 KB)
**Output**: `ND_MachDriver_ext.bin` (patched, 795 KB)

### Patcher Architecture

```
┌──────────────────────────────────────────────────────────┐
│  GaCKliNG Kernel Patcher v0.5                            │
│  ══════════════════════════════════════════════════════  │
│                                                          │
│  1. Load original firmware                               │
│  2. Locate Emacs changelog (offset 765,117)              │
│  3. Replace with:                                        │
│     - Hook table (256 bytes)                             │
│     - Hook manager code (2 KB)                           │
│     - CMD_REGISTER_HOOK handler (512 bytes)              │
│     - Free space (27+ KB for user code)                  │
│  4. Patch kernel at key points:                          │
│     - Boot init: Call init_hook_system                   │
│     - Main dispatch: Add CMD_REGISTER_HOOK handler       │
│     - VBLANK: Check hook_table[0]                        │
│     - CMD_FILL: Check hook_table[3]                      │
│     - (etc., for each hook slot)                         │
│  5. Recalculate checksums (if any)                       │
│  6. Write patched firmware                               │
└──────────────────────────────────────────────────────────┘
```

### Implementation (Python Pseudocode)

```python
#!/usr/bin/env python3
# gackling_patcher.py

import struct

class KernelPatcher:
    def __init__(self, firmware_path):
        with open(firmware_path, 'rb') as f:
            self.data = bytearray(f.read())

    def locate_changelog(self):
        # Find "* Version 18.36 released"
        marker = b"* Version 18.36 released"
        offset = self.data.find(marker)
        print(f"Found changelog at offset {offset}")
        return offset

    def inject_hook_system(self, offset):
        # 1. Build hook table (64 slots, all NULL)
        hook_table = struct.pack('<' + 'I'*64, *([0]*64))

        # 2. Assemble hook manager code
        hook_manager = assemble_i860("""
            init_hook_system:
                orh  0xF80B, %r0, %r16
                or   0xAD5D, %r16, %r16
                or   %r0, %r0, %r17
                or   64, %r0, %r18
            clear_loop:
                st.l %r17, 0(%r16)
                adds 4, %r16, %r16
                subs 1, %r18, %r18
                bnz  clear_loop
                nop
                bri  %r1
                nop

            register_hook:
                ; ... (implementation from above)
        """)

        # 3. Inject into freed space
        self.data[offset:offset+256] = hook_table
        self.data[offset+256:offset+256+len(hook_manager)] = hook_manager

        print(f"Injected {len(hook_table) + len(hook_manager)} bytes")

    def patch_boot_init(self):
        # Find kernel_init function (via pattern matching)
        # Insert: call init_hook_system

        # This requires disassembly and analysis!
        # (Simplified for demo)
        boot_offset = 0x1000  # Example
        call_insn = encode_i860_call(0xF80BAD5D + 256)  # Call hook manager
        self.data[boot_offset:boot_offset+8] = call_insn

    def patch_mailbox_dispatcher(self):
        # Add handler for CMD_REGISTER_HOOK (0x80)
        # (Similar approach - find dispatcher, add case)
        pass

    def patch_vblank(self):
        # Insert hook check at VBLANK handler
        pass

    def save(self, output_path):
        with open(output_path, 'wb') as f:
            f.write(self.data)
        print(f"Saved patched firmware to {output_path}")

def main():
    patcher = KernelPatcher('ND_MachDriver_reloc')

    changelog_offset = patcher.locate_changelog()
    patcher.inject_hook_system(changelog_offset)
    patcher.patch_boot_init()
    patcher.patch_mailbox_dispatcher()
    patcher.patch_vblank()
    # ... patch other hook points ...

    patcher.save('ND_MachDriver_ext.bin')
    print("✅ Patching complete!")

if __name__ == '__main__':
    main()
```

### Challenges in Implementation

**1. Disassembly Required**
- Must disassemble entire kernel to find patch points
- Pattern matching is fragile (different firmware versions)

**2. Instruction Encoding**
- Must correctly encode i860 branch/call instructions
- Offset calculations are tricky (PC-relative addressing)

**3. Testing**
- Each patch must be tested in emulator
- One wrong byte = kernel crash

**4. Versioning**
- Different NeXT firmware versions have different layouts
- Patcher must detect version and adjust

---

## Part 6: Comparison - Patch vs Clean Reimplementation

### Development Effort

| Task | Binary Patching | Clean Reimplementation (GaCKliNG) |
|------|-----------------|-----------------------------------|
| **Initial Research** | Medium (disassembly, analysis) | High (reverse engineer protocol) |
| **Core Implementation** | Medium (write patcher tool) | Very High (write entire kernel) |
| **Testing** | Very High (fragile, hard to debug) | Medium (standard development) |
| **Documentation** | Low (just patcher usage) | High (full kernel architecture) |
| **Maintenance** | Very High (breaks on version changes) | Low (you own the code) |
| **Total Effort** | **~4-6 weeks** | **~8-12 weeks** |

**Verdict**: Patching is faster to **initial proof-of-concept**, but slower to **stable production**.

---

### Risk Assessment

| Risk | Binary Patching | GaCKliNG |
|------|-----------------|----------|
| **Kernel crashes** | Very High (wrong offsets = instant crash) | Low (you control all code) |
| **Version incompatibility** | Critical (NeXT firmware update breaks everything) | None (independent) |
| **Maintenance burden** | Very High (every patch must be re-validated) | Low (standard code maintenance) |
| **Unknown bugs** | High (original kernel has unknown bugs you can't fix) | Low (you can fix your own bugs) |
| **GPL compliance** | Unclear (derivative work of proprietary firmware?) | Clear (100% GPL from scratch) |
| **Community contribution** | Impossible (can't share proprietary binary) | Easy (open source from day 1) |

**Verdict**: Clean reimplementation has **much lower long-term risk**.

---

### Feature Flexibility

| Feature | Binary Patching | GaCKliNG |
|---------|-----------------|----------|
| **Add new mailbox commands** | Limited (must hook existing dispatcher) | Unlimited (full control) |
| **Modify graphics primitives** | Very Hard (must hook/replace original) | Easy (rewrite from scratch) |
| **Add splash screen** | Easy (via HOOK_ON_BOOT) | Easy (built-in) |
| **Implement font cache** | Hard (must inject into existing memory manager) | Easy (designed from start) |
| **Support new video modes** | Very Hard (original RAMDAC init is complex) | Medium (write new init code) |
| **Fix original bugs** | Impossible (can't modify closed-source code) | Trivial (it's your code) |
| **Optimize performance** | Limited (can't touch hot paths) | Unlimited (rewrite everything) |

**Verdict**: GaCKliNG has **orders of magnitude more flexibility**.

---

### Legal and Licensing

| Aspect | Binary Patching | GaCKliNG |
|--------|-----------------|----------|
| **Distributable?** | **NO** (requires proprietary NeXT binary) | **YES** (100% original code) |
| **GPL compliant?** | **Unclear** (derivative work?) | **YES** (GPL from day 1) |
| **Commercial use?** | **NO** (copyright infringement risk) | **YES** (GPL allows commercial) |
| **Community forks?** | **NO** (can't share base binary) | **YES** (encouraged!) |
| **NeXT legal action risk?** | **Medium-High** (distributing modified proprietary binary) | **Low** (clean-room reimplementation) |

**Verdict**: Only GaCKliNG is **legally safe to distribute**.

---

### Summary Table

| Criteria | Binary Patching | GaCKliNG | Winner |
|----------|-----------------|----------|--------|
| Time to first demo | 4 weeks | 10 weeks | **Patching** |
| Stability | Low | High | **GaCKliNG** |
| Feature additions | Limited | Unlimited | **GaCKliNG** |
| Bug fixes | Impossible | Easy | **GaCKliNG** |
| Maintenance | Very High | Low | **GaCKliNG** |
| Legal safety | Risky | Safe | **GaCKliNG** |
| Community | Can't share | Open source | **GaCKliNG** |
| Learning value | Medium | Very High | **GaCKliNG** |
| Historical preservation | Medium | High | **GaCKliNG** |
| **Overall** | **Good for quick hacks** | **Good for real product** | **GaCKliNG** |

---

## Part 7: Why We Chose Clean Reimplementation

### Engineering Rationale

**1. Ownership of the Codebase**

```
Binary Patching:
├── 765 KB original NeXT code (unknown, buggy, unmaintainable)
└── 30 KB your code (known, but limited)

Result: You own 3.8% of the firmware.

GaCKliNG:
└── 795 KB your code (known, clean, documented)

Result: You own 100% of the firmware.
```

**Which would you rather maintain?**

---

**2. Stability and Debuggability**

**Scenario**: Kernel crashes on CMD_BLIT.

**With patching**:
```
1. Is it your hook code? (maybe)
2. Is it the original kernel? (maybe)
3. Did your hook corrupt the kernel's state? (maybe)
4. Can you fix the original kernel if it's buggy? (NO)

Debugging: Nightmare.
```

**With GaCKliNG**:
```
1. Is it your code? (YES)
2. Can you add debug logging? (YES)
3. Can you fix the bug? (YES)
4. Can you single-step in a debugger? (YES)

Debugging: Standard software development.
```

---

**3. Feature Implementation Complexity**

**Example**: Add 1366×768 video mode support.

**With patching**:
```
Challenge:
1. Find where original kernel programs RAMDAC (hard)
2. Reverse engineer the RAMDAC init sequence (very hard)
3. Hook the init function (medium)
4. Modify the timing registers (hard - what if you break 1120×832?)
5. Test without breaking original modes (very hard)

Effort: 2-3 weeks
Risk: High (might break existing modes)
```

**With GaCKliNG**:
```
Challenge:
1. Write RAMDAC init from datasheet (medium)
2. Add mode table entry (trivial)
3. Test all modes (standard QA)

Effort: 3-5 days
Risk: Low (you control all code paths)
```

---

**4. Community and Open Source**

**With patching**:
- ❌ Can't distribute (requires proprietary binary)
- ❌ Can't accept community patches (legal risk)
- ❌ Can't publish on GitHub (copyright violation)
- ❌ Can't write papers about it (reveals proprietary info)
- ✅ Can use personally (fair use)

**With GaCKliNG**:
- ✅ Can distribute freely (GPL)
- ✅ Can accept pull requests (it's open source!)
- ✅ Can publish on GitHub (encouraged!)
- ✅ Can write academic papers (it's your work)
- ✅ Can fork and modify (GPL freedom)

**Impact**: GaCKliNG can have a **community**, patching is a **solo project**.

---

**5. Historical Preservation**

**With patching**:
- You learn how to patch binaries (valuable skill)
- You don't learn how the kernel actually works (black box)
- Future developers can't study your work (no source)

**With GaCKliNG**:
- You learn NeXTdimension architecture (deep understanding)
- You document the entire system (historical preservation)
- Future developers can study and improve (open source legacy)

**30 years from now**, which has more value?

---

**6. The "It Just Works" Factor**

**With patching**:
```
User: Hey, GaCKliNG crashed when I ran Photoshop.
You:  Hmm, is it my hook code or NeXT's original kernel?
User: I don't know, it just crashed.
You:  I can't fix NeXT's bugs. Maybe avoid Photoshop?
User: ...
```

**With GaCKliNG**:
```
User: Hey, GaCKliNG crashed when I ran Photoshop.
You:  Let me check the logs. Oh, buffer overflow in blit function.
      [Fix the bug in GaCKliNG source]
      Done! Try this new build.
User: Works perfectly now!
```

**Ownership = Fixability.**

---

### The Decision

After weighing all factors, the GaCKliNG team chose **clean reimplementation** because:

1. ✅ **Lower long-term risk** (no dependency on proprietary code)
2. ✅ **Full control** (can fix any bug, add any feature)
3. ✅ **Legal safety** (GPL, distributable, forkable)
4. ✅ **Community building** (open source from day 1)
5. ✅ **Educational value** (deep understanding of architecture)
6. ✅ **Historical preservation** (document what NeXT built)
7. ✅ **Personal satisfaction** (build something from scratch)

**Yes, it takes longer.**
**Yes, it's more work.**
**But it's the right engineering decision for a long-term project.**

---

## Part 8: When Patching Makes Sense

### Use Cases Where Binary Patching is the Right Choice

**1. Rapid Prototyping**
- You want to test an idea **this weekend**
- Clean reimplementation would take months
- Example: "Can i860 do real-time video decoding?" → Patch in a decoder hook, test it

**2. ROM Firmware (Can't Rewrite)**
- Firmware is in ROM, can't be fully replaced
- You have RAM to spare
- Example: Patching game console firmware (ROM-based)

**3. Preserving Exact Original Behavior**
- You need bug-for-bug compatibility with original
- Example: Emulator developers patching BIOS to add debug hooks

**4. Learning Exercise**
- Goal is to learn reverse engineering, not ship a product
- Example: Student project to understand binary patching

**5. Closed Hardware**
- No specs available, reverse engineering is only option
- Example: Patching proprietary printer firmware to add features

---

### Why It Doesn't Make Sense for GaCKliNG

**GaCKliNG's goals**:
1. ✅ Long-term maintainable product (not a hack)
2. ✅ Open source community project (not proprietary)
3. ✅ Full feature flexibility (not limited hooks)
4. ✅ Historical documentation (not just functionality)
5. ✅ Legal safety (not gray area)

**Patching fails on 4 out of 5 goals.**

**Reimplementation succeeds on 5 out of 5 goals.**

**Decision is clear.**

---

## Part 9: Technical Appendix

### A. i860 Instruction Encoding Reference

**Call instruction**:
```
Format: call target26
Opcode: 0x68 (bits 31-26)
Target: 26-bit signed offset (PC-relative)

Encoding:
  31   26 25                    0
  ┌──────┬────────────────────────┐
  │ 0x68 │   26-bit offset        │
  └──────┴────────────────────────┘

Example: call 0xF80BAD5D (from 0xF8001238)
  Offset = (0xF80BAD5D - 0xF8001238) / 4 = 0x272C9
  Encoding: 0x68000000 | 0x272C9 = 0x680272C9
```

**Branch instruction**:
```
Format: br target26
Opcode: 0x68 (same as call, but doesn't save %r1)

(Identical encoding to call)
```

**Conditional branch**:
```
Format: btne src1, src2, target16
Opcode: 0x5A (bits 31-26)

Encoding:
  31   26 25  21 20  16 15            0
  ┌──────┬──────┬──────┬──────────────┐
  │ 0x5A │ src1 │ src2 │  16-bit offs │
  └──────┴──────┴──────┴──────────────┘

Example: btne %r24, %r0, call_hook
  If call_hook is 3 instructions away:
  Offset = 3
  src1 = 24 (r24)
  src2 = 0 (r0)
  Encoding: 0x5A1800003
```

---

### B. Finding Offsets in Mach-O Binaries

**Virtual address → File offset conversion**:

```python
def virtual_to_file_offset(vaddr, segments):
    """
    Convert virtual address to file offset.

    segments = [
        {'vmaddr': 0xF8000000, 'vmsize': 0xB4000,
         'fileoff': 840, 'filesize': 737280},
        {'vmaddr': 0xF80B4000, 'vmsize': 0x12000,
         'fileoff': 738120, 'filesize': 57344},
    ]
    """
    for seg in segments:
        vm_start = seg['vmaddr']
        vm_end = vm_start + seg['vmsize']

        if vm_start <= vaddr < vm_end:
            offset_in_segment = vaddr - vm_start
            file_offset = seg['fileoff'] + offset_in_segment
            return file_offset

    raise ValueError(f"Address {hex(vaddr)} not in any segment")

# Example:
vaddr = 0xF8001238  # Main dispatch loop
file_offset = virtual_to_file_offset(vaddr, segments)
# Result: 840 + 0x1238 = 5,496
```

---

### C. Hook Function ABI Contract

**Calling convention for hook functions**:

```c
/* Hook function signature */
typedef void (*hook_func_t)(void);

/* ABI requirements:
 *
 * On entry:
 *   %r1  = Return address (call site)
 *   %r2  = Stack pointer (you have ~256 bytes available)
 *   %r16-r31 = May contain kernel state (DO NOT CLOBBER without saving!)
 *   %f0-f31  = May contain FPU state (save if you use FPU)
 *
 * On exit:
 *   %r1  = Must be unchanged (unless you want to change return addr)
 *   %r2  = Must be unchanged (don't leak stack)
 *   ALL OTHER REGISTERS must be restored to entry state
 *
 * Failure to comply = kernel crash
 */

/* Example compliant hook (assembly) */
__asm__(
    "my_hook:                    \n"
    "    st.l %r16, -4(%r2)      \n"  // Save r16
    "    st.l %r17, -8(%r2)      \n"  // Save r17
    "    adds -16, %r2, %r2      \n"  // Adjust stack
    "                            \n"
    "    ; Your code here        \n"
    "    orh 0x1000, %r0, %r16   \n"  // Example: load VRAM base
    "    or  0x0000, %r16, %r16  \n"
    "    st.l %r0, 0(%r16)       \n"  // Clear first pixel
    "                            \n"
    "    adds 16, %r2, %r2       \n"  // Restore stack
    "    ld.l -4(%r2), %r16      \n"  // Restore r16
    "    ld.l -8(%r2), %r17      \n"  // Restore r17
    "    bri %r1                 \n"  // Return
    "    nop                     \n"  // Delay slot
);
```

---

### D. Example: Complete Patchable Binary

**File**: `ND_MachDriver_ext.bin` (output of patcher)

**Modifications from original**:
```
Offset      Original                        Patched
══════════  ══════════════════════════════  ══════════════════════════════
765,117     "* Version 18.36 released\n"    Hook table (256 bytes)
765,373     "Wed Jan 21 02:13:17..."        Hook manager code (2 KB)
767,421     (continued changelog)           CMD_REGISTER_HOOK handler (512 B)
767,933     (continued changelog)           Free space for user code (27 KB)

4,200       or %r0, %r0, %r16 (nop)         call init_hook_system
4,204       or %r0, %r0, %r17 (nop)         nop

18,500      br main_loop                    ld.l hook_table+8, %r24
18,504      nop                             btne %r24, %r0, call_vblank_hook

...
```

**Result**: Drop-in replacement for original firmware, but with extensibility hooks.

---

## Conclusion

### What We've Learned

**Binary patching is**:
- ✅ **Theoretically viable** - Yes, you can replace the Emacs changelog with code
- ✅ **Technically challenging** - Requires expert-level reverse engineering
- ✅ **Useful for rapid prototyping** - Quick way to test ideas
- ❌ **Not suitable for production** - Too fragile, unmaintainable, legally risky

**Clean reimplementation (GaCKliNG) is**:
- ✅ **More work upfront** - Takes longer to build from scratch
- ✅ **Lower long-term risk** - No dependency on proprietary code
- ✅ **Fully flexible** - Can implement any feature
- ✅ **Legally safe** - GPL, distributable, forkable
- ✅ **Better for community** - Open source, maintainable

### The Path Forward

**For GaCKliNG**: We're building from scratch. This document serves as a record of the alternative approach we considered and rejected.

**For others**: If you have a use case where patching makes sense (ROM firmware, rapid prototyping, learning exercise), this document provides a complete roadmap.

### The Irony

We discovered a 30 KB patch opportunity while investigating an **accidental 30 KB patch** (the Emacs changelog).

- NeXT accidentally patched in Stallman's changelog (build error)
- We could intentionally patch in our own code (engineering decision)
- But we're choosing to build clean instead (better engineering)

**History rhymes, but engineering improves.** 🚀

---

**Document Created**: November 5, 2025
**Alternative Evaluated**: Binary patching with hook table
**Decision**: Clean reimplementation (GaCKliNG)
**Reason**: Lower risk, higher flexibility, better community, legal safety

---

## References

**Binary Patching**:
- "Practical Binary Analysis" by Dennis Andriesse
- "Reverse Engineering for Beginners" by Dennis Yurichev
- "The IDA Pro Book" by Chris Eagle

**i860 Architecture**:
- Intel i860 XR Microprocessor Family Programmer's Reference Manual
- i860 Instruction Set Quick Reference
- MAME i860 core source code (i860dis.cpp)

**Mach-O Format**:
- "Mac OS X Internals" by Amit Singh
- Apple's Mach-O Programming Topics
- otool(1) man page

**GaCKliNG Documentation**:
- KERNEL_ARCHITECTURE_COMPLETE.md
- GACKLING_PROTOCOL_DESIGN.md
- ND_MACHDRIVER_MEMORY_MAP.md
- THE_EMACS_CHANGELOG_INCIDENT.md

---

*"The best code is the code you wrote yourself, understand completely, and can fix when it breaks."*
*- GaCKliNG Development Philosophy*

*"Patching is hacking. Reimplementation is engineering."*
*- Also GaCKliNG Development Philosophy*
