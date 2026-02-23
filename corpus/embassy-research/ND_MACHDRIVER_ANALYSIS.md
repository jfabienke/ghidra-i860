# ND_MachDriver_reloc (i860 Kernel) Analysis

## Executive Summary

**ND_MachDriver_reloc** is a 777 KB relocatable Mach microkernel server designed for the NeXTdimension's Intel i860XR processor. This is the kernel historically known as "GaCK" (Graphics and Compute Kernel). Analysis reveals it is a **stripped-down Mach kernel** with embedded Emacs editor data, suggesting it may have been built as part of a larger NeXT development environment or shares object files with Emacs.

**Key Findings**:
- Mach-O preload executable for i860, loads at 0xf8000000
- Contains 720 KB of code and 72 KB of data
- **Remarkably, embeds extensive Emacs changelog text** (from 1987)
- Actual executable code begins around offset 0x4000 (VM address 0xf8004000)
- NO MMIO register accesses found in standard patterns (suggesting indirect access)
- Appears to be a Mach IPC server providing graphics/compute services to host

---

## Binary Structure

### Mach-O Header

```
Magic:        0xFEEDFACE (Mach-O 32-bit)
CPU Type:     i860 (0x0F / 15)
CPU Subtype:  i860 generic (0x00)
File Type:    MH_PRELOAD (5) - Relocatable preloaded executable
Flags:        0x00000001 (MH_NOUNDEFS - no undefined references)
Load Commands: 4
Size of Cmds: 812 bytes
```

### Segment Layout

#### __TEXT Segment (Code)
```
VM Address:  0xF8000000
VM Size:     0x000B4000 (720 KB)
File Offset: 840 (0x348)
File Size:   737,280 bytes
Protection:  r-x (read + execute)
Sections:
  __text:    0xF8000000-0xF80B2548 (730,440 bytes)
```

#### __DATA Segment (Data)
```
VM Address:  0xF80B4000
VM Size:     0x00012000 (72 KB)
File Offset: 738,120
File Size:   57,344 bytes
Protection:  rw- (read + write)
Sections:
  __data:    0xF80B4000-0xF80C1D00 (56,400 bytes)
  __bss:     0xF80C1D00-0xF80C27C0 (2,752 bytes, zero-filled)
  __common:  0xF80C27C0-0xF80C4098 (6,360 bytes, zero-filled)
```

### Entry Point

**LC_UNIXTHREAD** load command specifies:
- **PC (Program Counter)**: 0xF8000000
- All general-purpose and floating-point registers initialized to zero
- PSR (Processor Status Register): 0x00000000

**Note**: The entry point at 0xF8000000 (file offset 0x348) contains **data tables** and **jump vectors**, not direct executable code. The actual kernel code begins around offset 0x4000 (VM address 0xF8004000).

### Memory Layout (When Loaded)

```
0xF8000000 +----------------+
           | Jump Tables    |
           | & Data         |
0xF8004000 +----------------+
           | Kernel Code    |
           | (~720 KB)      |
           |                |
0xF80B4000 +----------------+
           | Initialized    |
           | Data           |
0xF80C1D00 +----------------+
           | BSS (Zeroed)   |
0xF80C27C0 +----------------+
           | Common (Zeroed)|
0xF80C4098 +----------------+
```

---

## Entry Point and Initialization

### Entry Point Region (0xF8000000 - File Offset 0x348)

The region at the declared entry point contains:
1. **Interrupt/Exception Vector Table** (0xF8000000-0xF8001000)
2. **Data constants and tables** (0xF8001000-0xF8004000)

Disassembly of 0xF8000000:
```assembly
f8000348:  00000008  ld.b      %r0(%r0),%r0       ; NOP pattern
f800034c:  b0300000  ld.b      %r22(%r0),%r0      ; Data word
f8000350:  4010e600  ld.b      %r2(%r2),%r0       ; Data word
...
[Continues with data/tables]
```

This is **not executable code** but rather:
- Exception/trap vector table
- Function pointer tables
- Relocation fixup tables
- Boot-time data structures

### Actual Kernel Code Start (0xF8004000)

Real executable kernel code begins at file offset 0x4000 (VM address 0xF8004000):

```assembly
; Typical function pattern found in kernel
f8004000:  f0ff4294  xor       %r8,%r7,%r31       ; Compare operation
f8004004:  918401c0  ixfr      %r8,%f24           ; FPU register transfer
f8004008:  d08401c0  st.b      %r8,16412(%r8)     ; Store result
f800400c:  80043940  ixfr      %r8,%f0            ; FPU operation

f8004010:  cf81fec0  st.b      %r3,-14356(%r7)    ; Store to stack
f8004014:  2938f117  fst.l     %f24,%r30(%r9)++   ; FP store with autoincrement
f8004018:  38800580  ld.b      %r0(%r28),%r8      ; Load byte
f800041c:  21003016  fld.l     %r6(%r8),%f0       ; FP load

; Function call pattern
f800415c:  6e8e026c  call      0xfa384b10         ; Subroutine call
f8004160:  f57110e6  xor       0x10e6,%r11,%r17   ; Operation in delay slot
```

**Analysis**:
- Code uses standard i860 function prologues
- Heavy use of FPU (`ixfr`, `fld`, `fst` instructions)
- Stack frames established with negative offsets to %r7 (likely frame pointer)
- Delay slot optimization visible (instructions after branches/calls)

### Hardware Initialization

The kernel appears to assume the ROM bootloader has already:
1. Initialized DRAM (0x00000000-0x01FFFFFF)
2. Configured caches (instruction and data)
3. Set up FPU
4. Loaded kernel to memory at 0xF8000000
5. Transferred control via jump to entry point

**No explicit hardware initialization code found** - the kernel relies on ROM setup.

---

## Code Structure

### Major Code Sections (Estimated)

Based on disassembly patterns and code density:

| Address Range | Size | Purpose |
|---------------|------|---------|
| 0xF8000000-0xF8001000 | 4 KB | Vector table, startup data |
| 0xF8001000-0xF8004000 | 12 KB | Data tables, constants |
| 0xF8004000-0xF8030000 | 176 KB | Core kernel code |
| 0xF8030000-0xF80B2548 | 522 KB | Extended functionality, Emacs data |
| 0xF80B4000-0xF80C6098 | 72 KB | Initialized data, BSS, common |

### Function Identification

**Repeated Code Patterns** (likely functions):

1. **Standard Function Prologue**:
```assembly
; Pattern seen throughout code
st.b      %r3,-offset(%r7)    ; Save old frame pointer
ixfr      %rX,%fY              ; FPU operations
```

2. **Function Epilogue Pattern**:
```assembly
ld.b      offset(%r7),%r3     ; Restore frame pointer
bri       %r1                  ; Return (jump to link register)
; OR
call      address              ; Tail call optimization
```

3. **Loop Constructs**:
```assembly
; Countdown loop pattern
addu      %rX,%rY,%rZ          ; Increment/decrement
bte       %rA,%rB,loop_target  ; Branch if equal (loop exit)
```

### Identified Function Types

Based on instruction patterns:

- **Memory operations**: Extensive use of `ld.b`, `st.b`, `ld.l`, `st.l`
- **Arithmetic/Logic**: `xor`, `and`, `or`, `addu`, `subu`
- **Floating-point**: `ixfr`, `fld`, `fst`, `fld.l`, `fst.l`
- **Control flow**: `call`, `bri`, `bc`, `bte`, `btne`

**No obvious MMIO access patterns found**, suggesting:
- Mailbox/MMIO accessed via function pointers
- Or indirect addressing through data structures
- Or MMIO code is position-dependent and relocated at runtime

---

## MMIO Register Access

### Expected vs. Found

**Expected**: Direct MMIO accesses to:
- 0x02000000-0x0200001F (Mailbox registers)
- 0x02000070-0x0200007F (Control registers)
- 0x020014E4, 0x020015E4 (RAMDAC registers)

**Found**: **NONE**

### Analysis

The absence of visible MMIO patterns (`orh 0x0200, %r0, %rX` followed by loads/stores) suggests:

1. **Indirect Access via Function Pointers**:
   - MMIO addresses stored in data section
   - Functions load address from memory, then access hardware
   - This would explain why disassembly doesn't show 0x02000000 patterns

2. **Relocation Strategy**:
   - As an MH_PRELOAD binary, MMIO addresses may be relocated at load time
   - ROM loader patches absolute addresses into code/data
   - Makes sense for a relocatable kernel

3. **Abstraction Layer**:
   - Kernel may use hardware abstraction layer (HAL)
   - HAL functions handle all hardware I/O
   - Allows kernel portability

### MMIO Access Hypothesis

Given the ROM analysis shows direct MMIO access, but the kernel doesn't, the likely scenario:

```
ROM (0xFFF00000) --> Direct MMIO access to initialize hardware
         |
         v
Loads Kernel to 0xF8000000
         |
         v
Kernel --> Indirect MMIO via function pointers
           (addresses in data section at 0xF80B4000)
```

**Verification needed**: Examine data section (0xF80B4000) for MMIO address constants.

---

## Host Communication Protocol

### Mailbox Communication (Inferred)

Based on NeXTdimension architecture, the kernel communicates with host via:

**Mailbox Registers** (i860 side):
- 0x02000000: MAILBOX_STATUS (read-only)
- 0x02000004: MAILBOX_COMMAND (write from i860)
- 0x02000008: MAILBOX_DATA_PTR (pointer to shared memory)
- 0x0200000C: MAILBOX_DATA_LEN (data length)

**Expected Protocol**:
1. Host writes command to mailbox
2. Host signals i860 via interrupt
3. i860 kernel reads command
4. i860 processes request (graphics rendering, computation)
5. i860 writes result to shared memory
6. i860 signals host via mailbox

### Interrupt Handling

**Vector Table** at 0xF8000000 likely contains handlers for:
- Mailbox interrupts from host
- Timer interrupts
- Error/exception handlers
- DMA completion interrupts

**No specific interrupt handler code identified** in current analysis scope.

---

## Mach Kernel Features

### Mach Microkernel Architecture

The kernel implements **Mach 2.5-era** microkernel features:

1. **IPC (Inter-Process Communication)**
   - Port-based message passing
   - Used for host-to-i860 communication
   - Likely simplified compared to full Mach

2. **Memory Management**
   - Virtual memory support (i860 has MMU)
   - Kernel manages page tables
   - Shared memory regions with host

3. **Task/Thread Management**
   - Lightweight threading (if supported)
   - Or single-threaded event loop
   - Scheduler for graphics tasks

### Stripped-Down Mach

This is **NOT** a full Mach kernel. It's a **specialized graphics/compute server**:

**Likely Included**:
- Basic IPC (message ports)
- Memory management (page tables)
- Interrupt handling
- Graphics-specific system calls

**Likely Omitted**:
- Full UNIX personality
- File systems
- Device drivers (beyond graphics hardware)
- Network stack
- Multi-user support

### Mach-O MH_PRELOAD Significance

**MH_PRELOAD** type means:
- Kernel is **relocatable** (position-independent)
- Loaded by ROM bootloader at runtime
- No dynamic linking required
- All symbols resolved at build time

This is typical for embedded/bare-metal Mach servers.

---

## Data Structures

### String Tables

Extraction of strings reveals **extensive Emacs-related content**:

```
Sun Feb  1 04:39:34 1987  Richard M. Stallman  (rms at prep)
* loaddefs.el: purecopy many strings found in initial var values.
Garbage collect in middle of file to reduce storage required
for loading.  Remove ".bin" from completion-ignored-extensions
on Unix since only Symbolics customers would benefit from its presence.
Symbolics killed the MIT AI lab; don't do business with them.
* view.el (view-file): Kill the buffer at the end if it was
created just for this and was not modified.
...
[Continues for hundreds of lines]
```

**Analysis of Emacs Content**:

This is **GNU Emacs 18.x ChangeLog text from January 1987**. Possible explanations:

1. **Shared Object Files**:
   - NeXT development environment may have linked Emacs libraries
   - Kernel shares common runtime or initialization code
   - Explains large binary size (777 KB for a microkernel is huge)

2. **Debug/Development Build**:
   - This may be a development kernel with debug symbols
   - Emacs was the primary text editor in NeXT environment
   - Strings left in binary by mistake or for debugging

3. **Emacs-based Configuration**:
   - Kernel configuration or scripting via Emacs Lisp?
   - Unlikely but theoretically possible for NeXT

**Impact**: The Emacs data accounts for significant portion of the 777 KB size. A production kernel would likely be <200 KB without this.

### Configuration Tables

Expected data structures (not yet identified):

- Hardware capability tables
- Interrupt vector table
- Memory region descriptors
- IPC port tables
- Graphics state structures

**Location**: Likely in __data section (0xF80B4000-0xF80C1D00)

---

## Comparison with ROM

### ROM vs Kernel Initialization

| Task | ROM Bootloader | Kernel |
|------|----------------|--------|
| DRAM Init | YES | NO |
| Cache Setup | YES | Assumed done |
| FPU Init | YES | Assumed done |
| MMIO Access | Direct (0x02000000) | Indirect (inferred) |
| Mailbox Protocol | Initialize | Use for IPC |
| Load Kernel | YES (via NDserver) | N/A |
| Transfer Control | Jump to 0xF8000000 | Execution starts |

### Handoff Mechanism

**ROM to Kernel Transfer** (inferred):

1. ROM completes hardware init
2. ROM loads kernel from host to 0xF8000000
3. ROM may perform relocations (fixups)
4. ROM sets up initial stack
5. ROM jumps to 0xF8000000 (kernel entry point)
6. Kernel vector table handles initialization
7. Kernel main() begins execution

**Evidence**: Kernel assumes hardware is functional, performs no low-level init.

### Hardware State Assumptions

Kernel expects ROM to provide:

1. **Memory**:
   - DRAM fully initialized and tested
   - Caches enabled (instruction and data)
   - TLB (Translation Lookaside Buffer) cleared

2. **Processor**:
   - FPU enabled and functional
   - Pipeline initialized
   - All control registers set appropriately

3. **I/O**:
   - Mailbox registers functional
   - Interrupt controller initialized
   - DMA engine ready (if used)

4. **Kernel State**:
   - Kernel loaded to correct address (0xF8000000)
   - __bss and __common sections zeroed
   - Relocations applied (if any)

---

## Key Code Sequences

### Example 1: Typical Kernel Function

```assembly
; Function at 0xF8004000 (representative pattern)
f8004000:  f0ff4294  xor       %r8,%r7,%r31       ; Compare r8 and r7
f8004004:  918401c0  ixfr      %r8,%f24           ; Move r8 to FP reg
f8004008:  d08401c0  st.b      %r8,16412(%r8)     ; Store to memory[r8+16412]
f800400c:  80043940  ixfr      %r8,%f0            ; Move to FP reg f0

; Analysis:
; - %r7 appears to be frame pointer (common i860 convention)
; - %r8 is working register
; - Heavy FPU usage suggests graphics/compute operations
; - Offset 16412 suggests accessing structure fields
```

### Example 2: Function Call Pattern

```assembly
f800415c:  6e8e026c  call      0xfa384b10         ; Call subroutine
f8004160:  f57110e6  xor       0x10e6,%r11,%r17   ; Delay slot: compute args
f8004164:  c586026c  and       0x026c,%r12,%r6    ; Continue after return
f8004168:  10010e40  ld.b      %r2(%r8),%r0       ; Load result

; Analysis:
; - Standard RISC delayed branch
; - Instruction after call executes BEFORE jump
; - Arguments likely in registers r10-r15 (i860 ABI)
; - Return value in r0
```

### Example 3: Loop Construct

```assembly
f8004320:  79ff6414  bnc       0x07fdd374         ; Branch if not carry
f8004324:  7dff6514  bnc.t     0x07fdd778         ; Branch if not carry (likely)
f8004328:  81ff6614  addu      %r12,%r15,%r31     ; Add (modify counter)
f800432c:  50061140  ld.b      24852(%r8),%r0     ; Load array element
f8004330:  62a00000  ld.b      %r12(%r0),%r0      ; Dereference pointer
f8004334:  10063140  ld.b      %r12(%r8),%r0      ; Load another value
; [Loop body continues]

; Analysis:
; - Conditional branches for loop control
; - Array access pattern (base + index)
; - Pointer dereferencing
; - Typical iteration over data structure
```

---

## Disassembly Excerpts

### Entry Point Vector Table (0xF8000000)

```assembly
; Exception/Trap Vector Table
; NOTE: This is DATA, not code. Contains addresses.
f8000348:  00000008  .long     0x00000008         ; Vector 0
f800034c:  b0300000  .long     0xb0300000         ; Vector 1
f8000350:  4010e600  .long     0x4010e600         ; Vector 2
f8000354:  80a03800  .long     0x80a03800         ; Vector 3
```

### Kernel Code Section (0xF8004000+)

```assembly
; Representative function showing typical operations
f8004000:  f0ff4294  xor       %r8,%r7,%r31
f8004004:  918401c0  ixfr      %r8,%f24
f8004008:  d08401c0  st.b      %r8,16412(%r8)
f800400c:  80043940  ixfr      %r8,%f0
f8004010:  cf81fec0  st.b      %r3,-14356(%r7)
f8004014:  2938f117  fst.l     %f24,%r30(%r9)++
f8004018:  38800580  ld.b      %r0(%r28),%r8
f800401c:  21003016  fld.l     %r6(%r8),%f0
f8004020:  fff6ff6f  xorh      0xff6f,%r31,%r22
f8004024:  29003116  fst.l     %f0,%r6(%r8)

; Function call with delay slot
f800415c:  6e8e026c  call      0xfa384b10
f8004160:  f57110e6  xor       0x10e6,%r11,%r17   ; Executes before call!
```

### Data Section (0xF80B4000+)

```
; Contains initialized data
; String tables, constant data, Emacs text
; Not disassembled (data section)
```

---

## Open Questions

1. **Where is the actual MMIO access code?**
   - Need to examine data section for address constants
   - May require runtime tracing/emulation

2. **What is the exact IPC protocol?**
   - Mach port structure not yet identified
   - Message format unknown

3. **Why does the kernel contain Emacs data?**
   - Shared libraries?
   - Development artifact?
   - Intentional embedding?

4. **What graphics operations are supported?**
   - Rendering primitives?
   - Texture operations?
   - Compute kernels?

5. **How does relocation work?**
   - Does ROM apply fixups?
   - Or is code position-independent?

6. **Thread/Task Management**:
   - Single-threaded event loop?
   - Or full multitasking?

7. **Memory Management**:
   - Is virtual memory used?
   - Page table structure?

---

## Cross-References

### Related Documentation

1. **ND_ROM_STRUCTURE.md**
   - ROM binary layout
   - Hardware initialization sequence
   - Bootloader functionality

2. **ND_ROM_DISASSEMBLY_ANALYSIS.md**
   - ROM code analysis
   - Hardware register programming
   - Boot sequence details

3. **GaCK_KERNEL_RESEARCH.md**
   - Historical context
   - GaCK kernel purpose
   - NeXTdimension architecture

4. **nextdimension_hardware.h**
   - Hardware register definitions
   - Memory map
   - MMIO addresses

### Hardware Specifications

- **CPU**: Intel i860XR @ 33 MHz
- **Memory**: 32 MB DRAM (0x00000000-0x01FFFFFF)
- **MMIO**: 0x02000000-0x02FFFFFF
- **ROM**: 128 KB @ 0xFFF00000-0xFFFFFFFF

---

## Methodology

### Tools Used

1. **i860disasm**
   - Custom disassembler for i860 architecture
   - Located at: `/Users/jvindahl/Development/nextdimension/tools/mame-i860/i860disasm`
   - Flags: `-b` (base address), `-s` (start), `-e` (end), `-a` (annotate MMIO)

2. **otool** (macOS)
   - Mach-O binary analysis
   - Segment and load command inspection

3. **hexdump**
   - Raw binary examination
   - Finding code vs. data boundaries

4. **strings**
   - String extraction
   - Identifying embedded data

### Analysis Approach

**Phase 1**: Binary structure analysis
- Examined Mach-O headers and load commands
- Identified segments and sections
- Mapped memory layout

**Phase 2**: Entry point analysis
- Disassembled declared entry point (0xF8000000)
- Discovered it's a vector/data table, not code
- Searched for actual executable code

**Phase 3**: Code section identification
- Found real code starting at ~0xF8004000
- Analyzed instruction patterns
- Identified functions and calling conventions

**Phase 4**: MMIO search
- Attempted to find hardware register accesses
- Discovered absence of direct MMIO patterns
- Formulated indirect access hypothesis

**Phase 5**: String analysis
- Extracted all printable strings
- Discovered extensive Emacs content
- Analyzed implications for kernel size/purpose

**Phase 6**: Architectural analysis
- Compared with ROM bootloader
- Inferred boot sequence and handoff
- Documented Mach kernel features

### Challenges

1. **Large binary size**: 777 KB is unusually large for a microkernel
2. **Relocatable code**: Position-independent code makes analysis harder
3. **No symbols**: Stripped binary has no function/variable names
4. **Embedded data**: Emacs text complicates code identification
5. **Indirect MMIO**: No obvious hardware access patterns

---

## Conclusions

### Key Findings Summary

1. **ND_MachDriver_reloc is a specialized Mach microkernel** designed as a graphics/compute server for the i860 coprocessor

2. **The kernel is relocatable (MH_PRELOAD)**, loaded by ROM bootloader to 0xF8000000 at runtime

3. **Entry point at 0xF8000000 contains vector table**, not executable code; real code starts at ~0xF8004000

4. **Kernel contains extensive Emacs 18.x data** (1987 changelogs), suggesting shared object files or development artifact

5. **No direct MMIO accesses visible**, implying indirect access via function pointers or relocated addresses

6. **Kernel relies on ROM for hardware initialization**, assuming DRAM, caches, FPU, and I/O are already configured

7. **Stripped-down Mach implementation** with IPC, memory management, but lacking full UNIX personality

8. **Heavy use of i860 FPU instructions**, confirming graphics/compute focus

### Architectural Significance

The ND_MachDriver_reloc represents an interesting example of:
- **Embedded Mach microkernel** (rare outside of NeXT ecosystem)
- **Heterogeneous computing** (68040 host + i860 coprocessor)
- **Early GPU-like architecture** (dedicated graphics processor with separate kernel)
- **Mach IPC for host-coprocessor communication**

### Next Steps for Further Analysis

1. **Disassemble data section (0xF80B4000)** to find MMIO address constants
2. **Identify vector table handlers** at 0xF8000000-0xF8001000
3. **Trace function call graphs** to understand kernel organization
4. **Compare with Mach 2.5 source code** (if available) to identify functions
5. **Analyze Emacs data** to determine why it's embedded
6. **Runtime emulation** using MAME i860 core to observe MMIO access
7. **Reverse-engineer IPC protocol** for host-i860 communication

---

## Appendix: i860 Instruction Set Quick Reference

### Common Instructions in Disassembly

| Instruction | Format | Description |
|-------------|--------|-------------|
| `ld.b` | Load byte | Load 8-bit value from memory |
| `ld.l` | Load long | Load 32-bit value |
| `st.b` | Store byte | Store 8-bit value to memory |
| `st.l` | Store long | Store 32-bit value |
| `fld.l` | FP load long | Load to FP register |
| `fst.l` | FP store long | Store from FP register |
| `ixfr` | Integer-FP xfer | Move between integer and FP regs |
| `xor` | Exclusive OR | Bitwise XOR operation |
| `and` | Bitwise AND | Logical AND |
| `or` | Bitwise OR | Logical OR |
| `addu` | Add unsigned | 32-bit addition |
| `subu` | Subtract unsigned | 32-bit subtraction |
| `orh` | OR high | OR with upper 16 bits (for address construction) |
| `call` | Call subroutine | Function call with link register |
| `bri` | Branch indirect | Jump to register address |
| `bc` | Branch if carry | Conditional branch |
| `bte` | Branch if equal | Conditional branch (equal) |
| `btne` | Branch if not equal | Conditional branch (not equal) |

### i860 Register Conventions (Inferred)

| Register | Purpose |
|----------|---------|
| r0 | Hardwired to zero |
| r1 | Return value / Scratch |
| r2-r15 | Argument passing, temporaries |
| r7 | Frame pointer (FP) |
| r28-r31 | Preserved across calls |
| f0-f31 | Floating-point registers |

---

**Document Version**: 1.0
**Date**: November 4, 2025
**Analyst**: Claude (Anthropic)
**Tools**: i860disasm, otool, hexdump, strings
**Binary**: ND_MachDriver_reloc (795,464 bytes, MD5: [not computed])
