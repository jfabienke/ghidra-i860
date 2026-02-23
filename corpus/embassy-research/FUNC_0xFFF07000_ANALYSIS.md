# Function Analysis: 0xFFF07000 - Main Graphics Command Loop

## Overview

**Address**: 0xFFF07000
**Type**: Command dispatcher / Graphics operation loop
**Calls**: Unknown (indirect branches suggest dispatch table)
**Called By**: Unknown (needs reverse analysis)

**Evidence**:
- 20 VRAM accesses (highest in firmware)
- 3 Mailbox accesses
- Repeating execution patterns
- Indirect branches (computed jumps)
- Heavy FPU register usage

---

## Key Patterns Identified

### Pattern 1: Repeating Block (Data Processing Loop)

This sequence appears **4 times** in quick succession:

```i860asm
Location 1: 0xFFF06FFC
Location 2: 0xFFF070BC
Location 3: 0xFFF07144
Location 4: 0xFFF07210

; Pattern:
fff06ffc:  80040000  ld.b      %r0(%r0),%r8          ; Load byte (from command/data?)
fff07000:  80042840  ixfr      %r8,%f0               ; Move to FP reg (data path optimization)
fff07004:  f0ff4294  xor       %r8,%r7,%r31          ; Test/mask operation
fff07008:  918401c0  ixfr      %r8,%f24              ; Move through FP pipeline
fff0700c:  d08401c0  st.b      %r8,16412(%r8)        ; Write to offset 16412 (0x401C)
fff07010:  80043940  ixfr      %r8,%f0               ; Return from FP pipeline
```

**Analysis**:
- **Offset 16412 (0x401C)**: This is likely a VRAM address or hardware register
- **Multiple ixfr**: Using FPU for integer data movement (i860 optimization)
- **4 repetitions**: Suggests unrolled loop for performance
- **Purpose**: Likely copying/processing 4 pixels or data words

### Pattern 2: Indirect Branch (Dispatch Mechanism)

```i860asm
; Compute jump target
fff06f48:  a1510849  shl       %r1,%r10,%r17         ; Shift to form table index
fff06f4c:  edff1316  orh       0x1316,%r15,%r31      ; Form high address
fff06f50:  40401748  bri       %r2                   ; Indirect branch to computed address

; This appears multiple times, suggesting a dispatch table
```

**Analysis**:
- **Shift left**: Multiplying index by power of 2 (likely 4 or 8 for pointer table)
- **orh (or high)**: Building full 32-bit address
- **bri %r2**: Jump through register (dispatch to handler)
- **Purpose**: Command dispatcher - reads opcode, jumps to handler

### Pattern 3: Control Register Access

```i860asm
fff06f5c:  301012e4  ld.c      %fir,%r16             ; Read Fault Instruction Register
fff06fd4:  301011e4  ld.c      %fir,%r16             ; (repeated)
fff070a0:  306811e4  ld.c      %db,%r8               ; Read Data Breakpoint register
fff071d0:  306811e4  ld.c      %db,%r8               ; (repeated)
```

**Analysis**:
- **FIR reads**: Checking for faults (exception handling)
- **DB reads**: Possibly for debugging or hardware status
- **Purpose**: Hardware state monitoring within command loop

### Pattern 4: Load/Store Operations

```i860asm
; Common pattern throughout:
fff06f38:  101012e4  ld.s      %r2(%r0),%r16         ; Load short (16-bit)
fff06f3c:  80ff52ee  addu      %r10,%r7,%r31         ; Compute address
...
fff0700c:  d08401c0  st.b      %r8,16412(%r8)        ; Store byte to fixed offset
```

**Analysis**:
- **Fixed offset 16412**: Repeatedly accessed - likely frame buffer or command register
- **Mixed sizes**: byte/short/long operations suggest structured data
- **Purpose**: Reading command parameters, writing results

---

## Proposed Function Structure

```c
// Pseudo-C reconstruction

void graphics_command_loop(void) {
    while (1) {
        // Pattern 2: Read command from mailbox/queue
        uint32_t command = read_command();
        uint32_t opcode = command & 0xFF;

        // Pattern 2: Dispatch to handler
        handler_func = dispatch_table[opcode];
        handler_func(command);

        // Pattern 1: Process data (unrolled loop)
        for (int i = 0; i < 4; i++) {
            uint8_t data = read_data();

            // Use FPU pipeline for fast data movement
            // (i860 specific optimization)
            data = process_through_fpu(data);

            // Write to VRAM or hardware register at offset 0x401C
            *(volatile uint8_t*)(vram_base + 0x401C) = data;
        }

        // Pattern 3: Check for faults
        if (check_fir()) {
            handle_fault();
        }
    }
}
```

---

## Hardware Interaction

### VRAM Writes
**Count**: 20 accesses in this region

**Key offset**: 16412 (0x401C)
- Repeatedly written to
- Likely frame buffer position or hardware register
- Could be:
  - Cursor position register
  - RAMDAC data register
  - Video timing register
  - Pixel data output

### Mailbox Reads
**Count**: 3 accesses

**Purpose**: Reading commands from host
- M68k or x86 host sends graphics commands
- Mailbox provides communication channel
- Commands include opcode + parameters

### Control Registers
- **FIR** (Fault Instruction Register): Exception monitoring
- **DB** (Data Breakpoint): Hardware status or debugging

---

## Call Graph Context

**Callers**: Unknown (needs analysis)
- Likely called from main kernel loop
- Or invoked by interrupt handler when mailbox has data

**Callees**: Multiple via dispatch table
- Graphics primitives (fill, blit, line, etc.)
- Parameter extraction functions
- Hardware setup functions

---

## Optimization Techniques Used

### 1. FPU Register Usage for Integer Data
```i860asm
ixfr %r8,%f0    ; Move integer through FP pipeline
```
**Why**: i860 has dual integer/FP pipelines - using FP registers for integer data allows parallel execution

### 2. Loop Unrolling
The 4x repeated block suggests manual loop unrolling for performance

### 3. Computed Branches
```i860asm
bri %r2         ; Indirect branch
```
**Why**: Faster than long chain of conditional branches for dispatch

---

## Next Steps for Complete Annotation

1. **Find dispatch table**:
   - Search for data structure with function pointers
   - Likely near this function or in data section

2. **Identify called functions**:
   - Follow bri targets
   - Map opcode → handler relationship

3. **Trace callers**:
   - Search for direct calls to 0xFFF07000
   - Check interrupt handler for invocation

4. **Map VRAM offset 16412**:
   - Cross-reference with RAMDAC datasheet
   - Determine exact hardware function

---

## Confidence Assessment

| Aspect | Confidence | Reasoning |
|--------|------------|-----------|
| **Is a loop** | 95% | Repeating patterns, no clear exit |
| **Command dispatcher** | 85% | Indirect branches, opcode-like operations |
| **Graphics related** | 90% | Heavy VRAM access, FPU usage |
| **Called from interrupt** | 70% | Common pattern for command processing |
| **Dispatch table exists** | 80% | Multiple indirect branches with similar setup |

---

## For GaCKliNG Implementation

### Reference This For:

1. **Command Processing Loop**:
   ```rust
   loop {
       let cmd = mailbox.read();
       dispatch_command(cmd);
   }
   ```

2. **FPU Optimization Pattern**:
   - Use SIMD/vector ops for data movement
   - Parallel integer/FP operations

3. **Dispatch Mechanism**:
   ```rust
   let handler = DISPATCH_TABLE[opcode];
   handler(params);
   ```

4. **Hardware Register Access**:
   - Document offset 0x401C usage
   - Understand write patterns

---

**Analysis Date**: November 5, 2025
**Status**: Initial analysis complete, needs deep dive for complete annotation
**Priority**: CRITICAL - This is the main command processor
