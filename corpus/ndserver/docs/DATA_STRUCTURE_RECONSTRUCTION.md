# Data Structure Reconstruction

**Project**: NDserver Reverse Engineering
**Status**: 29/88 functions analyzed (33%)
**Primary Focus**: `nd_board_info_t` - Core board management structure

---

## Table of Contents

1. [nd_board_info_t (80 bytes)](#1-nd_board_info_t-80-bytes) - **PRIMARY STRUCTURE**
2. [segment_descriptor_t](#2-segment_descriptor_t) - Mach-O Format
3. [transfer_descriptor_t](#3-transfer_descriptor_t) - DMA Operations
4. [Message Structures](#4-message-structures) - IPC Protocol
5. [Reconstruction Methodology](#5-reconstruction-methodology)

---

## 1. nd_board_info_t (80 bytes)

### 1.1 Overview

**Purpose**: Represents a single NeXTdimension board registered in a NeXTBus slot.

**Lifecycle**:
- **Created**: `ND_RegisterBoardSlot` via `malloc(80)`
- **Stored**: Global slot table at 0x0000819C (array of 4 pointers)
- **Indexed**: By `slot_number / 2` (slots 0, 2, 4, 6, 8)
- **Lifetime**: Driver process lifetime
- **Destroyed**: Cleanup function `FUN_00003874` on error

**Initialization**: Requires 6 sequential initialization functions (all must succeed):
1. `FUN_00003cdc` - Initializes field 0x08
2. `FUN_000045f2` - Initializes fields 0x1C and 0x34
3. `FUN_00004822` - Initializes fields 0x28 and 0x3C
4. `FUN_0000493a` - Uses fields 0x28 and 0x3C (further init)
5. `FUN_000041fe` - Initializes field 0x0C
6. `FUN_00003f3a` - Initializes field 0x18 (depends on 0x0C)

**Evidence Sources**:
- Function `ND_RegisterBoardSlot` (0x000036B2) - primary allocator
- Function `ND_SetupBoardWithParameters` (0x00005AF6) - uses structure

---

### 1.2 Evidence-Based Reconstruction

```c
/**
 * NDserver Board Information Structure
 *
 * Size: 80 bytes (0x50)
 * Alignment: 4 bytes (standard malloc alignment)
 * Completeness: 60% (48/80 bytes confidently mapped)
 *
 * This structure represents a NeXTdimension graphics board installed
 * in a NeXTBus slot. It contains Mach ports for IPC, initialization
 * data from multiple setup functions, and board identification.
 */
typedef struct nd_board_info {

    /* ============================================================
     * SECTION 1: Board Identification (0x00-0x0B)
     * ============================================================ */

    /**
     * +0x00: Board ID or Magic Number
     *
     * Type: uint32_t
     * Confidence: HIGH
     *
     * Evidence:
     *   0x0000372C: move.l D5,(A2)         ; D5 = board_id param
     *   Function parameter: board_id
     *
     * Purpose: Unique identifier for this board or magic number.
     *
     * Observed values: TBD (depends on hardware enumeration)
     */
    uint32_t magic_or_board_id;

    /**
     * +0x04: Device Port Handle
     *
     * Type: mach_port_t (void* or uint32_t)
     * Confidence: HIGH
     *
     * Evidence:
     *   0x00003746-0x00003750: Mach port operation
     *   lea (0x4,A2),A3          ; A3 = &board_struct->port
     *   move.l A3,-(SP)          ; Push output pointer
     *   move.l D4,-(SP)          ; Push global_port
     *   jsr A5                   ; Call port_allocate or similar
     *
     * Purpose: Mach port for IPC communication with board driver.
     *          Primary channel for sending commands to NeXTdimension.
     *
     * Related: Used in message passing and hardware control.
     */
    mach_port_t device_port_handle;

    /**
     * +0x08: Secondary Port
     *
     * Type: mach_port_t
     * Confidence: HIGH
     *
     * Evidence:
     *   0x0000372E-0x00003742: Mach port operation
     *   lea (0x8,A2),A4          ; A4 = &field_0x08
     *   move.l A4,-(SP)
     *   jsr A5                   ; Same port operation
     *
     *   0x00003758: Used in FUN_00003cdc initialization
     *
     * Purpose: Second Mach port, likely for separate control/data channel
     *          or bidirectional communication.
     *
     * Hypothesis: One port for commands (0x04), one for data (0x08)?
     */
    mach_port_t secondary_port;


    /* ============================================================
     * SECTION 2: Initialization Data (0x0C-0x47)
     * ============================================================
     * Fields populated by 6 initialization functions.
     * Exact types unknown without analyzing those functions.
     */

    /**
     * +0x0C: Initialization Output 5
     *
     * Type: void* (likely pointer or handle)
     * Confidence: MEDIUM
     *
     * Evidence:
     *   0x000037CA-0x000037DA: FUN_000041fe call
     *   lea (0xc,A2),A3          ; A3 = &field_0x0C
     *   move.l A3,-(SP)          ; Push as output parameter
     *   bsr.l 0x000041fe         ; Init function 5
     *
     *   0x000037E6: move.l (A3),-(SP)  ; Push value for FUN_00003f3a
     *
     * Purpose: Unknown, but critical for init function 6 (FUN_00003f3a).
     *
     * Hypothesis: Could be a memory region pointer, device descriptor,
     *             or configuration structure.
     */
    void* init_output_5;  // Placeholder name

    uint32_t field_0x10;  // +0x10 [UNKNOWN - 4 bytes]
    uint32_t field_0x14;  // +0x14 [UNKNOWN - 4 bytes]

    /**
     * +0x18: Initialization Output 6
     *
     * Type: void*
     * Confidence: MEDIUM
     *
     * Evidence:
     *   0x000037E2: pea (0x18,A2)        ; Push &field_0x18
     *   bsr.l 0x00003f3a                 ; FUN_00003f3a (init 6)
     *
     * Purpose: Final initialization output, depends on field_0x0C.
     *
     * Relationship: FUN_00003f3a(board_id, field_0x0C, &field_0x18)
     */
    void* init_output_6;  // Placeholder name

    /**
     * +0x1C: Initialization Output 2a
     *
     * Type: uint32_t or void*
     * Confidence: HIGH
     *
     * Evidence:
     *   0x00003774: pea (0x1c,A2)        ; Push &field_0x1C (output)
     *   0x00003780: bsr.l 0x000045f2     ; FUN_000045f2 (init 2)
     *
     * Purpose: One of two outputs from init function 2.
     *
     * Function signature (inferred):
     *   FUN_000045f2(board_id, board_port, global_port, slot_num,
     *                &field_0x1C, &field_0x34)
     */
    uint32_t init_output_2a;  // Placeholder name

    uint32_t field_0x20;  // +0x20 [UNKNOWN - 8 bytes]
    uint32_t field_0x24;

    /**
     * +0x28: Initialization Output 3a
     *
     * Type: void*
     * Confidence: HIGH
     *
     * Evidence:
     *   0x00003794: move.l A4,-(SP)      ; A4 = &field_0x28
     *   0x000037A2: bsr.l 0x00004822     ; FUN_00004822 (init 3)
     *   0x000037B2: move.l A4,-(SP)      ; Reused in FUN_0000493a
     *
     * Purpose: One of two outputs from init 3, input to init 4.
     */
    void* init_output_3a;  // Placeholder name

    uint32_t field_0x2C;  // +0x2C [UNKNOWN - 8 bytes]
    uint32_t field_0x30;

    /**
     * +0x34: Initialization Output 2b
     *
     * Type: void*
     * Confidence: HIGH
     *
     * Evidence:
     *   0x00003770: pea (0x34,A2)        ; Push &field_0x34 (output)
     *   0x00003780: bsr.l 0x000045f2     ; FUN_000045f2 (init 2)
     *
     * Purpose: Second output from init function 2.
     */
    void* init_output_2b;  // Placeholder name

    uint32_t field_0x38;  // +0x38 [UNKNOWN - 4 bytes]

    /**
     * +0x3C: Initialization Output 3b
     *
     * Type: void*
     * Confidence: HIGH
     *
     * Evidence:
     *   0x0000378E: lea (0x3c,A2),A5    ; A5 = &field_0x3C
     *   0x00003792: move.l A5,-(SP)     ; Push as output
     *   0x000037A2: bsr.l 0x00004822    ; FUN_00004822 (init 3)
     *   0x000037B0: move.l A5,-(SP)     ; Reused in FUN_0000493a
     *
     * Purpose: Second output from init 3, input to init 4.
     */
    void* init_output_3b;  // Placeholder name

    uint32_t field_0x40;  // +0x40 [UNKNOWN - 8 bytes]
    uint32_t field_0x44;


    /* ============================================================
     * SECTION 3: Board Metadata (0x48-0x4F)
     * ============================================================ */

    /**
     * +0x48: NeXTBus Slot Number
     *
     * Type: uint32_t
     * Confidence: HIGH
     *
     * Evidence:
     *   0x00003724: move.l D3,(0x48,A2)  ; D3 = slot_num param
     *   Entry validation:
     *     moveq 0x8,D1
     *     cmp.l D3,D1                     ; Ensure slot <= 8
     *     btst.l #0x0,D3                  ; Ensure slot is even
     *
     * Valid values: 0, 2, 4, 6, 8 (NeXTBus physical slots)
     *
     * Purpose: Physical slot location on NeXTBus.
     *          Used for indexing into g_board_slot_table:
     *            index = slot_number / 2
     */
    uint32_t slot_number;

    /**
     * +0x4C: Flags or State
     *
     * Type: uint32_t
     * Confidence: HIGH
     *
     * Evidence:
     *   0x00003728: clr.l (0x4c,A2)      ; Clear to 0
     *
     * Initialized to: 0
     *
     * Purpose: Unknown. Possibilities:
     *   - Initialization state flags (0 = not ready, 1 = ready)
     *   - Feature flags
     *   - Error state
     *   - Reference count
     *
     * Hypothesis: Likely a state machine value or boolean flags.
     */
    uint32_t flags_or_state;

} nd_board_info_t;
```

---

### 1.3 Field Evidence Table (Detailed)

| Offset | Bytes | Type | Name | Confidence | Evidence Location | Notes |
|--------|-------|------|------|------------|-------------------|-------|
| **0x00** | 4 | uint32_t | magic_or_board_id | **HIGH** | 0x0000372C | Set from function parameter |
| **0x04** | 4 | mach_port_t | device_port_handle | **HIGH** | 0x00003746 | Mach port operation output |
| **0x08** | 4 | mach_port_t | secondary_port | **HIGH** | 0x00003732 | Mach port operation output |
| **0x0C** | 4 | void* | init_output_5 | **MEDIUM** | 0x000037CE | FUN_000041fe output |
| 0x10 | 4 | ? | field_0x10 | **LOW** | Not observed | **GAP** |
| 0x14 | 4 | ? | field_0x14 | **LOW** | Not observed | **GAP** |
| **0x18** | 4 | void* | init_output_6 | **MEDIUM** | 0x000037E2 | FUN_00003f3a output |
| **0x1C** | 4 | uint32_t | init_output_2a | **HIGH** | 0x00003774 | FUN_000045f2 output 1 |
| 0x20 | 4 | ? | field_0x20 | **LOW** | Not observed | **GAP** |
| 0x24 | 4 | ? | field_0x24 | **LOW** | Not observed | **GAP** |
| **0x28** | 4 | void* | init_output_3a | **HIGH** | 0x00003798 | FUN_00004822 output 1 |
| 0x2C | 4 | ? | field_0x2C | **LOW** | Not observed | **GAP** |
| 0x30 | 4 | ? | field_0x30 | **LOW** | Not observed | **GAP** |
| **0x34** | 4 | void* | init_output_2b | **HIGH** | 0x00003770 | FUN_000045f2 output 2 |
| 0x38 | 4 | ? | field_0x38 | **LOW** | Not observed | **GAP** |
| **0x3C** | 4 | void* | init_output_3b | **HIGH** | 0x00003792 | FUN_00004822 output 2 |
| 0x40 | 4 | ? | field_0x40 | **LOW** | Not observed | **GAP** |
| 0x44 | 4 | ? | field_0x44 | **LOW** | Not observed | **GAP** |
| **0x48** | 4 | uint32_t | slot_number | **HIGH** | 0x00003724 | Validated: 0, 2, 4, 6, 8 |
| **0x4C** | 4 | uint32_t | flags_or_state | **HIGH** | 0x00003728 | Initialized to 0 |

**Mapped**: 48 bytes (60%)
**Gaps**: 32 bytes (40%)

---

### 1.4 Usage Patterns

#### Allocation

**Location**: `ND_RegisterBoardSlot` at 0x000036FA

```asm
pea    (0x50).w              ; Push size = 80 bytes
pea    (0x1).w               ; Push flags = 1
bsr.l  0x0500220a            ; CALL vm_allocate/malloc
movea.l D0,A2                ; A2 = allocated pointer
addq.w  0x8,SP               ; Clean stack
tst.l   A2                   ; Check for NULL
bne.b   success
```

**Error handling**: Returns error code 6 (ERROR_NO_MEMORY) if NULL

#### Storage in Global Table

**Location**: `ND_RegisterBoardSlot` at 0x00003716

```asm
move.l  D3,D0                ; D0 = slot_num
asr.l   #0x1,D0              ; D0 = slot_num / 2 (index)
lea     (0x819c).l,A0        ; A0 = &g_board_slot_table
move.l  A2,(0x0,A0,D0*0x4)   ; slot_table[index] = board_info ptr
```

**Global table structure**:
```c
nd_board_info_t* g_board_slot_table[4];  // At 0x0000819C
// Index 0: Slot 0 board
// Index 1: Slot 2 board
// Index 2: Slot 4 board
// Index 3: Slot 6/8 board
```

#### Retrieval

**Location**: `ND_SetupBoardWithParameters` (inferred from function params)

```c
int slot_index = slot_number / 2;
nd_board_info_t* board = g_board_slot_table[slot_index];
if (!board) {
    return ERROR_BOARD_NOT_FOUND;
}
// Use board->device_port_handle for communication
```

#### Cleanup

**Location**: `FUN_00003874` (cleanup function)

```asm
; Cleanup on error path at 0x00003814
move.l  D2,-(SP)             ; Push error code
pea     (0x789f).l           ; Push error message
bsr.l   0x050028c4           ; CALL error_log
move.l  D3,-(SP)             ; Push slot_num
move.l  D5,-(SP)             ; Push board_id
bsr.l   0x00003874           ; CALL cleanup_function
```

**Expected cleanup actions**:
1. Remove from slot table
2. Free allocated memory
3. Release Mach ports
4. Log cleanup for debugging

---

### 1.5 Initialization Dependency Graph

```
ND_RegisterBoardSlot
  │
  ├─► malloc(80)                        → Allocate structure
  │
  ├─► Mach port ops (×2)                → fields 0x04, 0x08
  │
  ├─► FUN_00003cdc                      → Uses field 0x08
  │     Args: board_id, slot_num, port, &field_0x08
  │
  ├─► FUN_000045f2                      → fields 0x1C, 0x34
  │     Args: board_id, port, global_port, slot_num,
  │           &field_0x1C, &field_0x34
  │
  ├─► FUN_00004822                      → fields 0x28, 0x3C
  │     Args: board_id, port, global_port, slot_num,
  │           &field_0x28, &field_0x3C
  │
  ├─► FUN_0000493a                      → Uses 0x28, 0x3C
  │     Args: board_id, port, global_port, slot_num,
  │           field_0x28, field_0x3C
  │
  ├─► FUN_000041fe                      → field 0x0C
  │     Args: board_id, slot_num, &field_0x0C
  │
  └─► FUN_00003f3a                      → field 0x18
        Args: board_id, field_0x0C, &field_0x18
```

**All functions must succeed** (error on any → cleanup entire structure)

---

### 1.6 Hypothesis: Field Purposes

Based on initialization sequence and parameter passing:

| Field | Likely Purpose | Reasoning |
|-------|----------------|-----------|
| 0x08 | **Data port** | Initialized early, used in first init function |
| 0x1C, 0x34 | **Memory regions** | Init 2 takes ports + slot, likely memory mapping |
| 0x28, 0x3C | **Device handles** | Init 3 similar pattern, reused in init 4 |
| 0x0C | **Configuration** | Init 5 takes board_id + slot, config-like |
| 0x18 | **Resource handle** | Init 6 depends on 0x0C, derived resource |

**Next steps to confirm**:
1. Analyze the 6 initialization functions
2. Instrument driver with debugger to dump structure after init
3. Compare with NeXTSTEP kernel driver sources if available

---

### 1.7 Struct Completeness Analysis

**Mapped Sections**:
- **0x00-0x0B**: 100% (12/12 bytes) - Board ID and ports
- **0x0C-0x47**: 33% (20/60 bytes) - Init data (gaps)
- **0x48-0x4F**: 100% (8/8 bytes) - Metadata

**By Confidence**:
- **HIGH**: 40 bytes (50%)
- **MEDIUM**: 8 bytes (10%)
- **LOW/UNKNOWN**: 32 bytes (40%)

**Critical gaps to fill**:
1. Bytes 0x10-0x17 (8 bytes between ports and init outputs)
2. Bytes 0x20-0x27 (8 bytes in init section)
3. Bytes 0x2C-0x33 (8 bytes in init section)
4. Bytes 0x38-0x3B (4 bytes near end of init)
5. Bytes 0x40-0x47 (8 bytes before metadata)

**Recommended approach**:
- **Priority 1**: Analyze initialization functions (will reveal outputs)
- **Priority 2**: Runtime inspection with debugger/instrumented binary
- **Priority 3**: Static analysis of functions using the structure

---

## 2. segment_descriptor_t

### 2.1 Overview

**Purpose**: Mach-O binary format descriptor for kernel segment loading

**Evidence**: Used in `ND_LoadKernelSegments` (0x00003284)

**Format**: Standard Mach-O header (documented in `<mach-o/loader.h>`)

---

### 2.2 Structure Definition

```c
/**
 * Mach-O Segment Descriptor (Mach Header)
 *
 * This is a STANDARD structure from <mach-o/loader.h>
 * Size: 28 bytes minimum (header only)
 *
 * Used for loading i860 kernel segments into NeXTdimension memory.
 */
typedef struct segment_descriptor {
    uint32_t magic;         // +0x00: 0xFEEDFACE (MH_MAGIC) or
                             //        0xCEFAEDFE (MH_CIGAM - byte swapped)

    uint32_t cputype;       // +0x04: CPU_TYPE_I860 (expected)

    uint32_t cpusubtype;    // +0x08: CPU_SUBTYPE_I860_ALL

    uint32_t filetype;      // +0x0C: MH_EXECUTE, MH_OBJECT, etc.

    uint32_t ncmds;         // +0x10: Number of load commands

    uint32_t sizeofcmds;    // +0x14: Total size of load commands

    uint32_t flags;         // +0x18: Header flags

    // Followed by ncmds load commands (variable size)

} segment_descriptor_t;
```

### 2.3 Usage in NDserver

**Function**: `ND_LoadKernelSegments` checks magic value

```c
if (descriptor->magic == 0xFEEDFACE) {
    // Native byte order - proceed normally
} else if (descriptor->magic == 0xCEFAEDFE) {
    // Byte swapped - need to swap all fields
    byte_swap_header(descriptor);
}
```

**Load commands follow header**, defining:
- LC_SEGMENT: Memory segments to load
- LC_SYMTAB: Symbol table
- LC_DYSYMTAB: Dynamic symbol table
- etc.

**Reference**: See `man 5 Mach-O` or Apple's Mach-O documentation

---

## 3. transfer_descriptor_t

### 3.1 Overview

**Purpose**: Describes DMA/memory transfers between host and NeXTdimension

**Evidence**: Used in `ND_ProcessDMATransfer` and `ND_MemoryTransferDispatcher`

**Size**: Variable (contains string data or name classification)

---

### 3.2 Suspected Structure

```c
/**
 * DMA/Memory Transfer Descriptor
 *
 * Size: Variable
 * Confidence: LOW-MEDIUM (requires more analysis)
 *
 * Describes a data transfer operation between:
 *   - Host 68040 memory (0x04000000+)
 *   - ND i860 memory (0x00000000+ in i860 space)
 *   - ND VRAM (0x10000000 in i860 space)
 */
typedef struct transfer_descriptor {
    // === Suspected fields (unconfirmed) ===

    uint32_t source_address;      // Source memory address
    uint32_t dest_address;        // Destination address
    uint32_t length;              // Transfer size in bytes

    uint32_t flags;               // Transfer flags:
                                   // - Bit 0: Direction (0=host→ND, 1=ND→host)
                                   // - Bit 1: Byte swap (0=no, 1=yes)
                                   // - Bit 2: 2D transfer
                                   // - Bit 3: Chained descriptor

    uint32_t line_pitch;          // For 2D transfers: bytes per line
    uint32_t line_count;          // For 2D transfers: number of lines

    void*    next_descriptor;     // For chained transfers

    char*    segment_name;        // Segment/section name (optional)
                                   // Evidence: "name-based classification"

} transfer_descriptor_t;
```

### 3.3 Evidence for Fields

**Source/Dest/Length**: Standard DMA descriptor pattern

**Flags**: Inferred from:
- Endianness handling in `ND_ProcessDMATransfer`
- 2D transfer support suggested by function complexity

**Name field**: Function documentation mentions "name-based classification"

**Next steps**:
1. Analyze `ND_ProcessDMATransfer` in detail
2. Analyze `ND_MemoryTransferDispatcher`
3. Look for descriptor building/parsing code

---

## 4. Message Structures

### 4.1 Overview

**Purpose**: IPC messages between client applications and NDserver

**Evidence**: Multiple message handlers (ND_MessageHandler_CMD*)

**Pattern**: All handlers follow similar validation → dispatch pattern

---

### 4.2 Generic Message Header

```c
/**
 * Generic Message Header
 *
 * All message types likely share this header, followed by
 * type-specific payload.
 *
 * Confidence: MEDIUM (inferred from handler patterns)
 */
typedef struct nd_message_header {
    uint32_t message_type;        // +0x00: Discriminator
                                   // Known types: 0x28, 0x30, 0x42C, 0x434,
                                   //              0x43C, 0x838, 0x1EDC

    uint32_t message_size;        // +0x04: Total message size (header + payload)

    uint32_t sequence_number;     // +0x08: For request/response matching?

    uint32_t flags;               // +0x0C: Message flags (direction, priority, etc.)

    // Type-specific payload follows...

} nd_message_header_t;
```

### 4.3 Known Message Types

| Type | Handler Function | Purpose (Inferred) |
|------|------------------|-------------------|
| **0x28** | ND_MessageHandler_CMD28 | Unknown |
| **0x30** | ND_ValidateAndDispatchMessage0x30 | Validation + dispatch |
| **0x42C** | ND_MessageHandler_CMD42C (×2 variants) | Unknown (2 implementations) |
| **0x434** | ND_MessageHandler_CMD434 (×2 variants) | Unknown (2 implementations) |
| **0x43C** | ND_MessageHandler_CMD43C | Unknown |
| **0x838** | ND_MessageHandler_CMD838 | Unknown |
| **0x1EDC** | ND_MessageHandler_CMD1EDC | Unknown |

**Note**: Message type values appear arbitrary. May be defined in client-side headers.

### 4.4 Message Validation Pattern

All handlers follow similar pattern:

```c
int ND_MessageHandler_CMDXXX(nd_message_header_t* msg_in, void* response_out) {
    // 1. Validate message structure
    if (!msg_in || msg_in->message_type != EXPECTED_TYPE) {
        return ERROR_INVALID_MESSAGE;
    }

    // 2. Validate payload fields
    // (type-specific checks)

    // 3. Dispatch to actual handler
    result = perform_operation(msg_in->payload);

    // 4. Populate response
    populate_response(response_out, result);

    return SUCCESS;
}
```

**Next steps**:
1. Analyze all message handler functions
2. Extract payload structures for each type
3. Document message protocol completely

---

## 5. Reconstruction Methodology

### 5.1 Evidence Sources

**Primary Sources**:
1. **Assembly disassembly**: Field offset accesses (e.g., `0x4,A2`)
2. **Function parameters**: Stack frame analysis
3. **Allocation sizes**: `malloc(80)` → structure size
4. **Initialization sequences**: Order reveals dependencies

**Secondary Sources**:
1. **Cross-function usage**: Same offsets in different functions
2. **Validation code**: Range checks reveal field semantics
3. **Error handling**: Error messages hint at field purposes

### 5.2 Confidence Levels

| Level | Criteria | Action |
|-------|----------|--------|
| **HIGH** | Directly observed in assembly, confirmed usage | Accept as fact |
| **MEDIUM** | Inferred from context, consistent pattern | Likely correct, verify if critical |
| **LOW** | Speculative based on partial evidence | Mark clearly, investigate further |

### 5.3 Validation Techniques

**1. Cross-Reference Validation**:
- If offset 0x04 is `device_port` in function A and used as port in function B → HIGH confidence

**2. Size Consistency**:
- If `malloc(80)` allocates structure and all accesses are ≤ offset 0x4C → Consistent

**3. Type Inference**:
- If field is passed to `mach_port_send()` → Likely `mach_port_t`
- If compared to NULL → Likely pointer
- If range-checked 0-8 → Likely small integer

**4. Runtime Verification**:
- Instrument binary, dump structure after initialization
- Compare field values against hypotheses

### 5.4 Filling Gaps

**For unknown fields**:

**Priority 1**: Analyze functions that WRITE to those offsets
- Initialization functions are prime targets

**Priority 2**: Analyze functions that READ from those offsets
- Usage reveals type and purpose

**Priority 3**: Runtime inspection
- Set breakpoints after initialization, dump memory

**Priority 4**: Symbolic execution
- Use tools like angr to trace data flow

### 5.5 Tools and Resources

**Static Analysis**:
- Ghidra/IDA Pro: Disassembly and decompilation
- Hopper: Mac-native disassembler
- radare2/Cutter: Open-source alternative

**Dynamic Analysis**:
- lldb: Debugger for running binary (if runnable)
- DTrace: System call tracing
- GDB with custom scripts

**Documentation**:
- NeXTSTEP API documentation
- Mach IPC documentation
- NeXTdimension hardware spec (if available)

---

## Appendix: Quick Reference

### Structure Sizes

| Structure | Size (bytes) | Completeness |
|-----------|--------------|--------------|
| nd_board_info_t | 80 | 60% |
| segment_descriptor_t | 28+ | 100% (standard) |
| transfer_descriptor_t | Variable | 20% |
| nd_message_header_t | 16+ | 30% (inferred) |

### Next Analysis Targets (to complete structures)

**High Priority**:
1. FUN_00003cdc - Initializes nd_board_info field 0x08
2. FUN_000045f2 - Initializes fields 0x1C, 0x34
3. FUN_00004822 - Initializes fields 0x28, 0x3C

**Medium Priority**:
4. FUN_0000493a - Uses fields 0x28, 0x3C
5. FUN_000041fe - Initializes field 0x0C
6. FUN_00003f3a - Initializes field 0x18

**Analysis of these 6 functions will increase `nd_board_info_t` completeness to ~80%.**

---

**Document End**

For cross-references, see: `docs/CROSS_REFERENCE_GUIDE.md`
For function details, see: `docs/functions/*.md`
For machine-readable data, see: `database/cross_references.json`
