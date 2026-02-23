# Function Analysis: ND_MessageDispatcher

**Address**: `0x00006e6c`
**Size**: 272 bytes (68 instructions)
**Complexity**: Medium-High
**Purpose**: Message type dispatcher with jump table for command routing
**Status**: ✅ Analyzed (2025-11-08)

---

## Executive Summary

`ND_MessageDispatcher` is a **command/message router** that uses a **jump table** to dispatch different message types (0-5) to their respective handler functions. It implements a classic switch statement pattern with a jump table at `0x6e9a`. The function validates the message type field, dispatches to the appropriate handler, and provides error handling for out-of-range types.

**Key Characteristics**:
- Jump table dispatch (6 cases: types 0-5)
- 512-byte stack buffer for message/string handling
- Multiple call paths to `FUN_00003eae` (likely a send/transfer function)
- Global buffer at `0x4010000` (stdio-like FILE* structure)
- Error code `-0x131` (305 decimal) returned on failure
- Writes result to global `0x81ac` in one case

**Likely Role**: This appears to be a **message protocol dispatcher** that handles different types of NeXTdimension commands or I/O operations, possibly stdio operations (read/write/seek/close).

---

## Function Signature

### Reverse-Engineered C Prototype

```c
int ND_MessageDispatcher(
    nd_message_t*  message,      // A6+0x8:  Message structure with type field
    nd_result_t*   result        // A6+0xC:  Result structure (error code output)
);
```

### Parameters

| Offset | Register | Name      | Type            | Description                           |
|--------|----------|-----------|-----------------|---------------------------------------|
| +0x08  | A1→A3    | message   | nd_message_t*   | Message structure with type field     |
| +0x0C  | D1→A4    | result    | nd_result_t*    | Result structure (receives errors)    |

### Return Value

- **D0 = 0**: Success
- **D0 = 1**: Error (error code written to `result->field_0x1C`)

### Calling Convention

- **m68k System V ABI**: Link frame, stack arguments
- **Preserved registers**: D2, A2, A3, A4 (saved/restored)
- **Large stack allocation**: 512 bytes for local buffer

---

## Data Structures

### nd_message_t Structure (Partial)

```c
typedef struct nd_message {
    // ... unknown fields 0x00-0x0F ...
    uint32_t  field_0x10;        // +0x10: Unknown (used as param to FUN_00003eae)
    uint32_t  message_type;      // +0x14: Message type (0-5 valid)
    uint32_t  field_0x18;        // +0x18: Unknown (used as param to FUN_00003eae)
    // ... unknown fields 0x1C+ ...
    uint32_t  field_0x20;        // +0x20: Data value (case 4: written to 0x81ac)
    // ... more fields ...
} nd_message_t;
```

**Critical Field**:
- **+0x14 (message_type)**: Validated against range 0-5, used as jump table index

### nd_result_t Structure (Partial)

```c
typedef struct nd_result {
    // ... unknown fields 0x00-0x1B ...
    int32_t   error_code;        // +0x1C: Error code (-0x131 on failure)
    // ... more fields ...
} nd_result_t;
```

### Global Buffer Structure (0x4010000)

```c
// Appears to be a FILE* or stream-like structure
typedef struct global_buffer {
    int32_t   count_or_pos;      // +0x00: Counter/position (decremented)
    uint8_t*  data_ptr;          // +0x04: Pointer to data
    // ... more fields ...
} global_buffer_t;

// Additional related global
uint8_t* g_buffer_name = (void*)0x4010014;  // String/name buffer
```

---

## Complete Annotated Disassembly

```m68k
; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_MessageDispatcher
; ====================================================================================
; Address: 0x00006e6c
; Size: 272 bytes
; Purpose: Jump table dispatcher for message types 0-5
; ====================================================================================

; FUNCTION: int ND_MessageDispatcher(nd_message_t* message, nd_result_t* result)
;
; Dispatches messages based on type field (message->field_0x14) using a jump table.
; Supports 6 message types (0-5), each with different handling logic.
;
; PARAMETERS:
;   message (A6+0x8):  Pointer to message structure (contains type field +0x14)
;   result (A6+0xC):   Pointer to result structure (receives error codes +0x1C)
;
; RETURNS:
;   D0: 0 on success, 1 on error
;   result->error_code: Set to -0x131 on failure
;
; STACK FRAME: 512 bytes
;   -0x004 to -0x010: Unknown locals
;   -0x200: 512-byte buffer for string/message operations
;
; ====================================================================================

FUN_00006e6c:
    ; --- PROLOGUE ---
    link.w      A6, #-0x200               ; Create 512-byte stack frame
    movem.l     {D2,A2,A3,A4}, -(SP)      ; Save preserved registers

    ; --- LOAD AND BACKUP PARAMETERS ---
    movea.l     (0x8,A6), A1              ; A1 = message pointer
    move.l      (0xc,A6), D1              ; D1 = result pointer
    movea.l     A1, A3                    ; A3 = message (backup)
    movea.l     D1, A4                    ; A4 = result (backup)

    ; --- TYPE VALIDATION ---
    moveq       #0x5, D2                  ; D2 = 5 (max valid type)
    cmp.l       (0x14,A1), D2             ; if (message->message_type > 5)
    bcs.w       .out_of_range             ;   goto out_of_range handler

    ; --- JUMP TABLE DISPATCH ---
    move.l      (0x14,A1), D0             ; D0 = message->message_type (0-5)
    movea.l     #0x6e9a, A0               ; A0 = &jump_table
    movea.l     (0x0,A0,D0.l*4), A0       ; A0 = jump_table[message_type]
    jmp         (A0)                      ; Dispatch to case handler

; ====================================================================================
; JUMP TABLE DATA (Embedded between code sections)
; ====================================================================================
; Located at 0x00006e9a (24 bytes = 6 long-words)
;
; IMPORTANT: This table is all zeros in the NDserver binary!
; The actual case target addresses are unknown without runtime analysis.
; The table would be populated either:
;   1. By dynamic linker relocation
;   2. At runtime during initialization
;   3. Or Ghidra failed to extract (stripped/optimized binary)
;
; Expected structure:
;   jump_table:
;     DC.L  case_handler_0    ; Type 0 → Unknown target
;     DC.L  case_handler_1    ; Type 1 → Unknown target
;     DC.L  case_handler_2    ; Type 2 → Unknown target
;     DC.L  case_handler_3    ; Type 3 → Unknown target
;     DC.L  case_handler_4    ; Type 4 → Unknown target
;     DC.L  case_handler_5    ; Type 5 → Unknown target
;
; Known case handler entry points (identified by control flow):
;   0x6eb2: Case handler #1 - Simple library call
;   0x6ec6: Case handler #2 - Complex buffer/string operations
;   0x6f0a: Case handler #3 - Single byte read/write
;   0x6f68: Case handler #4 - Write value to global 0x81ac
;
; Missing handlers: 2 cases unaccounted for (may be duplicates/fall-through)
; ====================================================================================

; ====================================================================================
; CASE HANDLER #1: Simple Library Call (Address: 0x6eb2)
; ====================================================================================
; This handler makes a single library call and exits
;
.case_handler_1:
    pea         (0x4010014).l             ; push &g_buffer_name
    pea         (0x20,A3)                 ; push (message + 0x20)
    bsr.l       0x0500253a                ; call lib_function(message+0x20, &g_buffer_name)
    bra.w       .common_error_exit        ; goto error exit (returns 1)

; ====================================================================================
; CASE HANDLER #2: Complex String/Buffer Operations (Address: 0x6ec6)
; ====================================================================================
; This handler:
;   1. Calls lib functions to manipulate buffers
;   2. Uses local 512-byte stack buffer
;   3. Calls FUN_00003eae (likely a send/transfer function)
;   4. Handles string operations (sprintf, strlen, etc.)
;
.case_handler_2:
    ; --- LIBRARY CALL 1 ---
    pea         (0x4010014).l             ; push &g_buffer_name
    bsr.l       0x050024f8                ; result = lib_func_1(&g_buffer_name)

    ; --- PREPARE BUFFER ---
    pea         (0x4010000).l             ; push &global_buffer
    pea         (0x1ff).w                 ; push 511 (buffer size - 1)
    lea         (-0x200,A6), A2           ; A2 = &local_buffer (512 bytes)
    move.l      A2, -(SP)                 ; push &local_buffer
    bsr.l       0x05002510                ; result = lib_func_2(&local_buffer, 511, &global_buffer)
                                           ; Likely: fgets(local_buffer, 511, global_buffer)

    ; --- STRING LENGTH ---
    move.l      A2, -(SP)                 ; push &local_buffer
    bsr.l       0x05003038                ; result = strlen(local_buffer)
    addq.l      #0x1, D0                  ; result += 1 (include null terminator)

    ; --- CALL TRANSFER FUNCTION ---
    move.l      D0, -(SP)                 ; push (length + 1)
    move.l      A2, -(SP)                 ; push &local_buffer
    move.l      (0x18,A3), -(SP)          ; push message->field_0x18
    move.l      (0x10,A3), -(SP)          ; push message->field_0x10
    bsr.l       0x00003eae                ; result = FUN_00003eae(field_0x10, field_0x18,
                                           ;                       &local_buffer, length+1)
    adda.w      #0x24, SP                 ; Clean up 9 arguments (36 bytes)
    bra.b       .check_transfer_result    ; goto result check

; ====================================================================================
; CASE HANDLER #3: Single Byte Read/Write (Address: 0x6f0a)
; ====================================================================================
; This handler:
;   1. Reads a single byte from global buffer (FILE* style)
;   2. Transfers it via FUN_00003eae
;   3. Implements character I/O operation
;
.case_handler_3:
    ; --- READ BYTE FROM BUFFER ---
    lea         (0x4010000).l, A0         ; A0 = &global_buffer
    subq.l      #0x1, (A0)                ; global_buffer.count--
    bmi.b       .refill_buffer            ; if (count < 0) goto refill

    ; Fast path: buffer has data
    movea.l     (0x04010004).l, A0        ; A0 = global_buffer.data_ptr
    move.b      (A0), D0                  ; D0 = *data_ptr (read byte)
    addq.l      #0x1, (0x04010004).l      ; data_ptr++
    bra.b       .got_byte                 ; goto got_byte

.refill_buffer:
    ; Slow path: buffer empty, refill
    pea         (0x4010000).l             ; push &global_buffer
    bsr.l       0x0500208a                ; D0 = fgetc(&global_buffer)
    addq.w      #0x4, SP                  ; Clean up 1 argument

.got_byte:
    ; --- CREATE 2-BYTE BUFFER (byte + null terminator) ---
    move.b      D0, (-0x200,A6)           ; local_buffer[0] = byte
    clr.b       (-0x1ff,A6)               ; local_buffer[1] = '\0'

    ; --- TRANSFER SINGLE BYTE ---
    pea         (0x1).w                   ; push 1 (length)
    pea         (-0x200,A6)               ; push &local_buffer
    move.l      (0x18,A3), -(SP)          ; push message->field_0x18
    move.l      (0x10,A3), -(SP)          ; push message->field_0x10
    bsr.l       0x00003eae                ; result = FUN_00003eae(field_0x10, field_0x18,
                                           ;                       &local_buffer, 1)
    addq.w      #0x8, SP                  ; Clean up 2 args
    addq.w      #0x8, SP                  ; Clean up 2 more args (8 bytes each)

; --- COMMON: CHECK TRANSFER RESULT ---
.check_transfer_result:
    tst.l       D0                        ; if (result == 0)
    beq.b       .common_error_exit        ;   goto error exit (success → error is odd!)

    ; Transfer failed - log error
    move.l      D0, -(SP)                 ; push error_code
    pea         (0x7a39).l                ; push error_format_string
    bsr.l       0x050028c4                ; printf(error_format_string, error_code)
    bra.b       .common_error_exit        ; goto error exit

; ====================================================================================
; CASE HANDLER #4: Write Value to Global (Address: 0x6f68)
; ====================================================================================
; Simple assignment: copies message field to global variable
;
.case_handler_4:
    move.l      (0x20,A3), (0x000081ac).l ; global_0x81ac = message->field_0x20
    clr.l       D0                        ; return 0 (SUCCESS)
    bra.b       .epilogue                 ; goto epilogue

; ====================================================================================
; OUT OF RANGE HANDLER (Address: 0x6f74)
; ====================================================================================
; Handles invalid message types (> 5)
;
.out_of_range:
    move.l      D1, -(SP)                 ; push result
    move.l      A1, -(SP)                 ; push message
    bsr.l       0x000075e2                ; FUN_000075e2(message, result)
                                           ; Likely: error logging or default handler
    bra.b       .epilogue                 ; goto epilogue

; ====================================================================================
; COMMON ERROR EXIT (Address: 0x6f80)
; ====================================================================================
; Sets error code and returns failure
;
.common_error_exit:
    move.l      #-0x131, (0x1c,A4)        ; result->error_code = -0x131 (305)
    moveq       #0x1, D0                  ; return 1 (FAILURE)

; --- EPILOGUE ---
.epilogue:
    movem.l     (-0x210,A6), {D2,A2,A3,A4} ; Restore preserved registers
    unlk        A6                        ; Destroy stack frame
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_MessageDispatcher
; ====================================================================================
```

---

## Stack Frame Layout

```
High Address
┌─────────────────────────────────────┐
│  Return Address (from caller)       │  A6+0x4
├─────────────────────────────────────┤
│  Old Frame Pointer (saved A6)       │  A6+0x0  ← Current A6
├─────────────────────────────────────┤
│  Saved D2                            │  SP+0x0  (movem.l)
│  Saved A2                            │  SP+0x4
│  Saved A3                            │  SP+0x8
│  Saved A4                            │  SP+0xC
├─────────────────────────────────────┤
│  local_buffer[0..511]                │  A6-0x200 to A6-0x1 (512 bytes)
│  Used for string/message operations  │
├─────────────────────────────────────┤
│  (Potential alignment padding)       │
└─────────────────────────────────────┘
Low Address

Parameters (above frame):
  A6+0x8:  nd_message_t* message
  A6+0xC:  nd_result_t*  result

Local variables:
  A6-0x200: 512-byte buffer for string operations
```

---

## Hardware Access

### Global Variables Accessed

| Address      | Access | Purpose                                      |
|--------------|--------|----------------------------------------------|
| `0x4010000`  | R/W    | Global buffer structure (FILE* style)        |
| `0x4010004`  | R/W    | Buffer data pointer                          |
| `0x4010014`  | Read   | Buffer name/identifier string                |
| `0x000081ac` | Write  | Unknown global (case 4: stores field_0x20)   |

**Notes**:
- `0x4010000` appears to be a stdio-like FILE structure with buffering
- Pattern matches `fgetc()`, `fgets()` style operations
- Case 4 writing to `0x81ac` suggests a result/status register

---

## OS Functions and Library Calls

### Identified Library Functions

| Address      | Likely Identity      | Evidence                                    |
|--------------|----------------------|---------------------------------------------|
| `0x0500208a` | `fgetc(FILE*)`       | Single byte read with buffer refill         |
| `0x050024f8` | `fopen()` / related  | Opens or resets buffer                      |
| `0x05002510` | `fgets()`            | Reads string with size limit                |
| `0x0500253a` | `fputs()` / related  | String output function                      |
| `0x05003038` | `strlen()`           | String length (result+1 → include null)     |
| `0x050028c4` | `printf()` / logging | Error message formatting                    |

### Internal Function Calls

| Function         | Address    | Purpose                                    |
|------------------|------------|--------------------------------------------|
| `FUN_00003eae`   | `0x00003eae` | Transfer/send function (4 parameters)    |
| `FUN_000075e2`   | `0x000075e2` | Error handler for invalid types          |

**Notes on FUN_00003eae**:
```c
// Appears to be called with:
result = FUN_00003eae(
    message->field_0x10,    // Destination or handle
    message->field_0x18,    // Source or buffer ID
    buffer_pointer,         // Data to send
    length                  // Size of data
);
```

This suggests **FUN_00003eae is a data transfer function**, possibly:
- Mach IPC send operation
- DMA transfer request
- Buffer write to NeXTdimension hardware

---

## Reverse-Engineered C Pseudocode

```c
/**
 * ND_MessageDispatcher - Route messages by type to appropriate handlers
 *
 * @param message  Pointer to message structure with type field
 * @param result   Pointer to result structure (receives error codes)
 * @return 0 on success, 1 on error
 */
int ND_MessageDispatcher(nd_message_t* message, nd_result_t* result)
{
    uint8_t local_buffer[512];
    int32_t error_code;
    uint32_t type;

    // Validate message type
    type = message->message_type;
    if (type > 5) {
        // Out of range - call default handler
        return FUN_000075e2(message, result);
    }

    // Dispatch to handler based on type
    switch (type) {

        case TYPE_UNKNOWN_1:  // One of 0-5, exact mapping unknown
            // Simple library call
            lib_function_1(message->field_0x20, &g_buffer_name);
            goto error_exit;

        case TYPE_STRING_TRANSFER:  // Another of 0-5
            // Complex string/buffer operation
            lib_func_open(&g_buffer_name);
            fgets(local_buffer, 511, &global_buffer);

            uint32_t len = strlen(local_buffer) + 1;
            error_code = FUN_00003eae(
                message->field_0x10,
                message->field_0x18,
                local_buffer,
                len
            );

            if (error_code != 0) {
                printf(error_format, error_code);
            }
            goto error_exit;

        case TYPE_BYTE_TRANSFER:  // Another of 0-5
            // Single byte read and transfer
            int ch;
            if (global_buffer.count-- < 0) {
                ch = fgetc(&global_buffer);
            } else {
                ch = *global_buffer.data_ptr++;
            }

            local_buffer[0] = (uint8_t)ch;
            local_buffer[1] = '\0';

            error_code = FUN_00003eae(
                message->field_0x10,
                message->field_0x18,
                local_buffer,
                1
            );

            if (error_code != 0) {
                printf(error_format, error_code);
            }
            goto error_exit;

        case TYPE_WRITE_GLOBAL:  // Another of 0-5
            // Simple assignment to global variable
            global_0x81ac = message->field_0x20;
            return 0;  // Success

        default:
            // Remaining cases (2 unmapped types)
            // May fall through to error or have unreachable code
            break;
    }

error_exit:
    result->error_code = -0x131;  // Error code: 305
    return 1;  // Failure
}
```

---

## Call Graph

### Called By

```
FUN_00003c08 (0x3c08)
    └─> FUN_00006e6c (THIS FUNCTION)
```

### Calls To

```
FUN_00006e6c (THIS FUNCTION)
    ├─> 0x0500208a    (fgetc - library)
    ├─> 0x050024f8    (fopen/related - library)
    ├─> 0x05002510    (fgets - library)
    ├─> 0x0500253a    (fputs/related - library)
    ├─> 0x05003038    (strlen - library)
    ├─> 0x050028c4    (printf - library)
    ├─> FUN_00003eae  (transfer/send function)
    └─> FUN_000075e2  (error handler)
```

---

## Purpose Classification

### Primary Function
**Message/Command Dispatcher** - Routes operations based on type field

### Secondary Functions
1. **String I/O operations** (cases 2, 3)
2. **Global variable updates** (case 4)
3. **Error handling** (out of range types)
4. **Data transfer coordination** (via FUN_00003eae)

### Likely Use Case

This function appears to be part of a **command protocol handler** for NeXTdimension operations, specifically handling:
- **File-like I/O operations** (read string, read byte)
- **Transfer operations** to/from NeXTdimension
- **Configuration updates** (write to global 0x81ac)
- **Stream management** using global buffer at 0x4010000

**Hypothesis**: This may be handling **PostScript or display list commands** sent to the NeXTdimension graphics processor, with cases for:
- Text rendering (string transfer)
- Byte-level graphics data
- Coordinate/state updates

---

## Error Handling

### Error Codes

| Code    | Meaning                                      |
|---------|----------------------------------------------|
| `-0x131` | Generic error (305 decimal)                  |
| `1`      | Function return value indicating failure     |

### Error Paths

1. **Out of range type** (> 5)
   - Calls `FUN_000075e2(message, result)`
   - Likely logs error and returns

2. **Transfer failure** (cases 2, 3)
   - `FUN_00003eae` returns non-zero
   - Logs error via `printf`
   - Sets `result->error_code = -0x131`
   - Returns 1

3. **Library call failures**
   - Not explicitly handled (may propagate via FUN_00003eae return)

---

## Protocol Integration

### Message Type Field

**Location**: `message->field_0x14`
**Range**: 0-5 (6 valid types)
**Validation**: Checked against 5, branches to error handler if exceeded

### Message Structure Fields Used

| Offset | Purpose                                      |
|--------|----------------------------------------------|
| +0x10  | Parameter 1 to FUN_00003eae (destination?)   |
| +0x14  | Message type (dispatch selector)             |
| +0x18  | Parameter 2 to FUN_00003eae (source?)        |
| +0x20  | Data value (case 1, case 4)                  |

### Result Structure

| Offset | Purpose                                      |
|--------|----------------------------------------------|
| +0x1C  | Error code output (-0x131 on failure)        |

---

## m68k Architecture Details

### Register Usage

| Register | Purpose                            | Preserved? |
|----------|------------------------------------|------------|
| A1→A3    | Message pointer                    | Yes (A3)   |
| D1→A4    | Result pointer                     | Yes (A4)   |
| A2       | Local buffer pointer (-0x200,A6)   | Yes        |
| D2       | Constant 5 (max type value)        | Yes        |
| D0       | Return value / scratch             | No         |
| A0       | Jump table / scratch               | No         |

### Jump Table Implementation

**Classic m68k switch pattern**:
```m68k
move.l      (0x14,A1), D0              ; D0 = type
movea.l     #0x6e9a, A0                ; A0 = &jump_table
movea.l     (0x0,A0,D0.l*4), A0        ; A0 = jump_table[type]
jmp         (A0)                       ; Indirect jump
```

**Memory layout**:
- Jump table at `0x6e9a` (6 × 4 bytes = 24 bytes)
- Table entries are absolute addresses
- Falls between code blocks (0x6e9a-0x6eb1)

### Optimization Notes

1. **Single indirect jump** - More efficient than chain of `cmp/beq`
2. **Preserved registers** - Minimizes save/restore overhead
3. **Shared error exit** - Code reuse for multiple cases
4. **Large stack buffer** - Avoids heap allocation for temporary strings

---

## Analysis Insights

### Key Discoveries

1. **Jump Table Mystery**
   - Table data is all zeros in binary
   - Either runtime-initialized or stripped during linking
   - Four distinct case handlers identified by control flow
   - Two cases unaccounted for (may be unreachable or duplicate targets)

2. **FILE* Pattern**
   - Global buffer at `0x4010000` implements buffered I/O
   - Count/pointer structure matches stdio FILE
   - `fgetc()` with fast/slow paths (buffer hit/miss)

3. **Transfer Function Signature**
   - `FUN_00003eae(dest, src, buffer, length)`
   - Consistent 4-parameter pattern across cases
   - Return value checked for errors
   - Likely implements Mach IPC or DMA operation

4. **Error Code Semantics**
   - `-0x131` (305) is a specific error code
   - Suggests larger error code namespace
   - Worth checking if other functions use this code

### Architectural Patterns

- **Command dispatcher** - Central routing for heterogeneous operations
- **Buffered I/O** - Optimization for small reads
- **Error propagation** - Consistent return value checking
- **Mixed inline/external** - Some cases inline, others call helpers

---

## Unanswered Questions

1. **Jump Table Initialization**
   - Why is the table all zeros in the binary?
   - Is it relocated at load time?
   - Or initialized at runtime by another function?

2. **Message Type Mapping**
   - What do types 0-5 correspond to semantically?
   - Are they stdio operations (read/write/seek/close/flush/ioctl)?
   - Or NeXTdimension-specific commands?

3. **FUN_00003eae Details**
   - What protocol does it implement?
   - Is it Mach IPC, DMA, or something else?
   - What do parameters field_0x10 and field_0x18 represent?

4. **Global 0x81ac**
   - What does this address represent?
   - Is it a hardware register?
   - Or a software state variable?

5. **Missing Cases**
   - Are there really 6 distinct handlers, or do some types share code?
   - Why can't we identify all 6 case handlers?

6. **Error Code -0x131**
   - Is this a standard errno value?
   - Or NDserver-specific error code?
   - What does 305 mean in this context?

---

## Related Functions

### Directly Called

- **FUN_00003eae** (`0x3eae`) - Transfer/send function ← **HIGH PRIORITY**
- **FUN_000075e2** (`0x75e2`) - Error handler for invalid types

### Callers

- **FUN_00003c08** (`0x3c08`) - Calls this dispatcher

### Related By Pattern

- Other functions using jump tables (search for `movea.l #addr, A0; movea.l (A0,Dn*4)`)
- Other functions calling FUN_00003eae (transfer operations)
- Other functions using global buffer 0x4010000

---

## Testing Notes

### Test Cases for Validation

1. **Type 0-5**: Call with each valid type, verify correct handler invoked
2. **Type > 5**: Call with invalid type (6, 7, 0xFFFFFFFF), verify error handling
3. **String transfer**: Provide long string (>511 bytes), verify truncation
4. **Byte transfer**: Verify single-byte operation
5. **Global write**: Verify 0x81ac receives correct value
6. **Error propagation**: Force FUN_00003eae to fail, verify error code set

### Expected Behavior

- **Valid types**: Should dispatch to appropriate handler
- **Invalid types**: Should call FUN_000075e2, return non-zero
- **Transfer errors**: Should set `result->error_code = -0x131`
- **Case 4 success**: Should return 0 without setting error code

### Debugging Tips

1. **Set breakpoint at 0x6e8e** - Capture jump table reads
2. **Watch 0x4010000** - Monitor buffer state
3. **Watch 0x81ac** - See when case 4 is triggered
4. **Trace FUN_00003eae calls** - Understand transfer protocol
5. **Log type values** - Build histogram of message types seen in practice

---

## Function Size and Complexity Metrics

| Metric                  | Value   |
|-------------------------|---------|
| Total size              | 272 bytes |
| Number of instructions  | ~68     |
| Cyclomatic complexity   | ~8      |
| Number of branches      | 7       |
| Call depth              | 2-3     |
| Stack usage             | 512 bytes |
| Library calls           | 6       |
| Internal calls          | 2       |
| Jump table entries      | 6       |
| Identified cases        | 4       |
| Error paths             | 3       |

**Complexity Rating**: **Medium-High**
Moderate instruction count, but complex control flow with jump table and multiple call paths.

---

**Analysis Date**: 2025-11-08
**Analyst**: Claude Code
**Confidence**: High (control flow), Medium (semantic interpretation)
**Review Status**: Initial analysis complete, awaiting jump table resolution

---

**Next Steps**:
1. Analyze **FUN_00003eae** to understand transfer protocol
2. Analyze **FUN_000075e2** to understand error handling
3. Search for other functions accessing globals 0x4010000 and 0x81ac
4. Investigate jump table initialization (startup code)
5. Find callers to understand message sources
